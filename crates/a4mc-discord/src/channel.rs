//! The Discord channel's normalized `a4mc` surface.
//!
//! [`DiscordChannel`] wraps a [`DiscordApi`] and exposes the contract
//! surface: a [`ChannelDescriptor`] declaring what this dialect lowers,
//! and `send` lowering [`a4mc::OutboundMessage`] onto Discord's REST
//! message create endpoint. Discord supports a nonce with
//! `enforce_nonce`, but that is a bounded platform window, so the
//! adapter combines it with a local dedupe cache and declares
//! idempotency `adapted`, never native.
//!
//! Discord caps one message's content at 2,000 characters, below the
//! contract's 32 KiB bound. Sends split on a safe boundary and report
//! every part's message id. A send that stops mid-flight keeps its
//! confirmed prefix and next part index under the idempotency key, so a
//! same-key retry resumes at the failed part instead of reposting the
//! prefix; a part whose outcome is unclear is resent under the same
//! deterministic nonce, which `enforce_nonce` dedupes server-side.

use crate::transport::{DiscordApi, PostMessageRequest};
use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelError, ChannelId, ExternalMessageId, LaneMechanism,
    OutboundMessage, SendFeature, SendReceipt, Support, UpdateKind,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

/// The channel identifier this dialect lowers under.
pub const CHANNEL: &str = "discord";

/// Discord's per-message content bound, in characters.
pub const MAX_CONTENT_CHARS: usize = 2_000;

/// Bound on remembered send receipts; oldest completed entries evict
/// FIFO. In-flight reservations never occupy capacity.
const IDEMPOTENCY_CACHE_CAP: usize = 1024;

/// The dialect's declared capability report.
///
/// The Gateway is native; webhook and polling mechanisms are not
/// implemented by this crate. Every update kind Discord's Gateway
/// reports is lowered: bulk deletion expands to one deletion event per
/// id, reaction add/remove lower natively while remove-all variants are
/// surfaced as `Unsupported`, and member events additionally need the
/// privileged `GUILD_MEMBERS` intent. Send-side reply-to is native,
/// idempotency is adapted (nonce plus adapter-side dedupe); edit and
/// delete are not wired and are declared unsupported, never silently
/// dropped.
pub fn descriptor() -> ChannelDescriptor {
    ChannelDescriptor {
        channel: ChannelId::from(CHANNEL),
        receive: BTreeMap::from([
            (LaneMechanism::Socket, Support::Native),
            (LaneMechanism::Webhook, Support::Unsupported),
            (LaneMechanism::Poll, Support::Unsupported),
        ]),
        updates: BTreeMap::from([
            (UpdateKind::Message, Support::Native),
            (UpdateKind::MessageEdited, Support::Native),
            (UpdateKind::MessageDeleted, Support::Native),
            (UpdateKind::MemberJoined, Support::Native),
            (UpdateKind::MemberLeft, Support::Native),
            (UpdateKind::Reaction, Support::Native),
        ]),
        sends: BTreeMap::from([
            (SendFeature::Idempotency, Support::Adapted),
            (SendFeature::ReplyTo, Support::Native),
            (SendFeature::Edit, Support::Unsupported),
            (SendFeature::Delete, Support::Unsupported),
        ]),
    }
}

/// The normalized channel surface over one Discord REST client.
pub struct DiscordChannel<A: DiscordApi> {
    api: Arc<A>,
    sent_keys: Mutex<IdempotencyCache>,
    send_wake: Condvar,
}

#[derive(Clone)]
enum SendState {
    InFlight,
    /// A send that stopped mid-flight: the confirmed prefix and the
    /// next part to attempt. Retrying parts under the same key reposts
    /// the next part with its deterministic nonce — confirmed parts
    /// never leave the adapter twice.
    Partial {
        confirmed: Vec<ExternalMessageId>,
        next_part: usize,
    },
    Done(SendReceipt),
}

struct IdempotencyCache {
    order: VecDeque<String>,
    entries: HashMap<String, SendState>,
}

impl IdempotencyCache {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&self, key: &str) -> Option<SendState> {
        self.entries.get(key).cloned()
    }

    fn mark_in_flight(&mut self, key: String) {
        self.entries.insert(key, SendState::InFlight);
    }

    /// Record a send that stopped mid-flight: the confirmed prefix and
    /// the part index to resume at stay under the key so a same-key
    /// retry does not repost confirmed parts.
    fn set_partial(&mut self, key: String, confirmed: Vec<ExternalMessageId>, next_part: usize) {
        self.entries.insert(
            key,
            SendState::Partial {
                confirmed,
                next_part,
            },
        );
    }

    fn complete(&mut self, key: String, receipt: SendReceipt) {
        while self.order.len() >= IDEMPOTENCY_CACHE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, SendState::Done(receipt));
    }
}

impl<A: DiscordApi> DiscordChannel<A> {
    pub fn new(api: Arc<A>) -> Self {
        Self {
            api,
            sent_keys: Mutex::new(IdempotencyCache::new()),
            send_wake: Condvar::new(),
        }
    }

    pub fn api(&self) -> &Arc<A> {
        &self.api
    }

    /// Send one normalized outbound message.
    ///
    /// The contract validates first; the idempotency key is reserved
    /// under the cache lock before the first API call, so a repeat key
    /// while a send is in flight waits and replays the observed receipt
    /// instead of double-posting. A send that stops mid-flight leaves a
    /// partial record — confirmed part ids plus the next part index —
    /// under the key, so the retry (or a waiter that takes over)
    /// resumes at the failed part. A part with an unclear outcome is
    /// resent under its deterministic nonce, which `enforce_nonce`
    /// dedupes server-side; the completed receipt returns every
    /// confirmed and newly posted id.
    pub fn send(&self, outbound: &OutboundMessage) -> Result<SendReceipt, ChannelError> {
        outbound.validate()?;
        let channel = outbound.chat_id.as_str().trim();
        // Discord channel ids are snowflakes. Restrict the path segment to
        // alphanumerics and a bounded length so an untrusted id can never
        // rewrite the REST path.
        if channel.is_empty()
            || channel.len() > 64
            || !channel.chars().all(|ch| ch.is_ascii_alphanumeric())
        {
            return Err(ChannelError::new(
                "a4mc_discord_channel_id_invalid",
                "Discord channel id is not a bounded path segment",
            ));
        }
        let reply_to = match outbound.reply_to_message_id.as_ref() {
            Some(reply) if reply.as_str().trim().is_empty() => {
                return Err(ChannelError::new(
                    "a4mc_discord_reply_target_invalid",
                    "Discord reply target is empty",
                ));
            }
            Some(reply) => Some(reply.as_str().to_owned()),
            None => None,
        };
        let parts = split_content(&outbound.text);
        let (mut message_ids, start_part) = {
            let mut cache = self.sent_keys.lock().unwrap();
            loop {
                match cache.get(&outbound.idempotency_key) {
                    Some(SendState::Done(receipt)) => return Ok(receipt),
                    Some(SendState::InFlight) => {
                        cache = self.send_wake.wait(cache).unwrap();
                    }
                    Some(SendState::Partial {
                        confirmed,
                        next_part,
                    }) => {
                        cache.mark_in_flight(outbound.idempotency_key.clone());
                        break (confirmed, next_part.min(parts.len()));
                    }
                    None => {
                        cache.mark_in_flight(outbound.idempotency_key.clone());
                        break (Vec::with_capacity(parts.len()), 0);
                    }
                }
            }
        };

        for (index, part) in parts.iter().enumerate().skip(start_part) {
            let request = PostMessageRequest {
                channel_id: channel.to_owned(),
                content: (*part).to_owned(),
                reply_to_message_id: if index == 0 { reply_to.clone() } else { None },
                // One deterministic nonce per (key, part): reposting a
                // part whose earlier outcome is unclear is deduped by
                // the platform's enforce_nonce rather than blind.
                nonce: client_nonce(&outbound.idempotency_key, index),
            };
            match self.api.post_message(&request) {
                Ok(posted) => message_ids.push(ExternalMessageId::from(posted.id)),
                Err(error) => {
                    self.sent_keys.lock().unwrap().set_partial(
                        outbound.idempotency_key.clone(),
                        message_ids,
                        index,
                    );
                    self.send_wake.notify_all();
                    return Err(ChannelError::from(error));
                }
            }
        }
        let receipt = SendReceipt {
            idempotency_key: outbound.idempotency_key.clone(),
            message_ids,
        };
        self.sent_keys
            .lock()
            .unwrap()
            .complete(outbound.idempotency_key.clone(), receipt.clone());
        self.send_wake.notify_all();
        Ok(receipt)
    }
}

impl<A: DiscordApi> ChannelAdapter for DiscordChannel<A> {
    fn descriptor(&self) -> ChannelDescriptor {
        descriptor()
    }
}

/// Derive Discord's nonce from the contract's idempotency key and part
/// index. Deterministic (FNV-1a), 16 hex characters — inside Discord's
/// 25-character nonce bound — so a retried send carries the same nonce.
pub fn client_nonce(idempotency_key: &str, part: usize) -> String {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in idempotency_key
        .bytes()
        .chain([0x1f])
        .chain(part.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Split text into Discord-sized parts without dropping a character.
/// Prefers a newline in the window's trailing half so prose stays
/// readable; otherwise cuts at the character boundary.
fn split_content(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let remaining = &text[start..];
        if remaining.chars().count() <= MAX_CONTENT_CHARS {
            parts.push(remaining);
            break;
        }
        let mut end = start + MAX_CONTENT_CHARS;
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(position) = text[start..end].rfind('\n')
            && position >= MAX_CONTENT_CHARS / 2
        {
            end = start + position + 1;
        }
        if end <= start {
            // A 2,000-byte window always contains at least one character
            // on a valid UTF-8 boundary; this guard keeps the function
            // total even if the bound is ever lowered.
            end = text[start..]
                .char_indices()
                .nth(1)
                .map(|(index, _)| start + index)
                .unwrap_or(text.len());
        }
        parts.push(&text[start..end]);
        start = end;
    }
    if parts.is_empty() {
        parts.push("");
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DiscordApiError, MockDiscordApi};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    fn channel() -> (DiscordChannel<MockDiscordApi>, Arc<MockDiscordApi>) {
        let api = Arc::new(MockDiscordApi::default());
        let channel = DiscordChannel::new(Arc::clone(&api));
        (channel, api)
    }

    fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn descriptor_declares_gateway_native_and_send_honesty() {
        let report = descriptor();
        assert_eq!(report.channel.as_str(), "discord");
        assert_eq!(
            report.receive_support(LaneMechanism::Socket),
            Support::Native
        );
        assert_eq!(
            report.receive_support(LaneMechanism::Webhook),
            Support::Unsupported
        );
        assert_eq!(
            report.receive_support(LaneMechanism::Poll),
            Support::Unsupported
        );
        for kind in [
            UpdateKind::Message,
            UpdateKind::MessageEdited,
            UpdateKind::MessageDeleted,
            UpdateKind::MemberJoined,
            UpdateKind::MemberLeft,
            UpdateKind::Reaction,
        ] {
            assert_eq!(report.update_support(kind), Support::Native);
        }
        assert_eq!(
            report.send_support(SendFeature::Idempotency),
            Support::Adapted
        );
        assert_eq!(report.send_support(SendFeature::ReplyTo), Support::Native);
        assert_eq!(report.send_support(SendFeature::Edit), Support::Unsupported);
        assert_eq!(
            report.send_support(SendFeature::Delete),
            Support::Unsupported
        );
    }

    #[test]
    fn send_lowers_contract_and_returns_message_id() {
        let (channel, api) = channel();
        let outbound = OutboundMessage::new("C1", "hello", "send-1");
        let receipt = channel.send(&outbound).unwrap();
        assert_eq!(receipt.idempotency_key, "send-1");
        assert_eq!(receipt.message_ids.len(), 1);
        let posted = api.posted_requests();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].channel_id, "C1");
        assert_eq!(posted[0].content, "hello");
        assert_eq!(posted[0].nonce, client_nonce("send-1", 0));
        assert!(posted[0].reply_to_message_id.is_none());
    }

    #[test]
    fn reply_target_lowers_to_message_reference() {
        let (channel, api) = channel();
        let mut outbound = OutboundMessage::new("C1", "threaded", "send-2");
        outbound.reply_to_message_id = Some(ExternalMessageId::from("M0"));
        channel.send(&outbound).unwrap();
        let posted = api.posted_requests();
        assert_eq!(posted[0].reply_to_message_id.as_deref(), Some("M0"));
    }

    #[test]
    fn repeated_idempotency_key_does_not_double_post() {
        let (channel, api) = channel();
        let outbound = OutboundMessage::new("C1", "hello", "send-dup");
        let first = channel.send(&outbound).unwrap();
        let second = channel.send(&outbound).unwrap();
        assert_eq!(first, second);
        assert_eq!(api.posted_requests().len(), 1);
    }

    #[test]
    fn failed_send_releases_key_for_retry() {
        let (channel, api) = channel();
        *api.post_error.lock().unwrap() = Some(DiscordApiError::new(
            "a4mc_discord_api_failed",
            "fixture failure",
        ));
        let outbound = OutboundMessage::new("C1", "hello", "send-retry");
        assert!(channel.send(&outbound).is_err());
        *api.post_error.lock().unwrap() = None;
        channel.send(&outbound).unwrap();
        assert_eq!(api.posted_requests().len(), 1);
    }

    #[test]
    fn invalid_sends_are_rejected_before_the_api_call() {
        let (channel, api) = channel();
        assert!(channel.send(&OutboundMessage::new("C1", "", "k")).is_err());
        assert!(channel.send(&OutboundMessage::new("C1", "x", " ")).is_err());
        for invalid in ["C 1", "C/1", "C?1", ".."] {
            assert_eq!(
                channel
                    .send(&OutboundMessage::new(invalid, "x", "k"))
                    .unwrap_err()
                    .code,
                "a4mc_discord_channel_id_invalid"
            );
        }
        let mut empty_reply = OutboundMessage::new("C1", "x", "k2");
        empty_reply.reply_to_message_id = Some(ExternalMessageId::from(" "));
        assert_eq!(
            channel.send(&empty_reply).unwrap_err().code,
            "a4mc_discord_reply_target_invalid"
        );
        assert!(api.posted_requests().is_empty());
    }

    #[test]
    fn long_text_splits_without_dropping_characters() {
        let (channel, api) = channel();
        let text = format!("{}\n{}", "a".repeat(1_500), "b".repeat(1_500));
        let receipt = channel
            .send(&OutboundMessage::new("C1", text.clone(), "send-long"))
            .unwrap();
        assert_eq!(receipt.message_ids.len(), 2);
        let posted = api.posted_requests();
        let joined: String = posted
            .iter()
            .map(|request| request.content.as_str())
            .collect();
        assert_eq!(joined, text);
        assert_ne!(posted[0].nonce, posted[1].nonce);
        assert!(posted[0].content.chars().count() <= MAX_CONTENT_CHARS);
        assert!(posted[1].content.chars().count() <= MAX_CONTENT_CHARS);
    }

    #[test]
    fn split_prefers_newlines_and_preserves_multibyte_text() {
        let text = format!("{}\n{}", "x".repeat(1_500), "é".repeat(900));
        let parts = split_content(&text);
        assert_eq!(parts.concat(), text);
        assert!(
            parts
                .iter()
                .all(|part| part.chars().count() <= MAX_CONTENT_CHARS)
        );
        assert!(parts[0].ends_with('\n'));

        let emoji = "🙂".repeat(2_500);
        let parts = split_content(&emoji);
        assert_eq!(parts.concat(), emoji);
        assert!(
            parts
                .iter()
                .all(|part| part.chars().count() <= MAX_CONTENT_CHARS)
        );
    }

    #[test]
    fn client_nonce_is_deterministic_and_bounded() {
        let first = client_nonce("same-key", 0);
        let second = client_nonce("same-key", 0);
        let other = client_nonce("same-key", 1);
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(first.len() <= 25);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    struct GatedApi {
        inner: Arc<MockDiscordApi>,
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl DiscordApi for GatedApi {
        fn current_user(&self) -> Result<crate::transport::DiscordIdentity, DiscordApiError> {
            self.inner.current_user()
        }

        fn post_message(
            &self,
            request: &PostMessageRequest,
        ) -> Result<crate::transport::PostedMessage, DiscordApiError> {
            self.entered.store(true, Ordering::SeqCst);
            let (mutex, condvar) = &*self.release;
            let mut released = mutex.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            drop(released);
            self.inner.post_message(request)
        }
    }

    #[test]
    fn concurrent_same_key_posts_once_and_shares_the_receipt() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let api = Arc::new(MockDiscordApi::default());
        let channel = Arc::new(DiscordChannel::new(Arc::new(GatedApi {
            inner: Arc::clone(&api),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        })));

        let first = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("C1", "hello", "send-race")))
        };
        wait_until(|| entered.load(Ordering::SeqCst), Duration::from_secs(5));
        let second = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("C1", "hello", "send-race")))
        };
        thread::sleep(Duration::from_millis(50));
        {
            let (mutex, condvar) = &*release;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        assert_eq!(first, second);
        assert_eq!(api.posted_requests().len(), 1);
    }
}
