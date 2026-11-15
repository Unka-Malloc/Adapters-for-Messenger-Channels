//! The Slack channel's normalized `a4mc` surface.
//!
//! [`SlackChannel`] wraps a [`SlackApi`] and exposes the contract
//! surface: a [`ChannelDescriptor`] declaring what this dialect lowers,
//! and `send` lowering [`a4mc::OutboundMessage`] onto `chat.postMessage`.
//! Slack has no server-enforced idempotency key for bot posts, so the
//! adapter dedupes keys locally (marking the feature `adapted`, never
//! claimed native) while also carrying a deterministic `client_msg_id`
//! as far as the platform accepts it.

use crate::transport::{PostMessageRequest, SlackApi};
use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelError, ChannelId, ExternalMessageId, LaneMechanism,
    OutboundMessage, SendFeature, SendReceipt, Support, UpdateKind,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write;
use std::sync::{Arc, Condvar, Mutex};

/// The channel identifier this dialect lowers under.
pub const CHANNEL: &str = "slack";

/// Bound on remembered send receipts; oldest completed entries evict
/// FIFO. In-flight reservations never occupy capacity.
const IDEMPOTENCY_CACHE_CAP: usize = 1024;

/// The dialect's declared capability report.
///
/// Socket Mode is native; the webhook and polling mechanisms are not
/// implemented by this crate, so a firewall that permits no public
/// callback loses nothing. Every update kind Slack's event API reports
/// is lowered. Send-side reply-to is native (Slack threads); idempotency
/// is adapted (adapter-side dedupe); edit and delete are not wired yet
/// and are declared unsupported, never silently dropped.
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

/// The normalized channel surface over one Slack Web API client.
pub struct SlackChannel<A: SlackApi> {
    api: Arc<A>,
    sent_keys: Mutex<IdempotencyCache>,
    /// Wakes sends parked on an in-flight reservation; paired with the
    /// `sent_keys` mutex.
    send_wake: Condvar,
}

#[derive(Clone)]
enum SendState {
    InFlight,
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

    fn complete(&mut self, key: String, receipt: SendReceipt) {
        while self.order.len() >= IDEMPOTENCY_CACHE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, SendState::Done(receipt));
    }

    fn release(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

impl<A: SlackApi> SlackChannel<A> {
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
    /// under the cache lock before the API call, so a repeat key while a
    /// send is in flight waits and replays the observed receipt instead
    /// of double-posting. A failed send releases its reservation so the
    /// waiter or a later retry performs its own call.
    pub fn send(&self, outbound: &OutboundMessage) -> Result<SendReceipt, ChannelError> {
        outbound.validate()?;
        let channel = outbound.chat_id.as_str().trim();
        if channel.chars().any(char::is_whitespace) {
            return Err(ChannelError::new(
                "a4mc_slack_channel_id_invalid",
                "Slack channel id contains whitespace",
            ));
        }
        let thread_ts = match outbound.reply_to_message_id.as_ref() {
            Some(reply) if reply.as_str().trim().is_empty() => {
                return Err(ChannelError::new(
                    "a4mc_slack_reply_target_invalid",
                    "Slack reply target is empty",
                ));
            }
            Some(reply) => Some(reply.as_str().to_owned()),
            None => None,
        };
        {
            let mut cache = self.sent_keys.lock().unwrap();
            loop {
                match cache.get(&outbound.idempotency_key) {
                    Some(SendState::Done(receipt)) => return Ok(receipt),
                    Some(SendState::InFlight) => {
                        cache = self.send_wake.wait(cache).unwrap();
                    }
                    None => {
                        cache.mark_in_flight(outbound.idempotency_key.clone());
                        break;
                    }
                }
            }
        }
        let request = PostMessageRequest {
            channel: channel.to_owned(),
            text: outbound.text.clone(),
            thread_ts,
            client_msg_id: client_msg_id(&outbound.idempotency_key),
        };
        match self.api.post_message(&request) {
            Ok(posted) => {
                let receipt = SendReceipt {
                    idempotency_key: outbound.idempotency_key.clone(),
                    message_ids: vec![ExternalMessageId::from(posted.ts)],
                };
                self.sent_keys
                    .lock()
                    .unwrap()
                    .complete(outbound.idempotency_key.clone(), receipt.clone());
                self.send_wake.notify_all();
                Ok(receipt)
            }
            Err(error) => {
                self.sent_keys
                    .lock()
                    .unwrap()
                    .release(&outbound.idempotency_key);
                self.send_wake.notify_all();
                Err(ChannelError::from(error))
            }
        }
    }
}

impl<A: SlackApi> ChannelAdapter for SlackChannel<A> {
    fn descriptor(&self) -> ChannelDescriptor {
        descriptor()
    }
}

/// Derive the `client_msg_id` Slack accepts from the contract's
/// idempotency key. The derivation is deterministic (FNV-1a over the
/// key, shaped as a UUID) so a retried send carries the same client id.
pub fn client_msg_id(idempotency_key: &str) -> String {
    const OFFSET_BASIS: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut hash = OFFSET_BASIS;
    for byte in idempotency_key.bytes() {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    let mut bytes = hash.to_be_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{MockSlackApi, SlackApiError};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    fn channel() -> (SlackChannel<MockSlackApi>, Arc<MockSlackApi>) {
        let api = Arc::new(MockSlackApi::default());
        let channel = SlackChannel::new(Arc::clone(&api));
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
    fn descriptor_declares_socket_native_and_callback_honesty() {
        let report = descriptor();
        assert_eq!(report.channel.as_str(), "slack");
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
    }

    #[test]
    fn send_lowers_contract_and_returns_slack_ts() {
        let (channel, api) = channel();
        let outbound = OutboundMessage::new("C1", "hello", "send-1");
        let receipt = channel.send(&outbound).unwrap();
        assert_eq!(receipt.idempotency_key, "send-1");
        assert_eq!(receipt.message_ids.len(), 1);
        let posted = api.posted_requests();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].channel, "C1");
        assert_eq!(posted[0].text, "hello");
        assert_eq!(posted[0].client_msg_id, client_msg_id("send-1"));
        assert_eq!(posted[0].thread_ts, None);
    }

    #[test]
    fn reply_target_lowers_to_thread_ts() {
        let (channel, api) = channel();
        let mut outbound = OutboundMessage::new("C1", "threaded", "send-2");
        outbound.reply_to_message_id = Some(ExternalMessageId::from("1700000000.000001"));
        channel.send(&outbound).unwrap();
        let posted = api.posted_requests();
        assert_eq!(posted[0].thread_ts.as_deref(), Some("1700000000.000001"));
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
        *api.post_error.lock().unwrap() = Some(SlackApiError::new(
            "a4mc_slack_api_failed",
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
        assert_eq!(
            channel
                .send(&OutboundMessage::new("C 1", "x", "k"))
                .unwrap_err()
                .code,
            "a4mc_slack_channel_id_invalid"
        );
        let mut empty_reply = OutboundMessage::new("C1", "x", "k2");
        empty_reply.reply_to_message_id = Some(ExternalMessageId::from(" "));
        assert_eq!(
            channel.send(&empty_reply).unwrap_err().code,
            "a4mc_slack_reply_target_invalid"
        );
        assert!(api.posted_requests().is_empty());
    }

    #[test]
    fn client_msg_id_is_deterministic_and_uuid_shaped() {
        let first = client_msg_id("same-key");
        let second = client_msg_id("same-key");
        let other = client_msg_id("other-key");
        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(first.len(), 36);
        let positions: Vec<usize> = first
            .char_indices()
            .filter_map(|(index, ch)| (ch == '-').then_some(index))
            .collect();
        assert_eq!(positions, vec![8, 13, 18, 23]);
        assert_eq!(&first[14..15], "4");
        assert!(matches!(&first[19..20], "8" | "9" | "a" | "b"));
    }

    /// A mock whose `post_message` parks until released, proving a second
    /// same-key send waits rather than posting concurrently.
    struct GatedApi {
        inner: Arc<MockSlackApi>,
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl SlackApi for GatedApi {
        fn auth_test(&self) -> Result<crate::transport::SlackIdentity, SlackApiError> {
            self.inner.auth_test()
        }

        fn open_socket(&self) -> Result<crate::transport::SocketUrl, SlackApiError> {
            self.inner.open_socket()
        }

        fn post_message(
            &self,
            request: &PostMessageRequest,
        ) -> Result<crate::transport::PostedMessage, SlackApiError> {
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
        let api = Arc::new(MockSlackApi::default());
        let channel = Arc::new(SlackChannel::new(Arc::new(GatedApi {
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
        assert_eq!(api.posted.lock().unwrap().len(), 1);
    }
}
