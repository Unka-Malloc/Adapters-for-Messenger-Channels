//! The Slack channel's normalized `a4mc` surface.
//!
//! [`SlackChannel`] wraps a [`SlackApi`] and exposes the contract
//! surface: a [`ChannelDescriptor`] declaring what this dialect lowers,
//! and `send` lowering [`a4mc::OutboundMessage`] onto `chat.postMessage`.
//! Slack has no server-enforced idempotency key for bot posts, so the
//! adapter dedupes keys locally (marking the feature `adapted`, never
//! claimed native) while also carrying a deterministic `client_msg_id`
//! as far as the platform accepts it.
//!
//! The send path runs through [`a4mc::OutboundPipeline`]. No policy is
//! mounted by default; the host may supply one per channel through
//! [`SlackChannel::with_outbound_hooks`] or once for every dialect
//! through `LanePort::outbound_hooks`.

use crate::transport::{PostMessageRequest, SlackApi};
use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelError, ChannelId, ExternalMessageId, LaneMechanism,
    OutboundHooks, OutboundMessage, OutboundPipeline, PreparedSend, SendContext, SendFeature,
    SendReceipt, Support, UpdateKind, unix_now_ms,
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
/// is lowered. Send-side reply-to is native — Slack threading anchors
/// on the thread's parent: `thread_ts` must be the parent message's
/// ts, never a reply's own, so a host answering an inbound thread
/// message carries its `thread_id` (`OutboundMessage::thread_id`);
/// `reply_to_message_id` alone anchors only a reply to the thread's
/// root. Idempotency is adapted (adapter-side dedupe); edit and
/// delete are not wired yet and are declared unsupported, never
/// silently dropped.
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
    pipeline: OutboundPipeline,
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
            pipeline: OutboundPipeline::from_lane(CHANNEL),
            sent_keys: Mutex::new(IdempotencyCache::new()),
            send_wake: Condvar::new(),
        }
    }

    pub fn api(&self) -> &Arc<A> {
        &self.api
    }

    /// The channel's outbound pipeline. A fresh channel resolves the
    /// host's `LanePort::outbound_hooks` provider; without one it is
    /// pass-through.
    pub fn outbound_pipeline(&self) -> &OutboundPipeline {
        &self.pipeline
    }

    /// Mount one caller policy on this channel. It replaces any policy
    /// resolved from the lane port.
    pub fn with_outbound_hooks(mut self, hooks: Arc<dyn OutboundHooks>) -> Self {
        self.pipeline = OutboundPipeline::with_hooks(CHANNEL, hooks);
        self
    }

    /// Mount one caller policy on an already-shared channel.
    pub fn set_outbound_hooks(&mut self, hooks: Arc<dyn OutboundHooks>) {
        self.pipeline = OutboundPipeline::with_hooks(CHANNEL, hooks);
    }

    /// Send one normalized outbound message.
    ///
    /// The contract validates first; the mounted outbound policy then
    /// runs (`skip` → `batch` → `throttle` → `dedupe_key`) before the
    /// idempotency key is reserved under the cache lock and the API call
    /// is made, so a repeat key while a send is in flight waits and
    /// replays the observed receipt instead of double-posting. A failed
    /// send releases its reservation so the waiter or a later retry
    /// performs its own call.
    pub fn send(&self, outbound: &OutboundMessage) -> Result<SendReceipt, ChannelError> {
        self.send_at(outbound, unix_now_ms())
    }

    /// Send at a caller-supplied clock. Tests pin the clock so a
    /// mounted window/throttle policy is deterministic.
    pub fn send_at(
        &self,
        outbound: &OutboundMessage,
        now_ms: u64,
    ) -> Result<SendReceipt, ChannelError> {
        let ctx = SendContext::at(CHANNEL, now_ms);
        self.pipeline
            .execute(outbound, &ctx, |prepared| self.deliver(prepared))
    }

    fn deliver(&self, prepared: &PreparedSend) -> Result<SendReceipt, ChannelError> {
        let outbound = &prepared.message;
        let channel = outbound.chat_id.as_str().trim();
        if channel.chars().any(char::is_whitespace) {
            return Err(ChannelError::new(
                "a4mc_slack_channel_id_invalid",
                "Slack channel id contains whitespace",
            ));
        }
        // Slack anchors a thread on its parent's ts: `thread_id` is
        // the declared parent (required when replying to an inbound
        // thread message, whose own id is a child's); a bare
        // `reply_to_message_id` anchors a reply to the thread's root.
        for id in [&outbound.reply_to_message_id, &outbound.thread_id]
            .into_iter()
            .flatten()
        {
            if id.as_str().trim().is_empty() {
                return Err(ChannelError::new(
                    "a4mc_slack_reply_target_invalid",
                    "Slack reply target is empty",
                ));
            }
        }
        let thread_ts = outbound
            .thread_id
            .as_ref()
            .or(outbound.reply_to_message_id.as_ref())
            .map(|id| id.as_str().to_owned());
        let key = &prepared.dedupe_key;
        {
            let mut cache = self.sent_keys.lock().unwrap();
            loop {
                match cache.get(key) {
                    Some(SendState::Done(receipt)) => return Ok(receipt),
                    Some(SendState::InFlight) => {
                        cache = self.send_wake.wait(cache).unwrap();
                    }
                    None => {
                        cache.mark_in_flight(key.clone());
                        break;
                    }
                }
            }
        }
        let request = PostMessageRequest {
            channel: channel.to_owned(),
            text: outbound.text.clone(),
            thread_ts,
            client_msg_id: client_msg_id(key),
        };
        match self.api.post_message(&request) {
            Ok(posted) => {
                let receipt = SendReceipt {
                    idempotency_key: key.clone(),
                    message_ids: vec![ExternalMessageId::from(posted.ts)],
                };
                self.sent_keys
                    .lock()
                    .unwrap()
                    .complete(key.clone(), receipt.clone());
                self.send_wake.notify_all();
                Ok(receipt)
            }
            Err(error) => {
                self.sent_keys.lock().unwrap().release(key);
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
    fn a_thread_reply_anchors_on_the_parent_not_the_child() {
        // Replying to an inbound thread message supplies its own
        // (child) ts as the reply target; `thread_ts` must carry the
        // parent's `thread_id` — a child's ts is not a valid anchor.
        let (channel, api) = channel();
        let mut outbound = OutboundMessage::new("C1", "threaded", "send-3");
        outbound.reply_to_message_id = Some(ExternalMessageId::from("1700000000.000100"));
        outbound.thread_id = Some(ExternalMessageId::from("1700000000.000001"));
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

    /// One caller policy fixture, shared with the Telegram and Discord
    /// channel suites: the same decisions must give the same observable
    /// behavior in every dialect.
    #[derive(Default)]
    struct HookTrace {
        calls: Mutex<Vec<&'static str>>,
        receipts: Mutex<Vec<SendReceipt>>,
    }

    struct HookPolicy {
        trace: Arc<HookTrace>,
    }

    impl HookPolicy {
        fn record(&self, call: &'static str) {
            self.trace.calls.lock().unwrap().push(call);
        }
    }

    impl a4mc::OutboundHooks for HookPolicy {
        fn skip(&self, _: &a4mc::SendContext, message: &OutboundMessage) -> a4mc::SkipDecision {
            self.record("skip");
            if message.text == "skip-me" {
                a4mc::SkipDecision::skip("caller policy")
            } else {
                a4mc::SkipDecision::Send
            }
        }

        fn batch(&self, _: &a4mc::SendContext, message: &OutboundMessage) -> a4mc::BatchDecision {
            self.record("batch");
            if message.text == "batch-me" {
                a4mc::BatchDecision::replace(
                    message
                        .clone()
                        .with_text(format!("batched:{}", message.text)),
                )
            } else {
                a4mc::BatchDecision::PassThrough
            }
        }

        fn throttle(
            &self,
            _: &a4mc::SendContext,
            message: &OutboundMessage,
        ) -> a4mc::ThrottleDecision {
            self.record("throttle");
            if message.text == "throttle-me" {
                a4mc::ThrottleDecision::defer("budget exhausted", Some(Duration::from_millis(1500)))
            } else {
                a4mc::ThrottleDecision::Allow
            }
        }

        fn dedupe_key(&self, _: &a4mc::SendContext, message: &OutboundMessage) -> Option<String> {
            self.record("dedupe");
            message
                .text
                .starts_with("dedupe")
                .then(|| "hook-dedupe".to_owned())
        }

        fn on_receipt(&self, _: &a4mc::SendContext, _: &OutboundMessage, receipt: &SendReceipt) {
            self.record("receipt");
            self.trace.receipts.lock().unwrap().push(receipt.clone());
        }
    }

    #[test]
    fn unmounted_outbound_policy_is_a_pass_through() {
        let (channel, api) = channel();
        assert!(channel.outbound_pipeline().hooks().is_none());
        let receipt = channel
            .send_at(&OutboundMessage::new("C1", "plain", "plain-1"), 1_000)
            .unwrap();
        assert_eq!(receipt.idempotency_key, "plain-1");
        assert_eq!(receipt.message_ids.len(), 1);
        let posted = api.posted_requests();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].text, "plain");
    }

    #[test]
    fn mounted_hooks_apply_uniformly_to_every_send_decision() {
        let (channel, api) = channel();
        let trace = Arc::new(HookTrace::default());
        let channel = channel.with_outbound_hooks(Arc::new(HookPolicy {
            trace: Arc::clone(&trace),
        }));

        let plain = channel
            .send_at(&OutboundMessage::new("C1", "plain", "plain-1"), 1_000)
            .unwrap();
        assert_eq!(plain.idempotency_key, "plain-1");
        assert_eq!(trace.receipts.lock().unwrap().len(), 1);
        assert_eq!(
            *trace.calls.lock().unwrap(),
            vec!["skip", "batch", "throttle", "dedupe", "receipt"]
        );

        let skipped = channel
            .send_at(&OutboundMessage::new("C1", "skip-me", "skip-1"), 1_000)
            .unwrap();
        assert!(skipped.is_skipped());
        assert_eq!(skipped.idempotency_key, "skip-1");
        assert_eq!(api.posted_requests().len(), 1);
        assert_eq!(trace.receipts.lock().unwrap().len(), 1);

        let batched = channel
            .send_at(&OutboundMessage::new("C1", "batch-me", "batch-1"), 1_000)
            .unwrap();
        assert_eq!(batched.message_ids.len(), 1);
        assert_eq!(api.posted_requests()[1].text, "batched:batch-me");
        assert_eq!(trace.receipts.lock().unwrap().len(), 2);

        let error = channel
            .send_at(
                &OutboundMessage::new("C1", "throttle-me", "throttle-1"),
                1_000,
            )
            .unwrap_err();
        assert_eq!(error.code, "a4mc_outbound_throttled");
        assert!(error.message.contains("retryAfterMs=1500"));
        assert_eq!(api.posted_requests().len(), 2);
        assert_eq!(trace.receipts.lock().unwrap().len(), 2);

        let first = channel
            .send_at(&OutboundMessage::new("C1", "dedupe-a", "contract-a"), 1_000)
            .unwrap();
        let replay = channel
            .send_at(&OutboundMessage::new("C1", "dedupe-b", "contract-b"), 1_000)
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.idempotency_key, "hook-dedupe");
        assert_eq!(api.posted_requests().len(), 3);
        assert_eq!(
            api.posted_requests()[2].text,
            "dedupe-a",
            "the deduplicated replay must not post the second payload"
        );
        assert_eq!(
            api.posted_requests()[2].client_msg_id,
            client_msg_id("hook-dedupe")
        );
    }
}
