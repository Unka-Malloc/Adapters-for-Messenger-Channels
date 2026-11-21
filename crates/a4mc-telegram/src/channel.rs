//! The Telegram channel's normalized `a4mc` surface.
//!
//! [`TelegramChannel`] wraps a [`BotTransport`] and exposes the contract
//! surface: a [`ChannelDescriptor`] declaring what this dialect lowers,
//! and `send` lowering [`OutboundMessage`] onto `sendMessage` — including
//! adapter-side idempotency dedupe, since the Bot API has no native key.
//! A key is reserved while its send is in flight and resolved to the
//! observed receipt when it completes; a repeat send joins the in-flight
//! attempt or replays the receipt instead of double-posting.
//!
//! The send path runs through [`a4mc::OutboundPipeline`]. No policy is
//! mounted by default; the host may supply one per channel through
//! [`TelegramChannel::with_outbound_hooks`] or once for every dialect
//! through `LanePort::outbound_hooks`.

use crate::transport::{BotTransport, SendBinding, SendProgress, TelegramApiError};
use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelError, ChannelId, ExternalMessageId, LaneMechanism,
    OutboundHooks, OutboundMessage, OutboundPipeline, PreparedSend, SendContext, SendFeature,
    SendReceipt, Support, UpdateKind, unix_now_ms,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

/// The channel identifier this dialect lowers under.
pub const CHANNEL: &str = "telegram";

/// Bound on remembered send receipts — generous headroom over one
/// channel's send rate; oldest entries evict FIFO.
const IDEMPOTENCY_CACHE_CAP: usize = 1024;

/// The dialect's declared capability report. Message and edited-message
/// receive are native (`getUpdates` long polling); the Bot API also
/// offers a webhook mechanism this dialect does not implement — declared
/// unsupported, not silently dropped. Deletion is never reported by the
/// platform; member and reaction updates exist but are not wired yet.
pub fn descriptor() -> ChannelDescriptor {
    ChannelDescriptor {
        channel: ChannelId::from(CHANNEL),
        receive: BTreeMap::from([
            (LaneMechanism::Poll, Support::Native),
            (LaneMechanism::Webhook, Support::Unsupported),
            (LaneMechanism::Socket, Support::Unsupported),
        ]),
        updates: BTreeMap::from([
            (UpdateKind::Message, Support::Native),
            (UpdateKind::MessageEdited, Support::Native),
            (UpdateKind::MessageDeleted, Support::Unsupported),
            (UpdateKind::MemberJoined, Support::Unsupported),
            (UpdateKind::MemberLeft, Support::Unsupported),
            (UpdateKind::Reaction, Support::Unsupported),
        ]),
        sends: BTreeMap::from([
            (SendFeature::Idempotency, Support::Adapted),
            (SendFeature::ReplyTo, Support::Native),
            (SendFeature::Edit, Support::Unsupported),
            (SendFeature::Delete, Support::Unsupported),
        ]),
    }
}

/// The normalized channel surface over one Bot API transport.
pub struct TelegramChannel<T: BotTransport> {
    transport: Arc<T>,
    pipeline: OutboundPipeline,
    sent_keys: Mutex<IdempotencyCache>,
    /// Wakes sends parked on an in-flight reservation; paired with the
    /// `sent_keys` mutex.
    send_wake: Condvar,
}

/// One idempotency-key slot: a reservation held across an in-flight
/// send, the receipt of an observed send, or the progress of a send
/// that stopped mid-flight — its confirmed prefix and the part that
/// stopped it, so a same-key retry resumes instead of reposting.
#[derive(Clone)]
enum SendState {
    InFlight,
    Done(SendReceipt),
    Partial(SendProgress),
}

struct IdempotencyCache {
    /// FIFO order of *completed* keys for eviction — in-flight
    /// reservations never occupy capacity and are never evicted.
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

    /// Drop a reservation whose send failed before any part could be
    /// confirmed: only *observed* sends are deduped, so a fully failed
    /// attempt frees the key for its waiters or a later retry.
    fn release(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Record a send that stopped mid-flight: the confirmed prefix and
    /// resume point stay under the key so a retry continues the same
    /// logical send instead of reposting delivered parts.
    fn set_partial(&mut self, key: String, progress: SendProgress) {
        self.entries.insert(key, SendState::Partial(progress));
    }
}

impl<T: BotTransport> TelegramChannel<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            transport,
            pipeline: OutboundPipeline::from_lane(CHANNEL),
            sent_keys: Mutex::new(IdempotencyCache::new()),
            send_wake: Condvar::new(),
        }
    }

    pub fn transport(&self) -> &Arc<T> {
        &self.transport
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

    /// Drop a dedupe key's cached mid-flight checkpoint: the recorded
    /// reply that checkpoint was earned on has been safely replaced
    /// before any part was confirmed, so the stale position would only
    /// refuse the replacement's send as a resume mismatch. A partial
    /// holding confirmed parts or an uncertain outcome stays —
    /// confirmed chunks are never reposted, and an uncertain record is
    /// the dedupe record that keeps a possibly-posted part from being
    /// sent twice.
    pub(crate) fn discard_partial(&self, key: &str) {
        let mut cache = self.sent_keys.lock().unwrap();
        if matches!(
            cache.entries.get(key),
            Some(SendState::Partial(progress))
                if progress.confirmed.is_empty() && !progress.outcome_unknown
        ) {
            cache.entries.remove(key);
        }
    }

    /// Send one normalized outbound message.
    ///
    /// The contract validates first; the mounted outbound policy then
    /// runs (`skip` → `batch` → `throttle` → `dedupe_key`) before the
    /// idempotency key is reserved under the cache lock *before* the
    /// transport call, so check-and-send is atomic: a repeat key while a
    /// send is in flight waits on `send_wake` and replays the observed
    /// receipt instead of posting a duplicate (adapter-side dedupe — the
    /// platform itself has no key, which is why the descriptor marks
    /// idempotency `Adapted`). A failed send releases its reservation:
    /// dedupe covers observed sends only, so the waiter then performs its
    /// own transport call rather than pinning the key to someone else's
    /// failure. Reply targets and platform id shapes lower here, never
    /// inside the transport.
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
        let mut observed = None;
        self.pipeline.execute(outbound, &ctx, |prepared| {
            self.deliver(
                prepared,
                None,
                &mut observed,
                &mut |_: &SendProgress| Ok(()),
            )
        })
    }

    /// Send like [`TelegramChannel::send`], for a caller that persists
    /// delivery progress: `resume` is the checkpoint an earlier
    /// attempt of the same logical send recorded (the confirmed part
    /// prefix is never reposted; an uncertain stopping outcome is
    /// refused like a cached `Partial`), `observe` receives each
    /// part-level checkpoint the transport reaches — an in-flight
    /// marker before every POST and the confirmation after it — and
    /// the failure carries the checkpoint the attempt left behind so
    /// the caller can persist it again instead of restarting the send
    /// from zero.
    pub(crate) fn send_tracked(
        &self,
        outbound: &OutboundMessage,
        resume: Option<&SendProgress>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<SendReceipt, TrackedSendError> {
        let ctx = SendContext::at(CHANNEL, unix_now_ms());
        let mut observed = None;
        self.pipeline
            .execute(outbound, &ctx, |prepared| {
                self.deliver(prepared, resume, &mut observed, observe)
            })
            .map_err(|error| TrackedSendError {
                error,
                progress: observed,
            })
    }

    fn deliver(
        &self,
        prepared: &PreparedSend,
        resume: Option<&SendProgress>,
        observed: &mut Option<Box<SendProgress>>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<SendReceipt, ChannelError> {
        let outbound = &prepared.message;
        let chat_id: i64 = outbound.chat_id.as_str().parse().map_err(|_| {
            ChannelError::new(
                "a4mc_telegram_chat_id_invalid",
                "chat id is not a Telegram integer",
            )
        })?;
        let reply_to = outbound
            .reply_to_message_id
            .as_ref()
            .map(|id| {
                id.as_str().parse::<i64>().map_err(|_| {
                    ChannelError::new(
                        "a4mc_telegram_message_id_invalid",
                        "reply target is not a Telegram message id",
                    )
                })
            })
            .transpose()?;
        let key = &prepared.dedupe_key;
        // A checkpoint only ever resumes the prepared send it was
        // earned on: the hooks just ran, so a policy that rewrote the
        // text or the destination cannot borrow the old chunk
        // position and drop a tail into a different message.
        let expected = send_binding(chat_id, outbound, key);
        // The caller's checkpoint is validated against the prepared
        // send BEFORE the key's cache is consulted: a hook that remapped
        // this send onto a key another send already used must not let a
        // foreign checkpoint inherit that send's receipt or resume its
        // partial progress.
        if resume.is_some_and(|progress| progress.outcome_unknown) {
            return Err(ambiguous_send_error());
        }
        if resume.is_some_and(|p| !binding_applies(p.binding.as_ref(), &expected)) {
            return Err(resume_mismatch_error());
        }
        let progress = {
            let mut cache = self.sent_keys.lock().unwrap();
            loop {
                match cache.get(key) {
                    Some(SendState::Done(receipt)) => return Ok(receipt),
                    Some(SendState::InFlight) => {
                        cache = self.send_wake.wait(cache).unwrap();
                    }
                    Some(SendState::Partial(progress)) => {
                        if progress.outcome_unknown {
                            // The stopping part may already be posted;
                            // resending it could duplicate a delivered
                            // message, so the key refuses rather than
                            // blindly reposting.
                            return Err(ambiguous_send_error());
                        }
                        if !binding_applies(progress.binding.as_ref(), &expected) {
                            // Hand the refused checkpoint back to the
                            // caller: its confirmed prefix and the
                            // effective key its binding names decide
                            // whether dropping it is safe — a binding
                            // mismatch alone never proves the platform
                            // confirmed nothing.
                            *observed = Some(Box::new(progress.clone()));
                            return Err(resume_mismatch_error());
                        }
                        cache.mark_in_flight(key.clone());
                        break progress;
                    }
                    None => {
                        cache.mark_in_flight(key.clone());
                        let mut progress = resume.cloned().unwrap_or_default();
                        progress.binding = Some(expected.clone());
                        break progress;
                    }
                }
            }
        };
        match self.transport.send_message(
            chat_id,
            &outbound.text,
            reply_to,
            Some(&progress),
            observe,
        ) {
            Ok(message_ids) => {
                let receipt = SendReceipt {
                    idempotency_key: key.clone(),
                    message_ids: progress
                        .confirmed
                        .into_iter()
                        .chain(message_ids)
                        .map(ExternalMessageId::from)
                        .collect(),
                };
                self.sent_keys
                    .lock()
                    .unwrap()
                    .complete(key.clone(), receipt.clone());
                self.send_wake.notify_all();
                Ok(receipt)
            }
            Err(error) => {
                *observed = error.send_progress.clone();
                {
                    let mut cache = self.sent_keys.lock().unwrap();
                    match error.send_progress.as_deref().cloned() {
                        Some(progress) => cache.set_partial(key.clone(), progress),
                        None => cache.release(key),
                    }
                }
                self.send_wake.notify_all();
                Err(ChannelError::from(error))
            }
        }
    }
}

/// The effective-send fingerprint a checkpoint is bound to: the dedupe
/// key, the lowered destination, and a digest of the lowered payload.
/// The payload digests rather than duplicates — checkpoints live in
/// bounded durable state.
fn send_binding(chat_id: i64, outbound: &OutboundMessage, key: &str) -> SendBinding {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    // Field-separated encoding: every field is length-prefixed so a
    // text tail can never collide with a reply-target prefix — text
    // ending in NUL + "7" with no target hashes differently from the
    // bare text with reply target "7".
    hasher.update((outbound.text.len() as u64).to_be_bytes());
    hasher.update(outbound.text.as_bytes());
    match &outbound.reply_to_message_id {
        Some(reply_to) => {
            let bytes = reply_to.as_str().as_bytes();
            hasher.update([1u8]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update([0u8]),
    }
    SendBinding {
        dedupe_key: key.to_owned(),
        chat_id,
        payload_digest: format!("{:x}", hasher.finalize()),
    }
}

/// Whether a stored checkpoint binding may resume this prepared send.
/// A checkpoint recorded before bindings existed carries none and
/// resumes unverifiable — exactly as it did when written.
fn binding_applies(stored: Option<&SendBinding>, expected: &SendBinding) -> bool {
    stored.is_none_or(|stored| stored == expected)
}

/// The stable refusal for a send whose stopping part's outcome never
/// reached us — the platform may have posted it, so resending could
/// duplicate a delivered message.
fn ambiguous_send_error() -> ChannelError {
    ChannelError::new(
        "a4mc_telegram_send_ambiguous",
        "send stopped with an unconfirmed part; its delivery cannot be verified or safely retried",
    )
}

/// The stable refusal for a checkpoint that cannot apply to this
/// prepared send — its position belongs to a different outbound
/// message.
fn resume_mismatch_error() -> ChannelError {
    ChannelError::new(
        "a4mc_telegram_resume_mismatch",
        "send checkpoint does not match the prepared send; its progress belongs to a different outbound message",
    )
}

/// The failure of one [`TelegramChannel::send_tracked`] call: the
/// normalized error plus the mid-flight checkpoint the transport
/// recorded — `None` for failures outside a chunked send or before
/// the transport ran. A resume-mismatch refusal instead carries the
/// cached checkpoint that could not apply, so the caller can inspect
/// the progress it would have to discard.
#[derive(Debug)]
pub(crate) struct TrackedSendError {
    pub error: ChannelError,
    pub progress: Option<Box<SendProgress>>,
}

impl<T: BotTransport> ChannelAdapter for TelegramChannel<T> {
    fn descriptor(&self) -> ChannelDescriptor {
        descriptor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{BotIdentity, MockBotTransport, SendProgress, TelegramApiError, Update};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    fn channel() -> (TelegramChannel<MockBotTransport>, Arc<MockBotTransport>) {
        let transport = Arc::new(MockBotTransport::default());
        let channel = TelegramChannel::new(Arc::clone(&transport));
        (channel, transport)
    }

    fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// A mock whose `send_message` parks until the test releases it, so a
    /// second same-key send provably arrives while the first is in flight.
    struct GatedSendTransport {
        inner: MockBotTransport,
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl BotTransport for GatedSendTransport {
        fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
            self.inner.get_me()
        }
        fn delete_webhook(&self) -> Result<(), TelegramApiError> {
            self.inner.delete_webhook()
        }
        fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
            self.inner.set_my_commands(commands)
        }
        fn get_updates(
            &self,
            offset: i64,
            timeout_secs: u64,
        ) -> Result<Vec<Update>, TelegramApiError> {
            self.inner.get_updates(offset, timeout_secs)
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            reply_to_message_id: Option<i64>,
            resume: Option<&SendProgress>,
            observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.entered.store(true, Ordering::SeqCst);
            let (mutex, condvar) = &*self.release;
            let mut released = mutex.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            drop(released);
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume, observe)
        }
    }

    #[test]
    fn descriptor_declares_gaps_honestly() {
        let report = descriptor();
        assert_eq!(report.channel.as_str(), "telegram");
        assert_eq!(report.receive_support(LaneMechanism::Poll), Support::Native);
        assert_eq!(
            report.receive_support(LaneMechanism::Webhook),
            Support::Unsupported
        );
        assert_eq!(report.update_support(UpdateKind::Message), Support::Native);
        assert_eq!(
            report.update_support(UpdateKind::MessageDeleted),
            Support::Unsupported
        );
        assert_eq!(
            report.send_support(SendFeature::Idempotency),
            Support::Adapted
        );
        assert_eq!(report.send_support(SendFeature::ReplyTo), Support::Native);
    }

    #[test]
    fn send_lowers_contract_and_returns_platform_ids() {
        let (channel, transport) = channel();
        let mut outbound = OutboundMessage::new("42", "hello", "send-1");
        outbound.reply_to_message_id = Some(a4mc::ExternalMessageId::from("7"));
        let receipt = channel.send(&outbound).unwrap();
        assert_eq!(receipt.idempotency_key, "send-1");
        assert_eq!(receipt.message_ids.len(), 1);
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
        assert_eq!(transport.sent.lock().unwrap()[0].0, 42);
    }

    #[test]
    fn repeated_idempotency_key_does_not_double_post() {
        let (channel, transport) = channel();
        let outbound = OutboundMessage::new("42", "hello", "send-dup");
        let first = channel.send(&outbound).unwrap();
        let second = channel.send(&outbound).unwrap();
        assert_eq!(first, second);
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_same_key_send_posts_once_and_shares_one_receipt() {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let inner = MockBotTransport::default();
        let sent = Arc::clone(&inner.sent);
        let channel = Arc::new(TelegramChannel::new(Arc::new(GatedSendTransport {
            inner,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        })));

        let first = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("42", "hello", "send-race")))
        };
        wait_until(|| entered.load(Ordering::SeqCst), Duration::from_secs(5));
        let second = {
            let channel = Arc::clone(&channel);
            thread::spawn(move || channel.send(&OutboundMessage::new("42", "hello", "send-race")))
        };
        // Give the second send its window to reach the in-flight wait
        // before the first completes.
        thread::sleep(Duration::from_millis(50));
        {
            let (mutex, condvar) = &*release;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        assert_eq!(first, second);
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn same_key_retry_resumes_at_the_rejected_part() {
        let transport = MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_api_failed", "fixture rejection"),
                false,
            )),
            ..Default::default()
        };
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000); // two platform parts
        let outbound = OutboundMessage::new("42", &text, "send-partial");

        let error = channel.send(&outbound).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_api_failed");
        assert_eq!(sent.lock().unwrap().len(), 1, "only the prefix posted");

        let receipt = channel.send(&outbound).unwrap();
        let posts = sent.lock().unwrap();
        assert_eq!(posts.len(), 2, "the confirmed prefix was not reposted");
        assert_eq!(posts[1].1.len(), 5000 - 4096);
        assert_eq!(receipt.message_ids.len(), 2);
    }

    #[test]
    fn a_tracked_send_reports_the_checkpoint_its_failure_earned() {
        let transport = MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_api_failed", "fixture rejection"),
                false,
            )),
            ..Default::default()
        };
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000);
        let outbound = OutboundMessage::new("42", &text, "send-tracked");

        let failure = channel
            .send_tracked(&outbound, None, &mut |_| Ok(()))
            .unwrap_err();
        assert_eq!(failure.error.code, "a4mc_telegram_api_failed");
        let progress = failure.progress.expect("checkpoint not reported");
        assert_eq!(progress.next_part, 1);
        assert_eq!(progress.confirmed.len(), 1);
        assert!(!progress.outcome_unknown);
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_resumed_checkpoint_posts_only_the_unconfirmed_tail() {
        let transport = MockBotTransport::default();
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000);
        let outbound = OutboundMessage::new("42", &text, "send-resume");

        let receipt = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![7],
                    next_part: 1,
                    outcome_unknown: false,
                    binding: None,
                }),
                &mut |_| Ok(()),
            )
            .unwrap();
        let posts = sent.lock().unwrap();
        assert_eq!(posts.len(), 1, "the confirmed prefix was reposted");
        assert_eq!(posts[0].1.len(), 5000 - 4096);
        assert_eq!(receipt.message_ids.len(), 2, "receipt lost the prefix");
    }

    #[test]
    fn a_resumed_checkpoint_with_an_unknown_outcome_is_refused() {
        let transport = MockBotTransport::default();
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000);
        let outbound = OutboundMessage::new("42", &text, "send-resume-ambiguous");

        let failure = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![7],
                    next_part: 1,
                    outcome_unknown: true,
                    binding: None,
                }),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(failure.error.code, "a4mc_telegram_send_ambiguous");
        assert!(
            sent.lock().unwrap().is_empty(),
            "an unconfirmed part must never be blindly reposted"
        );
    }

    #[test]
    fn same_key_retry_does_not_blindly_repost_an_unknown_outcome() {
        let transport = MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_network_failed", "fixture outage"),
                true,
            )),
            ..Default::default()
        };
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000);
        let outbound = OutboundMessage::new("42", &text, "send-ambiguous");

        channel.send(&outbound).unwrap_err();
        let error = channel.send(&outbound).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_send_ambiguous");
        assert_eq!(
            sent.lock().unwrap().len(),
            1,
            "an unconfirmed part must never be blindly reposted"
        );
    }

    #[test]
    fn same_key_retry_resumes_at_the_rate_limited_part_and_keeps_the_hint() {
        let transport = MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new(
                    "a4mc_telegram_throttled",
                    "sendMessage: Bot API rate limited",
                )
                .with_retry_after(Some(7)),
                false,
            )),
            ..Default::default()
        };
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000); // two platform parts
        let outbound = OutboundMessage::new("42", &text, "send-partial-throttled");

        // The first part posts, the second is rate-limited: the host-facing
        // error must carry the platform's wait hint, and the key must keep
        // the confirmed prefix instead of releasing for a full repost.
        let error = channel.send(&outbound).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(
            error.retry_after_ms,
            Some(7_000),
            "the normalized send dropped the platform's retry hint"
        );
        assert_eq!(sent.lock().unwrap().len(), 1, "only the prefix posted");

        let receipt = channel.send(&outbound).unwrap();
        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.len(),
            2,
            "the confirmed prefix must not be reposted on a same-key retry"
        );
        assert_eq!(posts[1].1.len(), 5000 - 4096);
        assert_eq!(receipt.message_ids.len(), 2);
    }

    #[test]
    fn throttled_send_releases_the_key_for_a_caller_retry() {
        let (channel, transport) = channel();
        *transport.fail_send_with.lock().unwrap() = Some(
            TelegramApiError::new(
                "a4mc_telegram_throttled",
                "sendMessage: Bot API rate limited",
            )
            .with_retry_after(Some(7)),
        );
        let outbound = OutboundMessage::new("42", "hello", "send-throttled");
        let error = channel.send(&outbound).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after_ms, Some(7_000));
        assert!(transport.sent.lock().unwrap().is_empty());

        // A failed send is not an observed send: the key must be free so
        // the caller can honor the platform hint and retry.
        *transport.fail_send_with.lock().unwrap() = None;
        let receipt = channel.send(&outbound).unwrap();
        assert_eq!(receipt.idempotency_key, "send-throttled");
        assert_eq!(
            transport.sent.lock().unwrap().len(),
            1,
            "retry after a throttled send must post exactly once"
        );
    }

    #[test]
    fn invalid_sends_and_non_telegram_ids_are_rejected() {
        let (channel, _transport) = channel();
        assert!(channel.send(&OutboundMessage::new("42", "", "k")).is_err());
        assert!(channel.send(&OutboundMessage::new("42", "x", " ")).is_err());
        assert_eq!(
            channel
                .send(&OutboundMessage::new("not-a-chat", "x", "k"))
                .unwrap_err()
                .code,
            "a4mc_telegram_chat_id_invalid"
        );
    }

    /// One caller policy fixture, repeated in the Slack and Discord
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
        let (channel, transport) = channel();
        assert!(channel.outbound_pipeline().hooks().is_none());
        let receipt = channel
            .send_at(&OutboundMessage::new("42", "plain", "plain-1"), 1_000)
            .unwrap();
        assert_eq!(receipt.idempotency_key, "plain-1");
        assert_eq!(receipt.message_ids.len(), 1);
        let sent = transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, "plain");
    }

    #[test]
    fn mounted_hooks_apply_uniformly_to_every_send_decision() {
        let (channel, transport) = channel();
        let trace = Arc::new(HookTrace::default());
        let channel = channel.with_outbound_hooks(Arc::new(HookPolicy {
            trace: Arc::clone(&trace),
        }));

        let plain = channel
            .send_at(&OutboundMessage::new("42", "plain", "plain-1"), 1_000)
            .unwrap();
        assert_eq!(plain.idempotency_key, "plain-1");
        assert_eq!(trace.receipts.lock().unwrap().len(), 1);
        assert_eq!(
            *trace.calls.lock().unwrap(),
            vec!["skip", "batch", "throttle", "dedupe", "receipt"]
        );

        let skipped = channel
            .send_at(&OutboundMessage::new("42", "skip-me", "skip-1"), 1_000)
            .unwrap();
        assert!(skipped.is_skipped());
        assert_eq!(skipped.idempotency_key, "skip-1");
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
        assert_eq!(trace.receipts.lock().unwrap().len(), 1);

        let batched = channel
            .send_at(&OutboundMessage::new("42", "batch-me", "batch-1"), 1_000)
            .unwrap();
        assert_eq!(batched.message_ids.len(), 1);
        assert_eq!(transport.sent.lock().unwrap()[1].1, "batched:batch-me");
        assert_eq!(trace.receipts.lock().unwrap().len(), 2);

        let error = channel
            .send_at(
                &OutboundMessage::new("42", "throttle-me", "throttle-1"),
                1_000,
            )
            .unwrap_err();
        assert_eq!(error.code, "a4mc_outbound_throttled");
        assert!(error.message.contains("retryAfterMs=1500"));
        assert_eq!(transport.sent.lock().unwrap().len(), 2);
        assert_eq!(trace.receipts.lock().unwrap().len(), 2);

        let first = channel
            .send_at(&OutboundMessage::new("42", "dedupe-a", "contract-a"), 1_000)
            .unwrap();
        let replay = channel
            .send_at(&OutboundMessage::new("42", "dedupe-b", "contract-b"), 1_000)
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.idempotency_key, "hook-dedupe");
        assert_eq!(transport.sent.lock().unwrap().len(), 3);
        assert_eq!(
            transport.sent.lock().unwrap()[2].1,
            "dedupe-a",
            "the deduplicated replay must not post the second payload"
        );
    }

    /// A batch hook that rewrites the outbound text to a caller-chosen
    /// prefix — the finding's "hooks alter the payload" knob.
    struct ReplacingHooks {
        prefix: &'static str,
    }

    impl a4mc::OutboundHooks for ReplacingHooks {
        fn batch(&self, _: &a4mc::SendContext, message: &OutboundMessage) -> a4mc::BatchDecision {
            a4mc::BatchDecision::replace(
                message
                    .clone()
                    .with_text(format!("{}{}", self.prefix, message.text)),
            )
        }
    }

    #[test]
    fn a_checkpoint_from_another_prepared_send_never_resumes() {
        let transport = MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_api_failed", "fixture rejection"),
                false,
            )),
            ..Default::default()
        };
        let sent = Arc::clone(&transport.sent);
        let mut channel = TelegramChannel::new(Arc::new(transport))
            .with_outbound_hooks(Arc::new(ReplacingHooks { prefix: "first:" }));
        let text = "x".repeat(5000); // two platform parts
        let outbound = OutboundMessage::new("42", &text, "send-bound");

        channel.send(&outbound).unwrap_err();
        assert_eq!(sent.lock().unwrap().len(), 1, "only the prefix posted");

        // The same key, prepared differently this time: the retry must
        // not borrow the stopped send's chunk position — the tail would
        // land inside a different message.
        channel.set_outbound_hooks(Arc::new(ReplacingHooks { prefix: "second:" }));
        let error = channel.send(&outbound).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_resume_mismatch");
        assert_eq!(
            sent.lock().unwrap().len(),
            1,
            "a foreign checkpoint posted its tail under this key"
        );

        // The unchanged prepared send resumes the same checkpoint.
        channel.set_outbound_hooks(Arc::new(ReplacingHooks { prefix: "first:" }));
        let receipt = channel.send(&outbound).unwrap();
        let posts = sent.lock().unwrap();
        assert_eq!(posts.len(), 2, "the confirmed prefix was reposted");
        assert_eq!(posts[1].1.len(), "first:".len() + 5000 - 4096);
        assert_eq!(receipt.message_ids.len(), 2);
    }

    #[test]
    fn a_caller_checkpoint_bound_to_another_send_is_refused() {
        let transport = MockBotTransport::default();
        let sent = Arc::clone(&transport.sent);
        let channel = TelegramChannel::new(Arc::new(transport));
        let text = "x".repeat(5000);
        let outbound = OutboundMessage::new("42", &text, "send-foreign");

        let failure = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![7],
                    next_part: 1,
                    outcome_unknown: false,
                    binding: Some(SendBinding {
                        dedupe_key: "send-foreign".into(),
                        chat_id: 43,
                        payload_digest: "different-payload".into(),
                    }),
                }),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(failure.error.code, "a4mc_telegram_resume_mismatch");
        assert!(
            sent.lock().unwrap().is_empty(),
            "a checkpoint from a different outbound message posted parts"
        );
    }

    #[test]
    fn the_payload_digest_separates_text_from_the_reply_target() {
        // A text suffix must never collide with a reply target: both
        // payloads below are contract-valid and used to hash to the
        // same byte stream.
        let mut bare = OutboundMessage::new("42", "note\u{0}7", "send-digest");
        bare.reply_to_message_id = None;
        let mut targeted = OutboundMessage::new("42", "note", "send-digest");
        targeted.reply_to_message_id = Some(a4mc::ExternalMessageId::from("7"));
        assert_ne!(
            send_binding(42, &bare, "send-digest").payload_digest,
            send_binding(42, &targeted, "send-digest").payload_digest,
            "a text suffix collided with the reply target"
        );
        // Field separation, not mere field presence: the same text
        // with and without a target also digests differently.
        let mut third = OutboundMessage::new("42", "note\u{0}7", "send-digest");
        third.reply_to_message_id = Some(a4mc::ExternalMessageId::from("7"));
        assert_ne!(
            send_binding(42, &bare, "send-digest").payload_digest,
            send_binding(42, &third, "send-digest").payload_digest,
        );
    }

    #[test]
    fn a_cached_receipt_never_bypasses_caller_checkpoint_validation() {
        // The first send leaves a receipt under its effective key; a
        // caller-supplied checkpoint bound to a different prepared
        // send must be refused before that receipt is returned — the
        // cache is not a shortcut around checkpoint validation.
        let transport = MockBotTransport::default();
        let channel = TelegramChannel::new(Arc::new(transport));
        let outbound = OutboundMessage::new("42", "hello", "send-cached");
        channel.send(&outbound).unwrap();

        let failure = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![7],
                    next_part: 1,
                    outcome_unknown: false,
                    binding: Some(SendBinding {
                        dedupe_key: "send-cached".into(),
                        chat_id: 42,
                        payload_digest: "foreign".into(),
                    }),
                }),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(failure.error.code, "a4mc_telegram_resume_mismatch");

        // An uncertain caller checkpoint against a finished key is
        // refused as ambiguous, not satisfied by the cached receipt.
        let failure = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![7],
                    next_part: 0,
                    outcome_unknown: true,
                    binding: None,
                }),
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(failure.error.code, "a4mc_telegram_send_ambiguous");

        // The bound checkpoint still resolves against the cache.
        let expected = send_binding(42, &outbound, "send-cached");
        let receipt = channel
            .send_tracked(
                &outbound,
                Some(&SendProgress {
                    confirmed: vec![],
                    next_part: 0,
                    outcome_unknown: false,
                    binding: Some(expected),
                }),
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(receipt.idempotency_key, "send-cached");
    }
}
