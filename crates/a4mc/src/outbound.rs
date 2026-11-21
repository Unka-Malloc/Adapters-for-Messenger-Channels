//! Pluggable outbound interception points.
//!
//! A channel delivers messages; it does not decide whether a message is
//! worth sending. The host owns that policy, so this module exposes one
//! small hook trait the caller mounts around a channel's send path:
//!
//! * [`OutboundHooks::skip`] — drop a message by caller decision;
//! * [`OutboundHooks::batch`] — fold a message into a window payload, or
//!   defer it until the window closes;
//! * [`OutboundHooks::throttle`] — enforce the caller's send budget;
//! * [`OutboundHooks::dedupe_key`] — derive the idempotency/dedupe key;
//! * [`OutboundHooks::on_receipt`] — observe the receipt the send returns.
//!
//! Every hook defaults to pass-through, and a channel with no hooks
//! mounted never calls one: an unmounted policy is byte-for-byte the
//! plain channel send. A mounted policy runs in one documented order
//! (`skip` → `batch` → `throttle` → `dedupe_key` → deliver →
//! `on_receipt`), so every dialect that uses [`OutboundPipeline`] gives
//! the same answer for the same message.
//!
//! The pipeline carries no business policy of its own: it validates the
//! contract bounds, invokes the caller's hooks, and maps a deferral to a
//! bounded [`ChannelError`]. Channel transports still do only reliable
//! send/receive.

use crate::error::ChannelError;
use crate::identity::ChannelId;
use crate::send::{MAX_IDEMPOTENCY_KEY_CHARS, OutboundMessage, SendReceipt};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the Unix epoch, saturating at zero.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The channel and clock one hook invocation observes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendContext {
    /// The dialect channel performing the send.
    pub channel: ChannelId,
    /// Caller-supplied clock in Unix milliseconds. Tests pin this so a
    /// batch window or throttle budget is deterministic.
    pub now_ms: u64,
}

impl SendContext {
    pub fn at(channel: impl Into<ChannelId>, now_ms: u64) -> Self {
        Self {
            channel: channel.into(),
            now_ms,
        }
    }

    pub fn now(channel: impl Into<ChannelId>) -> Self {
        Self::at(channel, unix_now_ms())
    }
}

/// Conditional-skip decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipDecision {
    /// No caller policy suppresses this send.
    Send,
    /// Intentionally drop the send. No transport call is made.
    Skip { reason: String },
}

impl SkipDecision {
    pub fn skip(reason: impl Into<String>) -> Self {
        Self::Skip {
            reason: reason.into(),
        }
    }
}

/// Window-batching decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchDecision {
    /// Send the message as it stands.
    PassThrough,
    /// Send this replacement payload instead (typically a window merge).
    Replace(OutboundMessage),
    /// Hold the message for a later window. The caller retries after the
    /// hint, if any.
    Defer {
        reason: String,
        retry_after: Option<Duration>,
    },
}

impl BatchDecision {
    pub fn replace(message: OutboundMessage) -> Self {
        Self::Replace(message)
    }

    pub fn defer(reason: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self::Defer {
            reason: reason.into(),
            retry_after,
        }
    }
}

/// Throttle-budget decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// The caller's budget allows this send now.
    Allow,
    /// The caller's budget is exhausted; retry after the hint.
    Defer {
        reason: String,
        retry_after: Option<Duration>,
    },
}

impl ThrottleDecision {
    pub fn defer(reason: impl Into<String>, retry_after: Option<Duration>) -> Self {
        Self::Defer {
            reason: reason.into(),
            retry_after,
        }
    }
}

/// Which pipeline stage deferred a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferSource {
    /// The caller's window-batching callback held the send.
    Batch,
    /// The caller's throttle budget held the send.
    Throttle,
}

impl DeferSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Throttle => "throttle",
        }
    }

    /// Stable error code for a deferred send.
    pub fn error_code(self) -> &'static str {
        match self {
            Self::Batch => "a4mc_outbound_batched",
            Self::Throttle => "a4mc_outbound_throttled",
        }
    }
}

/// A message cleared for delivery with the effective dedupe key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSend {
    /// The payload to lower, after batching substitution.
    pub message: OutboundMessage,
    /// The key the channel uses for idempotency dedupe and echoes on the
    /// receipt. Equals [`OutboundMessage::dedupe_key`] unless the caller's
    /// hook derived an override.
    pub dedupe_key: String,
}

/// One pipeline pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendPlan {
    /// Deliver `prepared`.
    Send(PreparedSend),
    /// The caller intentionally suppressed the send.
    Skipped {
        /// The caller's reason, bounded for an error/diagnostic surface.
        reason: String,
    },
    /// The caller's batching or throttle policy held the send.
    Deferred {
        source: DeferSource,
        reason: String,
        retry_after: Option<Duration>,
    },
}

/// Caller-mounted outbound policy. Every method defaults to pass-through,
/// so a minimal implementation overrides only the decision it owns.
///
/// Hooks must be thread-safe and must not block indefinitely: a channel
/// invokes them on its send path. They are called in pipeline order
/// `skip`, `batch`, `throttle`, `dedupe_key`; `on_receipt` runs only
/// after a non-skipped send returns a receipt.
pub trait OutboundHooks: Send + Sync {
    /// Conditionally suppress a send before any other hook runs.
    fn skip(&self, _ctx: &SendContext, _message: &OutboundMessage) -> SkipDecision {
        SkipDecision::Send
    }

    /// Fold this message into a window, or hold it until the window
    /// closes. Returning [`BatchDecision::Replace`] lets the caller send
    /// the merged payload in place of the original.
    fn batch(&self, _ctx: &SendContext, _message: &OutboundMessage) -> BatchDecision {
        BatchDecision::PassThrough
    }

    /// Charge the caller's throttle budget. A deferral returns the
    /// stable `a4mc_outbound_throttled` error without touching the
    /// transport.
    fn throttle(&self, _ctx: &SendContext, _message: &OutboundMessage) -> ThrottleDecision {
        ThrottleDecision::Allow
    }

    /// Derive the idempotency/dedupe key for this send. `None` keeps the
    /// key the contract message carries.
    fn dedupe_key(&self, _ctx: &SendContext, _message: &OutboundMessage) -> Option<String> {
        None
    }

    /// Observe the receipt a successful `send` returns. A deduplicated
    /// replay reports the already-observed receipt; a skipped send
    /// reports nothing.
    fn on_receipt(&self, _ctx: &SendContext, _message: &OutboundMessage, _receipt: &SendReceipt) {
        let _ = (_ctx, _message, _receipt);
    }
}

/// The ordered outbound pipeline one channel drives.
///
/// Construct it with [`OutboundPipeline::from_lane`] so the composing
/// host can mount hooks once through the installed
/// [`crate::lane::LanePort`], or with
/// [`OutboundPipeline::with_hooks`] for a channel-local policy. A
/// pipeline with no hooks is a pass-through.
#[derive(Clone)]
pub struct OutboundPipeline {
    channel: ChannelId,
    hooks: Option<Arc<dyn OutboundHooks>>,
}

impl OutboundPipeline {
    /// A pass-through pipeline: no caller policy is mounted.
    pub fn pass_through(channel: impl Into<ChannelId>) -> Self {
        Self {
            channel: channel.into(),
            hooks: None,
        }
    }

    /// A pipeline with one caller-mounted policy.
    pub fn with_hooks(channel: impl Into<ChannelId>, hooks: Arc<dyn OutboundHooks>) -> Self {
        Self {
            channel: channel.into(),
            hooks: Some(hooks),
        }
    }

    /// Resolve an explicit policy, or the host's policy from the
    /// installed lane port when no channel-local one was supplied.
    /// Without either, the result is pass-through.
    pub fn resolve(channel: impl Into<ChannelId>, hooks: Option<Arc<dyn OutboundHooks>>) -> Self {
        match hooks {
            Some(hooks) => Self::with_hooks(channel, hooks),
            None => Self::from_lane(channel),
        }
    }

    /// Resolve the host's hook provider from the installed lane port.
    /// The port is process-wide; a channel constructed before the host
    /// installs it resolves pass-through.
    pub fn from_lane(channel: impl Into<ChannelId>) -> Self {
        let hooks = crate::lane::require()
            .ok()
            .and_then(|port| port.outbound_hooks)
            .map(|provider| provider());
        Self {
            channel: channel.into(),
            hooks,
        }
    }

    pub fn channel(&self) -> &ChannelId {
        &self.channel
    }

    pub fn hooks(&self) -> Option<&Arc<dyn OutboundHooks>> {
        self.hooks.as_ref()
    }

    /// Run the hook chain and return the plan for one send. Validation
    /// runs first: an invalid contract message never reaches caller
    /// policy.
    pub fn plan(
        &self,
        message: &OutboundMessage,
        ctx: &SendContext,
    ) -> Result<SendPlan, ChannelError> {
        message.validate()?;
        let Some(hooks) = &self.hooks else {
            return Ok(SendPlan::Send(PreparedSend {
                message: message.clone(),
                dedupe_key: message.dedupe_key().to_owned(),
            }));
        };

        if let SkipDecision::Skip { reason } = hooks.skip(ctx, message) {
            return Ok(SendPlan::Skipped {
                reason: bounded_reason(&reason, "skipped by caller policy"),
            });
        }

        let mut effective = message.clone();
        match hooks.batch(ctx, &effective) {
            BatchDecision::PassThrough => {}
            BatchDecision::Replace(replacement) => {
                replacement.validate().map_err(|error| {
                    ChannelError::new(
                        "a4mc_outbound_batch_invalid",
                        format!("batch replacement is not a valid send: {error}"),
                    )
                })?;
                effective = replacement;
            }
            BatchDecision::Defer {
                reason,
                retry_after,
            } => {
                return Ok(SendPlan::Deferred {
                    source: DeferSource::Batch,
                    reason: bounded_reason(&reason, "held by the batch window"),
                    retry_after,
                });
            }
        }

        if let ThrottleDecision::Defer {
            reason,
            retry_after,
        } = hooks.throttle(ctx, &effective)
        {
            return Ok(SendPlan::Deferred {
                source: DeferSource::Throttle,
                reason: bounded_reason(&reason, "throttle budget exhausted"),
                retry_after,
            });
        }

        let dedupe_key = match hooks.dedupe_key(ctx, &effective) {
            Some(key) => key,
            None => effective.dedupe_key().to_owned(),
        };
        validate_dedupe_key(&dedupe_key)?;
        Ok(SendPlan::Send(PreparedSend {
            message: effective,
            dedupe_key,
        }))
    }

    /// Plan and deliver one send, applying the same skip/deferral and
    /// receipt rules in every dialect. `deliver` owns the platform
    /// lowering, idempotency cache and transport call; it runs only when
    /// the plan cleared the send.
    ///
    /// A skipped send returns an empty [`SendReceipt`] and makes no
    /// transport call. A deferred send returns the stage's stable error
    /// code (`a4mc_outbound_batched` / `a4mc_outbound_throttled`).
    pub fn execute<F>(
        &self,
        message: &OutboundMessage,
        ctx: &SendContext,
        deliver: F,
    ) -> Result<SendReceipt, ChannelError>
    where
        F: FnOnce(&PreparedSend) -> Result<SendReceipt, ChannelError>,
    {
        match self.plan(message, ctx)? {
            SendPlan::Send(prepared) => {
                let receipt = deliver(&prepared)?;
                if let Some(hooks) = &self.hooks {
                    hooks.on_receipt(ctx, &prepared.message, &receipt);
                }
                Ok(receipt)
            }
            SendPlan::Skipped { .. } => Ok(SendReceipt::skipped(message.dedupe_key())),
            SendPlan::Deferred {
                source,
                reason,
                retry_after,
            } => Err(defer_error(source, &reason, retry_after)),
        }
    }
}

impl std::fmt::Debug for OutboundPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundPipeline")
            .field("channel", &self.channel)
            .field("hooks", &self.hooks.is_some())
            .finish()
    }
}

fn validate_dedupe_key(key: &str) -> Result<(), ChannelError> {
    let key = key.trim();
    if key.is_empty() || key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS {
        return Err(ChannelError::new(
            "a4mc_idempotency_key_invalid",
            "dedupe key missing or oversized",
        ));
    }
    Ok(())
}

fn defer_error(source: DeferSource, reason: &str, retry_after: Option<Duration>) -> ChannelError {
    let mut message = format!("deferred by {}: {reason}", source.as_str());
    if let Some(retry_after) = retry_after {
        message.push_str(&format!(
            " (retryAfterMs={})",
            u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX)
        ));
    }
    ChannelError::new(source.error_code(), message)
}

/// Keep a caller-supplied reason bounded; it becomes part of an error
/// message that may be logged or shown to a user.
fn bounded_reason(reason: &str, fallback: &str) -> String {
    const MAX_REASON_CHARS: usize = 240;
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return fallback.to_owned();
    }
    if trimmed.chars().count() <= MAX_REASON_CHARS {
        return trimmed.to_owned();
    }
    let mut bounded: String = trimmed.chars().take(MAX_REASON_CHARS - 1).collect();
    bounded.push('…');
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Trace {
        calls: Mutex<Vec<&'static str>>,
        receipts: Mutex<Vec<SendReceipt>>,
    }

    struct Policy {
        trace: Arc<Trace>,
        skip: bool,
        batch: bool,
        throttle: bool,
        dedupe: Option<String>,
    }

    impl Policy {
        fn new(trace: &Arc<Trace>) -> Self {
            Self {
                trace: Arc::clone(trace),
                skip: false,
                batch: false,
                throttle: false,
                dedupe: None,
            }
        }

        fn call(&self, name: &'static str) {
            self.trace.calls.lock().unwrap().push(name);
        }
    }

    impl OutboundHooks for Policy {
        fn skip(&self, _: &SendContext, _: &OutboundMessage) -> SkipDecision {
            self.call("skip");
            if self.skip {
                SkipDecision::skip("policy says no")
            } else {
                SkipDecision::Send
            }
        }

        fn batch(&self, _: &SendContext, message: &OutboundMessage) -> BatchDecision {
            self.call("batch");
            if self.batch {
                let mut merged = message.clone();
                merged.text = format!("window:{}", message.text);
                BatchDecision::replace(merged)
            } else {
                BatchDecision::PassThrough
            }
        }

        fn throttle(&self, _: &SendContext, _: &OutboundMessage) -> ThrottleDecision {
            self.call("throttle");
            if self.throttle {
                ThrottleDecision::defer("budget", Some(Duration::from_millis(1500)))
            } else {
                ThrottleDecision::Allow
            }
        }

        fn dedupe_key(&self, _: &SendContext, _: &OutboundMessage) -> Option<String> {
            self.call("dedupe");
            self.dedupe.clone()
        }

        fn on_receipt(&self, _: &SendContext, _: &OutboundMessage, receipt: &SendReceipt) {
            self.call("receipt");
            self.trace.receipts.lock().unwrap().push(receipt.clone());
        }
    }

    fn context() -> SendContext {
        SendContext::at("fixture", 1_700_000_000_000)
    }

    fn receipt(prepared: &PreparedSend) -> Result<SendReceipt, ChannelError> {
        Ok(SendReceipt {
            idempotency_key: prepared.dedupe_key.clone(),
            message_ids: vec![crate::ExternalMessageId::from("1")],
        })
    }

    #[test]
    fn unmounted_policy_is_byte_for_byte_pass_through() {
        let pipeline = OutboundPipeline::pass_through("fixture");
        let message = OutboundMessage::new("7", "hello", "key-1");
        let plan = pipeline.plan(&message, &context()).unwrap();
        let SendPlan::Send(prepared) = plan else {
            panic!("pass-through must send");
        };
        assert_eq!(prepared.message, message);
        assert_eq!(prepared.dedupe_key, "key-1");

        let mut delivered = None;
        let returned = pipeline
            .execute(&message, &context(), |prepared| {
                delivered = Some(prepared.message.clone());
                receipt(prepared)
            })
            .unwrap();
        assert_eq!(delivered.unwrap(), message);
        assert_eq!(returned.idempotency_key, "key-1");
    }

    #[test]
    fn hooks_run_in_documented_order_and_observe_the_receipt() {
        let trace = Arc::new(Trace::default());
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(Policy::new(&trace)));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let returned = pipeline.execute(&message, &context(), receipt).unwrap();
        assert_eq!(
            *trace.calls.lock().unwrap(),
            vec!["skip", "batch", "throttle", "dedupe", "receipt"]
        );
        assert_eq!(trace.receipts.lock().unwrap().as_slice(), [returned]);
    }

    #[test]
    fn skip_returns_an_empty_receipt_without_delivery() {
        let trace = Arc::new(Trace::default());
        let mut policy = Policy::new(&trace);
        policy.skip = true;
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(policy));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let mut delivered = false;
        let returned = pipeline
            .execute(&message, &context(), |prepared| {
                delivered = true;
                receipt(prepared)
            })
            .unwrap();
        assert!(!delivered);
        assert_eq!(returned.idempotency_key, "key-1");
        assert!(returned.is_skipped());
        assert!(trace.receipts.lock().unwrap().is_empty());
        assert_eq!(*trace.calls.lock().unwrap(), vec!["skip"]);
    }

    #[test]
    fn batch_replacement_is_what_gets_delivered() {
        let trace = Arc::new(Trace::default());
        let mut policy = Policy::new(&trace);
        policy.batch = true;
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(policy));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let returned = pipeline
            .execute(&message, &context(), |prepared| {
                assert_eq!(prepared.message.text, "window:hello");
                receipt(prepared)
            })
            .unwrap();
        assert_eq!(returned.idempotency_key, "key-1");
    }

    #[test]
    fn throttle_deferral_is_a_bounded_structured_error() {
        let trace = Arc::new(Trace::default());
        let mut policy = Policy::new(&trace);
        policy.throttle = true;
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(policy));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let error = pipeline.execute(&message, &context(), receipt).unwrap_err();
        assert_eq!(error.code, "a4mc_outbound_throttled");
        assert!(error.message.contains("deferred by throttle: budget"));
        assert!(error.message.contains("retryAfterMs=1500"));
    }

    #[test]
    fn dedupe_override_replaces_the_contract_key_and_is_validated() {
        let trace = Arc::new(Trace::default());
        let mut policy = Policy::new(&trace);
        policy.dedupe = Some("derived-key".into());
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(policy));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let plan = pipeline.plan(&message, &context()).unwrap();
        let SendPlan::Send(prepared) = plan else {
            panic!("dedupe override must still send");
        };
        assert_eq!(prepared.dedupe_key, "derived-key");
        assert_eq!(prepared.message.idempotency_key, "key-1");

        let invalid = OutboundPipeline::with_hooks(
            "fixture",
            Arc::new({
                let mut policy = Policy::new(&Arc::new(Trace::default()));
                policy.dedupe = Some("   ".into());
                policy
            }),
        );
        assert_eq!(
            invalid.plan(&message, &context()).unwrap_err().code,
            "a4mc_idempotency_key_invalid"
        );
    }

    #[test]
    fn invalid_contract_message_never_reaches_policy() {
        let trace = Arc::new(Trace::default());
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(Policy::new(&trace)));
        let message = OutboundMessage::new("7", "", "key-1");
        assert!(pipeline.plan(&message, &context()).is_err());
        assert!(trace.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn batch_deferral_uses_the_batch_code() {
        struct BatchDefer;
        impl OutboundHooks for BatchDefer {
            fn batch(&self, _: &SendContext, _: &OutboundMessage) -> BatchDecision {
                BatchDecision::defer("window still open", None)
            }
        }
        let pipeline = OutboundPipeline::with_hooks("fixture", Arc::new(BatchDefer));
        let message = OutboundMessage::new("7", "hello", "key-1");
        let error = pipeline.execute(&message, &context(), receipt).unwrap_err();
        assert_eq!(error.code, "a4mc_outbound_batched");
        assert!(!error.message.contains("retryAfterMs"));
    }
}
