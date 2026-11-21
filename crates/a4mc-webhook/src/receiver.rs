//! Bounded replay suppression on top of signature verification.
//!
//! A valid signature can still be replayed inside the timestamp window.
//! [`WebhookReceiver`] remembers verified signatures in a bounded FIFO
//! cache — but only after the host commits them. A first delivery
//! returns [`DeliveryOutcome::Event`]; once the host has accepted the
//! event durably or finished handling it, [`WebhookReceiver::commit`]
//! suppresses replays, which then return [`DeliveryOutcome::Duplicate`]
//! and are answered success without running the update again. A
//! delivery never committed stays retry-eligible: a handler that
//! failed returns an HTTP error and the sender's retry verifies as a
//! fresh event instead of being answered success unseen. The cache
//! holds digests only — never bodies, secrets or signatures of failed
//! verifications.

use crate::error::WebhookError;
use crate::request::WebhookRequest;
use crate::signature::{WebhookDelivery, WebhookVerifier};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

/// The result of receiving one signed request.
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryOutcome {
    /// A newly verified delivery.
    Event(Box<WebhookDelivery>),
    /// A verified replay of an already delivered request.
    Duplicate,
}

/// Verifies requests and suppresses bounded-window replays.
#[derive(Debug)]
pub struct WebhookReceiver {
    verifier: WebhookVerifier,
    seen: Mutex<SeenSignatures>,
}

impl WebhookReceiver {
    pub fn new(verifier: WebhookVerifier) -> Self {
        Self {
            verifier,
            seen: Mutex::new(SeenSignatures::new(1024)),
        }
    }

    /// Resolve the secret through custody and build the receiver.
    pub fn from_custody(tolerance_secs: u64) -> Result<Self, WebhookError> {
        Ok(Self::new(WebhookVerifier::from_custody(tolerance_secs)?))
    }

    pub fn verifier(&self) -> &WebhookVerifier {
        &self.verifier
    }

    /// Verify and classify one request at `now_unix`. A signature is
    /// only reported [`DeliveryOutcome::Duplicate`] after
    /// [`Self::commit`] — nothing is suppressed merely for having
    /// been delivered once.
    pub fn receive(
        &self,
        request: &WebhookRequest,
        now_unix: u64,
    ) -> Result<DeliveryOutcome, WebhookError> {
        let delivery = self.verifier.verify(request, now_unix)?;
        let committed = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&delivery.signature);
        if committed {
            Ok(DeliveryOutcome::Duplicate)
        } else {
            Ok(DeliveryOutcome::Event(Box::new(delivery)))
        }
    }

    /// Commit replay suppression for one delivered event: call only
    /// after the host has accepted it — stored durably for processing
    /// or handled successfully. A failed first attempt is never
    /// committed, so the sender's retry is classified
    /// [`DeliveryOutcome::Event`] and runs again.
    pub fn commit(&self, delivery: &WebhookDelivery) {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mark(&delivery.signature);
    }
}

#[derive(Debug)]
struct SeenSignatures {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl SeenSignatures {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    fn contains(&self, signature: &str) -> bool {
        !signature.is_empty() && self.seen.contains(signature)
    }

    fn mark(&mut self, signature: &str) {
        if signature.is_empty() || !self.seen.insert(signature.to_owned()) {
            return;
        }
        self.order.push_back(signature.to_owned());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookSecret, sign};
    use a4mc::SecretToken;
    use std::sync::OnceLock;

    const BODY: &str = r#"{"kind":"message","chat":{"id":"1","kind":"direct","title":null},"author":{"id":"2","username":null,"displayName":null},"messageId":"3","threadId":null,"sentAt":null,"editedAt":null,"content":"text","text":"hi","caption":null,"attachments":[],"replyTo":null,"forwardLabel":null,"location":null,"venueLabel":null,"contactLabel":null,"pollQuestion":null}"#;

    /// A per-run signing key shared by this test module. No static
    /// secret literal is committed.
    fn fixture_key() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            format!(
                "a4mc-webhook-{}-{nanos}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            )
        })
    }

    fn fixture_secret() -> WebhookSecret {
        WebhookSecret::new(SecretToken::try_from_string(fixture_key().into()).unwrap()).unwrap()
    }

    fn receiver() -> WebhookReceiver {
        WebhookReceiver::new(WebhookVerifier::new(fixture_secret(), 300))
    }

    fn request(timestamp: u64, body: &str) -> WebhookRequest {
        let secret = fixture_secret();
        WebhookRequest::new("POST", body.as_bytes().to_vec())
            .with_header(TIMESTAMP_HEADER, timestamp.to_string())
            .with_header(SIGNATURE_HEADER, sign(&secret, timestamp, body.as_bytes()))
    }

    #[test]
    fn committed_replay_is_a_duplicate_and_does_not_run_twice() {
        let receiver = receiver();
        let request = request(1_700_000_000, BODY);
        let DeliveryOutcome::Event(first) = receiver.receive(&request, 1_700_000_000).unwrap()
        else {
            panic!("first delivery should be an event");
        };
        assert_eq!(first.signed_at, 1_700_000_000);
        receiver.commit(&first);
        assert_eq!(
            receiver.receive(&request, 1_700_000_000).unwrap(),
            DeliveryOutcome::Duplicate
        );
    }

    #[test]
    fn an_uncommitted_delivery_stays_retryable() {
        let receiver = receiver();
        let request = request(1_700_000_000, BODY);
        let DeliveryOutcome::Event(first) = receiver.receive(&request, 1_700_000_000).unwrap()
        else {
            panic!("first delivery should be an event");
        };
        // The host failed to handle the event and never committed it:
        // the sender's retry must verify as a fresh event, not be
        // suppressed as a duplicate.
        let DeliveryOutcome::Event(retry) = receiver.receive(&request, 1_700_000_000).unwrap()
        else {
            panic!("a retry after host failure must re-deliver the event");
        };
        assert_eq!(retry.signature, first.signature);
        // Once the retried delivery is accepted, suppression commits.
        receiver.commit(&retry);
        assert_eq!(
            receiver.receive(&request, 1_700_000_000).unwrap(),
            DeliveryOutcome::Duplicate
        );
    }

    #[test]
    fn distinct_signatures_are_independent_deliveries() {
        let receiver = receiver();
        let first = request(1_700_000_000, BODY);
        let second = request(1_700_000_001, BODY);
        assert!(matches!(
            receiver.receive(&first, 1_700_000_001).unwrap(),
            DeliveryOutcome::Event(_)
        ));
        assert!(matches!(
            receiver.receive(&second, 1_700_000_001).unwrap(),
            DeliveryOutcome::Event(_)
        ));
    }

    #[test]
    fn failed_verification_never_enters_the_replay_cache() {
        let receiver = receiver();
        let request = request(1_700_000_000, BODY).with_header(SIGNATURE_HEADER, "sha256=bad");
        assert_eq!(
            receiver.receive(&request, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_signature_invalid"
        );
        let valid = self::request(1_700_000_000, BODY);
        assert!(matches!(
            receiver.receive(&valid, 1_700_000_000).unwrap(),
            DeliveryOutcome::Event(_)
        ));
    }

    #[test]
    fn bounded_cache_evicts_oldest_signatures() {
        let mut seen = SeenSignatures::new(2);
        seen.mark("a");
        seen.mark("b");
        assert!(seen.contains("a"));
        assert!(!seen.contains("z"));
        seen.mark("c");
        assert!(!seen.contains("a"));
        assert!(seen.contains("c"));
        // A re-committed signature stays suppressed, not duplicated.
        seen.mark("b");
        assert!(seen.contains("b"));
    }
}
