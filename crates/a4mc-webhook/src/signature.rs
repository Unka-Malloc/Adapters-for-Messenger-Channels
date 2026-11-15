//! HMAC-SHA256 request verification.
//!
//! The signed content is the decimal timestamp, a `.` separator, and the
//! exact request body bytes. A request carries:
//!
//! * `X-A4MC-Timestamp: <unix seconds>`
//! * `X-A4MC-Signature: sha256=<64 lowercase or uppercase hex>`
//!
//! The signature is checked in constant time over those bytes, and the
//! timestamp must fall inside a bounded window around the verifier's
//! clock. Verification happens before JSON parsing, so an unsigned body
//! is never interpreted. Every failure is fail-closed and sanitized: no
//! secret, body, signature value or host detail appears in the error.
//!
//! The signing secret resolves through the host-installed
//! [`a4mc::custody`] port under [`crate::CHANNEL`]; the crate never reads
//! keychains, files or environment itself.

use crate::error::WebhookError;
use crate::payload;
use crate::request::WebhookRequest;
use a4mc::{ChannelEvent, ChannelId, SecretToken};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Header carrying the HMAC-SHA256 signature.
pub const SIGNATURE_HEADER: &str = "x-a4mc-signature";
/// Header carrying the signing timestamp in unix seconds.
pub const TIMESTAMP_HEADER: &str = "x-a4mc-timestamp";
/// Required signature algorithm prefix.
pub const SIGNATURE_PREFIX: &str = "sha256=";
/// Default accepted clock skew, in seconds.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;
/// Default maximum body size, in bytes.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Maximum length of one header value, in bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// The HMAC signing secret, sourced from host custody.
///
/// The inner [`SecretToken`] has no serialized form and a redacted
/// `Debug`; this wrapper repeats the redaction so a composed verifier
/// cannot print the key either.
pub struct WebhookSecret {
    token: SecretToken,
}

impl WebhookSecret {
    pub fn new(token: SecretToken) -> Result<Self, WebhookError> {
        if token.expose_bytes().is_empty() {
            return Err(WebhookError::new(
                "a4mc_webhook_secret_invalid",
                "webhook secret is empty",
            ));
        }
        Ok(Self { token })
    }

    /// Resolve the signing secret through the installed custody port.
    pub fn from_custody() -> Result<Self, WebhookError> {
        let port = a4mc::custody::require().map_err(|error| {
            WebhookError::new("a4mc_webhook_custody_unavailable", error.to_string())
        })?;
        let token = port
            .channel_token(&ChannelId::from(crate::CHANNEL))
            .map_err(|error| WebhookError::new("a4mc_webhook_custody_failed", error.to_string()))?
            .ok_or_else(|| {
                WebhookError::new(
                    "a4mc_webhook_secret_missing",
                    "custody holds no webhook signing secret",
                )
            })?;
        Self::new(token)
    }

    pub(crate) fn key_bytes(&self) -> &[u8] {
        self.token.expose_bytes()
    }
}

impl Clone for WebhookSecret {
    fn clone(&self) -> Self {
        Self {
            token: self.token.copy_for_persistent_read(),
        }
    }
}

impl fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebhookSecret([redacted])")
    }
}

/// One verified delivery, ready for host policy.
#[derive(Debug, Clone, PartialEq)]
pub struct WebhookDelivery {
    /// Normalized event, stamped with this dialect's channel id.
    pub event: ChannelEvent,
    /// The verified unix timestamp from the signature header.
    pub signed_at: u64,
    /// Lowercase hex HMAC digest (without the algorithm prefix). This is
    /// a capability-free digest, not the secret; the receiver uses it as
    /// a bounded replay key.
    pub signature: String,
}

/// Verifies signed webhook requests against one secret.
#[derive(Debug, Clone)]
pub struct WebhookVerifier {
    secret: WebhookSecret,
    tolerance_secs: u64,
    max_body_bytes: usize,
}

impl WebhookVerifier {
    pub fn new(secret: WebhookSecret, tolerance_secs: u64) -> Self {
        Self {
            secret,
            tolerance_secs,
            max_body_bytes: MAX_BODY_BYTES,
        }
    }

    /// Resolve the secret through custody and build the verifier.
    pub fn from_custody(tolerance_secs: u64) -> Result<Self, WebhookError> {
        Ok(Self::new(WebhookSecret::from_custody()?, tolerance_secs))
    }

    /// Override the body bound (tests and hosts with a tighter limit).
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes.max(1);
        self
    }

    /// Verify one request at `now_unix` and lower its payload.
    ///
    /// Every check is fail-closed: a malformed, missing, stale or
    /// mismatched signature returns an error, and the payload is parsed
    /// only after the signature verifies.
    pub fn verify(
        &self,
        request: &WebhookRequest,
        now_unix: u64,
    ) -> Result<WebhookDelivery, WebhookError> {
        if request.method() != "POST" {
            return Err(WebhookError::new(
                "a4mc_webhook_method_invalid",
                "webhook requests must use POST",
            ));
        }
        if request.body().is_empty() {
            return Err(WebhookError::new(
                "a4mc_webhook_body_empty",
                "webhook body is empty",
            ));
        }
        if request.body_len() > self.max_body_bytes {
            return Err(WebhookError::new(
                "a4mc_webhook_body_too_large",
                "webhook body exceeded the configured bound",
            ));
        }
        for (name, value) in request.headers() {
            if name.len() > 256 || value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(WebhookError::new(
                    "a4mc_webhook_headers_too_large",
                    "webhook header exceeded the configured bound",
                ));
            }
        }
        let timestamp_text = request.header(TIMESTAMP_HEADER).ok_or_else(|| {
            WebhookError::new(
                "a4mc_webhook_timestamp_missing",
                "webhook timestamp header is missing",
            )
        })?;
        let signed_at: u64 = timestamp_text.parse().map_err(|_| {
            WebhookError::new(
                "a4mc_webhook_timestamp_invalid",
                "webhook timestamp is not unix seconds",
            )
        })?;
        if signed_at.abs_diff(now_unix) > self.tolerance_secs {
            return Err(WebhookError::new(
                "a4mc_webhook_timestamp_stale",
                "webhook timestamp is outside the accepted window",
            ));
        }
        let signature_header = request.header(SIGNATURE_HEADER).ok_or_else(|| {
            WebhookError::new(
                "a4mc_webhook_signature_missing",
                "webhook signature header is missing",
            )
        })?;
        let (scheme, signature_hex) = signature_header.split_once('=').ok_or_else(|| {
            WebhookError::new(
                "a4mc_webhook_signature_invalid",
                "webhook signature is malformed",
            )
        })?;
        if !scheme.eq_ignore_ascii_case("sha256") || signature_hex.len() != 64 {
            return Err(WebhookError::new(
                "a4mc_webhook_signature_invalid",
                "webhook signature is malformed",
            ));
        }
        let expected = decode_hex(signature_hex).ok_or_else(|| {
            WebhookError::new(
                "a4mc_webhook_signature_invalid",
                "webhook signature is malformed",
            )
        })?;
        let mut mac = HmacSha256::new_from_slice(self.secret.key_bytes()).map_err(|_| {
            WebhookError::new(
                "a4mc_webhook_secret_invalid",
                "webhook secret could not initialize HMAC",
            )
        })?;
        mac.update(timestamp_text.as_bytes());
        mac.update(b".");
        mac.update(request.body());
        mac.verify_slice(&expected).map_err(|_| {
            WebhookError::new(
                "a4mc_webhook_signature_invalid",
                "webhook signature does not match",
            )
        })?;

        let event = payload::parse(request.body())?;
        Ok(WebhookDelivery {
            event,
            signed_at,
            signature: signature_hex.to_ascii_lowercase(),
        })
    }
}

/// Sign a body exactly as a sender would. The host or an upstream system
/// uses this to produce `X-A4MC-Signature`; the dialect uses the same
/// routine for verification fixtures.
pub fn sign(secret: &WebhookSecret, timestamp: u64, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.key_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!(
        "{SIGNATURE_PREFIX}{}",
        encode_hex(&mac.finalize().into_bytes())
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::WebhookRequest;
    use a4mc::{ChannelError, InboundUpdate};
    use std::sync::{Arc, Mutex};

    /// Custody is process-wide; serialize tests that install it.
    static CUSTODY_LOCK: Mutex<()> = Mutex::new(());

    const BODY: &str = r#"{"kind":"message","chat":{"id":"1","kind":"direct","title":null},"author":{"id":"2","username":null,"displayName":null},"messageId":"3","threadId":null,"sentAt":null,"editedAt":null,"content":"text","text":"hi","caption":null,"attachments":[],"replyTo":null,"forwardLabel":null,"location":null,"venueLabel":null,"contactLabel":null,"pollQuestion":null}"#;
    const BODY_SIGNATURE: &str = "0e094ff23f6f5c2a2137b58d689ffb6a99483748a2cffca6922b93dcaa6ba703";

    fn secret(value: &str) -> WebhookSecret {
        WebhookSecret::new(SecretToken::try_from_string(value.into()).unwrap()).unwrap()
    }

    fn verifier() -> WebhookVerifier {
        WebhookVerifier::new(secret("fixture-webhook-secret"), DEFAULT_TOLERANCE_SECS)
    }

    fn signed(body: impl Into<Vec<u8>>) -> WebhookRequest {
        let body = body.into();
        let timestamp = 1_700_000_000u64;
        let signature = sign(&secret("fixture-webhook-secret"), timestamp, &body);
        WebhookRequest::new("POST", body)
            .with_header(TIMESTAMP_HEADER, timestamp.to_string())
            .with_header(SIGNATURE_HEADER, signature)
    }

    #[test]
    fn known_hmac_vector_verifies_and_lowers() {
        let request = WebhookRequest::new("POST", BODY)
            .with_header("X-A4MC-Timestamp", "1700000000")
            .with_header("X-A4MC-Signature", format!("sha256={BODY_SIGNATURE}"));
        let delivery = verifier().verify(&request, 1_700_000_000).unwrap();
        assert_eq!(delivery.signed_at, 1_700_000_000);
        assert_eq!(delivery.signature, BODY_SIGNATURE);
        assert_eq!(delivery.event.channel.as_str(), "webhook");
        let InboundUpdate::Message(message) = delivery.event.update else {
            panic!("expected message");
        };
        assert_eq!(message.message_id.as_str(), "3");
        assert_eq!(message.text.as_deref(), Some("hi"));
    }

    #[test]
    fn generated_signature_roundtrips_and_header_case_is_ignored() {
        let request = signed(BODY.as_bytes().to_vec());
        let delivery = verifier().verify(&request, 1_700_000_000).unwrap();
        assert_eq!(delivery.event.channel.as_str(), crate::CHANNEL);
        assert_eq!(delivery.signature.len(), 64);
    }

    #[test]
    fn tampered_body_wrong_secret_and_malformed_signature_fail_closed() {
        let request = signed(BODY.as_bytes().to_vec());
        let tampered = WebhookRequest::new("POST", BODY.replace("hi", "bye"))
            .with_header(TIMESTAMP_HEADER, "1700000000")
            .with_header(SIGNATURE_HEADER, request.header(SIGNATURE_HEADER).unwrap());
        assert_eq!(
            verifier()
                .verify(&tampered, 1_700_000_000)
                .unwrap_err()
                .code,
            "a4mc_webhook_signature_invalid"
        );

        let other = WebhookVerifier::new(secret("fixture-other-secret"), 300);
        assert_eq!(
            other.verify(&request, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_signature_invalid"
        );

        let malformed = WebhookRequest::new("POST", BODY.as_bytes().to_vec())
            .with_header(TIMESTAMP_HEADER, "1700000000")
            .with_header(SIGNATURE_HEADER, "sha256=zzzz");
        assert_eq!(
            verifier()
                .verify(&malformed, 1_700_000_000)
                .unwrap_err()
                .code,
            "a4mc_webhook_signature_invalid"
        );
    }

    #[test]
    fn missing_headers_and_bad_methods_are_rejected() {
        let missing_timestamp = WebhookRequest::new("POST", BODY.as_bytes().to_vec())
            .with_header(SIGNATURE_HEADER, format!("sha256={BODY_SIGNATURE}"));
        assert_eq!(
            verifier()
                .verify(&missing_timestamp, 1_700_000_000)
                .unwrap_err()
                .code,
            "a4mc_webhook_timestamp_missing"
        );

        let missing_signature = WebhookRequest::new("POST", BODY.as_bytes().to_vec())
            .with_header(TIMESTAMP_HEADER, "1700000000");
        assert_eq!(
            verifier()
                .verify(&missing_signature, 1_700_000_000)
                .unwrap_err()
                .code,
            "a4mc_webhook_signature_missing"
        );

        let get = WebhookRequest::new("GET", BODY.as_bytes().to_vec())
            .with_header(TIMESTAMP_HEADER, "1700000000")
            .with_header(SIGNATURE_HEADER, format!("sha256={BODY_SIGNATURE}"));
        assert_eq!(
            verifier().verify(&get, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_method_invalid"
        );
    }

    #[test]
    fn timestamps_outside_the_window_are_rejected() {
        let request = signed(BODY.as_bytes().to_vec());
        assert_eq!(
            verifier()
                .verify(&request, 1_700_000_000 + DEFAULT_TOLERANCE_SECS + 1)
                .unwrap_err()
                .code,
            "a4mc_webhook_timestamp_stale"
        );
        assert_eq!(
            verifier()
                .verify(&request, 1_700_000_000 - DEFAULT_TOLERANCE_SECS - 1)
                .unwrap_err()
                .code,
            "a4mc_webhook_timestamp_stale"
        );
        assert!(
            verifier()
                .verify(&request, 1_700_000_000 + DEFAULT_TOLERANCE_SECS)
                .is_ok()
        );
    }

    #[test]
    fn body_bound_is_enforced_before_parsing() {
        let request = signed(BODY.as_bytes().to_vec());
        let verifier = verifier().with_max_body_bytes(8);
        assert_eq!(
            verifier.verify(&request, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_body_too_large"
        );
        let empty = WebhookRequest::new("POST", Vec::new());
        assert_eq!(
            verifier.verify(&empty, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_body_empty"
        );
    }

    #[test]
    fn a_valid_signature_over_invalid_json_is_a_payload_error() {
        let request = signed(b"not json".to_vec());
        assert_eq!(
            verifier().verify(&request, 1_700_000_000).unwrap_err().code,
            "a4mc_webhook_payload_invalid"
        );
    }

    #[test]
    fn secret_and_request_debug_never_show_values_or_body() {
        let secret_debug = format!("{:?}", secret("fixture-CANARY-secret"));
        assert!(secret_debug.contains("[redacted]"));
        assert!(!secret_debug.contains("CANARY"));

        let request = signed(BODY.as_bytes().to_vec()).with_header("authorization", "CANARY");
        let debug = format!("{request:?}");
        assert!(debug.contains("body_len"));
        assert!(!debug.contains("CANARY"));
        assert!(!debug.contains("\"hi\""));
    }

    #[test]
    fn resolves_secret_through_custody_channel_key() {
        let _guard = CUSTODY_LOCK.lock().unwrap();
        a4mc::custody::clear();

        struct FixtureCustody;
        impl a4mc::CustodyPort for FixtureCustody {
            fn channel_token(
                &self,
                channel: &ChannelId,
            ) -> Result<Option<SecretToken>, ChannelError> {
                match channel.as_str() {
                    crate::CHANNEL => Ok(Some(
                        SecretToken::try_from_string("fixture-webhook-secret".into()).unwrap(),
                    )),
                    _ => Ok(None),
                }
            }
        }

        let port: Arc<dyn a4mc::CustodyPort> = Arc::new(FixtureCustody);
        a4mc::custody::install(Arc::clone(&port)).unwrap();
        let resolved = WebhookSecret::from_custody().unwrap();
        assert_eq!(resolved.key_bytes(), b"fixture-webhook-secret");
        a4mc::custody::clear();
    }

    #[test]
    fn custody_without_a_secret_fails_closed() {
        let _guard = CUSTODY_LOCK.lock().unwrap();
        a4mc::custody::clear();
        assert_eq!(
            WebhookSecret::from_custody().unwrap_err().code,
            "a4mc_webhook_custody_unavailable"
        );
    }
}
