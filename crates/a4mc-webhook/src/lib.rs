//! a4mc-webhook — the signed-HTTP webhook dialect of the A4MC channel
//! contract.
//!
//! The composing host owns the HTTP server and adapts an inbound request
//! into [`WebhookRequest`]; this crate owns the trust boundary and the
//! lowering:
//!
//! * [`signature`] — HMAC-SHA256 verification over
//!   `timestamp + "." + body`, a bounded timestamp window, constant-time
//!   comparison, and fail-closed rejection before any parsing. The
//!   signing secret resolves through [`a4mc::custody`] under
//!   [`CHANNEL`]; the crate reads no keychain, file or environment.
//! * [`payload`] — the verified body is the contract's own JSON: a
//!   [`a4mc::ChannelEvent`], an [`a4mc::InboundUpdate`], or a bare
//!   [`a4mc::InboundMessage`]. Every normalized field survives the
//!   translation, and the event is stamped with [`CHANNEL`].
//! * [`receiver`] — optional bounded replay suppression over verified
//!   signatures, so an exact retry is acknowledged without running the
//!   update twice.
//! * [`channel`] — a complete descriptor declaring webhook native,
//!   socket/poll unsupported, every update kind native, and every send
//!   feature unsupported (a webhook is receive-only).
//!
//! ## Signed request
//!
//! ```text
//! POST /webhook HTTP/1.1
//! X-A4MC-Timestamp: 1700000000
//! X-A4MC-Signature: sha256=<hex HMAC-SHA256(secret, "1700000000." + body)>
//!
//! {"kind":"message", ...}
//! ```
//!
//! Any missing, malformed, stale or mismatched signature returns a
//! [`WebhookError`]; the payload is never parsed first.

pub mod channel;
pub mod error;
pub mod payload;
pub mod receiver;
pub mod request;
pub mod signature;

pub use channel::{CHANNEL, WebhookAdapter, descriptor};
pub use error::WebhookError;
pub use payload::parse;
pub use receiver::{DeliveryOutcome, WebhookReceiver};
pub use request::WebhookRequest;
pub use signature::{
    DEFAULT_TOLERANCE_SECS, MAX_BODY_BYTES, MAX_HEADER_VALUE_BYTES, SIGNATURE_HEADER,
    SIGNATURE_PREFIX, TIMESTAMP_HEADER, WebhookDelivery, WebhookSecret, WebhookVerifier, sign,
};

/// This dialect's channel identifier on the a4mc contract.
pub fn channel_id() -> a4mc::ChannelId {
    a4mc::ChannelId::from(CHANNEL)
}
