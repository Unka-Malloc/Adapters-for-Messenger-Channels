//! Normalized outbound sends and their delivery receipts.

use crate::error::ChannelError;
use crate::identity::{ExternalChatId, ExternalMessageId};
use serde::{Deserialize, Serialize};

/// Upper bound for one outbound text body (characters).
pub const MAX_OUTBOUND_TEXT_CHARS: usize = 32 * 1024;
/// Upper bound for an idempotency key (characters).
pub const MAX_IDEMPOTENCY_KEY_CHARS: usize = 128;

/// One outbound message send. Every send carries an `idempotency_key`:
/// callers derive it so a retried send is safe (e.g. `reply:<update>`).
/// Whether the platform or the adapter honors the key is declared per
/// adapter via [`crate::descriptor::SendFeature::Idempotency`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundMessage {
    pub chat_id: ExternalChatId,
    pub text: String,
    /// The platform message this send replies to, when threaded.
    pub reply_to_message_id: Option<ExternalMessageId>,
    pub idempotency_key: String,
}

impl OutboundMessage {
    pub fn new(
        chat_id: impl Into<ExternalChatId>,
        text: impl Into<String>,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self {
            chat_id: chat_id.into(),
            text: text.into(),
            reply_to_message_id: None,
            idempotency_key: idempotency_key.into(),
        }
    }

    /// Bounded-payload check run at the contract edge. Adapters validate
    /// before lowering; invalid sends are rejected, never truncated.
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.chat_id.as_str().trim().is_empty() {
            return Err(ChannelError::new(
                "a4mc_outbound_chat_invalid",
                "outbound send has no chat id",
            ));
        }
        if self.text.trim().is_empty() {
            return Err(ChannelError::new(
                "a4mc_outbound_text_empty",
                "outbound send has no text",
            ));
        }
        if self.text.chars().count() > MAX_OUTBOUND_TEXT_CHARS {
            return Err(ChannelError::new(
                "a4mc_outbound_text_too_large",
                "outbound text exceeded bound",
            ));
        }
        let key = self.idempotency_key.trim();
        if key.is_empty() || self.idempotency_key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS {
            return Err(ChannelError::new(
                "a4mc_idempotency_key_invalid",
                "idempotency key missing or oversized",
            ));
        }
        Ok(())
    }
}

/// The delivery receipt of one accepted send. A rejected send is an
/// error, not a receipt: `send` returns `Err(ChannelError)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendReceipt {
    /// The key the send carried — echoed so callers can correlate.
    pub idempotency_key: String,
    /// Platform message ids, one per transmitted part (a dialect that
    /// chunks long text reports every part's id, in send order).
    pub message_ids: Vec<ExternalMessageId>,
}
