//! a4mc-telegram — the Telegram dialect of the A4MC channel contract.
//!
//! This crate lowers Telegram onto [`a4mc`]:
//!
//! * [`transport`] — Bot API client (`getUpdates` long polling today;
//!   the platform's webhook mechanism is declared unsupported, not
//!   silently dropped);
//! * [`inbound`] / [`lower`] — update parsing/classification and the
//!   projection onto `a4mc::InboundUpdate`;
//! * [`channel`] — the normalized surface: the [`a4mc::ChannelAdapter`]
//!   descriptor and `OutboundMessage` sends with adapter-side
//!   idempotency dedupe;
//! * [`binding`], [`control`], [`runtime`] — the channel's own state and
//!   UX: per-chat pairing/agent/session bindings, the slash-command
//!   surface, and the bounded fair scheduler that runs the channel loop;
//! * [`bridge`] — turns reach local agent work only through the
//!   host-installed `a4mc::lane` port.
//!
//! Bot-token custody stays in the host: [`transport::live_transport`]
//! resolves the token through the `a4mc::custody` port — the crate never
//! reads keychains, files or environment for it, and secret bytes never
//! appear in serialized or debug forms.

pub mod binding;
pub mod bridge;
pub mod channel;
pub mod control;
pub mod inbound;
pub mod lower;
mod private_io;
pub mod runtime;
pub mod transport;

pub use binding::{BINDING_SCHEMA, BindingStore, ChatBinding, PairingRecord};
pub use channel::{CHANNEL, TelegramChannel, descriptor};
pub use control::{ControlCommand, ControlOutcome, parse_control_command};
pub use inbound::{InboundKind, InboundMessage, MediaRef, ReplyRef};
pub use lower::{lower_event, lower_message, lower_update};
pub use runtime::{RuntimeConfig, run_channel_loop};
pub use transport::{
    BotIdentity, BotTransport, LiveBotTransport, MockBotTransport, TelegramApiError, Update,
    bot_commands, live_transport, validate_bot_token,
};

/// This dialect's channel identifier on the a4mc contract.
pub fn channel_id() -> a4mc::ChannelId {
    a4mc::ChannelId::from(CHANNEL)
}
