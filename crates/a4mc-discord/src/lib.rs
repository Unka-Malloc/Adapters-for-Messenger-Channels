//! a4mc-discord — the Discord dialect of the A4MC channel contract.
//!
//! This crate lowers Discord onto [`a4mc`] without requiring public
//! ingress:
//!
//! * [`transport`] — Discord REST client (`GET /users/@me`,
//!   `POST /channels/{id}/messages`). The bot token resolves through the
//!   host-installed [`a4mc::custody`] port under [`CHANNEL`]; the crate
//!   never reads keychains, files or environment for it.
//! * [`gateway`] — Discord Gateway protocol v10 over a persistent
//!   websocket: `HELLO`, `IDENTIFY`/`RESUME`, heartbeats with zombie
//!   detection, dispatch sequence tracking, `RECONNECT` and
//!   `INVALID_SESSION`, plus a live tungstenite connector. No public
//!   callback is needed behind an enterprise firewall.
//! * [`lower`] — Gateway dispatches projected onto
//!   [`a4mc::InboundUpdate`]: messages, edits, deletions, member changes
//!   and reactions. Event kinds this dialect does not wire lower to
//!   `Unsupported`, never silently dropped.
//! * [`channel`] — the normalized surface: a [`a4mc::ChannelAdapter`]
//!   descriptor declaring the Gateway native and callback/poll
//!   mechanisms unsupported, plus `OutboundMessage` sends with a
//!   deterministic nonce and adapter-side idempotency dedupe.
//!
//! ## Credentials
//!
//! One bot token is issued by Discord and resolved through
//! [`a4mc::custody`] for [`CHANNEL`]. It has no serialized form and a
//! redacted `Debug`; the Gateway `IDENTIFY` frame is the only place it
//! is exposed.
//!
//! ## Receive path
//!
//! [`run_gateway`] connects to the Gateway, identifies (or resumes),
//! heartbeats on the advertised interval, and lowers each dispatch
//! before invoking the host's [`gateway::GatewayHandler`]. Resume state
//! (`sequence`, session id, resume URL) survives a reconnect.

pub mod channel;
pub mod gateway;
pub mod lower;
pub mod transport;

pub use channel::{CHANNEL, DiscordChannel, client_nonce, descriptor};
pub use gateway::{
    DEFAULT_GATEWAY_URL, DEFAULT_INTENTS, GatewayConfig, GatewayConnection, GatewayConnector,
    GatewayHandler, GatewayModeConfig, GatewayPayload, GatewayRead, GatewaySession, GatewayUrl,
    HANDLER_FAILED_CODE, INTENT_DIRECT_MESSAGE_REACTIONS, INTENT_DIRECT_MESSAGES,
    INTENT_GUILD_MEMBERS, INTENT_GUILD_MESSAGE_REACTIONS, INTENT_GUILD_MESSAGES, INTENT_GUILDS,
    LiveGatewayConnector, SessionOutcome, TERMINAL_CLOSE_CODE, is_terminal_close_code, run_gateway,
    run_gateway_session,
};
pub use lower::{lower_event, lower_events, lower_update, parse_timestamp};
pub use transport::{
    DEFAULT_API_ROOT, DiscordApi, DiscordApiError, DiscordIdentity, DiscordToken, LiveDiscordApi,
    MockDiscordApi, PostMessageRequest, PostedMessage, live_api,
};

/// This dialect's channel identifier on the a4mc contract.
pub fn channel_id() -> a4mc::ChannelId {
    a4mc::ChannelId::from(CHANNEL)
}
