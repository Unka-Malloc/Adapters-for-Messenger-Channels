//! a4mc-slack — the Slack dialect of the A4MC channel contract.
//!
//! This crate lowers Slack onto [`a4mc`] without requiring public
//! ingress:
//!
//! * [`transport`] — Slack Web API client (`auth.test`,
//!   `apps.connections.open`, `chat.postMessage`). Both the app-level
//!   Socket Mode token and the bot token resolve through the
//!   host-installed [`a4mc::custody`] port; the crate never reads
//!   keychains, files or environment for them.
//! * [`socket`] — Slack Socket Mode: hello/envelope/disconnect framing,
//!   acknowledgement before dispatch, bounded envelope-id dedupe,
//!   reconnects with a fresh short-lived socket URL, and a live
//!   tungstenite connector. A persistent outbound websocket means no
//!   public callback is needed behind an enterprise firewall.
//! * [`lower`] — Slack event callbacks projected onto
//!   [`a4mc::InboundUpdate`]: messages, edits, deletions, member changes
//!   and reactions. Event kinds this dialect does not wire lower to
//!   `Unsupported`, never silently dropped.
//! * [`channel`] — the normalized surface: a [`a4mc::ChannelAdapter`]
//!   descriptor that declares Socket Mode native and callback/poll
//!   mechanisms unsupported, plus `OutboundMessage` sends with
//!   adapter-side idempotency dedupe and a deterministic
//!   `client_msg_id`.
//! * [`bridge`] — turns reach local agent work only through the
//!   host-installed [`a4mc::lane`] port.
//!
//! ## Credentials
//!
//! Slack issues two independently scoped credentials. The host's custody
//! port answers [`APP_TOKEN_CHANNEL`] with the app-level token used for
//! `apps.connections.open`, and [`CHANNEL`] with the bot token used for
//! Web API sends. Neither token appears in serialized or debug forms.
//!
//! ## Receive path
//!
//! [`run_socket_mode`] asks Slack for a socket URL, opens one websocket,
//! acknowledges every envelope before invoking the host's
//! [`socket::SocketHandler`], and reconnects when Slack asks for it.
//! Duplicate envelope ids are acknowledged again but dispatched once,
//! so a retry cannot duplicate a host turn.

pub mod bridge;
pub mod channel;
pub mod lower;
pub mod socket;
pub mod transport;

pub use bridge::{
    AgentSummary, BridgeError, SessionSummary, ensure_known_agent, list_agents, list_sessions,
    open_session, send_turn,
};
pub use channel::{CHANNEL, SlackChannel, client_msg_id, descriptor};
pub use lower::{lower_event, lower_update};
pub use socket::{
    LiveSocketConnector, SeenEnvelopes, SessionOutcome, SocketConnection, SocketConnector,
    SocketEnvelope, SocketFrame, SocketHandler, SocketModeConfig, SocketRead, ack_frame,
    run_socket_mode, run_socket_session,
};
pub use transport::{
    LiveSlackApi, MockSlackApi, PostMessageRequest, PostedMessage, SlackApi, SlackApiError,
    SlackIdentity, SlackTokens, SocketUrl, live_api,
};

/// The custody lookup key for the Slack app-level Socket Mode token.
///
/// Slack scopes this token to `connections:write`; it is not the bot
/// token and cannot post messages.
pub const APP_TOKEN_CHANNEL: &str = "slack-app";

/// This dialect's channel identifier on the a4mc contract.
pub fn channel_id() -> a4mc::ChannelId {
    a4mc::ChannelId::from(CHANNEL)
}
