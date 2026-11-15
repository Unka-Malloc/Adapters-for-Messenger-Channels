//! Discord Gateway websocket receive.
//!
//! The Gateway is a persistent, server-to-client websocket. This module
//! speaks protocol v10 framing: `HELLO`, `IDENTIFY`/`RESUME`, heartbeats,
//! dispatch events, `RECONNECT` and `INVALID_SESSION`. No public callback
//! URL or inbound ingress is involved, so the dialect works where a
//! firewall forbids inbound callbacks.
//!
//! Dispatch events are lowered in [`crate::lower`] and handed to the
//! host's [`GatewayHandler`]. Duplicate sequence numbers (possible after
//! a resume replay) are observed once at this layer, and the session
//! state carries the sequence, session id and resume URL across
//! reconnects.
//!
//! Tokens travel only from host custody into the `IDENTIFY` frame; they
//! are never logged, serialized into errors, or included in a debug form.

use crate::transport::DiscordApiError;
use crate::transport::DiscordToken;
use a4mc::{ChannelEvent, SecretToken};
use serde_json::{Value, json};
use std::fmt;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Discord Gateway protocol version and JSON encoding.
pub const DEFAULT_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";

/// Gateway opcodes this dialect handles or observes.
pub const OP_DISPATCH: u8 = 0;
pub const OP_HEARTBEAT: u8 = 1;
pub const OP_IDENTIFY: u8 = 2;
pub const OP_RESUME: u8 = 6;
pub const OP_RECONNECT: u8 = 7;
pub const OP_INVALID_SESSION: u8 = 9;
pub const OP_HELLO: u8 = 10;
pub const OP_HEARTBEAT_ACK: u8 = 11;

/// Guild lifecycle events.
pub const INTENT_GUILDS: u64 = 1 << 0;
/// Guild member add/remove events. Discord marks this a privileged
/// intent: an application without the grant receives no member events.
pub const INTENT_GUILD_MEMBERS: u64 = 1 << 1;
/// Guild message create/update/delete events.
pub const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
/// Guild message reaction add/remove events.
pub const INTENT_GUILD_MESSAGE_REACTIONS: u64 = 1 << 10;
/// Direct message create/update/delete events.
pub const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
/// Direct message reaction add/remove events.
pub const INTENT_DIRECT_MESSAGE_REACTIONS: u64 = 1 << 13;

/// The intents needed to receive every update kind this dialect lowers.
pub const DEFAULT_INTENTS: u64 = INTENT_GUILDS
    | INTENT_GUILD_MEMBERS
    | INTENT_GUILD_MESSAGES
    | INTENT_GUILD_MESSAGE_REACTIONS
    | INTENT_DIRECT_MESSAGES
    | INTENT_DIRECT_MESSAGE_REACTIONS;

const MAX_GATEWAY_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// A Gateway URL. The value is not itself a secret, but a resume URL is
/// a short-lived capability and is redacted in `Debug` so it never lands
/// in a log by accident.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct GatewayUrl(String);

impl GatewayUrl {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GatewayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayUrl([redacted])")
    }
}

/// One decoded Gateway payload.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayPayload {
    pub op: u8,
    pub data: Value,
    /// Gateway sequence number, carried by dispatch events.
    pub sequence: Option<u64>,
    /// Dispatch event name (`MESSAGE_CREATE`, `READY`, ...).
    pub event: Option<String>,
}

impl GatewayPayload {
    /// Decode one websocket text frame. The error is bounded and never
    /// echoes the frame body.
    pub fn parse(text: &str) -> Result<Self, DiscordApiError> {
        if text.len() > MAX_GATEWAY_FRAME_BYTES {
            return Err(DiscordApiError::new(
                "a4mc_discord_gateway_invalid",
                "Gateway frame exceeded bound",
            ));
        }
        let value: Value = serde_json::from_str(text).map_err(|_| {
            DiscordApiError::new(
                "a4mc_discord_gateway_invalid",
                "Gateway frame was not valid JSON",
            )
        })?;
        let op = value
            .get("op")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| {
                DiscordApiError::new(
                    "a4mc_discord_gateway_invalid",
                    "Gateway frame has no valid opcode",
                )
            })?;
        Ok(Self {
            op,
            data: value.get("d").cloned().unwrap_or(Value::Null),
            sequence: value.get("s").and_then(Value::as_u64),
            event: value
                .get("t")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        })
    }
}

/// The result of one bounded socket read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayRead {
    Text(String),
    /// No frame arrived before the read timeout; a heartbeat is due.
    Timeout,
    /// The peer closed the socket.
    Closed,
}

/// A Gateway websocket connection.
///
/// `read_frame` is time-bounded so the session can send protocol
/// heartbeats while the socket is idle. Implementations are synchronous
/// and owned by one session thread.
pub trait GatewayConnection: Send {
    fn read_frame(&mut self, timeout: Duration) -> Result<GatewayRead, DiscordApiError>;
    fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError>;
    fn close(&mut self) {}
}

/// Opens one Gateway connection for a URL.
pub trait GatewayConnector: Send + Sync {
    fn connect(&self, url: &GatewayUrl) -> Result<Box<dyn GatewayConnection>, DiscordApiError>;
}

/// tungstenite-backed live connector. TLS roots come from the platform
/// store; the Gateway URL never appears in errors.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveGatewayConnector;

impl GatewayConnector for LiveGatewayConnector {
    fn connect(&self, url: &GatewayUrl) -> Result<Box<dyn GatewayConnection>, DiscordApiError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (socket, _response) = tungstenite::connect(url.expose()).map_err(|_| {
            DiscordApiError::new(
                "a4mc_discord_gateway_connect_failed",
                "Gateway connection failed",
            )
        })?;
        Ok(Box::new(LiveGatewayConnection { socket }))
    }
}

struct LiveGatewayConnection {
    socket: tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
}

impl LiveGatewayConnection {
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), DiscordApiError> {
        let stream = match self.socket.get_ref() {
            tungstenite::stream::MaybeTlsStream::Plain(stream) => stream,
            tungstenite::stream::MaybeTlsStream::Rustls(stream) => &stream.sock,
            _ => {
                return Err(DiscordApiError::new(
                    "a4mc_discord_gateway_failed",
                    "Gateway stream does not expose a TCP socket",
                ));
            }
        };
        stream
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|_| {
                DiscordApiError::new(
                    "a4mc_discord_gateway_failed",
                    "Gateway read timeout could not be set",
                )
            })
    }
}

impl GatewayConnection for LiveGatewayConnection {
    fn read_frame(&mut self, timeout: Duration) -> Result<GatewayRead, DiscordApiError> {
        self.set_read_timeout(timeout)?;
        loop {
            match self.socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    return Ok(GatewayRead::Text(text.to_string()));
                }
                Ok(tungstenite::Message::Binary(_))
                | Ok(tungstenite::Message::Ping(_))
                | Ok(tungstenite::Message::Pong(_))
                | Ok(tungstenite::Message::Frame(_)) => {}
                Ok(tungstenite::Message::Close(_)) => return Ok(GatewayRead::Closed),
                Err(tungstenite::Error::ConnectionClosed)
                | Err(tungstenite::Error::AlreadyClosed) => return Ok(GatewayRead::Closed),
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(GatewayRead::Timeout);
                }
                Err(_) => {
                    return Err(DiscordApiError::new(
                        "a4mc_discord_gateway_failed",
                        "Gateway read failed",
                    ));
                }
            }
        }
    }

    fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError> {
        self.socket
            .send(tungstenite::Message::text(text.to_owned()))
            .map_err(|_| {
                DiscordApiError::new("a4mc_discord_gateway_failed", "Gateway write failed")
            })
    }

    fn close(&mut self) {
        let _ = self.socket.close(None);
        let _ = self.socket.flush();
    }
}

/// The host's answer to one Gateway dispatch.
pub trait GatewayHandler {
    /// A lowered dispatch. `payload` carries the raw data and event name
    /// for host policy.
    fn on_dispatch(
        &mut self,
        event: &ChannelEvent,
        payload: &GatewayPayload,
    ) -> Result<(), DiscordApiError>;
}

/// Cross-reconnect Gateway session state.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct GatewaySession {
    /// Last observed sequence number.
    pub sequence: Option<u64>,
    /// Session id from `READY`; needed for `RESUME`.
    pub session_id: Option<String>,
    /// `resume_gateway_url` from `READY`.
    pub resume_gateway_url: Option<String>,
}

impl std::fmt::Debug for GatewaySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySession")
            .field("sequence", &self.sequence)
            .field("session_id", &self.session_id)
            .field(
                "resume_gateway_url",
                &self.resume_gateway_url.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl GatewaySession {
    pub fn can_resume(&self) -> bool {
        self.session_id.is_some() && self.sequence.is_some()
    }

    pub fn clear(&mut self) {
        self.sequence = None;
        self.session_id = None;
        self.resume_gateway_url = None;
    }
}

/// Identify/heartbeat settings for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub intents: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            intents: DEFAULT_INTENTS,
        }
    }
}

/// Why one session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Reconnect (and resume when the session state allows it).
    Reconnect,
    /// The host's stop flag was observed.
    Stopped,
}

/// Run one already-connected Gateway session until reconnect, close or
/// stop.
///
/// The session sends `IDENTIFY` on the first `HELLO` (or `RESUME` when
/// `session` carries a session id and sequence), sends a heartbeat on the
/// advertised interval, and treats a missing heartbeat acknowledgement
/// as a zombie connection rather than piling up more heartbeats.
pub fn run_gateway_session(
    connection: &mut dyn GatewayConnection,
    token: &SecretToken,
    handler: &mut dyn GatewayHandler,
    session: &mut GatewaySession,
    config: &GatewayConfig,
    stop: &AtomicBool,
) -> Result<SessionOutcome, DiscordApiError> {
    let mut heartbeat_interval = Duration::from_secs(60);
    let mut next_heartbeat: Option<Instant> = None;
    let mut awaiting_ack = false;
    let mut hello_seen = false;

    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(SessionOutcome::Stopped);
        }
        let timeout = match next_heartbeat {
            Some(at) => at
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
            None => Duration::from_secs(60),
        };
        match connection.read_frame(timeout)? {
            GatewayRead::Closed => return Ok(SessionOutcome::Reconnect),
            GatewayRead::Timeout => {
                if next_heartbeat.is_some() {
                    if awaiting_ack {
                        // The server stopped acknowledging heartbeats:
                        // reconnect instead of treating a zombie as live.
                        return Ok(SessionOutcome::Reconnect);
                    }
                    send_heartbeat(connection, session.sequence)?;
                    awaiting_ack = true;
                    next_heartbeat = Some(Instant::now() + heartbeat_interval);
                }
            }
            GatewayRead::Text(text) => {
                let payload = GatewayPayload::parse(&text)?;
                let duplicate = payload
                    .sequence
                    .is_some_and(|sequence| session.sequence.is_some_and(|last| sequence <= last));
                if let Some(sequence) = payload.sequence {
                    session.sequence =
                        Some(session.sequence.map_or(sequence, |last| last.max(sequence)));
                }
                match payload.op {
                    OP_HELLO => {
                        if hello_seen {
                            continue;
                        }
                        hello_seen = true;
                        let millis = payload
                            .data
                            .get("heartbeat_interval")
                            .and_then(Value::as_u64)
                            .unwrap_or(60_000)
                            .clamp(1, 3_600_000);
                        heartbeat_interval = Duration::from_millis(millis);
                        send_handshake(connection, token, session, config)?;
                        send_heartbeat(connection, session.sequence)?;
                        awaiting_ack = true;
                        next_heartbeat = Some(Instant::now() + heartbeat_interval);
                    }
                    OP_HEARTBEAT => {
                        send_heartbeat(connection, session.sequence)?;
                        awaiting_ack = true;
                        next_heartbeat = Some(Instant::now() + heartbeat_interval);
                    }
                    OP_HEARTBEAT_ACK => awaiting_ack = false,
                    OP_RECONNECT => return Ok(SessionOutcome::Reconnect),
                    OP_INVALID_SESSION => {
                        if !payload.data.as_bool().unwrap_or(false) {
                            session.clear();
                        }
                        return Ok(SessionOutcome::Reconnect);
                    }
                    OP_DISPATCH => {
                        if duplicate {
                            continue;
                        }
                        let event_name = payload.event.as_deref().unwrap_or("unknown_event");
                        if event_name == "READY" {
                            session.session_id = payload
                                .data
                                .get("session_id")
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                                .map(str::to_owned);
                            session.resume_gateway_url = payload
                                .data
                                .get("resume_gateway_url")
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                                .map(str::to_owned);
                        }
                        // READY/RESUMED are session lifecycle, not
                        // channel updates; their state is recorded above
                        // and they are not lowered as host work.
                        if matches!(event_name, "READY" | "RESUMED") {
                            continue;
                        }
                        for event in
                            crate::lower::lower_events(event_name, &payload.data, payload.sequence)
                        {
                            handler.on_dispatch(&event, &payload)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn send_handshake(
    connection: &mut dyn GatewayConnection,
    token: &SecretToken,
    session: &GatewaySession,
    config: &GatewayConfig,
) -> Result<(), DiscordApiError> {
    let token = token.expose_utf8().map_err(|_| {
        DiscordApiError::new("a4mc_discord_token_invalid", "Discord token is not UTF-8")
    })?;
    let payload = if session.can_resume() {
        json!({
            "op": OP_RESUME,
            "d": {
                "token": token,
                "session_id": session.session_id,
                "seq": session.sequence,
            }
        })
    } else {
        json!({
            "op": OP_IDENTIFY,
            "d": {
                "token": token,
                "intents": config.intents,
                "properties": {
                    "os": std::env::consts::OS,
                    "browser": "a4mc-discord",
                    "device": "a4mc-discord",
                }
            }
        })
    };
    connection.send_text(&payload.to_string())
}

fn send_heartbeat(
    connection: &mut dyn GatewayConnection,
    sequence: Option<u64>,
) -> Result<(), DiscordApiError> {
    connection.send_text(&json!({ "op": OP_HEARTBEAT, "d": sequence }).to_string())
}

/// Reconnect policy for [`run_gateway`].
#[derive(Debug, Clone)]
pub struct GatewayModeConfig {
    /// Initial Gateway URL. Resume URLs from `READY` override it after a
    /// session that can resume.
    pub gateway_url: GatewayUrl,
    pub intents: u64,
    /// Maximum sessions to open; `0` means run until `stop`.
    pub max_sessions: usize,
    pub reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
    pub stop: Arc<AtomicBool>,
}

impl Default for GatewayModeConfig {
    fn default() -> Self {
        Self {
            gateway_url: GatewayUrl::new(DEFAULT_GATEWAY_URL),
            intents: DEFAULT_INTENTS,
            max_sessions: 0,
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(30),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Run the Gateway until the stop flag is set (or `max_sessions` is
/// reached), resuming a live session when Discord lets it.
pub fn run_gateway(
    connector: &dyn GatewayConnector,
    token: &DiscordToken,
    handler: &mut dyn GatewayHandler,
    config: &GatewayModeConfig,
) -> Result<(), DiscordApiError> {
    let session_config = GatewayConfig {
        intents: config.intents,
    };
    let mut session = GatewaySession::default();
    let mut sessions = 0usize;
    let mut backoff = config.reconnect_delay;
    loop {
        if config.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if config.max_sessions != 0 && sessions >= config.max_sessions {
            return Ok(());
        }
        sessions += 1;
        let url = session
            .resume_gateway_url
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(resume_url)
            .unwrap_or_else(|| config.gateway_url.clone());
        let mut connection = match connector.connect(&url) {
            Ok(connection) => connection,
            Err(error) => {
                if config.max_sessions != 0 && sessions >= config.max_sessions {
                    return Err(error);
                }
                backoff = sleep_before_retry(backoff, config.max_reconnect_delay);
                continue;
            }
        };
        let outcome = run_gateway_session(
            &mut *connection,
            token.token(),
            handler,
            &mut session,
            &session_config,
            &config.stop,
        );
        connection.close();
        let delay = match outcome {
            Ok(SessionOutcome::Stopped) => return Ok(()),
            Ok(SessionOutcome::Reconnect) => {
                backoff = config.reconnect_delay;
                config.reconnect_delay
            }
            Err(error) => {
                if config.max_sessions != 0 && sessions >= config.max_sessions {
                    return Err(error);
                }
                backoff = backoff.max(config.reconnect_delay);
                let delay = backoff;
                backoff = backoff.saturating_mul(2).min(config.max_reconnect_delay);
                delay
            }
        };
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }
}

fn resume_url(base: &str) -> GatewayUrl {
    let base = base.trim_end_matches('/');
    if base.contains('?') {
        GatewayUrl::new(base.to_owned())
    } else {
        GatewayUrl::new(format!("{base}/?v=10&encoding=json"))
    }
}

fn sleep_before_retry(backoff: Duration, max: Duration) -> Duration {
    let delay = backoff;
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    delay.saturating_mul(2).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use a4mc::InboundUpdate;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingHandler {
        events: Vec<ChannelEvent>,
        payloads: Vec<GatewayPayload>,
    }

    impl GatewayHandler for RecordingHandler {
        fn on_dispatch(
            &mut self,
            event: &ChannelEvent,
            payload: &GatewayPayload,
        ) -> Result<(), DiscordApiError> {
            self.events.push(event.clone());
            self.payloads.push(payload.clone());
            Ok(())
        }
    }

    struct ScriptedConnection {
        frames: VecDeque<GatewayRead>,
        sent: Arc<Mutex<Vec<Value>>>,
    }

    impl ScriptedConnection {
        fn new(
            frames: impl IntoIterator<Item = GatewayRead>,
            sent: Arc<Mutex<Vec<Value>>>,
        ) -> Self {
            Self {
                frames: frames.into_iter().collect(),
                sent,
            }
        }
    }

    impl GatewayConnection for ScriptedConnection {
        fn read_frame(&mut self, _timeout: Duration) -> Result<GatewayRead, DiscordApiError> {
            Ok(self.frames.pop_front().unwrap_or(GatewayRead::Closed))
        }

        fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError> {
            self.sent
                .lock()
                .unwrap()
                .push(serde_json::from_str(text).unwrap());
            Ok(())
        }
    }

    fn hello() -> GatewayRead {
        GatewayRead::Text(json!({"op": 10, "d": {"heartbeat_interval": 30_000}}).to_string())
    }

    fn ready() -> GatewayRead {
        GatewayRead::Text(
            json!({
                "op": 0,
                "s": 1,
                "t": "READY",
                "d": {
                    "session_id": "session-1",
                    "resume_gateway_url": "wss://resume.invalid"
                }
            })
            .to_string(),
        )
    }

    fn message(sequence: u64) -> GatewayRead {
        GatewayRead::Text(
            json!({
                "op": 0,
                "s": sequence,
                "t": "MESSAGE_CREATE",
                "d": {
                    "id": format!("M{sequence}"),
                    "channel_id": "C1",
                    "author": { "id": "U1", "username": "alice" },
                    "content": "hello",
                    "timestamp": "2023-11-14T22:13:20Z"
                }
            })
            .to_string(),
        )
    }

    fn reconnect() -> GatewayRead {
        GatewayRead::Text(json!({"op": OP_RECONNECT}).to_string())
    }

    #[test]
    fn parses_hello_dispatch_and_reconnect_payloads() {
        let hello = GatewayPayload::parse(
            &json!({"op": 10, "d": {"heartbeat_interval": 1000}}).to_string(),
        )
        .unwrap();
        assert_eq!(hello.op, OP_HELLO);
        assert_eq!(hello.data["heartbeat_interval"], json!(1000));

        let dispatch = GatewayPayload::parse(
            &json!({"op": 0, "s": 9, "t": "MESSAGE_CREATE", "d": {"id": "M1"}}).to_string(),
        )
        .unwrap();
        assert_eq!(dispatch.op, OP_DISPATCH);
        assert_eq!(dispatch.sequence, Some(9));
        assert_eq!(dispatch.event.as_deref(), Some("MESSAGE_CREATE"));

        assert!(GatewayPayload::parse("not json").is_err());
        assert!(GatewayPayload::parse("{}").is_err());
    }

    #[test]
    fn hello_identifies_heartbeats_and_dispatches_once() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            [hello(), ready(), message(2), message(2), reconnect()],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();

        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();

        assert_eq!(outcome, SessionOutcome::Reconnect);
        assert_eq!(handler.events.len(), 1);
        let InboundUpdate::Message(message) = &handler.events[0].update else {
            panic!("expected message");
        };
        assert_eq!(message.message_id.as_str(), "M2");
        assert_eq!(session.sequence, Some(2));
        assert_eq!(session.session_id.as_deref(), Some("session-1"));
        assert_eq!(
            session.resume_gateway_url.as_deref(),
            Some("wss://resume.invalid")
        );

        let sent = sent.lock().unwrap();
        assert_eq!(sent[0]["op"], json!(OP_IDENTIFY));
        assert_eq!(sent[0]["d"]["token"], json!("fixture-discord-value"));
        assert_eq!(sent[0]["d"]["intents"], json!(DEFAULT_INTENTS));
        assert_eq!(sent[1]["op"], json!(OP_HEARTBEAT));
        assert_eq!(sent[1]["d"], Value::Null);
    }

    #[test]
    fn a_resumable_session_sends_resume_instead_of_identify() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new([hello()], Arc::clone(&sent));
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession {
            sequence: Some(4),
            session_id: Some("session-1".into()),
            resume_gateway_url: None,
        };
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();

        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();

        assert_eq!(outcome, SessionOutcome::Reconnect);
        let sent = sent.lock().unwrap();
        assert_eq!(sent[0]["op"], json!(OP_RESUME));
        assert_eq!(sent[0]["d"]["session_id"], json!("session-1"));
        assert_eq!(sent[0]["d"]["seq"], json!(4));
    }

    #[test]
    fn invalid_session_clears_state_only_when_not_resumable() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            [GatewayRead::Text(
                json!({"op": OP_INVALID_SESSION, "d": false}).to_string(),
            )],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession {
            sequence: Some(4),
            session_id: Some("session-1".into()),
            resume_gateway_url: None,
        };
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();
        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        assert!(!session.can_resume());
        assert!(session.session_id.is_none());
    }

    #[test]
    fn a_heartbeat_timeout_sends_the_next_heartbeat() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            [
                hello(),
                GatewayRead::Text(json!({"op": OP_HEARTBEAT_ACK}).to_string()),
                GatewayRead::Timeout,
            ],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();
        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.iter()
                .filter(|payload| payload["op"] == json!(OP_HEARTBEAT))
                .count(),
            2
        );
    }

    #[test]
    fn a_missing_heartbeat_ack_ends_the_zombie_session() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection =
            ScriptedConnection::new([hello(), GatewayRead::Timeout], Arc::clone(&sent));
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();
        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        let sent = sent.lock().unwrap();
        assert_eq!(
            sent.iter()
                .filter(|payload| payload["op"] == json!(OP_HEARTBEAT))
                .count(),
            1,
            "a zombie session must not keep sending heartbeats"
        );
    }

    #[test]
    fn stop_flag_ends_the_session_without_a_frame() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new([], Arc::clone(&sent));
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(true);
        let token = SecretToken::try_from_string("fixture-discord-value".into()).unwrap();
        let outcome = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap();
        assert_eq!(outcome, SessionOutcome::Stopped);
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn resume_url_is_normalized_with_protocol_query() {
        assert_eq!(
            resume_url("wss://resume.invalid/").expose(),
            "wss://resume.invalid/?v=10&encoding=json"
        );
        assert_eq!(
            resume_url("wss://resume.invalid/?v=10&encoding=json").expose(),
            "wss://resume.invalid/?v=10&encoding=json"
        );
        assert_eq!(
            format!("{:?}", GatewayUrl::new("wss://gateway.invalid")),
            "GatewayUrl([redacted])"
        );
        let session = GatewaySession {
            resume_gateway_url: Some("wss://resume.invalid/CANARY".into()),
            ..GatewaySession::default()
        };
        let debug = format!("{session:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("CANARY"));
    }
}
