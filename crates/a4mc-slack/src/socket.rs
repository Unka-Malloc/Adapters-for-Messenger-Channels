//! Slack Socket Mode: envelope framing, acknowledgement, dedupe, and a
//! bounded reconnect loop.
//!
//! Socket Mode is Slack's persistent, bidirectional receive mechanism.
//! The host calls `apps.connections.open` with an app-level token, then
//! opens the returned websocket. No public callback URL or inbound
//! ingress is involved, so the dialect works inside an enterprise
//! firewall that forbids public callbacks.
//!
//! Every delivered envelope is acknowledged before it is handed to the
//! host. That keeps the three-second acknowledgement budget independent
//! of agent work, and the envelope id is recorded only after the ACK
//! write succeeds: a transient write failure leaves the envelope
//! uncommitted so Slack's explicit retry is dispatched instead of being
//! mistaken for a duplicate. A successful ACK followed by a handler
//! failure is surfaced to the host as `a4mc_slack_handler_failed`; it is
//! not folded into the reconnect backoff. A `disconnect` frame ends the
//! session and the loop reconnects with a fresh socket URL.

use crate::transport::{SlackApi, SlackApiError, SocketUrl};
use a4mc::ChannelEvent;
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// One envelope delivered over Socket Mode.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketEnvelope {
    pub envelope_id: String,
    /// `events_api`, `slash_commands`, `interactive`, or another
    /// envelope type Slack introduces. Unknown kinds are acknowledged
    /// and surfaced to the host, never silently dropped.
    pub kind: String,
    pub payload: Value,
    pub retry_attempt: u32,
    pub retry_reason: Option<String>,
    pub accepts_response_payload: bool,
}

/// One decoded Socket Mode frame.
#[derive(Debug, Clone, PartialEq)]
pub enum SocketFrame {
    Hello { num_connections: u32 },
    Envelope(SocketEnvelope),
    Disconnect { reason: Option<String> },
    Unknown { kind: String },
}

impl SocketFrame {
    /// Decode one websocket text frame. The returned error is bounded and
    /// does not echo the frame body.
    pub fn parse(text: &str) -> Result<Self, SlackApiError> {
        let value: Value = serde_json::from_str(text).map_err(|_| {
            SlackApiError::new(
                "a4mc_slack_socket_invalid",
                "Socket Mode frame was not valid JSON",
            )
        })?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| !kind.is_empty())
            .ok_or_else(|| {
                SlackApiError::new("a4mc_slack_socket_invalid", "Socket Mode frame has no type")
            })?;
        match kind {
            "hello" => Ok(Self::Hello {
                num_connections: value
                    .get("num_connections")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(1),
            }),
            "disconnect" => Ok(Self::Disconnect {
                reason: value
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }),
            _ => match value.get("envelope_id").and_then(Value::as_str) {
                Some(envelope_id) if !envelope_id.is_empty() => {
                    Ok(Self::Envelope(SocketEnvelope {
                        envelope_id: envelope_id.to_owned(),
                        kind: kind.to_owned(),
                        payload: value.get("payload").cloned().unwrap_or(Value::Null),
                        retry_attempt: value
                            .get("retry_attempt")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .unwrap_or(0),
                        retry_reason: value
                            .get("retry_reason")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        accepts_response_payload: value
                            .get("accepts_response_payload")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    }))
                }
                _ => Ok(Self::Unknown {
                    kind: kind.to_owned(),
                }),
            },
        }
    }
}

/// The acknowledgement body for one envelope. The dialect acknowledges
/// receipt only; slash-command or interaction responses belong to the
/// host and are sent separately.
pub fn ack_frame(envelope_id: &str) -> String {
    json!({ "envelope_id": envelope_id }).to_string()
}

/// A bidirectional websocket connection carrying Socket Mode frames.
///
/// Implementations are synchronous and owned by one session thread. Live
/// connection uses tungstenite; tests and host fixtures use an in-memory
/// scripted connection.
pub trait SocketConnection: Send {
    /// Read one text frame, or `None` when the peer closed the socket.
    fn read_text(&mut self) -> Result<Option<String>, SlackApiError>;
    fn send_text(&mut self, text: &str) -> Result<(), SlackApiError>;
    fn close(&mut self) {}
}

/// Opens one Socket Mode connection for a short-lived URL.
pub trait SocketConnector: Send + Sync {
    fn connect(&self, url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError>;
}

/// tungstenite-backed live connector. TLS roots come from the platform
/// store; the Socket Mode URL (and its ticket) never appears in errors.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveSocketConnector;

impl SocketConnector for LiveSocketConnector {
    fn connect(&self, url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError> {
        // The crate enables rustls' ring provider. Install it as the
        // process default so a host that unifies features with another
        // rustls user still has a provider before tungstenite builds its
        // client config. An already-installed provider wins.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (socket, _response) = tungstenite::connect(url.expose()).map_err(|_| {
            SlackApiError::new(
                "a4mc_slack_socket_connect_failed",
                "Socket Mode connection failed",
            )
        })?;
        Ok(Box::new(LiveSocketConnection { socket }))
    }
}

struct LiveSocketConnection {
    socket: tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
}

impl SocketConnection for LiveSocketConnection {
    fn read_text(&mut self) -> Result<Option<String>, SlackApiError> {
        loop {
            match self.socket.read() {
                Ok(tungstenite::Message::Text(text)) => return Ok(Some(text.to_string())),
                Ok(tungstenite::Message::Binary(_)) | Ok(tungstenite::Message::Pong(_)) => {}
                Ok(tungstenite::Message::Ping(payload)) => {
                    self.socket
                        .send(tungstenite::Message::Pong(payload))
                        .map_err(|_| {
                            SlackApiError::new(
                                "a4mc_slack_socket_failed",
                                "Socket Mode pong failed",
                            )
                        })?;
                }
                Ok(tungstenite::Message::Frame(_)) => {}
                Ok(tungstenite::Message::Close(_)) => return Ok(None),
                Err(tungstenite::Error::ConnectionClosed)
                | Err(tungstenite::Error::AlreadyClosed) => return Ok(None),
                Err(_) => {
                    return Err(SlackApiError::new(
                        "a4mc_slack_socket_failed",
                        "Socket Mode read failed",
                    ));
                }
            }
        }
    }

    fn send_text(&mut self, text: &str) -> Result<(), SlackApiError> {
        self.socket
            .send(tungstenite::Message::text(text.to_owned()))
            .map_err(|_| SlackApiError::new("a4mc_slack_socket_failed", "Socket Mode write failed"))
    }

    fn close(&mut self) {
        let _ = self.socket.close(None);
    }
}

/// Bounded envelope-id cache. Slack retries an unacknowledged envelope;
/// acknowledging twice is harmless, dispatching twice is not.
#[derive(Debug)]
pub struct SeenEnvelopes {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl SeenEnvelopes {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    /// Report whether `envelope_id` was already committed, without
    /// committing it. The session checks this before writing the ACK so
    /// a failed write leaves the envelope eligible for redelivery.
    pub fn contains(&self, envelope_id: &str) -> bool {
        !envelope_id.is_empty() && self.seen.contains(envelope_id)
    }

    /// Commit `envelope_id` after its ACK write succeeded. Empty ids are
    /// not recorded (there is nothing to dedupe).
    pub fn remember(&mut self, envelope_id: &str) {
        if envelope_id.is_empty() || !self.seen.insert(envelope_id.to_owned()) {
            return;
        }
        self.order.push_back(envelope_id.to_owned());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    /// Mark `envelope_id` seen and report whether this is its first
    /// delivery. Empty ids are always first (there is nothing to dedupe).
    pub fn is_first(&mut self, envelope_id: &str) -> bool {
        if envelope_id.is_empty() {
            return true;
        }
        if self.contains(envelope_id) {
            return false;
        }
        self.remember(envelope_id);
        true
    }
}

/// The host's answer to one delivered envelope.
pub trait SocketHandler {
    /// An `events_api` payload lowered onto the normalized contract.
    /// The raw payload travels in `envelope` for host policy.
    fn on_event(
        &mut self,
        event: &ChannelEvent,
        envelope: &SocketEnvelope,
    ) -> Result<(), SlackApiError>;

    /// A `slash_commands`, `interactive`, or other non-event envelope.
    /// Hosts that do not implement interactions may keep the default.
    fn on_other(&mut self, _envelope: &SocketEnvelope) -> Result<(), SlackApiError> {
        Ok(())
    }
}

/// Why one session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Slack asked for a reconnect (or the peer closed the socket).
    Reconnect,
    /// The host's stop flag was observed.
    Stopped,
}

/// Run one already-connected Socket Mode session until disconnect, close
/// or stop. Every envelope is acknowledged before the handler runs; a
/// duplicate envelope id is acknowledged again but dispatched at most
/// once. Membership is committed only after the ACK write succeeds, so a
/// failed write leaves the envelope eligible for Slack's explicit retry.
pub fn run_socket_session(
    connection: &mut dyn SocketConnection,
    handler: &mut dyn SocketHandler,
    seen: &mut SeenEnvelopes,
    stop: &AtomicBool,
) -> Result<SessionOutcome, SlackApiError> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(SessionOutcome::Stopped);
        }
        let Some(text) = connection.read_text()? else {
            return Ok(SessionOutcome::Reconnect);
        };
        match SocketFrame::parse(&text)? {
            SocketFrame::Hello { .. } | SocketFrame::Unknown { .. } => {}
            SocketFrame::Disconnect { .. } => return Ok(SessionOutcome::Reconnect),
            SocketFrame::Envelope(envelope) => {
                let duplicate = seen.contains(&envelope.envelope_id);
                // Commit only after the ACK is on the wire. If this write
                // fails, `?` returns before the id is remembered, so the
                // retried envelope is dispatched instead of dropped as a
                // duplicate.
                connection.send_text(&ack_frame(&envelope.envelope_id))?;
                seen.remember(&envelope.envelope_id);
                if duplicate {
                    continue;
                }
                let result = if envelope.kind == "events_api" {
                    let event = crate::lower::lower_event(&envelope.payload);
                    handler.on_event(&event, &envelope)
                } else {
                    handler.on_other(&envelope)
                };
                result.map_err(handler_error)?;
            }
        }
    }
}

/// Give a host handler failure its own code so [`run_socket_mode`] can
/// return it instead of treating it as a broken socket and reconnecting.
fn handler_error(error: SlackApiError) -> SlackApiError {
    SlackApiError::new(
        "a4mc_slack_handler_failed",
        format!("{}: {}", error.code, error.message),
    )
}

/// Reconnect policy for [`run_socket_mode`].
#[derive(Debug, Clone)]
pub struct SocketModeConfig {
    /// Maximum sessions to open; `0` means run until `stop`.
    pub max_sessions: usize,
    /// Delay before opening the next session.
    pub reconnect_delay: Duration,
    /// Upper bound for exponential backoff after a failed session.
    pub max_reconnect_delay: Duration,
    /// Envelope-id dedupe capacity.
    pub seen_capacity: usize,
    /// Host-owned stop flag, checked between frames and sessions.
    pub stop: Arc<AtomicBool>,
}

impl Default for SocketModeConfig {
    fn default() -> Self {
        Self {
            max_sessions: 0,
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(30),
            seen_capacity: 1024,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Run Socket Mode until the stop flag is set (or `max_sessions` is
/// reached). Each session asks the Web API for a fresh socket URL, so a
/// reconnect never reuses a consumed ticket.
///
/// A failure to obtain a socket URL is returned to the host (token or
/// scope problems are terminal). A failed websocket connect or a broken
/// session is retried with bounded exponential backoff.
pub fn run_socket_mode(
    api: &dyn SlackApi,
    connector: &dyn SocketConnector,
    handler: &mut dyn SocketHandler,
    config: &SocketModeConfig,
) -> Result<(), SlackApiError> {
    let mut seen = SeenEnvelopes::new(config.seen_capacity);
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
        let url = api.open_socket()?;
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
        let outcome = run_socket_session(&mut *connection, handler, &mut seen, &config.stop);
        connection.close();
        let delay = match outcome {
            Ok(SessionOutcome::Stopped) => return Ok(()),
            Ok(SessionOutcome::Reconnect) => {
                backoff = config.reconnect_delay;
                config.reconnect_delay
            }
            Err(error) => {
                // A host handler failure is not a transport outage:
                // reconnecting cannot undo it and would hide it behind
                // the backoff loop. Return it to the host.
                if error.code == "a4mc_slack_handler_failed" {
                    return Err(error);
                }
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
    use std::net::TcpListener;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingHandler {
        events: Vec<ChannelEvent>,
        others: Vec<String>,
    }

    impl SocketHandler for RecordingHandler {
        fn on_event(
            &mut self,
            event: &ChannelEvent,
            _envelope: &SocketEnvelope,
        ) -> Result<(), SlackApiError> {
            self.events.push(event.clone());
            Ok(())
        }

        fn on_other(&mut self, envelope: &SocketEnvelope) -> Result<(), SlackApiError> {
            self.others.push(envelope.kind.clone());
            Ok(())
        }
    }

    struct FailingHandler;

    impl SocketHandler for FailingHandler {
        fn on_event(
            &mut self,
            _event: &ChannelEvent,
            _envelope: &SocketEnvelope,
        ) -> Result<(), SlackApiError> {
            Err(SlackApiError::new(
                "a4mc_slack_handler_failed",
                "fixture handler failure",
            ))
        }
    }

    struct ScriptedConnection {
        incoming: VecDeque<String>,
        sent: Arc<Mutex<Vec<String>>>,
        fail_read: Option<SlackApiError>,
        fail_next_send: Option<SlackApiError>,
    }

    impl ScriptedConnection {
        fn new(incoming: Vec<String>, sent: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                incoming: incoming.into(),
                sent,
                fail_read: None,
                fail_next_send: None,
            }
        }
    }

    impl SocketConnection for ScriptedConnection {
        fn read_text(&mut self) -> Result<Option<String>, SlackApiError> {
            if let Some(error) = self.fail_read.clone() {
                return Err(error);
            }
            Ok(self.incoming.pop_front())
        }

        fn send_text(&mut self, text: &str) -> Result<(), SlackApiError> {
            if let Some(error) = self.fail_next_send.take() {
                return Err(error);
            }
            self.sent.lock().unwrap().push(text.to_owned());
            Ok(())
        }
    }

    struct ScriptedConnector {
        connections: Mutex<VecDeque<Box<dyn SocketConnection>>>,
    }

    impl SocketConnector for ScriptedConnector {
        fn connect(&self, _url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError> {
            self.connections.lock().unwrap().pop_front().ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_socket_exhausted",
                    "fixture connector ran out of connections",
                )
            })
        }
    }

    fn envelope(id: &str, kind: &str, payload: Value) -> String {
        json!({
            "envelope_id": id,
            "type": kind,
            "payload": payload,
            "accepts_response_payload": false,
        })
        .to_string()
    }

    fn message_payload(ts: &str) -> Value {
        json!({
            "type": "event_callback",
            "team_id": "T1",
            "event_id": format!("Ev{ts}"),
            "event_time": 1_700_000_000,
            "event": {
                "type": "message",
                "channel": "C1",
                "user": "U1",
                "text": "hello",
                "ts": ts,
            }
        })
    }

    #[test]
    fn acknowledges_before_dispatch_and_dedupes_retries() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            vec![
                json!({"type": "hello", "num_connections": 1}).to_string(),
                envelope("e1", "events_api", message_payload("1700000000.000001")),
                envelope("e1", "events_api", message_payload("1700000000.000001")),
                envelope("e2", "slash_commands", json!({"command": "/status"})),
                json!({"type": "disconnect", "reason": "refresh_requested"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut seen = SeenEnvelopes::new(16);
        let stop = AtomicBool::new(false);

        let outcome = run_socket_session(&mut connection, &mut handler, &mut seen, &stop).unwrap();

        assert_eq!(outcome, SessionOutcome::Reconnect);
        assert_eq!(handler.events.len(), 1);
        assert_eq!(handler.others, vec!["slash_commands".to_owned()]);
        let acks: Vec<Value> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect();
        assert_eq!(acks.len(), 3);
        assert_eq!(acks[0]["envelope_id"], json!("e1"));
        assert_eq!(acks[1]["envelope_id"], json!("e1"));
        assert_eq!(acks[2]["envelope_id"], json!("e2"));
        assert_eq!(acks[0].as_object().unwrap().len(), 1);
    }

    #[test]
    fn handler_failure_happens_after_ack_and_is_reported() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            vec![envelope(
                "e1",
                "events_api",
                message_payload("1700000000.000001"),
            )],
            Arc::clone(&sent),
        );
        let mut handler = FailingHandler;
        let mut seen = SeenEnvelopes::new(4);
        let stop = AtomicBool::new(false);

        let error =
            run_socket_session(&mut connection, &mut handler, &mut seen, &stop).unwrap_err();
        assert_eq!(error.code, "a4mc_slack_handler_failed");
        assert!(error.message.contains("fixture handler failure"));
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn failed_ack_does_not_commit_the_envelope_for_dedupe() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut failing = ScriptedConnection::new(
            vec![envelope(
                "e1",
                "events_api",
                message_payload("1700000000.000001"),
            )],
            Arc::clone(&sent),
        );
        failing.fail_next_send = Some(SlackApiError::new(
            "a4mc_slack_socket_failed",
            "fixture ack write failed",
        ));
        let mut seen = SeenEnvelopes::new(8);
        let stop = AtomicBool::new(false);
        let mut handler = RecordingHandler::default();

        let error = run_socket_session(&mut failing, &mut handler, &mut seen, &stop).unwrap_err();
        assert_eq!(error.code, "a4mc_slack_socket_failed");
        assert!(sent.lock().unwrap().is_empty());
        assert!(
            !seen.contains("e1"),
            "a failed ACK must leave the envelope eligible for redelivery"
        );

        // Slack's explicit retry of the same envelope is dispatched.
        let mut retry = ScriptedConnection::new(
            vec![envelope(
                "e1",
                "events_api",
                message_payload("1700000000.000001"),
            )],
            Arc::clone(&sent),
        );
        let outcome = run_socket_session(&mut retry, &mut handler, &mut seen, &stop).unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        assert_eq!(handler.events.len(), 1);
        assert_eq!(sent.lock().unwrap().len(), 1);
        assert!(seen.contains("e1"));
    }

    #[test]
    fn socket_mode_returns_a_handler_failure_instead_of_folding_it_into_backoff() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let connection = ScriptedConnection::new(
            vec![envelope(
                "e1",
                "events_api",
                message_payload("1700000000.000001"),
            )],
            Arc::clone(&sent),
        );
        let connector = ScriptedConnector {
            connections: Mutex::new(VecDeque::from([
                Box::new(connection) as Box<dyn SocketConnection>
            ])),
        };
        let api = crate::transport::MockSlackApi::default();
        let mut handler = FailingHandler;
        let config = SocketModeConfig {
            max_sessions: 0,
            reconnect_delay: Duration::ZERO,
            ..SocketModeConfig::default()
        };

        let error = run_socket_mode(&api, &connector, &mut handler, &config).unwrap_err();
        assert_eq!(error.code, "a4mc_slack_handler_failed");
    }

    #[test]
    fn stop_flag_ends_session_without_reading() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            vec![json!({"type": "hello"}).to_string()],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut seen = SeenEnvelopes::new(4);
        let stop = AtomicBool::new(true);
        let outcome = run_socket_session(&mut connection, &mut handler, &mut seen, &stop).unwrap();
        assert_eq!(outcome, SessionOutcome::Stopped);
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn seen_cache_is_bounded() {
        let mut seen = SeenEnvelopes::new(2);
        assert!(seen.is_first("a"));
        assert!(!seen.is_first("a"));
        assert!(seen.is_first("b"));
        assert!(seen.is_first("c")); // evicts `a`
        assert!(!seen.is_first("c"));
        assert!(seen.is_first("a")); // evicts `b`
        assert!(!seen.is_first("a"));
        assert!(seen.is_first("b")); // `b` had been evicted
    }

    #[test]
    fn socket_frame_parses_hello_envelope_disconnect_and_unknown() {
        assert_eq!(
            SocketFrame::parse(r#"{"type":"hello","num_connections":3}"#).unwrap(),
            SocketFrame::Hello { num_connections: 3 }
        );
        let frame = SocketFrame::parse(&envelope("e1", "events_api", json!({"x": 1}))).unwrap();
        let SocketFrame::Envelope(envelope) = frame else {
            panic!("expected envelope");
        };
        assert_eq!(envelope.envelope_id, "e1");
        assert_eq!(envelope.kind, "events_api");
        assert_eq!(envelope.payload["x"], json!(1));
        assert_eq!(
            SocketFrame::parse(r#"{"type":"disconnect","reason":"refresh"}"#).unwrap(),
            SocketFrame::Disconnect {
                reason: Some("refresh".into())
            }
        );
        assert_eq!(
            SocketFrame::parse(r#"{"type":"mystery"}"#).unwrap(),
            SocketFrame::Unknown {
                kind: "mystery".into()
            }
        );
        assert_eq!(
            SocketFrame::parse("not json").unwrap_err().code,
            "a4mc_slack_socket_invalid"
        );
        assert_eq!(
            SocketFrame::parse(r#"{"num":1}"#).unwrap_err().code,
            "a4mc_slack_socket_invalid"
        );
    }

    #[test]
    fn loop_reconnects_for_each_bounded_session() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let first = ScriptedConnection::new(
            vec![
                json!({"type": "hello"}).to_string(),
                envelope("e1", "events_api", message_payload("1700000000.000001")),
                json!({"type": "disconnect", "reason": "refresh_requested"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        let second = ScriptedConnection::new(
            vec![
                json!({"type": "hello"}).to_string(),
                envelope("e2", "events_api", message_payload("1700000000.000002")),
                json!({"type": "disconnect", "reason": "refresh_requested"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        let connector = ScriptedConnector {
            connections: Mutex::new(VecDeque::from([
                Box::new(first) as Box<dyn SocketConnection>,
                Box::new(second) as Box<dyn SocketConnection>,
            ])),
        };
        let api = crate::transport::MockSlackApi::default();
        let mut handler = RecordingHandler::default();
        let config = SocketModeConfig {
            max_sessions: 2,
            reconnect_delay: Duration::ZERO,
            seen_capacity: 16,
            ..SocketModeConfig::default()
        };

        run_socket_mode(&api, &connector, &mut handler, &config).unwrap();

        assert_eq!(handler.events.len(), 2);
        assert_eq!(sent.lock().unwrap().len(), 2);
    }

    #[test]
    fn live_connector_carries_a_simulated_event_and_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            socket
                .send(tungstenite::Message::text(
                    json!({"type": "hello", "num_connections": 1}).to_string(),
                ))
                .unwrap();
            socket
                .send(tungstenite::Message::text(envelope(
                    "e1",
                    "events_api",
                    message_payload("1700000000.000001"),
                )))
                .unwrap();
            let ack = socket.read().unwrap();
            let ack: Value = serde_json::from_str(ack.to_text().unwrap()).unwrap();
            assert_eq!(ack["envelope_id"], json!("e1"));
            socket
                .send(tungstenite::Message::text(
                    json!({"type": "disconnect", "reason": "test_done"}).to_string(),
                ))
                .unwrap();
        });

        let connector = LiveSocketConnector;
        let mut connection = connector
            .connect(&SocketUrl::new(format!("ws://127.0.0.1:{port}")))
            .unwrap();
        let mut handler = RecordingHandler::default();
        let mut seen = SeenEnvelopes::new(8);
        let stop = AtomicBool::new(false);
        let outcome = run_socket_session(&mut *connection, &mut handler, &mut seen, &stop).unwrap();
        server.join().unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        assert_eq!(handler.events.len(), 1);
        let InboundUpdate::Message(message) = &handler.events[0].update else {
            panic!("expected message");
        };
        assert_eq!(message.text.as_deref(), Some("hello"));
    }

    struct FlakyConnector {
        attempts: std::sync::atomic::AtomicUsize,
        connection: Mutex<Option<Box<dyn SocketConnection>>>,
    }

    impl SocketConnector for FlakyConnector {
        fn connect(&self, _url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(SlackApiError::new(
                    "a4mc_slack_socket_connect_failed",
                    "fixture connect failure",
                ));
            }
            self.connection.lock().unwrap().take().ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_socket_exhausted",
                    "fixture connector ran out of connections",
                )
            })
        }
    }

    #[test]
    fn connector_failures_are_retried_within_the_session_bound() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let connection = ScriptedConnection::new(
            vec![
                json!({"type": "hello"}).to_string(),
                json!({"type": "disconnect", "reason": "test_done"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        let connector = FlakyConnector {
            attempts: std::sync::atomic::AtomicUsize::new(0),
            connection: Mutex::new(Some(Box::new(connection))),
        };
        let api = crate::transport::MockSlackApi::default();
        let mut handler = RecordingHandler::default();
        let config = SocketModeConfig {
            max_sessions: 2,
            reconnect_delay: Duration::ZERO,
            ..SocketModeConfig::default()
        };

        run_socket_mode(&api, &connector, &mut handler, &config).unwrap();

        assert_eq!(connector.attempts.load(Ordering::SeqCst), 2);
        assert!(handler.events.is_empty());
    }
}
