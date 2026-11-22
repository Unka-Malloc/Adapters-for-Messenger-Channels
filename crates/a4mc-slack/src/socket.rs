//! Slack Socket Mode: envelope framing, acknowledgement, dedupe, and a
//! bounded reconnect loop.
//!
//! Socket Mode is Slack's persistent, bidirectional receive mechanism.
//! The host calls `apps.connections.open` with an app-level token, then
//! opens the returned websocket. No public callback URL or inbound
//! ingress is involved, so the dialect works inside an enterprise
//! firewall that forbids public callbacks.
//!
//! The host must durably receive each envelope before the
//! acknowledgement goes out — an envelope Slack believes consumed must
//! already have a resumable home on this side. Once the host has the
//! work, the ack is sent; if that write fails the socket is dropped and
//! Slack retries, and the retry is answered with the missing ack
//! instead of a second dispatch. A handler failure is surfaced to the
//! host as `a4mc_slack_handler_failed`; it is not folded into the
//! reconnect backoff. A `disconnect` frame ends the session and the
//! loop reconnects with a fresh socket URL.

use crate::transport::{SlackApi, SlackApiError, SocketUrl};
use a4mc::ChannelEvent;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

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

/// The result of one bounded socket read.
#[derive(Debug, Clone, PartialEq)]
pub enum SocketRead {
    /// One text frame.
    Text(String),
    /// The peer closed the socket.
    Closed,
    /// No frame arrived before the read's deadline; the session loop
    /// uses the pause to service accepted-envelope reports.
    Timeout,
}

impl From<String> for SocketRead {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

/// A bidirectional websocket connection carrying Socket Mode frames.
///
/// Implementations are synchronous and owned by one session thread. Live
/// connection uses tungstenite; tests and host fixtures use an in-memory
/// scripted connection.
pub trait SocketConnection: Send {
    /// Read one text frame, bounded by `timeout`: an empty wait reports
    /// [`SocketRead::Timeout`] so the session loop can keep servicing
    /// acknowledgement work instead of parking inside a read.
    fn read(&mut self, timeout: Duration) -> Result<SocketRead, SlackApiError>;
    fn send_text(&mut self, text: &str) -> Result<(), SlackApiError>;
    fn close(&mut self) {}
}

/// Opens one Socket Mode connection for a short-lived URL.
pub trait SocketConnector: Send + Sync {
    fn connect(&self, url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError>;
}

/// Authorities a socket URL may target: Slack's own domain family only.
/// A `ws://` (plaintext) endpoint is only constructible for a loopback
/// host so a Socket Mode ticket can never travel unencrypted off the
/// machine.
const APPROVED_SOCKET_AUTHORITIES: &[&str] = &["slack.com"];

fn endpoint_refused() -> SlackApiError {
    SlackApiError::new(
        "a4mc_slack_socket_endpoint_refused",
        "Socket Mode URL is outside the approved endpoint policy",
    )
}

#[derive(Debug)]
struct SocketEndpoint {
    host: String,
    port: u16,
    /// Path plus query for the upgrade `GET` line.
    target: String,
    tls: bool,
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Validate a socket URL against the endpoint policy: `wss://` on a
/// Slack authority, or `ws://` loopback for local fixtures.
fn parse_socket_endpoint(url: &str) -> Result<SocketEndpoint, SlackApiError> {
    let (tls, rest) = url
        .trim()
        .strip_prefix("wss://")
        .map(|rest| (true, rest))
        .or_else(|| url.trim().strip_prefix("ws://").map(|rest| (false, rest)))
        .ok_or_else(endpoint_refused)?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(authority, path)| {
            (authority, if path.is_empty() { "/" } else { path })
        });
    let target = if path == "/" {
        "/".to_owned()
    } else {
        format!("/{path}")
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(endpoint_refused());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| endpoint_refused())?),
        None => (authority, if tls { 443 } else { 80 }),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(endpoint_refused());
    }
    let approved = if tls {
        APPROVED_SOCKET_AUTHORITIES
            .iter()
            .any(|authority| host == *authority || host.ends_with(&format!(".{authority}")))
    } else {
        loopback_host(&host)
    };
    if !approved {
        return Err(endpoint_refused());
    }
    Ok(SocketEndpoint {
        host,
        port,
        target,
        tls,
    })
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

/// Open the socket with the upgrade handshake written by this adapter.
/// tungstenite's connect helper logs the request URI at debug and the
/// full request — including the unconsumed Socket Mode ticket in its
/// target — at trace; neither diagnostic exists on this path. TLS peer
/// verification uses the platform root store.
fn connect_websocket(
    endpoint: &SocketEndpoint,
) -> Result<tungstenite::WebSocket<Box<dyn SocketStream>>, SlackApiError> {
    let failed = || {
        SlackApiError::new(
            "a4mc_slack_socket_connect_failed",
            "Socket Mode connection failed",
        )
    };
    let tcp = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .ok()
        .and_then(|addrs| {
            addrs
                .into_iter()
                .find_map(|addr| TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).ok())
        })
        .ok_or_else(failed)?;
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let mut stream: Box<dyn SocketStream> = if endpoint.tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(failed());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name =
            rustls::pki_types::ServerName::try_from(endpoint.host.clone()).map_err(|_| failed())?;
        let conn =
            rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|_| failed())?;
        Box::new(rustls::StreamOwned::new(conn, tcp))
    } else {
        Box::new(tcp)
    };

    // Upgrade handshake written directly: the ticket-bearing request
    // target never enters a dependency's diagnostics.
    use base64::Engine;
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let host_header = if endpoint.port == 443 && endpoint.tls {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        endpoint.target
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|_| failed())?;

    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    let boundary = loop {
        let read = stream.read(&mut chunk).map_err(|_| failed())?;
        if read == 0 {
            return Err(failed());
        }
        head.extend_from_slice(&chunk[..read]);
        if head.len() > MAX_HANDSHAKE_RESPONSE {
            return Err(failed());
        }
        if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
    };
    // One read can coalesce the 101 response and the peer's first frame;
    // bytes after the header belong to the websocket, not the handshake.
    let leftover = head.split_off(boundary);
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.lines();
    let accepted = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .is_some_and(|status| status == "101");
    let expect = {
        use sha1::Digest;
        let mut digest = sha1::Sha1::new();
        digest.update(key.as_bytes());
        digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(digest.finalize())
    };
    let accepted = accepted
        && lines.any(|line| {
            line.split_once(':')
                .map(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("sec-websocket-accept")
                        && value.trim() == expect
                })
                .unwrap_or(false)
        });
    if !accepted {
        return Err(failed());
    }
    Ok(tungstenite::WebSocket::from_partially_read(
        stream,
        leftover,
        tungstenite::protocol::Role::Client,
        None,
    ))
}

/// tungstenite-backed live connector. TLS roots come from the platform
/// store; the Socket Mode URL (and its ticket) never appears in errors
/// or diagnostics.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveSocketConnector;

/// The byte stream under a live socket: TCP, or rustls over TCP.
trait SocketStream: Read + Write + Send {
    /// Bound the next read on the underlying stream to `timeout`.
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), SlackApiError>;
}

fn socket_failed() -> SlackApiError {
    SlackApiError::new("a4mc_slack_socket_failed", "Socket Mode socket failed")
}

impl SocketStream for TcpStream {
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), SlackApiError> {
        TcpStream::set_read_timeout(self, Some(timeout)).map_err(|_| socket_failed())
    }
}

impl SocketStream for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), SlackApiError> {
        self.sock
            .set_read_timeout(Some(timeout))
            .map_err(|_| socket_failed())
    }
}

impl SocketConnector for LiveSocketConnector {
    fn connect(&self, url: &SocketUrl) -> Result<Box<dyn SocketConnection>, SlackApiError> {
        let endpoint = parse_socket_endpoint(url.expose())?;
        let socket = connect_websocket(&endpoint)?;
        Ok(Box::new(LiveSocketConnection { socket }))
    }
}

struct LiveSocketConnection {
    socket: tungstenite::WebSocket<Box<dyn SocketStream>>,
}

impl SocketConnection for LiveSocketConnection {
    fn read(&mut self, timeout: Duration) -> Result<SocketRead, SlackApiError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(SocketRead::Timeout);
            }
            self.socket.get_mut().set_read_timeout(remaining)?;
            match self.socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    return Ok(SocketRead::Text(text.to_string()));
                }
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
                Ok(tungstenite::Message::Close(_)) => return Ok(SocketRead::Closed),
                Err(tungstenite::Error::ConnectionClosed)
                | Err(tungstenite::Error::AlreadyClosed) => return Ok(SocketRead::Closed),
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(SocketRead::Timeout);
                }
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
/// acknowledging twice is harmless, dispatching twice is not. An id is
/// marked only after the host durably received the envelope, so a lost
/// ack write re-delivers a retry that only re-acks rather than skipping
/// work the host never took.
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

    /// Whether this envelope id was already durably received by the host.
    pub fn contains(&self, envelope_id: &str) -> bool {
        !envelope_id.is_empty() && self.seen.contains(envelope_id)
    }

    /// Mark `envelope_id` durably received. Call only after the host has
    /// taken the work; empty ids are never marked (nothing to dedupe).
    pub fn mark(&mut self, envelope_id: &str) {
        if envelope_id.is_empty() {
            return;
        }
        if !self.seen.insert(envelope_id.to_owned()) {
            return;
        }
        self.order.push_back(envelope_id.to_owned());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }
}

/// The host's answer to one delivered envelope. The handler runs on a
/// worker off the socket's read path, so it must be safe to move there.
pub trait SocketHandler: Send {
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

/// Bound on envelopes queued for the host worker. One further envelope
/// can wait in the session's deferred slot; load beyond that ends the
/// session — Slack retries the unacknowledged backlog on the next
/// socket — instead of growing an unbounded queue inside the loop.
const ENVELOPE_HANDOFF_BOUND: usize = 64;

/// How long one socket read waits before the loop services worker
/// reports again — far inside Slack's acknowledgement window, so a
/// quiet socket never parks an earned ack behind a read.
const READ_SERVICE_SLICE: Duration = Duration::from_millis(200);

/// The worker's answer for one envelope: the host durably accepted it
/// (ack it — possibly again, for a retry that overtook the mark), or
/// the host failed it (end the session; the unmarked id is retried and
/// re-dispatched).
enum AcceptReport {
    Ack(String),
    Failed(SlackApiError),
}

/// Run one already-connected Socket Mode session until disconnect, close
/// or stop.
///
/// A first-seen envelope is handed to the host — its durable receive —
/// on a worker fed through a bounded channel, so a synchronous lane
/// turn can never stall the socket's reads or the acks other envelopes
/// already earned. The worker marks the id once the host accepts, then
/// the loop writes the ack: if the ack write fails, the socket is
/// dropped, Slack retries, and the retry is answered with the missing
/// ack and no second dispatch. A handler failure keeps the id unmarked
/// so the retry re-dispatches the work the host never took.
pub fn run_socket_session(
    connection: &mut dyn SocketConnection,
    handler: &mut dyn SocketHandler,
    seen: &mut SeenEnvelopes,
    stop: &AtomicBool,
) -> Result<SessionOutcome, SlackApiError> {
    let seen = Arc::new(Mutex::new(seen));
    let (work_tx, work_rx) = sync_channel::<SocketEnvelope>(ENVELOPE_HANDOFF_BOUND);
    let (ack_tx, ack_rx) = sync_channel::<AcceptReport>(ENVELOPE_HANDOFF_BOUND);
    std::thread::scope(|scope| {
        let worker_seen = Arc::clone(&seen);
        let worker = scope.spawn(move || {
            while let Ok(envelope) = work_rx.recv() {
                let envelope_id = envelope.envelope_id.clone();
                let report = {
                    if worker_seen.lock().unwrap().contains(&envelope_id) {
                        // A retry queued before the original's mark
                        // landed: the work is already the host's, so
                        // only the missing ack is owed.
                        AcceptReport::Ack(envelope_id)
                    } else {
                        let result = if envelope.kind == "events_api" {
                            let event = crate::lower::lower_event(&envelope.payload);
                            handler.on_event(&event, &envelope)
                        } else {
                            handler.on_other(&envelope)
                        };
                        match result {
                            Ok(()) => {
                                // The host has the work; commit the
                                // dedupe mark before the ack, so a lost
                                // ack only ever re-acks.
                                worker_seen.lock().unwrap().mark(&envelope_id);
                                AcceptReport::Ack(envelope_id)
                            }
                            Err(error) => AcceptReport::Failed(handler_error(error)),
                        }
                    }
                };
                if ack_tx.send(report).is_err() {
                    return;
                }
            }
        });
        let outcome = socket_loop(connection, &seen, stop, &work_tx, &ack_rx);
        // Let the worker finish what it queued so a reconnect does not
        // redeliver work the host actually accepted. Drain the report
        // channel *while* it exits — one in-flight envelope plus a full
        // queue can leave one more report than the channel's bound, so
        // joining before draining would deadlock on the last send —
        // then collect the late answers: acks go out best-effort (a
        // miss only re-asks for the retry the mark already covers), a
        // failure surfaces.
        drop(work_tx);
        let mut first_failure = None;
        while let Ok(report) = ack_rx.recv() {
            match report {
                AcceptReport::Ack(envelope_id) => {
                    let _ = connection.send_text(&ack_frame(&envelope_id));
                }
                AcceptReport::Failed(error) => {
                    first_failure.get_or_insert(error);
                }
            }
        }
        let panicked = worker.join().is_err();
        if panicked {
            return Err(SlackApiError::new(
                "a4mc_slack_handler_failed",
                "Socket Mode handler worker panicked",
            ));
        }
        if let Some(error) = first_failure {
            return Err(error);
        }
        outcome
    })
}

/// The socket side of one session: read frames bounded by
/// [`READ_SERVICE_SLICE`], hand unseen envelopes to the handler worker,
/// and write acks for the envelopes the host has accepted — all off the
/// worker's critical path.
fn socket_loop(
    connection: &mut dyn SocketConnection,
    seen: &Mutex<&mut SeenEnvelopes>,
    stop: &AtomicBool,
    work_tx: &SyncSender<SocketEnvelope>,
    ack_rx: &Receiver<AcceptReport>,
) -> Result<SessionOutcome, SlackApiError> {
    // One envelope deferred because the bounded handoff was full; it
    // is retried every iteration. A second deferral means the host
    // cannot keep up — the session ends so Slack redelivers the
    // unacknowledged backlog.
    let mut deferred: Option<SocketEnvelope> = None;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(SessionOutcome::Stopped);
        }
        while let Ok(report) = ack_rx.try_recv() {
            match report {
                AcceptReport::Ack(envelope_id) => {
                    connection.send_text(&ack_frame(&envelope_id))?;
                }
                AcceptReport::Failed(error) => return Err(error),
            }
        }
        if let Some(envelope) = deferred.take() {
            match work_tx.try_send(envelope) {
                Ok(()) => {}
                Err(TrySendError::Full(envelope)) => deferred = Some(envelope),
                Err(TrySendError::Disconnected(_)) => {
                    return Err(SlackApiError::new(
                        "a4mc_slack_handler_failed",
                        "Socket Mode handler worker stopped",
                    ));
                }
            }
        }
        match connection.read(READ_SERVICE_SLICE)? {
            SocketRead::Closed => return Ok(SessionOutcome::Reconnect),
            SocketRead::Timeout => {}
            SocketRead::Text(text) => match SocketFrame::parse(&text)? {
                SocketFrame::Hello { .. } | SocketFrame::Unknown { .. } => {}
                SocketFrame::Disconnect { .. } => return Ok(SessionOutcome::Reconnect),
                SocketFrame::Envelope(envelope) => {
                    if seen.lock().unwrap().contains(&envelope.envelope_id) {
                        // A retry of durably accepted work: answer the
                        // missing ack, never a second dispatch.
                        connection.send_text(&ack_frame(&envelope.envelope_id))?;
                        continue;
                    }
                    if deferred.is_some() {
                        return Err(SlackApiError::new(
                            "a4mc_slack_handler_overloaded",
                            "Socket Mode handler fell behind the envelope stream",
                        ));
                    }
                    match work_tx.try_send(envelope) {
                        Ok(()) => {}
                        Err(TrySendError::Full(envelope)) => deferred = Some(envelope),
                        Err(TrySendError::Disconnected(_)) => {
                            return Err(SlackApiError::new(
                                "a4mc_slack_handler_failed",
                                "Socket Mode handler worker stopped",
                            ));
                        }
                    }
                }
            },
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
        let url = match api.open_socket() {
            Ok(url) => url,
            Err(error) => {
                // Credential and scope rejections fail every retry
                // identically — surface them. Anything else (a 429, a
                // network outage, a server fault) is transient: it
                // takes the same reconnect backoff a failed websocket
                // connect would, honoring the platform's wait hint.
                if open_socket_terminal(&error.code) {
                    return Err(error);
                }
                if config.max_sessions != 0 && sessions >= config.max_sessions {
                    return Err(error);
                }
                backoff = backoff.max(config.reconnect_delay);
                let delay = error
                    .retry_after
                    .map_or(backoff, |hint| backoff.max(Duration::from_secs(hint)));
                backoff = backoff.saturating_mul(2).min(config.max_reconnect_delay);
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                continue;
            }
        };
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

/// `apps.connections.open` failures the reconnect backoff cannot fix:
/// a rejected, missing, expired, revoked or mis-scoped credential
/// fails every call the same way — retrying can never mint a fresh
/// token, so the loop returns it instead of parking on a ticket the
/// host must replace. Everything else is transient and retries.
fn open_socket_terminal(code: &str) -> bool {
    matches!(
        code,
        "a4mc_slack_unauthorized"
            | "a4mc_slack_token_invalid"
            | "a4mc_slack_token_expired"
            | "a4mc_slack_token_revoked"
            | "a4mc_slack_app_token_missing"
            | "a4mc_slack_bot_token_missing"
            | "a4mc_slack_custody_unavailable"
            | "a4mc_slack_custody_failed"
            | "a4mc_slack_missing_scope"
            | "a4mc_slack_no_permission"
            | "a4mc_slack_not_allowed_token_type"
            | "a4mc_slack_account_inactive"
            | "a4mc_slack_api_root_refused"
    )
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

    /// A handler whose calls park until the test releases them — a
    /// stand-in for a synchronous lane turn.
    struct BlockableHandler {
        entered: Arc<std::sync::atomic::AtomicUsize>,
        release: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl BlockableHandler {
        fn wait_for_release(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let (lock, condvar) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
        }
    }

    impl SocketHandler for BlockableHandler {
        fn on_event(
            &mut self,
            _event: &ChannelEvent,
            _envelope: &SocketEnvelope,
        ) -> Result<(), SlackApiError> {
            self.wait_for_release();
            Ok(())
        }

        fn on_other(&mut self, _envelope: &SocketEnvelope) -> Result<(), SlackApiError> {
            self.wait_for_release();
            Ok(())
        }
    }

    struct ScriptedConnection {
        incoming: VecDeque<SocketRead>,
        sent: Arc<Mutex<Vec<String>>>,
        fail_read: Option<SlackApiError>,
        fail_send: Option<SlackApiError>,
        reads: Option<Arc<std::sync::atomic::AtomicUsize>>,
        /// Simulated per-read cost so the handler worker can claim a
        /// dispatch before the bounded handoff fills.
        read_delay: Duration,
    }

    impl ScriptedConnection {
        fn new(
            incoming: impl IntoIterator<Item = impl Into<SocketRead>>,
            sent: Arc<Mutex<Vec<String>>>,
        ) -> Self {
            Self {
                incoming: incoming.into_iter().map(Into::into).collect(),
                sent,
                fail_read: None,
                fail_send: None,
                reads: None,
                read_delay: Duration::ZERO,
            }
        }
    }

    impl SocketConnection for ScriptedConnection {
        fn read(&mut self, _timeout: Duration) -> Result<SocketRead, SlackApiError> {
            if !self.read_delay.is_zero() {
                std::thread::sleep(self.read_delay);
            }
            if let Some(counter) = &self.reads {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(error) = self.fail_read.clone() {
                return Err(error);
            }
            Ok(self.incoming.pop_front().unwrap_or(SocketRead::Closed))
        }

        fn send_text(&mut self, text: &str) -> Result<(), SlackApiError> {
            if let Some(error) = self.fail_send.clone() {
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
    fn receives_then_acknowledges_and_dedupes_retries() {
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
    fn a_blocked_handler_does_not_stall_reads_or_acks() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let mut connection = ScriptedConnection::new(
            vec![
                envelope("e1", "events_api", message_payload("1700000000.000001")),
                envelope("e2", "events_api", message_payload("1700000000.000002")),
                envelope("e3", "slash_commands", json!({"command": "/status"})),
                json!({"type": "disconnect", "reason": "test_done"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        connection.reads = Some(Arc::clone(&reads));
        let mut handler = BlockableHandler {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        };
        let mut seen = SeenEnvelopes::new(16);
        let stop = AtomicBool::new(false);

        let outcome = std::thread::scope(|scope| {
            let session =
                scope.spawn(|| run_socket_session(&mut connection, &mut handler, &mut seen, &stop));
            // While the first handler call is parked, the socket keeps
            // draining: every later envelope and the disconnect frame
            // are read instead of waiting behind it.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while entered.load(Ordering::SeqCst) == 0 || reads.load(Ordering::SeqCst) < 4 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the read loop stalled behind a blocked handler"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let (lock, condvar) = &*release;
            *lock.lock().unwrap() = true;
            condvar.notify_all();
            session.join().unwrap()
        });

        assert_eq!(outcome.unwrap(), SessionOutcome::Reconnect);
        let acks: Vec<Value> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect();
        assert_eq!(acks.len(), 3);
        for (index, id) in ["e1", "e2", "e3"].iter().enumerate() {
            assert_eq!(acks[index]["envelope_id"], json!(id));
        }
        assert!(seen.contains("e1"));
        assert!(seen.contains("e2"));
        assert!(seen.contains("e3"));
    }

    #[test]
    fn a_saturated_queue_still_drains_before_the_worker_joins() {
        // One envelope in flight plus a full 64-slot handoff leaves 65
        // reports for a 64-slot channel at teardown: joining the worker
        // before draining that channel deadlocked, so teardown drains
        // while the worker exits and joins it after.
        let sent = Arc::new(Mutex::new(Vec::new()));
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let mut frames: Vec<String> = (1..=65)
            .map(|index| {
                envelope(
                    &format!("e{index}"),
                    "events_api",
                    message_payload(&format!("1700000000.{index:06}")),
                )
            })
            .collect();
        frames.push(json!({"type": "disconnect", "reason": "test_done"}).to_string());
        let mut connection = ScriptedConnection::new(frames, Arc::clone(&sent));
        connection.reads = Some(Arc::clone(&reads));
        // Paced reads let the worker claim the first envelope before
        // the handoff fills, so the queue saturates deterministically
        // instead of racing the read loop.
        connection.read_delay = Duration::from_millis(5);
        let mut handler = BlockableHandler {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        };
        let mut seen = SeenEnvelopes::new(128);
        let stop = AtomicBool::new(false);

        let outcome = std::thread::scope(|scope| {
            let session =
                scope.spawn(|| run_socket_session(&mut connection, &mut handler, &mut seen, &stop));
            // The first handler call parks while the read loop fills
            // the bounded handoff and consumes the disconnect frame.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while entered.load(Ordering::SeqCst) == 0 || reads.load(Ordering::SeqCst) < 66 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the read loop stalled behind a blocked handler"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let (lock, condvar) = &*release;
            *lock.lock().unwrap() = true;
            condvar.notify_all();
            session.join().unwrap()
        });

        assert_eq!(outcome.unwrap(), SessionOutcome::Reconnect);
        assert_eq!(entered.load(Ordering::SeqCst), 65);
        assert_eq!(sent.lock().unwrap().len(), 65);
        assert!(seen.contains("e1"));
        assert!(seen.contains("e65"));
    }

    #[test]
    fn handler_failure_happens_before_ack_and_is_reported() {
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
        // No ack went out: Slack will redeliver, and the unmarked id
        // re-dispatches instead of being silently dropped.
        assert!(sent.lock().unwrap().is_empty());
        assert!(!seen.contains("e1"));
    }

    #[test]
    fn a_retry_after_a_lost_ack_only_resends_the_ack() {
        let first_sent = Arc::new(Mutex::new(Vec::new()));
        let mut first = ScriptedConnection::new(
            vec![envelope(
                "e1",
                "events_api",
                message_payload("1700000000.000001"),
            )],
            Arc::clone(&first_sent),
        );
        first.fail_send = Some(SlackApiError::new(
            "a4mc_slack_socket_failed",
            "fixture ack write failure",
        ));
        let mut handler = RecordingHandler::default();
        let mut seen = SeenEnvelopes::new(4);
        let stop = AtomicBool::new(false);

        // The envelope is durably received; every ack write fails.
        // Whether the session reports the write failure or the socket
        // simply closes, Slack redelivers — the committed mark is what
        // protects the retry from re-dispatching.
        let _ = run_socket_session(&mut first, &mut handler, &mut seen, &stop);
        assert_eq!(handler.events.len(), 1);
        assert!(seen.contains("e1"));

        let second_sent = Arc::new(Mutex::new(Vec::new()));
        let mut second = ScriptedConnection::new(
            vec![
                envelope("e1", "events_api", message_payload("1700000000.000001")),
                json!({"type": "disconnect", "reason": "test_done"}).to_string(),
            ],
            Arc::clone(&second_sent),
        );
        let outcome = run_socket_session(&mut second, &mut handler, &mut seen, &stop).unwrap();
        assert_eq!(outcome, SessionOutcome::Reconnect);
        // The retry only makes up the lost ack — no second dispatch.
        assert_eq!(handler.events.len(), 1);
        let acks = second_sent.lock().unwrap();
        assert_eq!(acks.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&acks[0]).unwrap()["envelope_id"],
            json!("e1")
        );
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
    fn endpoint_policy_requires_wss_on_a_slack_authority() {
        for refused in [
            "ws://wss-primary.slack.com/link/?ticket=t",
            "http://wss-primary.slack.com/",
            "wss://evil.example/link/?ticket=t",
            "wss://user:pw@wss-primary.slack.com/",
            "wss://noslack.com.evil.example/",
            "ws://10.0.0.5/",
        ] {
            assert_eq!(
                parse_socket_endpoint(refused).unwrap_err().code,
                "a4mc_slack_socket_endpoint_refused",
                "{refused} was not refused"
            );
        }
        // Plaintext may only reach loopback — local fixtures stay
        // possible while a ticket can never leave the machine
        // unencrypted.
        let loopback = parse_socket_endpoint("ws://127.0.0.1:8080/link/?ticket=t").unwrap();
        assert!(!loopback.tls);
        assert_eq!(loopback.port, 8080);
        assert_eq!(loopback.target, "/link/?ticket=t");
        for url in [
            "wss://wss-primary.slack.com/link/?ticket=t&app_id=A1",
            "wss://slack.com/",
        ] {
            let endpoint = parse_socket_endpoint(url).unwrap();
            assert!(endpoint.tls);
            assert_eq!(endpoint.port, 443);
            assert!(endpoint.target.starts_with('/'));
        }
    }

    #[test]
    fn seen_cache_is_bounded() {
        let mut seen = SeenEnvelopes::new(2);
        seen.mark("a");
        assert!(seen.contains("a"));
        seen.mark("a");
        seen.mark("b");
        seen.mark("c"); // evicts `a`
        assert!(!seen.contains("a"));
        assert!(seen.contains("c"));
        seen.mark("d"); // evicts `b`
        assert!(!seen.contains("b"));
        assert!(seen.contains("d"));
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

    /// An `apps.connections.open` mock that returns each scripted error
    /// once, then delegates to the inner mock — a transient ticket
    /// outage followed by recovery.
    struct FlakyTicketApi {
        inner: crate::transport::MockSlackApi,
        failures: Mutex<VecDeque<SlackApiError>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl SlackApi for FlakyTicketApi {
        fn auth_test(&self) -> Result<crate::transport::SlackIdentity, SlackApiError> {
            self.inner.auth_test()
        }

        fn open_socket(&self) -> Result<SocketUrl, SlackApiError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(error) = self.failures.lock().unwrap().pop_front() {
                return Err(error);
            }
            self.inner.open_socket()
        }

        fn post_message(
            &self,
            request: &crate::transport::PostMessageRequest,
        ) -> Result<crate::transport::PostedMessage, SlackApiError> {
            self.inner.post_message(request)
        }
    }

    #[test]
    fn a_transient_ticket_failure_retries_through_the_reconnect_backoff() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let connection = ScriptedConnection::new(
            vec![
                json!({"type": "hello"}).to_string(),
                json!({"type": "disconnect", "reason": "test_done"}).to_string(),
            ],
            Arc::clone(&sent),
        );
        let connector = ScriptedConnector {
            connections: Mutex::new(VecDeque::from([
                Box::new(connection) as Box<dyn SocketConnection>
            ])),
        };
        let api = FlakyTicketApi {
            inner: crate::transport::MockSlackApi::default(),
            failures: Mutex::new(VecDeque::from([
                SlackApiError::new("a4mc_slack_throttled", "fixture rate limit")
                    .with_retry_after(Some(0)),
                SlackApiError::new("a4mc_slack_network_failed", "fixture outage"),
            ])),
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let mut handler = RecordingHandler::default();
        let config = SocketModeConfig {
            max_sessions: 3,
            reconnect_delay: Duration::ZERO,
            ..SocketModeConfig::default()
        };

        run_socket_mode(&api, &connector, &mut handler, &config).unwrap();

        // Two transient ticket failures inside the session bound, then
        // the recovered call opened the session: before, the first
        // error ended the receive loop entirely.
        assert_eq!(api.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn credential_and_scope_ticket_failures_stay_terminal() {
        // Expired and revoked app tokens fail every `connections.open`
        // identically — the host must replace the credential, so the
        // loop surfaces the error instead of retrying it forever.
        for code in [
            "a4mc_slack_unauthorized",
            "a4mc_slack_missing_scope",
            "a4mc_slack_token_expired",
            "a4mc_slack_token_revoked",
        ] {
            let api = FlakyTicketApi {
                inner: crate::transport::MockSlackApi::default(),
                failures: Mutex::new(VecDeque::from([SlackApiError::new(
                    code,
                    "fixture credential rejection",
                )])),
                calls: std::sync::atomic::AtomicUsize::new(0),
            };
            let connector = ScriptedConnector {
                connections: Mutex::new(VecDeque::new()),
            };
            let mut handler = RecordingHandler::default();
            let config = SocketModeConfig {
                reconnect_delay: Duration::ZERO,
                ..SocketModeConfig::default()
            };

            let error = run_socket_mode(&api, &connector, &mut handler, &config).unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(
                api.calls.load(Ordering::SeqCst),
                1,
                "a {code} ticket failure must not be retried"
            );
        }
    }
}
