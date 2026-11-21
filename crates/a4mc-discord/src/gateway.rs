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
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
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
/// intent: an application without the grant receives no member events,
/// and enabling it without the grant makes the Gateway close with 4014.
/// It is therefore **opt-in** — add it to [`GatewayConfig::intents`]
/// only after Discord has granted the intent.
pub const INTENT_GUILD_MEMBERS: u64 = 1 << 1;
/// Guild message create/update/delete events.
pub const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
/// Guild message reaction add/remove events.
pub const INTENT_GUILD_MESSAGE_REACTIONS: u64 = 1 << 10;
/// Direct message create/update/delete events.
pub const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
/// Direct message reaction add/remove events.
pub const INTENT_DIRECT_MESSAGE_REACTIONS: u64 = 1 << 13;
/// Access to the text, embeds, attachments and components of guild
/// messages. Discord marks this a privileged intent: without the
/// grant a `MESSAGE_CREATE` dispatch still arrives but its content
/// fields are empty (direct messages, mentions of the bot and the
/// bot's own messages keep their content), and enabling it without
/// the grant makes the Gateway close with 4014. It is therefore
/// **opt-in** — add it to [`GatewayConfig::intents`] only after
/// Discord has granted the intent.
pub const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

/// The intents needed to receive every update kind this dialect lowers,
/// excluding the privileged [`INTENT_GUILD_MEMBERS`] and
/// [`INTENT_MESSAGE_CONTENT`] opt-ins. With this default, guild message
/// events arrive with ids, authors and timestamps but empty content
/// fields; direct messages carry their content without the grant.
pub const DEFAULT_INTENTS: u64 = INTENT_GUILDS
    | INTENT_GUILD_MESSAGES
    | INTENT_GUILD_MESSAGE_REACTIONS
    | INTENT_DIRECT_MESSAGES
    | INTENT_DIRECT_MESSAGE_REACTIONS;

/// Error code for a host handler that failed a dispatched event. The
/// gateway returns this to its caller instead of treating it as a
/// transient socket failure and reconnecting over the event.
pub const HANDLER_FAILED_CODE: &str = "a4mc_discord_handler_failed";
/// Error code for a Gateway close code that Discord documents as
/// non-reconnectable (bad token, bad shard, bad intents, ...).
pub const TERMINAL_CLOSE_CODE: &str = "a4mc_discord_gateway_terminal_close";

/// Close codes Discord documents as `Reconnect = false`. Reconnecting
/// with the same configuration can only fail the same way, so the
/// gateway surfaces the code instead of burning a 1-second handshake
/// loop forever.
pub fn is_terminal_close_code(code: u16) -> bool {
    matches!(code, 4004 | 4010 | 4011 | 4012 | 4013 | 4014)
}

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
    /// The peer closed the socket, carrying the websocket close code
    /// when the peer supplied one.
    Closed(Option<u16>),
}

/// A Gateway websocket connection.
///
/// `read_frame` is time-bounded so the session can send protocol
/// heartbeats while the socket is idle. Implementations are synchronous
/// and owned by one session thread.
pub trait GatewayConnection: Send {
    fn read_frame(&mut self, timeout: Duration) -> Result<GatewayRead, DiscordApiError>;
    fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError>;
    /// Send one frame whose payload is credential material. The default
    /// delegates to `send_text`; the live implementation writes the
    /// masked frame itself so no dependency diagnostic can ever echo a
    /// token-bearing payload.
    fn send_secret(&mut self, text: &str) -> Result<(), DiscordApiError> {
        self.send_text(text)
    }
    fn close(&mut self) {}
}

/// Opens one Gateway connection for a URL.
pub trait GatewayConnector: Send + Sync {
    fn connect(&self, url: &GatewayUrl) -> Result<Box<dyn GatewayConnection>, DiscordApiError>;
}

/// Authorities a credentialed Gateway connection may target: the
/// provider's own domain family only. Resume URLs from `READY` stay on
/// the same family; anything else — a plaintext scheme or a foreign
/// authority — is refused before handshake data leaves the process.
const APPROVED_GATEWAY_AUTHORITIES: &[&str] = &["discord.gg"];

fn endpoint_refused() -> DiscordApiError {
    DiscordApiError::new(
        "a4mc_discord_gateway_endpoint_refused",
        "Gateway URL is outside the approved endpoint policy",
    )
}

/// One validated Gateway endpoint. `tls` is `true` for `wss://`; a
/// plaintext `ws://` endpoint is only constructible for a loopback host,
/// so the token can never travel unencrypted off the machine.
#[derive(Debug)]
struct GatewayEndpoint {
    host: String,
    port: u16,
    /// Path plus query for the upgrade `GET` line.
    target: String,
    tls: bool,
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Validate a Gateway URL against the endpoint policy: `wss://` on a
/// Discord authority, or `ws://` loopback for local fixtures. Redirects
/// are never followed, so the policy holds for every byte sent.
fn parse_gateway_endpoint(url: &str) -> Result<GatewayEndpoint, DiscordApiError> {
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
        APPROVED_GATEWAY_AUTHORITIES
            .iter()
            .any(|authority| host == *authority || host.ends_with(&format!(".{authority}")))
    } else {
        // Plaintext may only ever reach loopback — a credential can
        // never leave the machine unencrypted.
        loopback_host(&host)
    };
    if !approved {
        return Err(endpoint_refused());
    }
    Ok(GatewayEndpoint {
        host,
        port,
        target,
        tls,
    })
}

/// The byte stream under a live websocket. Exposes the read timeout the
/// session needs to interleave heartbeats with idle waits.
trait GatewayStream: Read + Write + Send {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl GatewayStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl GatewayStream for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

/// Open the websocket with the upgrade handshake written by this
/// adapter. tungstenite's connect helper logs the request URI at debug
/// and the full request — including a ticket-bearing target — at trace,
/// and follows redirects to authorities the endpoint policy never
/// approved; none of that can happen on this path. TLS peer verification
/// uses the platform root store.
fn connect_websocket(
    endpoint: &GatewayEndpoint,
) -> Result<tungstenite::WebSocket<Box<dyn GatewayStream>>, DiscordApiError> {
    let failed = || {
        DiscordApiError::new(
            "a4mc_discord_gateway_connect_failed",
            "Gateway connection failed",
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
    let mut stream: Box<dyn GatewayStream> = if endpoint.tls {
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

    // Upgrade handshake written directly: the request target never
    // enters a dependency's diagnostics.
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
/// store; the Gateway URL never appears in errors or diagnostics.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveGatewayConnector;

impl GatewayConnector for LiveGatewayConnector {
    fn connect(&self, url: &GatewayUrl) -> Result<Box<dyn GatewayConnection>, DiscordApiError> {
        let endpoint = parse_gateway_endpoint(url.expose())?;
        let socket = connect_websocket(&endpoint)?;
        Ok(Box::new(LiveGatewayConnection { socket }))
    }
}

struct LiveGatewayConnection {
    socket: tungstenite::WebSocket<Box<dyn GatewayStream>>,
}

impl LiveGatewayConnection {
    fn set_read_timeout(&self, timeout: Duration) -> Result<(), DiscordApiError> {
        self.socket
            .get_ref()
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|_| {
                DiscordApiError::new(
                    "a4mc_discord_gateway_failed",
                    "Gateway read timeout could not be set",
                )
            })
    }
}

/// Encode one client text frame (FIN, masked) and write it straight to
/// the stream. tungstenite's send path traces the full frame payload —
/// hex, but still the bytes — so a token-bearing `IDENTIFY`/`RESUME`
/// never goes through it.
fn write_masked_text_frame(stream: &mut dyn Write, payload: &[u8]) -> Result<(), DiscordApiError> {
    let mut mask = [0u8; 4];
    OsRng.fill_bytes(&mut mask);
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x81);
    let len = payload.len();
    if len <= 125 {
        frame.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, mask)| byte ^ mask),
    );
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|_| DiscordApiError::new("a4mc_discord_gateway_failed", "Gateway write failed"))
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
                Ok(tungstenite::Message::Close(frame)) => {
                    return Ok(GatewayRead::Closed(
                        frame.map(|frame| u16::from(frame.code)),
                    ));
                }
                Err(tungstenite::Error::ConnectionClosed)
                | Err(tungstenite::Error::AlreadyClosed) => return Ok(GatewayRead::Closed(None)),
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

    fn send_secret(&mut self, text: &str) -> Result<(), DiscordApiError> {
        // The masked frame is written to the stream directly: no
        // dependency code path ever handles — or logs — the
        // credential-bearing payload.
        write_masked_text_frame(self.socket.get_mut(), text.as_bytes())
    }

    fn close(&mut self) {
        let _ = self.socket.close(None);
        let _ = self.socket.flush();
    }
}

/// The host's answer to one Gateway dispatch. Handlers run on a worker
/// thread fed by a bounded handoff so a slow host turn can never stall
/// the connection's heartbeat schedule.
pub trait GatewayHandler: Send {
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
    /// Resume sequence: the last dispatch the host handler accepted.
    /// A dispatch that fails the handler does not advance this value, so
    /// a later resume replays the unhandled event instead of skipping it.
    pub sequence: Option<u64>,
    /// Session id from `READY`; needed for `RESUME`.
    pub session_id: Option<String>,
    /// `resume_gateway_url` from `READY`.
    pub resume_gateway_url: Option<String>,
    /// Last dispatch sequence successfully handed to the host. Kept
    /// separate from received frames so a handler failure never lets the
    /// resume cursor move past work the host did not observe.
    pub last_dispatched: Option<u64>,
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
        self.last_dispatched = None;
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

/// Bound on dispatches queued for the host worker. One further dispatch
/// can wait in the session's deferred slot; load beyond that ends the
/// session — the uncommitted cursor replays the work on reconnect —
/// instead of growing an unbounded queue inside the connection loop.
const DISPATCH_HANDOFF_BOUND: usize = 64;

/// Error code for host work arriving faster than the bounded handoff
/// can absorb. Reconnectable: the dispatches stay unconfirmed and the
/// platform replays them.
const HANDLER_OVERLOADED_CODE: &str = "a4mc_discord_handler_overloaded";

/// One dispatch handed to the host worker: the lowered events plus the
/// sequence the resume cursor advances to once the host accepts them.
struct DispatchWork {
    events: Vec<ChannelEvent>,
    payload: GatewayPayload,
}

/// The worker's answer for one dispatch, in receive order.
struct DispatchAck {
    sequence: Option<u64>,
    result: Result<(), DiscordApiError>,
}

/// Run one already-connected Gateway session until reconnect, close or
/// stop.
///
/// The session sends `IDENTIFY` on the first `HELLO` (or `RESUME` when
/// `session` carries a session id and sequence), sends a heartbeat on the
/// advertised interval, and treats a missing heartbeat acknowledgement
/// as a zombie connection rather than piling up more heartbeats.
/// Heartbeat sends and their acknowledgement checks are scheduled on
/// independent monotonic deadlines, and host dispatch work runs on a
/// worker fed through a bounded handoff, so a slow handler can never
/// stall the connection's heartbeat cadence.
pub fn run_gateway_session(
    connection: &mut dyn GatewayConnection,
    token: &SecretToken,
    handler: &mut dyn GatewayHandler,
    session: &mut GatewaySession,
    config: &GatewayConfig,
    stop: &AtomicBool,
) -> Result<SessionOutcome, DiscordApiError> {
    let (work_tx, work_rx) = sync_channel::<DispatchWork>(DISPATCH_HANDOFF_BOUND);
    let (ack_tx, ack_rx) = sync_channel::<DispatchAck>(DISPATCH_HANDOFF_BOUND);
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            while let Ok(work) = work_rx.recv() {
                let mut result = Ok(());
                for event in &work.events {
                    if let Err(error) = handler.on_dispatch(event, &work.payload) {
                        result = Err(error);
                        break;
                    }
                }
                if ack_tx
                    .send(DispatchAck {
                        sequence: work.payload.sequence,
                        result,
                    })
                    .is_err()
                {
                    return;
                }
            }
        });
        let outcome = session_loop(connection, token, session, config, stop, &work_tx, &ack_rx);
        // No more work will be handed off; let the worker finish what it
        // queued so a resumed session does not rerun work the host
        // actually accepted, then collect every late answer.
        drop(work_tx);
        let panicked = worker.join().is_err();
        let mut first_failure = None;
        while let Ok(ack) = ack_rx.try_recv() {
            match ack.result {
                Ok(()) => commit_dispatch(session, ack.sequence),
                Err(error) => {
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
        if panicked {
            return Err(DiscordApiError::new(
                HANDLER_FAILED_CODE,
                "Gateway handler worker panicked",
            ));
        }
        if let Some(error) = first_failure {
            return Err(handler_failure(error));
        }
        outcome
    })
}

#[allow(clippy::too_many_arguments)]
fn session_loop(
    connection: &mut dyn GatewayConnection,
    token: &SecretToken,
    session: &mut GatewaySession,
    config: &GatewayConfig,
    stop: &AtomicBool,
    work_tx: &SyncSender<DispatchWork>,
    ack_rx: &Receiver<DispatchAck>,
) -> Result<SessionOutcome, DiscordApiError> {
    let mut heartbeat_interval = Duration::from_secs(60);
    // Two independent monotonic deadlines: when the next heartbeat is
    // due, and when the last heartbeat's acknowledgement is expected.
    // Other traffic (a server HEARTBEAT request, dispatches) can touch
    // one without masking the other.
    let mut next_heartbeat: Option<Instant> = None;
    let mut ack_due: Option<Instant> = None;
    let mut hello_seen = false;
    // Frames received advance this local cursor for heartbeats and
    // duplicate detection. `session.sequence` only advances after the
    // host handler accepts a dispatch.
    let mut last_received = session.sequence;
    if session.last_dispatched.is_none() {
        session.last_dispatched = session.sequence;
    }
    // One dispatch deferred because the bounded handoff was full. It is
    // retried every iteration; a second deferral means the host cannot
    // keep up and the session ends so the platform replays the backlog.
    let mut deferred: Option<DispatchWork> = None;

    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(SessionOutcome::Stopped);
        }
        // Commit accepted dispatches and surface host failures. The
        // resume cursor never passes work the host did not take.
        while let Ok(ack) = ack_rx.try_recv() {
            match ack.result {
                Ok(()) => commit_dispatch(session, ack.sequence),
                Err(error) => return Err(handler_failure(error)),
            }
        }
        if let Some(work) = deferred.take() {
            match work_tx.try_send(work) {
                Ok(()) => {}
                Err(TrySendError::Full(work)) => deferred = Some(work),
                Err(TrySendError::Disconnected(_)) => {
                    return Err(DiscordApiError::new(
                        HANDLER_FAILED_CODE,
                        "Gateway handler worker stopped",
                    ));
                }
            }
        }
        let now = Instant::now();
        let timeout = [next_heartbeat, ack_due]
            .into_iter()
            .flatten()
            .map(|at| {
                at.saturating_duration_since(now)
                    .max(Duration::from_millis(1))
            })
            .min()
            .unwrap_or(Duration::from_secs(60));
        match connection.read_frame(timeout)? {
            GatewayRead::Closed(code) => {
                if let Some(code) = code.filter(|code| is_terminal_close_code(*code)) {
                    return Err(DiscordApiError::new(
                        TERMINAL_CLOSE_CODE,
                        format!("Gateway closed with non-reconnectable code {code}"),
                    ));
                }
                // 4007 (invalid sequence) and 4009 (session timed out)
                // are reconnectable, but the session Discord closed is
                // dead: the next connection must IDENTIFY a fresh one
                // from the initial URL, not RESUME the corpse.
                if matches!(code, Some(4007 | 4009)) {
                    session.clear();
                }
                return Ok(SessionOutcome::Reconnect);
            }
            GatewayRead::Timeout => {
                // The read waited out the earliest of the scheduled
                // deadlines. When that was the acknowledgement check,
                // the server stopped acknowledging heartbeats: a
                // zombie connection is reconnected, not fed more
                // heartbeats.
                let ack_fired =
                    ack_due.is_some_and(|due| next_heartbeat.is_none_or(|at| due <= at));
                if ack_fired {
                    return Ok(SessionOutcome::Reconnect);
                }
                if next_heartbeat.is_some() {
                    send_heartbeat(connection, last_received)?;
                    let now = Instant::now();
                    next_heartbeat = Some(now + heartbeat_interval);
                    ack_due = Some(now + heartbeat_interval);
                }
            }
            GatewayRead::Text(text) => {
                let payload = GatewayPayload::parse(&text)?;
                let duplicate = payload
                    .sequence
                    .is_some_and(|sequence| last_received.is_some_and(|last| sequence <= last));
                if let Some(sequence) = payload.sequence {
                    last_received = Some(last_received.map_or(sequence, |last| last.max(sequence)));
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
                        send_heartbeat(connection, last_received)?;
                        let now = Instant::now();
                        next_heartbeat = Some(now + heartbeat_interval);
                        ack_due = Some(now + heartbeat_interval);
                    }
                    OP_HEARTBEAT => {
                        send_heartbeat(connection, last_received)?;
                        let now = Instant::now();
                        next_heartbeat = Some(now + heartbeat_interval);
                        ack_due = Some(now + heartbeat_interval);
                    }
                    OP_HEARTBEAT_ACK => ack_due = None,
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
                            commit_dispatch(session, payload.sequence);
                            continue;
                        }
                        let events =
                            crate::lower::lower_events(event_name, &payload.data, payload.sequence);
                        let work = DispatchWork { events, payload };
                        if deferred.is_some() {
                            // One deferral already waits for room; a
                            // second means the host cannot keep up.
                            return Err(DiscordApiError::new(
                                HANDLER_OVERLOADED_CODE,
                                "Gateway handler fell behind the dispatch stream",
                            ));
                        }
                        match work_tx.try_send(work) {
                            Ok(()) => {}
                            Err(TrySendError::Full(work)) => deferred = Some(work),
                            Err(TrySendError::Disconnected(_)) => {
                                return Err(DiscordApiError::new(
                                    HANDLER_FAILED_CODE,
                                    "Gateway handler worker stopped",
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Wrap a host handler failure in a distinct, host-visible code so the
/// reconnect loop can return it instead of treating it as a transient
/// transport error.
fn handler_failure(error: DiscordApiError) -> DiscordApiError {
    DiscordApiError::new(
        HANDLER_FAILED_CODE,
        format!("Gateway handler failed: {}: {}", error.code, error.message),
    )
}

fn commit_dispatch(session: &mut GatewaySession, sequence: Option<u64>) {
    if let Some(sequence) = sequence {
        session.last_dispatched = Some(
            session
                .last_dispatched
                .map_or(sequence, |last| last.max(sequence)),
        );
        session.sequence = Some(session.sequence.map_or(sequence, |last| last.max(sequence)));
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
    connection.send_secret(&payload.to_string())
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
                // A handler failure and a documented non-reconnectable
                // close are terminal for this configuration: retrying
                // would silently drop the same dispatch again or burn a
                // permanent handshake loop. Surface both to the host.
                if error.code == HANDLER_FAILED_CODE || error.code == TERMINAL_CLOSE_CODE {
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

    fn fixture_token() -> String {
        use std::sync::atomic::AtomicU64;
        use std::time::{SystemTime, UNIX_EPOCH};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        format!(
            "a4mc-discord-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )
    }

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
            Ok(self.frames.pop_front().unwrap_or(GatewayRead::Closed(None)))
        }

        fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError> {
            self.sent
                .lock()
                .unwrap()
                .push(serde_json::from_str(text).unwrap());
            Ok(())
        }
    }

    struct FailingHandler;

    impl GatewayHandler for FailingHandler {
        fn on_dispatch(
            &mut self,
            _event: &ChannelEvent,
            _payload: &GatewayPayload,
        ) -> Result<(), DiscordApiError> {
            Err(DiscordApiError::new(
                "a4mc_discord_fixture_handler",
                "fixture handler rejected the dispatch",
            ))
        }
    }

    struct ScriptedConnector {
        connections: Mutex<VecDeque<Box<dyn GatewayConnection>>>,
        urls: Mutex<Vec<String>>,
    }

    impl GatewayConnector for ScriptedConnector {
        fn connect(&self, url: &GatewayUrl) -> Result<Box<dyn GatewayConnection>, DiscordApiError> {
            self.urls.lock().unwrap().push(url.expose().to_owned());
            self.connections.lock().unwrap().pop_front().ok_or_else(|| {
                DiscordApiError::new(
                    "a4mc_discord_fixture_exhausted",
                    "fixture connector ran out of connections",
                )
            })
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
        let token_value = fixture_token();
        let token = SecretToken::try_from_string(token_value.clone()).unwrap();

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
        assert_eq!(sent[0]["d"]["token"], json!(token_value));
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
            last_dispatched: None,
        };
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();

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
            last_dispatched: None,
        };
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();
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
        let token = SecretToken::try_from_string(fixture_token()).unwrap();
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
        let token = SecretToken::try_from_string(fixture_token()).unwrap();
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
        let token = SecretToken::try_from_string(fixture_token()).unwrap();
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

    #[test]
    fn handler_failure_is_returned_and_does_not_advance_the_resume_cursor() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection =
            ScriptedConnection::new([hello(), ready(), message(2)], Arc::clone(&sent));
        let mut handler = FailingHandler;
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();

        let error = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap_err();

        assert_eq!(error.code, HANDLER_FAILED_CODE);
        assert!(
            error.message.contains("a4mc_discord_fixture_handler"),
            "handler detail was lost: {error}"
        );
        // READY (sequence 1) was accepted; the rejected MESSAGE_CREATE
        // (sequence 2) must remain replayable.
        assert_eq!(session.sequence, Some(1));
        assert_eq!(session.last_dispatched, Some(1));
    }

    #[test]
    fn run_gateway_surfaces_handler_failure_instead_of_reconnecting_forever() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let connection = ScriptedConnection::new([hello(), ready(), message(2)], sent);
        let connector = ScriptedConnector {
            connections: Mutex::new(VecDeque::from([
                Box::new(connection) as Box<dyn GatewayConnection>
            ])),
            urls: Mutex::new(Vec::new()),
        };
        let token =
            DiscordToken::new(SecretToken::try_from_string(fixture_token()).unwrap()).unwrap();
        let mut handler = FailingHandler;
        let config = GatewayModeConfig {
            max_sessions: 0,
            reconnect_delay: Duration::ZERO,
            max_reconnect_delay: Duration::ZERO,
            ..GatewayModeConfig::default()
        };

        let error = run_gateway(&connector, &token, &mut handler, &config).unwrap_err();
        assert_eq!(error.code, HANDLER_FAILED_CODE);
    }

    #[test]
    fn terminal_close_code_ends_the_session_without_reconnect() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection =
            ScriptedConnection::new([GatewayRead::Closed(Some(4004))], Arc::clone(&sent));
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();

        let error = run_gateway_session(
            &mut connection,
            &token,
            &mut handler,
            &mut session,
            &GatewayConfig::default(),
            &stop,
        )
        .unwrap_err();
        assert_eq!(error.code, TERMINAL_CLOSE_CODE);
        assert!(error.message.contains("4004"));
        assert!(is_terminal_close_code(4004));
        assert!(is_terminal_close_code(4014));
        assert!(!is_terminal_close_code(4000));
    }

    #[test]
    fn non_terminal_close_code_still_reconnects() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection =
            ScriptedConnection::new([GatewayRead::Closed(Some(4000))], Arc::clone(&sent));
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();

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
    }

    #[test]
    fn a_dead_session_close_reconnects_with_identify_at_the_initial_url() {
        // 4007 (invalid sequence) and 4009 (session timed out) retire
        // the session: the next connection must open at the initial
        // URL and IDENTIFY, never RESUME the closed session.
        for code in [4007u16, 4009] {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let first = ScriptedConnection::new(
                [hello(), ready(), GatewayRead::Closed(Some(code))],
                Arc::clone(&sent),
            );
            let second =
                ScriptedConnection::new([hello(), GatewayRead::Closed(None)], Arc::clone(&sent));
            let connector = ScriptedConnector {
                connections: Mutex::new(VecDeque::from([
                    Box::new(first) as Box<dyn GatewayConnection>,
                    Box::new(second) as Box<dyn GatewayConnection>,
                ])),
                urls: Mutex::new(Vec::new()),
            };
            let token =
                DiscordToken::new(SecretToken::try_from_string(fixture_token()).unwrap()).unwrap();
            let mut handler = RecordingHandler::default();
            let config = GatewayModeConfig {
                gateway_url: GatewayUrl::new("wss://gateway.fixture/?v=10"),
                max_sessions: 2,
                reconnect_delay: Duration::ZERO,
                ..GatewayModeConfig::default()
            };

            run_gateway(&connector, &token, &mut handler, &config).unwrap();

            let urls = connector.urls.lock().unwrap();
            assert_eq!(
                urls.iter()
                    .filter(|url| url.contains("resume.invalid"))
                    .count(),
                0,
                "close code {code} dialed the dead session's resume URL: {urls:?}"
            );
            assert!(
                urls.iter()
                    .all(|url| url.starts_with("wss://gateway.fixture/")),
                "close code {code} skipped the initial URL: {urls:?}"
            );
            drop(urls);
            let sent = sent.lock().unwrap();
            assert!(
                sent.iter().all(|payload| payload["op"] != json!(OP_RESUME)),
                "close code {code} still resumed the dead session: {sent:?}"
            );
            assert_eq!(
                sent.iter()
                    .filter(|payload| payload["op"] == json!(OP_IDENTIFY))
                    .count(),
                2,
                "close code {code} did not identify fresh sessions: {sent:?}"
            );
        }
    }

    #[test]
    fn a_resumable_close_keeps_the_session_for_resume() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = ScriptedConnection::new(
            [hello(), ready(), GatewayRead::Closed(Some(4000))],
            Arc::clone(&sent),
        );
        let mut handler = RecordingHandler::default();
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();
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
        assert!(session.can_resume());
    }

    #[test]
    fn default_intents_leave_privileged_member_events_opt_in() {
        assert_eq!(DEFAULT_INTENTS & INTENT_GUILD_MEMBERS, 0);
        assert_eq!(GatewayConfig::default().intents & INTENT_GUILD_MEMBERS, 0);
        assert_eq!(DEFAULT_INTENTS & INTENT_MESSAGE_CONTENT, 0);
        assert_eq!(
            GatewayConfig::default().intents & INTENT_MESSAGE_CONTENT,
            0,
            "message content must stay opt-in until Discord grants it"
        );
    }

    #[test]
    fn endpoint_policy_requires_wss_on_a_discord_authority() {
        assert_eq!(
            parse_gateway_endpoint("ws://gateway.discord.gg/?v=10")
                .unwrap_err()
                .code,
            "a4mc_discord_gateway_endpoint_refused"
        );
        assert_eq!(
            parse_gateway_endpoint("http://gateway.discord.gg/")
                .unwrap_err()
                .code,
            "a4mc_discord_gateway_endpoint_refused"
        );
        assert_eq!(
            parse_gateway_endpoint("wss://evil.example/?v=10")
                .unwrap_err()
                .code,
            "a4mc_discord_gateway_endpoint_refused"
        );
        assert_eq!(
            parse_gateway_endpoint("wss://user:pw@gateway.discord.gg/")
                .unwrap_err()
                .code,
            "a4mc_discord_gateway_endpoint_refused"
        );
        assert_eq!(
            parse_gateway_endpoint("wss://nodiscord.gg.evil.example/")
                .unwrap_err()
                .code,
            "a4mc_discord_gateway_endpoint_refused"
        );
        // Plaintext may only reach loopback — local fixtures stay
        // possible while a credential can never leave the machine
        // unencrypted.
        let loopback = parse_gateway_endpoint("ws://127.0.0.1:8080/?v=10").unwrap();
        assert!(!loopback.tls);
        assert_eq!(loopback.port, 8080);
        assert!(
            parse_gateway_endpoint("ws://10.0.0.5/?v=10")
                .unwrap_err()
                .code
                == "a4mc_discord_gateway_endpoint_refused"
        );
        // The provider authority and its regional resume hosts pass.
        for url in [
            "wss://gateway.discord.gg/?v=10&encoding=json",
            "wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json",
            "wss://discord.gg/",
        ] {
            let endpoint = parse_gateway_endpoint(url).unwrap();
            assert!(endpoint.tls);
            assert_eq!(endpoint.port, 443);
            assert!(endpoint.target.starts_with('/'));
        }
    }

    #[test]
    fn secret_frames_are_client_masked_text_frames() {
        let mut bytes = Vec::new();
        write_masked_text_frame(&mut bytes, br#"{"op":2,"d":{"token":"secret"}}"#).unwrap();
        assert_eq!(bytes[0], 0x81, "FIN + text opcode");
        assert_eq!(bytes[1] & 0x80, 0x80, "client frames must be masked");
        let len = usize::from(bytes[1] & 0x7f);
        let mask = &bytes[2..6];
        let payload: Vec<u8> = bytes[6..6 + len]
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, mask)| byte ^ mask)
            .collect();
        assert_eq!(payload, br#"{"op":2,"d":{"token":"secret"}}"#);
        assert_eq!(bytes.len(), 6 + len, "no trailing bytes");
    }

    /// A scripted connection that paces its reads so the handler worker
    /// has time to park before heartbeat deadlines fire.
    struct PacedConnection {
        inner: ScriptedConnection,
    }

    impl GatewayConnection for PacedConnection {
        fn read_frame(&mut self, timeout: Duration) -> Result<GatewayRead, DiscordApiError> {
            std::thread::sleep(Duration::from_millis(10));
            self.inner.read_frame(timeout)
        }
        fn send_text(&mut self, text: &str) -> Result<(), DiscordApiError> {
            self.inner.send_text(text)
        }
    }

    /// The host turn parks until released; it records how many
    /// heartbeats had already been sent when it blocked, so the test
    /// can prove later beats flowed while it was parked.
    struct BlockingHandler {
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, std::sync::Condvar)>,
        sent: Arc<Mutex<Vec<Value>>>,
        beats_at_enter: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl GatewayHandler for BlockingHandler {
        fn on_dispatch(
            &mut self,
            _event: &ChannelEvent,
            _payload: &GatewayPayload,
        ) -> Result<(), DiscordApiError> {
            self.beats_at_enter.store(
                self.sent
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|payload| payload["op"] == json!(OP_HEARTBEAT))
                    .count(),
                Ordering::SeqCst,
            );
            self.entered.store(true, Ordering::SeqCst);
            let (mutex, condvar) = &*self.release;
            let mut released = mutex.lock().unwrap();
            while !*released {
                released = condvar.wait(released).unwrap();
            }
            Ok(())
        }
    }

    #[test]
    fn a_blocked_handler_does_not_stall_the_heartbeat_schedule() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut connection = PacedConnection {
            inner: ScriptedConnection::new(
                [
                    hello(),
                    message(2),
                    GatewayRead::Text(json!({"op": OP_HEARTBEAT_ACK}).to_string()),
                    // Each scripted Timeout is the earliest deadline
                    // firing; with the handler parked these must still
                    // produce heartbeats (each acknowledged before the
                    // next deadline).
                    GatewayRead::Timeout,
                    GatewayRead::Text(json!({"op": OP_HEARTBEAT_ACK}).to_string()),
                    GatewayRead::Timeout,
                    GatewayRead::Text(json!({"op": OP_HEARTBEAT_ACK}).to_string()),
                    GatewayRead::Timeout,
                    reconnect(),
                ],
                Arc::clone(&sent),
            ),
        };
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let beats_at_enter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handler = BlockingHandler {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            sent: Arc::clone(&sent),
            beats_at_enter: Arc::clone(&beats_at_enter),
        };
        let mut session = GatewaySession::default();
        let stop = AtomicBool::new(false);
        let token = SecretToken::try_from_string(fixture_token()).unwrap();

        let runner = std::thread::spawn(move || {
            let outcome = run_gateway_session(
                &mut connection,
                &token,
                &mut handler,
                &mut session,
                &GatewayConfig::default(),
                &stop,
            );
            (outcome, session)
        });
        // The dispatch parks the worker while the paced connection keeps
        // reading; the heartbeat deadlines fire inside the block before
        // it is released.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "dispatch never reached the handler"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(80));
        {
            let (mutex, condvar) = &*release;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        let (outcome, session) = runner.join().unwrap();
        let outcome = outcome.unwrap();

        assert_eq!(outcome, SessionOutcome::Reconnect);
        let beats = sent
            .lock()
            .unwrap()
            .iter()
            .filter(|payload| payload["op"] == json!(OP_HEARTBEAT))
            .count();
        // HELLO's initial heartbeat plus one per fired deadline.
        assert_eq!(beats, 4);
        assert!(
            beats_at_enter.load(Ordering::SeqCst) < beats,
            "no heartbeat flowed while the handler was parked"
        );
        // The parked dispatch was committed after the handler accepted.
        assert_eq!(session.sequence, Some(2));
    }
}
