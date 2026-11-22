//! Telegram Bot API transport (long polling by default).
//!
//! The transport speaks Bot API on one side and this crate's
//! telegram-native shapes on the other. The bot token arrives already
//! resolved — custody is the host's port; this module never reads
//! keychains, files or environment for it — and is held zeroizing. API
//! failures are sanitized: error messages never echo the token, request
//! or response bodies.

use super::inbound::parse_message_update;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

#[cfg(test)]
use super::inbound::InboundKind;
pub use super::inbound::InboundMessage;

pub const DEFAULT_API_ROOT: &str = "https://api.telegram.org";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramApiError {
    pub code: String,
    pub message: String,
    /// The platform's `retry_after` hint in seconds, carried when the
    /// Bot API throttled the call (HTTP 429 / `error_code` 429).
    /// `None` on every non-throttled failure.
    pub retry_after: Option<u64>,
    /// Progress of a chunked `sendMessage` call that stopped mid-flight:
    /// the confirmed prefix and where it stopped, so the idempotency
    /// owner can resume instead of reposting delivered parts. `None`
    /// for failures outside a multi-part send. Boxed so a `Result`
    /// carrying this error stays small on the hot path.
    pub send_progress: Option<Box<SendProgress>>,
}

/// The effective send a checkpoint is bound to: the dedupe key, the
/// lowered destination, and a digest of the lowered payload. A saved
/// chunk position may only resume the send it was earned on — a retry
/// whose prepared destination, text or key differs is refused rather
/// than continuing someone else's message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendBinding {
    /// The dedupe key the original send attempt ran under.
    pub dedupe_key: String,
    /// The lowered destination chat.
    pub chat_id: i64,
    /// SHA-256 hex over the effective text and reply target, so the
    /// full payload need not be duplicated into the checkpoint.
    pub payload_digest: String,
}

/// Where a chunked `sendMessage` send stopped, kept by the idempotency
/// owner so a retry resumes instead of blindly reposting confirmed parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendProgress {
    /// Platform message ids confirmed in send order before the stop.
    pub confirmed: Vec<i64>,
    /// Index of the part that stopped the send — the resume point.
    pub next_part: usize,
    /// True when the stopping part's outcome never reached us — a
    /// transport failure or a response that cannot be evaluated — so the
    /// platform may have posted it. False when the platform definitively
    /// rejected the part and it is safe to send again.
    pub outcome_unknown: bool,
    /// The prepared send this checkpoint was earned on. Absent on
    /// checkpoints recorded before the binding existed; those resume
    /// unverifiable, exactly as they did when written.
    #[serde(default)]
    pub binding: Option<SendBinding>,
}

impl TelegramApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after: None,
            send_progress: None,
        }
    }

    /// Attach the platform's `retry_after` hint to a throttled failure.
    pub fn with_retry_after(mut self, retry_after: Option<u64>) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// Attach the mid-flight progress of a stopped chunked send.
    pub fn with_send_progress(mut self, progress: SendProgress) -> Self {
        self.send_progress = Some(Box::new(progress));
        self
    }
}

impl std::fmt::Display for TelegramApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TelegramApiError {}

impl From<TelegramApiError> for a4mc::ChannelError {
    fn from(error: TelegramApiError) -> Self {
        // The platform's retry floor is part of the failure the host
        // sees: without it a rate-limit error gives callers nothing to
        // wait on before retrying.
        let mut converted = a4mc::ChannelError::new(error.code, error.message);
        if let Some(seconds) = error.retry_after {
            converted = converted.with_retry_after_ms(seconds.saturating_mul(1000));
        }
        converted
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BotIdentity {
    pub id: i64,
    pub username: String,
    pub first_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub update_id: i64,
    pub message: Option<InboundMessage>,
}

pub trait BotTransport: Send + Sync {
    fn get_me(&self) -> Result<BotIdentity, TelegramApiError>;
    fn delete_webhook(&self) -> Result<(), TelegramApiError>;
    fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError>;
    fn get_updates(&self, offset: i64, timeout_secs: u64) -> Result<Vec<Update>, TelegramApiError>;
    /// Send `text` (chunked at the platform limit), optionally threaded
    /// under `reply_to_message_id`. `resume` is the progress a previous
    /// attempt of the same logical send recorded: parts before
    /// `resume.next_part` are confirmed and never reposted. Returns the
    /// platform message ids of the parts this call transmitted, in send
    /// order. `observe` runs as each part reaches a checkpoint — an
    /// in-flight marker (`next_part` at the part about to post,
    /// `outcome_unknown` set) before every POST and the confirmed
    /// progress after it — so a persistent observer can surface an
    /// interrupted attempt instead of silently reposting it. An
    /// observer error aborts the send before the part is posted. A
    /// mid-flight failure carries the updated progress on the error so
    /// the caller can resume or refuse to retry.
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
        resume: Option<&SendProgress>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<Vec<i64>, TelegramApiError>;
}

/// `Arc<T>` transports itself so one transport can be shared between the
/// polling loop and a normalized send surface.
impl<T: BotTransport + ?Sized> BotTransport for Arc<T> {
    fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
        (**self).get_me()
    }
    fn delete_webhook(&self) -> Result<(), TelegramApiError> {
        (**self).delete_webhook()
    }
    fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
        (**self).set_my_commands(commands)
    }
    fn get_updates(&self, offset: i64, timeout_secs: u64) -> Result<Vec<Update>, TelegramApiError> {
        (**self).get_updates(offset, timeout_secs)
    }
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
        resume: Option<&SendProgress>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<Vec<i64>, TelegramApiError> {
        (**self).send_message(chat_id, text, reply_to_message_id, resume, observe)
    }
}

pub fn bot_commands() -> Vec<(String, String)> {
    vec![
        ("start".into(), "Request a pairing code".into()),
        ("help".into(), "Show help".into()),
        ("commands".into(), "List commands".into()),
        ("whoami".into(), "Show your Telegram ids".into()),
        ("pair".into(), "Show or renew pairing code".into()),
        ("unpair".into(), "Revoke this chat pairing".into()),
        ("status".into(), "Show pairing, agent, session".into()),
        ("agent".into(), "List or select a local agent".into()),
        ("session".into(), "List or select a conversation".into()),
        ("new".into(), "Start a new conversation".into()),
        ("reset".into(), "Same as /new".into()),
        ("stop".into(), "Stop note (turns are sequential)".into()),
    ]
}

/// One validated Bot API endpoint: HTTPS on an approved authority, with
/// any path prefix the configured root carried preserved.
#[derive(Debug)]
struct ApiEndpoint {
    host: String,
    port: u16,
    base_path: String,
    /// Plaintext is only constructible by test fixtures; every live path
    /// comes through `parse_api_endpoint`, which refuses non-HTTPS.
    tls: bool,
}

/// Authorities credentialed Bot API requests may target: the provider's
/// documented API domain family only.
const APPROVED_API_AUTHORITIES: &[&str] = &["telegram.org"];

fn api_root_refused() -> TelegramApiError {
    TelegramApiError::new(
        "a4mc_telegram_api_root_refused",
        "Bot API root is outside the approved endpoint policy",
    )
}

/// Validate a configured Bot API root for credentialed live requests:
/// HTTPS only — plaintext can never carry the token — on the provider's
/// own authority. Plaintext loopback fixtures go through the test-only
/// construction path; redirects are never followed, so the policy holds
/// for every byte that leaves the process.
fn parse_api_endpoint(root: &str) -> Result<ApiEndpoint, TelegramApiError> {
    let rest = root
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .ok_or_else(api_root_refused)?;
    let (authority, base) = rest
        .split_once('/')
        .map_or((rest, ""), |(authority, base)| (authority, base));
    if authority.is_empty() || authority.contains('@') {
        return Err(api_root_refused());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| api_root_refused())?),
        None => (authority, 443),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let approved = APPROVED_API_AUTHORITIES
        .iter()
        .any(|authority| host == *authority || host.ends_with(&format!(".{authority}")));
    if host.is_empty() || !approved {
        return Err(api_root_refused());
    }
    Ok(ApiEndpoint {
        host,
        port,
        base_path: if base.is_empty() {
            String::new()
        } else {
            format!("/{base}")
        },
        tls: true,
    })
}

/// Live Bot API client speaking HTTPS itself.
///
/// The bot token travels inside the request path, so the HTTP request is
/// written by this adapter over a rustls session: no HTTP client
/// dependency ever sees — or logs — the credential-bearing request
/// line, and no redirect can move the token to another authority. TLS
/// peer verification uses the platform root store.
pub struct LiveBotTransport {
    endpoint: ApiEndpoint,
    token: Zeroizing<String>,
}

// Never derive Debug: the token field must not leak into diagnostics.
impl std::fmt::Debug for LiveBotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveBotTransport")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl LiveBotTransport {
    /// Build the live client after validating `api_root` against the
    /// credentialed endpoint policy (`https://` on the provider's
    /// authority). `None` keeps the default [`DEFAULT_API_ROOT`].
    pub fn new(token: impl Into<String>, api_root: Option<&str>) -> Result<Self, TelegramApiError> {
        Ok(Self {
            endpoint: parse_api_endpoint(api_root.unwrap_or(DEFAULT_API_ROOT))?,
            token: Zeroizing::new(token.into()),
        })
    }

    /// Test-only construction for plaintext loopback fixtures: skips the
    /// endpoint policy so `http://127.0.0.1:{port}` responders can stand
    /// in for the API. Only exists under `cfg(test)` — no production
    /// build can ever select this path.
    #[cfg(test)]
    fn new_for_test(token: impl Into<String>, api_root: Option<&str>) -> Self {
        let root = api_root
            .unwrap_or(DEFAULT_API_ROOT)
            .trim()
            .trim_end_matches('/');
        let (tls, rest) = root
            .strip_prefix("https://")
            .map(|rest| (true, rest))
            .or_else(|| root.strip_prefix("http://").map(|rest| (false, rest)))
            .unwrap_or((true, root));
        let (authority, base) = rest
            .split_once('/')
            .map_or((rest, ""), |(authority, base)| (authority, base));
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().unwrap_or(443)),
            None => (authority, 443),
        };
        Self {
            endpoint: ApiEndpoint {
                host: host.to_owned(),
                port,
                base_path: if base.is_empty() {
                    String::new()
                } else {
                    format!("/{base}")
                },
                tls,
            },
            token: Zeroizing::new(token.into()),
        }
    }

    fn call_json(&self, method: &str, body: Value) -> Result<Value, TelegramApiError> {
        // The token is inside the request path; `https_post` writes the
        // request itself so no dependency diagnostic can echo it.
        let path = format!(
            "{}/bot{}/{}",
            self.endpoint.base_path,
            self.token.as_str(),
            method
        );
        let payload = serde_json::to_vec(&body).map_err(|_| {
            TelegramApiError::new(
                "a4mc_telegram_json_invalid",
                "Bot API request was not valid JSON",
            )
        })?;
        let response = https_post(&self.endpoint, &path, &payload)?;
        // A 429 is classified from the status line alone — the body may
        // be empty or non-JSON while the Retry-After header still
        // carries the platform's wait. Requiring JSON first would
        // reclassify a clean throttle as an ambiguous parse failure.
        if response.status == 429 {
            let hinted = serde_json::from_slice::<Value>(&response.body)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/parameters/retry_after")
                        .and_then(Value::as_u64)
                });
            return Err(TelegramApiError::new(
                "a4mc_telegram_throttled",
                format!("{method}: Bot API rate limited"),
            )
            .with_retry_after(response.retry_after.or(hinted)));
        }
        let value: Value = serde_json::from_slice(&response.body).map_err(|_| {
            TelegramApiError::new(
                "a4mc_telegram_json_invalid",
                "Bot API response was not valid JSON",
            )
        })?;
        let status = response.status;
        if status == 401 || value["error_code"].as_i64() == Some(401) {
            return Err(TelegramApiError::new(
                "a4mc_telegram_unauthorized",
                "getMe/Bot API rejected the bot token",
            ));
        }
        if status == 409 || value["error_code"].as_i64() == Some(409) {
            return Err(TelegramApiError::new(
                "a4mc_telegram_conflict",
                "getUpdates conflict: another poller is using this bot token",
            ));
        }
        if value["ok"].as_bool() != Some(true) {
            let retry_after = response.retry_after.or_else(|| {
                value
                    .pointer("/parameters/retry_after")
                    .and_then(Value::as_u64)
            });
            let code = if status == 429 || value["error_code"].as_i64() == Some(429) {
                "a4mc_telegram_throttled"
            } else if status >= 500 || value["error_code"].as_i64().unwrap_or_default() >= 500 {
                // A server-side failure means the request reached the
                // platform but its effect is uncertain.
                "a4mc_telegram_server_failed"
            } else {
                "a4mc_telegram_api_failed"
            };
            return Err(
                TelegramApiError::new(code, format!("{method}: Bot API request failed"))
                    .with_retry_after(retry_after),
            );
        }
        Ok(value["result"].clone())
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_HEAD_BYTES: usize = 16 * 1024;

struct HttpResponse {
    status: u16,
    retry_after: Option<u64>,
    body: Vec<u8>,
}

/// One POST over a fresh session, closed after the response so body
/// framing stays trivially correct. Nothing on this path logs: `path`
/// carries the bot token. Redirects are never followed — the endpoint
/// policy above is the only authority a credentialed request reaches.
fn https_post(
    endpoint: &ApiEndpoint,
    path: &str,
    payload: &[u8],
) -> Result<HttpResponse, TelegramApiError> {
    // Failures before any request byte leaves are distinct from
    // failures in flight: nothing can have reached the platform, so
    // the send is safe to retry — the two outcomes must not share a
    // code.
    let connect_failed =
        || TelegramApiError::new("a4mc_telegram_connect_failed", "Bot API connection failure");
    let failed =
        || TelegramApiError::new("a4mc_telegram_network_failed", "Bot API transport failure");
    let stream = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .ok()
        .and_then(|addrs| {
            addrs
                .into_iter()
                .find_map(|addr| TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).ok())
        })
        .ok_or_else(connect_failed)?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let host_header = if endpoint.port == 443 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let write_request = |stream: &mut dyn Write| -> Result<(), TelegramApiError> {
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(payload))
            .and_then(|()| stream.flush())
            .map_err(|_| failed())
    };
    if endpoint.tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(connect_failed());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
            .map_err(|_| connect_failed())?;
        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|_| connect_failed())?;
        let mut stream = rustls::StreamOwned::new(conn, stream);
        write_request(&mut stream)?;
        read_response(&mut stream)
    } else {
        let mut stream = stream;
        write_request(&mut stream)?;
        read_response(&mut stream)
    }
}

/// Read one framed response in two phases: the head — status line
/// plus the headers that matter (`Retry-After`, `Transfer-Encoding`,
/// `Content-Length`) — is parsed as soon as its terminator arrives,
/// then the body is read under the same bound until its declared
/// framing completes. A body framed by `Content-Length` or a chunked
/// `Transfer-Encoding` ends the read the moment the frame is
/// complete — no wait for the connection's close — and a close that
/// arrives before the declared length or the terminal chunk is a
/// truncation, not a body. Only a response that declares neither is
/// close-delimited. A throttle answer's classification lives entirely
/// in the head, so a 429 whose body stalls, truncates or frames
/// incompletely still returns as a throttle with its `Retry-After`
/// instead of degrading into an ambiguous read failure.
fn read_response(stream: &mut dyn Read) -> Result<HttpResponse, TelegramApiError> {
    let failed =
        || TelegramApiError::new("a4mc_telegram_read_failed", "Bot API response read failed");
    let oversized = || {
        TelegramApiError::new(
            "a4mc_telegram_response_too_large",
            "Bot API response exceeded bound",
        )
    };
    // Framing slack on the raw body bound so a chunked answer whose
    // decoded body just fits the response bound is not refused on
    // chunk headers alone.
    let raw_cap = MAX_RESPONSE_BYTES + 64 * 1024;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    // The head bound is enforced at the terminator itself — body
    // bytes that arrive inside the same read never count against it,
    // so a valid head under the limit cannot be hidden by the body
    // that followed it.
    let head_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Err(failed()),
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    if position + 4 > MAX_HEAD_BYTES {
                        return Err(failed());
                    }
                    break position + 4;
                }
                if raw.len() > MAX_HEAD_BYTES {
                    return Err(failed());
                }
            }
            Err(_) => return Err(failed()),
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(failed)?;
    let mut retry_after = None;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "retry-after" {
                retry_after = value.parse::<u64>().ok();
            } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if name == "content-length" {
                let length = value.parse::<usize>().map_err(|_| failed())?;
                if content_length.is_some_and(|seen| seen != length) {
                    return Err(failed());
                }
                content_length = Some(length);
            }
        }
    }
    // A 429's classification needs no body: any body-read or decode
    // failure — a stall, a truncated frame, an oversized payload —
    // degrades the body to absent rather than the status to
    // ambiguous.
    let throttled_body_lost = || {
        (status == 429).then(|| HttpResponse {
            status,
            retry_after,
            body: Vec::new(),
        })
    };
    let mut body_raw = raw.split_off(head_end);
    loop {
        // A declared frame ends the read as soon as it is complete:
        // stopping before another read keeps a peer's unclean close
        // (a TLS truncation alert behind the last body byte) from
        // shadowing a response that already arrived whole.
        let complete = if chunked {
            matches!(chunked_state(&body_raw), ChunkedState::Complete)
        } else {
            content_length.is_some_and(|length| body_raw.len() >= length)
        };
        if complete {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                body_raw.extend_from_slice(&chunk[..read]);
                if body_raw.len() > raw_cap {
                    return throttled_body_lost().map_or_else(|| Err(oversized()), Ok);
                }
            }
            Err(_) => {
                return throttled_body_lost().map_or_else(|| Err(failed()), Ok);
            }
        }
    }
    let body = if chunked {
        match decode_chunked(&body_raw) {
            Some(body) => body,
            None => {
                return throttled_body_lost().map_or_else(|| Err(failed()), Ok);
            }
        }
    } else if let Some(length) = content_length {
        if body_raw.len() < length {
            // A clean close before the declared length is truncation,
            // never a shorter body.
            return throttled_body_lost().map_or_else(|| Err(failed()), Ok);
        }
        body_raw.truncate(length);
        body_raw
    } else {
        body_raw
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return throttled_body_lost().map_or_else(|| Err(oversized()), Ok);
    }
    Ok(HttpResponse {
        status,
        retry_after,
        body,
    })
}

/// How far a raw body buffer gets through chunked framing. The read
/// loop uses this cheap header scan to stop as soon as the frame is
/// complete; [`decode_chunked`] then performs the authoritative parse.
enum ChunkedState {
    /// The terminal `0` chunk and the trailer section's closing line
    /// have all arrived.
    Complete,
    /// A clean prefix: more of the frame may still arrive.
    Incomplete,
    /// A chunk header or data boundary violates the framing.
    Malformed,
}

fn chunked_state(raw: &[u8]) -> ChunkedState {
    let mut rest = raw;
    let mut decoded = 0usize;
    loop {
        let Some(end) = rest.windows(2).position(|window| window == b"\r\n") else {
            return ChunkedState::Incomplete;
        };
        let Ok(header) = std::str::from_utf8(&rest[..end]) else {
            return ChunkedState::Malformed;
        };
        let Ok(size) = usize::from_str_radix(header.trim().split(';').next().unwrap_or(""), 16)
        else {
            return ChunkedState::Malformed;
        };
        rest = &rest[end + 2..];
        if size == 0 {
            // The trailer section ends in a blank line: an immediate
            // CRLF when empty, or header lines closed by one.
            return if chunked_tail_complete(rest) {
                ChunkedState::Complete
            } else {
                ChunkedState::Incomplete
            };
        }
        if rest.len() < size + 2 {
            return ChunkedState::Incomplete;
        }
        decoded += size;
        if decoded > MAX_RESPONSE_BYTES {
            return ChunkedState::Malformed;
        }
        rest = &rest[size..];
        if !rest.starts_with(b"\r\n") {
            return ChunkedState::Malformed;
        }
        rest = &rest[2..];
    }
}

/// Whether the trailer section after a terminal `0` chunk has closed:
/// an immediate CRLF when empty, or trailer header lines followed by
/// the blank line.
fn chunked_tail_complete(rest: &[u8]) -> bool {
    rest.starts_with(b"\r\n") || rest.windows(4).any(|window| window == b"\r\n\r\n")
}

fn decode_chunked(raw: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut rest = raw;
    loop {
        let end = rest.windows(2).position(|window| window == b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..end])
                .ok()?
                .trim()
                .split(';')
                .next()?,
            16,
        )
        .ok()?;
        rest = &rest[end + 2..];
        if size == 0 {
            // The frame is complete only once the trailer section's
            // blank line arrived; anything still behind it is ignored.
            return chunked_tail_complete(rest).then_some(body);
        }
        if rest.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&rest[..size]);
        if body.len() > MAX_RESPONSE_BYTES {
            return None;
        }
        rest = &rest[size..];
        if !rest.starts_with(b"\r\n") {
            return None;
        }
        rest = &rest[2..];
    }
}

impl BotTransport for LiveBotTransport {
    fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
        let result = self.call_json("getMe", json!({}))?;
        Ok(BotIdentity {
            id: result["id"].as_i64().unwrap_or_default(),
            username: result["username"].as_str().unwrap_or("").to_owned(),
            first_name: result["first_name"].as_str().unwrap_or("").to_owned(),
        })
    }

    fn delete_webhook(&self) -> Result<(), TelegramApiError> {
        let _ = self.call_json("deleteWebhook", json!({ "drop_pending_updates": false }))?;
        Ok(())
    }

    fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
        let payload = commands
            .iter()
            .map(|(command, description)| {
                json!({
                    "command": command,
                    "description": description,
                })
            })
            .collect::<Vec<_>>();
        let _ = self.call_json("setMyCommands", json!({ "commands": payload }))?;
        Ok(())
    }

    fn get_updates(&self, offset: i64, timeout_secs: u64) -> Result<Vec<Update>, TelegramApiError> {
        let result = self.call_json(
            "getUpdates",
            json!({
                "offset": offset,
                "timeout": timeout_secs,
                "allowed_updates": ["message", "edited_message"],
            }),
        )?;
        let items = result.as_array().cloned().unwrap_or_default();
        Ok(items.iter().filter_map(parse_update).collect())
    }

    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
        resume: Option<&SendProgress>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<Vec<i64>, TelegramApiError> {
        let chunks = bounded_send_parts(text)?;
        let start = resume.map_or(0, |progress| progress.next_part);
        if start > chunks.len() {
            return Err(TelegramApiError::new(
                "a4mc_telegram_resume_invalid",
                "send resume position is outside the chunked text",
            ));
        }
        let mut progress = SendProgress {
            confirmed: resume.map_or_else(Vec::new, |p| p.confirmed.clone()),
            next_part: start,
            outcome_unknown: false,
            binding: resume.and_then(|p| p.binding.clone()),
        };
        let mut sent_ids = Vec::with_capacity(chunks.len() - start);
        for (index, chunk) in chunks.iter().enumerate().skip(start) {
            // In-flight marker before the POST: a crash after the
            // platform accepts the request leaves this part honestly
            // uncertain, so restart reconciles instead of reposting.
            progress.next_part = index;
            progress.outcome_unknown = true;
            if let Err(error) = observe(&progress) {
                // The marker could not be recorded — but nothing was
                // posted either, so the checkpoint is safe to retry.
                progress.outcome_unknown = false;
                return Err(error.with_send_progress(progress));
            }
            let mut body = json!({
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": true,
            });
            if index == 0
                && let Some(reply_to) = reply_to_message_id
            {
                body["reply_to_message_id"] = json!(reply_to);
                body["allow_sending_without_reply"] = json!(true);
            }
            match self.call_json("sendMessage", body) {
                Ok(result) => {
                    let id = result["message_id"].as_i64().unwrap_or_default();
                    sent_ids.push(id);
                    progress.confirmed.push(id);
                    progress.next_part = index + 1;
                    progress.outcome_unknown = false;
                    if let Err(error) = observe(&progress) {
                        return Err(error.with_send_progress(progress));
                    }
                }
                Err(error) => {
                    let outcome_unknown = result_is_unknown(&error);
                    progress.next_part = index;
                    progress.outcome_unknown = outcome_unknown;
                    return Err(error.with_send_progress(progress));
                }
            }
        }
        Ok(sent_ids)
    }
}

/// Whether an API failure leaves the request's effect unconfirmed —
/// the platform may have received and posted it — versus a definitive
/// rejection. Unconfirmed failures must never be blindly reposted.
fn result_is_unknown(error: &TelegramApiError) -> bool {
    matches!(
        error.code.as_str(),
        "a4mc_telegram_network_failed"
            | "a4mc_telegram_read_failed"
            | "a4mc_telegram_json_invalid"
            | "a4mc_telegram_response_too_large"
            | "a4mc_telegram_server_failed"
    )
}

/// Shape check for a BotFather token: nonempty, bounded, ASCII, no
/// whitespace, `id:secret` colon-separated.
pub fn validate_bot_token(token: &str) -> Result<(), TelegramApiError> {
    let trimmed = token.trim();
    let invalid = |_: ()| TelegramApiError::new("a4mc_telegram_token_invalid", "bot token shape");
    if trimmed.is_empty()
        || trimmed.len() > MAX_TOKEN_BYTES
        || trimmed.chars().any(|ch| ch.is_whitespace())
        || !trimmed.is_ascii()
        || !trimmed.contains(':')
    {
        return Err(invalid(()));
    }
    Ok(())
}

/// Resolve the bot token through the host-installed custody port and
/// build the live transport. The crate never reads keychains, files or
/// environment for the token itself.
pub fn live_transport(api_root: Option<&str>) -> Result<LiveBotTransport> {
    let port = a4mc::custody::require().map_err(|error| anyhow!(error.to_string()))?;
    let token = port
        .channel_token(&crate::channel_id())
        .map_err(|error| anyhow!(error.to_string()))?
        .ok_or_else(|| anyhow!("a4mc_telegram_token_missing"))?;
    let token = token
        .expose_utf8()
        .map_err(|_| anyhow!("a4mc_telegram_token_invalid"))?;
    validate_bot_token(token).map_err(|error| anyhow!(error.to_string()))?;
    LiveBotTransport::new(token.to_owned(), api_root).map_err(|error| anyhow!(error.to_string()))
}

fn parse_update(value: &Value) -> Option<Update> {
    let update_id = value.get("update_id")?.as_i64()?;
    let message = value
        .get("message")
        .and_then(|message| parse_message_update(update_id, message, false))
        .or_else(|| {
            value
                .get("edited_message")
                .and_then(|message| parse_message_update(update_id, message, true))
        });
    Some(Update { update_id, message })
}

/// The platform's `sendMessage` text bound per post, counted the way
/// the platform counts characters: UTF-16 code units, so every astral
/// character costs two.
const TELEGRAM_TEXT_LIMIT: usize = 4096;

/// Per-chat send budget: the most `sendMessage` posts one logical send
/// may fan out to. Sized to admit the worst-case expansion of the
/// contract's `MAX_OUTBOUND_TEXT_CHARS` — every character astral — into
/// platform units; a contract-valid text always fits inside it.
const MAX_SEND_PARTS: usize = a4mc::MAX_OUTBOUND_TEXT_CHARS * 2 / TELEGRAM_TEXT_LIMIT + 1;

/// One part's length in platform characters (UTF-16 code units).
fn platform_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Bound one outbound text for the wire. Text above the contract's
/// `MAX_OUTBOUND_TEXT_CHARS` is rejected instead of fanning out into an
/// unbounded post sequence; what remains is chunked at the platform
/// limit inside the per-chat part budget.
fn bounded_send_parts(text: &str) -> Result<Vec<&str>, TelegramApiError> {
    if text.is_empty() {
        return Err(TelegramApiError::new(
            "a4mc_telegram_text_empty",
            "outbound text is empty",
        ));
    }
    if text.chars().count() > a4mc::MAX_OUTBOUND_TEXT_CHARS {
        return Err(TelegramApiError::new(
            "a4mc_telegram_text_too_large",
            "outbound text exceeded bound",
        ));
    }
    let chunks = chunk_telegram_text(text, TELEGRAM_TEXT_LIMIT);
    if chunks.len() > MAX_SEND_PARTS {
        return Err(TelegramApiError::new(
            "a4mc_telegram_part_budget_exceeded",
            "outbound text exceeded the per-chat send part budget",
        ));
    }
    Ok(chunks)
}

/// Split `text` into parts of at most `limit` platform characters
/// (UTF-16 code units), preserving char boundaries. The split produces
/// the minimal part count for the text — a newline in the tail of the
/// window is taken as the cut only when it reads better without costing
/// an extra part.
///
/// The dialect posts plain text (no `parse_mode`), so Markdown is carried
/// literally: a fence or emphasis marker split across two posts is still
/// the same characters, never a platform parse failure. The function is
/// total even for a degenerate `limit` smaller than one platform unit.
pub fn chunk_telegram_text(text: &str, limit: usize) -> Vec<&str> {
    if text.is_empty() {
        return vec![text];
    }
    let limit = limit.max(1);
    let minimal = platform_len(text).div_ceil(limit);
    let mut chunks = Vec::with_capacity(minimal);
    let mut rest = text;
    while !rest.is_empty() {
        if platform_len(rest) <= limit {
            chunks.push(rest);
            break;
        }
        // Largest char-boundary prefix inside the platform budget.
        let mut units = 0usize;
        let mut end = 0usize;
        for (index, ch) in rest.char_indices() {
            let width = ch.len_utf16();
            if units + width > limit {
                break;
            }
            units += width;
            end = index + ch.len_utf8();
        }
        if end == 0 {
            // The first scalar is wider than the whole window: emit it
            // whole rather than looping forever on an empty chunk.
            end = rest.chars().next().map_or(0, char::len_utf8);
        }
        // Prefer a newline in the tail of the window only when the
        // remaining text still fits the minimal part budget — never at
        // the cost of another serial request/response/message.
        if let Some(split) = rest[..end].rfind('\n') {
            let split = split + 1;
            if platform_len(&rest[..split]) > limit / 4
                && chunks.len() + 1 + platform_len(&rest[split..]).div_ceil(limit) <= minimal
            {
                end = split;
            }
        }
        chunks.push(&rest[..end]);
        rest = &rest[end..];
    }
    chunks
}

/// In-memory transport for tests and host-side fixtures.
pub struct MockBotTransport {
    pub identity: BotIdentity,
    pub updates: Arc<Mutex<Vec<Update>>>,
    pub sent: Arc<Mutex<Vec<(i64, String)>>>,
    pub observed_offsets: Arc<Mutex<Vec<i64>>>,
    pub fail_get_updates_with: Option<TelegramApiError>,
    /// Scripted `sendMessage` failure for the whole call. Shared so a
    /// test can clear the failure and exercise the caller's retry
    /// against the same mock.
    pub fail_send_with: Arc<Mutex<Option<TelegramApiError>>>,
    /// Fail the chunked part at this absolute index with this error and
    /// this unknown-outcome flag — for resume/ambiguous-path coverage.
    /// The fault is transient: each index fires at most once, so a retry
    /// that resumes at the stopped part observes a healthy transport.
    /// The progress attached to the error is computed like a real
    /// transport: prior parts stay confirmed.
    pub fail_send_at_part: Option<(usize, TelegramApiError, bool)>,
    /// Part indexes already failed by `fail_send_at_part` — one shot each.
    pub fired_parts: Mutex<HashSet<usize>>,
    pub commands: Arc<Mutex<Vec<(String, String)>>>,
    pub webhook_deleted: Arc<Mutex<bool>>,
    pub next_message_id: Arc<AtomicI64>,
}

impl Default for MockBotTransport {
    fn default() -> Self {
        Self {
            identity: BotIdentity::default(),
            updates: Arc::new(Mutex::new(Vec::new())),
            sent: Arc::new(Mutex::new(Vec::new())),
            observed_offsets: Arc::new(Mutex::new(Vec::new())),
            fail_get_updates_with: None,
            fail_send_with: Arc::new(Mutex::new(None)),
            fail_send_at_part: None,
            fired_parts: Mutex::new(HashSet::new()),
            commands: Arc::new(Mutex::new(Vec::new())),
            webhook_deleted: Arc::new(Mutex::new(false)),
            next_message_id: Arc::new(AtomicI64::new(1)),
        }
    }
}

impl Default for BotIdentity {
    fn default() -> Self {
        Self {
            id: 1,
            username: "a4mc_bot".into(),
            first_name: "A4MC".into(),
        }
    }
}

impl BotTransport for MockBotTransport {
    fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
        Ok(self.identity.clone())
    }

    fn delete_webhook(&self) -> Result<(), TelegramApiError> {
        *self.webhook_deleted.lock().unwrap() = true;
        Ok(())
    }

    fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
        *self.commands.lock().unwrap() = commands.to_vec();
        Ok(())
    }

    fn get_updates(
        &self,
        offset: i64,
        _timeout_secs: u64,
    ) -> Result<Vec<Update>, TelegramApiError> {
        self.observed_offsets.lock().unwrap().push(offset);
        if let Some(error) = self.fail_get_updates_with.clone() {
            return Err(error);
        }
        let mut guard = self.updates.lock().unwrap();
        let (keep, take): (Vec<_>, Vec<_>) = guard
            .drain(..)
            .partition(|update| update.update_id < offset);
        *guard = keep;
        Ok(take)
    }

    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        _reply_to_message_id: Option<i64>,
        resume: Option<&SendProgress>,
        observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
    ) -> Result<Vec<i64>, TelegramApiError> {
        if let Some(error) = self.fail_send_with.lock().unwrap().clone() {
            return Err(error);
        }
        let parts = bounded_send_parts(text)?;
        let start = resume.map_or(0, |progress| progress.next_part);
        if start > parts.len() {
            return Err(TelegramApiError::new(
                "a4mc_telegram_resume_invalid",
                "send resume position is outside the chunked text",
            ));
        }
        let mut progress = SendProgress {
            confirmed: resume.map_or_else(Vec::new, |p| p.confirmed.clone()),
            next_part: start,
            outcome_unknown: false,
            binding: resume.and_then(|p| p.binding.clone()),
        };
        let mut sent_ids = Vec::with_capacity(parts.len() - start);
        for (index, part) in parts.iter().enumerate().skip(start) {
            // Same cadence as the live transport: the marker precedes
            // the post, the confirmation follows it.
            progress.next_part = index;
            progress.outcome_unknown = true;
            if let Err(error) = observe(&progress) {
                progress.outcome_unknown = false;
                return Err(error.with_send_progress(progress));
            }
            if let Some((at, error, unknown)) = self.fail_send_at_part.as_ref()
                && *at == index
                && self.fired_parts.lock().unwrap().insert(index)
            {
                progress.next_part = index;
                progress.outcome_unknown = *unknown;
                return Err(error.clone().with_send_progress(progress));
            }
            self.sent
                .lock()
                .unwrap()
                .push((chat_id, (*part).to_owned()));
            let id = self.next_message_id.fetch_add(1, Ordering::SeqCst);
            sent_ids.push(id);
            progress.confirmed.push(id);
            progress.next_part = index + 1;
            progress.outcome_unknown = false;
            if let Err(error) = observe(&progress) {
                return Err(error.with_send_progress(progress));
            }
        }
        Ok(sent_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// Read one complete HTTP request (headers plus declared body) so a
    /// loopback close never resets an in-flight client write. Returns the
    /// request body as UTF-8 text.
    fn read_request_body(stream: &mut TcpStream) -> Option<String> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        let header_end = loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                return None;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header = String::from_utf8_lossy(&request[..header_end]);
        let body_len: usize = header
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(0);
        while request.len() < header_end + body_len {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                return None;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        Some(String::from_utf8_lossy(&request[header_end..header_end + body_len]).into_owned())
    }

    /// Serve a scripted sequence of responses, one fresh connection per
    /// response, and return the captured request bodies in order.
    fn serve_scripted(
        responses: Vec<(u16, &'static str, &'static str, &'static str)>,
    ) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut bodies = Vec::with_capacity(responses.len());
            for (status, content_type, extra_headers, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                bodies.push(read_request_body(&mut stream).expect("complete request"));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            bodies
        });
        (port, handle)
    }

    fn serve_once(
        status: u16,
        content_type: &'static str,
        body: &'static str,
    ) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        serve_scripted(vec![(status, content_type, "", body)])
    }

    fn serve_once_with_headers(
        status: u16,
        content_type: &'static str,
        headers: &'static str,
        body: &'static str,
    ) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        serve_scripted(vec![(status, content_type, headers, body)])
    }

    #[test]
    fn parses_private_message_update() {
        let update = parse_update(&json!({
            "update_id": 10,
            "message": {
                "message_id": 3,
                "text": "/agent cursor",
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 7, "username": "alice" }
            }
        }))
        .unwrap();
        let message = update.message.unwrap();
        assert_eq!(message.chat_id, 42);
        assert_eq!(message.user_id, 7);
        assert!(message.is_private);
        assert_eq!(message.control_text(), "/agent cursor");
    }

    #[test]
    fn parses_edited_photo_update() {
        let update = parse_update(&json!({
            "update_id": 11,
            "edited_message": {
                "message_id": 4,
                "caption": "updated",
                "photo": [{ "file_id": "p1", "width": 1, "height": 1 }],
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 7 }
            }
        }))
        .unwrap();
        let message = update.message.unwrap();
        assert!(message.edited);
        assert_eq!(message.kind, InboundKind::Photo);
        assert!(message.agent_text().contains("[edited]"));
        assert!(message.agent_text().contains("updated"));
    }

    #[test]
    fn chunks_long_text_on_boundaries() {
        let text = format!("{}\n{}", "a".repeat(30), "b".repeat(30));
        let chunks = chunk_telegram_text(&text, 40);
        assert!(chunks.len() >= 2);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 40));
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn chunks_borrow_the_source_text_without_duplicate_ownership() {
        let text = format!("{}\n{}", "a".repeat(30), "b".repeat(30));
        let chunks = chunk_telegram_text(&text, 40);
        assert!(chunks.len() >= 2);
        assert_eq!(chunks.concat(), text);
        assert_eq!(chunks[0].as_ptr(), text.as_ptr());
    }

    #[test]
    fn chunks_multibyte_text_without_splitting_a_scalar() {
        let text = "😀".repeat(2_500);
        let chunks = chunk_telegram_text(&text, TELEGRAM_TEXT_LIMIT);
        assert!(chunks.len() >= 2);
        assert_eq!(chunks.concat(), text);
        assert!(chunks.iter().all(|chunk| !chunk.is_empty()));
        assert!(
            chunks
                .iter()
                .all(|chunk| platform_len(chunk) <= TELEGRAM_TEXT_LIMIT)
        );
        // Telegram counts UTF-16 units: every astral character costs two,
        // so an emoji part holds at most half the platform limit in chars.
        assert!(chunks.iter().all(|chunk| chunk.chars().count() <= 2_048));
    }

    #[test]
    fn chunking_is_total_for_degenerate_limits() {
        let text = "a😀é中";
        for limit in [0, 1, 2, 3] {
            let chunks = chunk_telegram_text(text, limit);
            assert_eq!(chunks.concat(), text, "lossy at limit {limit}");
            assert!(
                chunks.iter().all(|chunk| !chunk.is_empty()),
                "empty chunk at limit {limit}"
            );
        }
    }

    #[test]
    fn chunking_prefers_a_newline_in_the_trailing_window() {
        let text = format!("{}\n{}", "a".repeat(30), "b".repeat(30));
        let chunks = chunk_telegram_text(&text, 40);
        assert_eq!(chunks[0], format!("{}\n", "a".repeat(30)));
        assert_eq!(chunks.concat(), text);
        assert!(chunks.iter().all(|chunk| chunk.len() <= 40));
    }

    #[test]
    fn send_parts_reject_empty_text() {
        let error = bounded_send_parts("").unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_text_empty");
    }

    #[test]
    fn send_parts_reject_text_above_the_contract_bound() {
        let oversized = "x".repeat(a4mc::MAX_OUTBOUND_TEXT_CHARS + 1);
        let error = bounded_send_parts(&oversized).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_text_too_large");
        // The whole contract range still fits inside the part budget.
        let maximal = "x".repeat(a4mc::MAX_OUTBOUND_TEXT_CHARS);
        let parts = bounded_send_parts(&maximal).unwrap();
        assert!(!parts.is_empty());
        assert!(parts.len() <= MAX_SEND_PARTS);
    }

    #[test]
    fn send_parts_chunk_at_platform_chars_without_fan_out() {
        // Astral text costs two platform characters each; a contract-
        // valid text still fits the part budget and the newline cut can
        // never fragment it into extra posts.
        let unit = format!("{}\n", "😀".repeat(275)); // 276 chars, 551 units
        let fragmented = unit.repeat(118); // 32568 chars — inside the bound
        let parts = bounded_send_parts(&fragmented).unwrap();
        assert!(parts.len() <= MAX_SEND_PARTS);
        assert!(
            parts
                .iter()
                .all(|part| platform_len(part) <= TELEGRAM_TEXT_LIMIT)
        );
        assert_eq!(parts.concat(), fragmented);
        assert_eq!(
            parts.len(),
            platform_len(&fragmented).div_ceil(TELEGRAM_TEXT_LIMIT),
            "the split must stay at the minimal part count"
        );
    }

    #[test]
    fn credentialed_requests_refuse_endpoints_outside_the_policy() {
        for root in [
            "http://api.telegram.org",
            "https://example.com",
            "https://telegram.org.evil.example",
            "wss://api.telegram.org",
        ] {
            assert_eq!(
                LiveBotTransport::new("token", Some(root)).unwrap_err().code,
                "a4mc_telegram_api_root_refused",
                "{root} was not refused"
            );
        }
        LiveBotTransport::new("token", None).unwrap();
        LiveBotTransport::new("token", Some("https://api.telegram.org")).unwrap();
    }

    #[test]
    fn long_markdown_is_split_verbatim_and_sent_as_plain_text() {
        let markdown = format!(
            "```rust\n{}\n```\n\n## tail\n{}",
            "let value = \"数据\";\n".repeat(400),
            "😀".repeat(600)
        );
        let parts = chunk_telegram_text(&markdown, TELEGRAM_TEXT_LIMIT);
        assert!(parts.len() >= 2);
        assert_eq!(parts.concat(), markdown);
        assert!(
            parts
                .iter()
                .all(|part| platform_len(part) <= TELEGRAM_TEXT_LIMIT)
        );

        let expected_parts = parts.len();
        let responses = (0..expected_parts)
            .map(|_| {
                (
                    200u16,
                    "application/json",
                    "",
                    "{\"ok\":true,\"result\":{\"message_id\":1}}",
                )
            })
            .collect();
        let (port, handle) = serve_scripted(responses);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let ids = transport
            .send_message(42, &markdown, Some(7), None, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(ids.len(), expected_parts);

        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), expected_parts);
        let mut reassembled = String::new();
        for (index, body) in bodies.iter().enumerate() {
            let value: Value = serde_json::from_str(body).unwrap();
            assert_eq!(value["chat_id"].as_i64(), Some(42));
            // No parse_mode is attached: Markdown markers are literal
            // text, so a split fence can never fail platform parsing.
            assert!(value.get("parse_mode").is_none());
            let chunk = value["text"].as_str().unwrap();
            assert!(platform_len(chunk) <= TELEGRAM_TEXT_LIMIT);
            reassembled.push_str(chunk);
            if index == 0 {
                assert_eq!(value["reply_to_message_id"].as_i64(), Some(7));
            } else {
                assert!(value.get("reply_to_message_id").is_none());
            }
        }
        assert_eq!(reassembled, markdown);
    }

    #[test]
    fn throttled_status_carries_retry_after_header() {
        let body = "{\"ok\":false,\"error_code\":429}";
        let (port, handle) =
            serve_once_with_headers(429, "application/json", "Retry-After: 7\r\n", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(7));
    }

    #[test]
    fn throttled_status_carries_body_retry_after() {
        let body = "{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":11}}";
        let (port, handle) = serve_once_with_headers(429, "application/json", "", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(11));
    }

    #[test]
    fn throttled_status_with_an_empty_body_uses_the_header() {
        // A 429 whose body never arrived is still a throttle: the
        // status line and Retry-After header classify it before any
        // JSON is required — never an ambiguous failure.
        let (port, handle) = serve_once_with_headers(429, "text/plain", "Retry-After: 4\r\n", "");
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(4));
    }

    #[test]
    fn throttled_status_with_a_non_json_body_uses_the_header() {
        // Proxies and frontends answer 429 with HTML or plain text;
        // the classification must not depend on parsing it.
        let (port, handle) = serve_once_with_headers(
            429,
            "text/html",
            "Retry-After: 2\r\n",
            "<html>rate limited</html>",
        );
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport
            .send_message(42, "hello", None, None, &mut |_| Ok(()))
            .unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(2));
        assert!(
            !result_is_unknown(&error),
            "a throttle must not read as an ambiguous send"
        );
    }

    #[test]
    fn ok_false_throttled_body_carries_retry_after() {
        let body = "{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":13}}";
        let (port, handle) = serve_once(200, "application/json", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(13));
    }

    #[test]
    fn send_throttle_surfaces_retry_after_without_posting_twice() {
        let body = "{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":9}}";
        let (port, handle) = serve_once_with_headers(429, "application/json", "", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport
            .send_message(42, "hello", None, None, &mut |_| Ok(()))
            .unwrap_err();
        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 1, "a throttle must not retry post blindly");
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(9));
    }

    #[test]
    fn http_error_never_leaks_token_or_body() {
        let fixture_ref = ["synthetic", "telegram", "credential"].join("-");
        let body = "{\"description\":\"leak-CANARY_BODY-leak\"}";
        let (port, handle) = serve_once(500, "application/json", body);
        let transport =
            LiveBotTransport::new_for_test(&fixture_ref, Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_server_failed");
        assert!(!error.message.contains(fixture_ref.as_str()));
        assert!(!error.message.contains("CANARY_BODY"));
        assert!(!error.message.contains("127.0.0.1"));
    }

    #[test]
    fn api_failure_description_is_not_forwarded() {
        let body = "{\"ok\":false,\"description\":\"CANARY_BODY description\"}";
        let (port, handle) = serve_once(200, "application/json", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_api_failed");
        assert!(!error.message.contains("CANARY_BODY"));
    }

    #[test]
    fn invalid_json_error_is_sanitized() {
        let body = "CANARY_BODY not json";
        let (port, handle) = serve_once(200, "application/json", body);
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_json_invalid");
        assert!(!error.message.contains("CANARY_BODY"));
    }

    #[test]
    fn an_in_flight_marker_precedes_every_part_post() {
        let transport = MockBotTransport::default();
        let calls: Arc<Mutex<Vec<(usize, bool, usize)>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let mut observe = move |progress: &SendProgress| {
            recorded.lock().unwrap().push((
                progress.next_part,
                progress.outcome_unknown,
                progress.confirmed.len(),
            ));
            Ok(())
        };
        let text = "x".repeat(5000); // two platform parts
        transport
            .send_message(42, &text, None, None, &mut observe)
            .unwrap();
        // Marker (uncertain, next_part = the part about to post) then
        // confirmation (certain, next_part advanced) — alternating for
        // every part, never a post left unmarked.
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(0, true, 0), (1, false, 1), (1, true, 1), (2, false, 2),]
        );
    }

    #[test]
    fn a_pre_connect_failure_is_distinct_and_certain() {
        // A port nothing can ever listen on: connect fails before any
        // request byte leaves, so the send's outcome is certain — safe
        // to retry — and must not share a code with in-flight failures.
        // Port 0 is reserved and unbindable, so there is no window in
        // which another listener could claim the destination — unlike a
        // dropped port-0 binding, which a parallel test process could
        // take between the drop and this connect.
        let transport = LiveBotTransport::new_for_test("token", Some("http://127.0.0.1:0"));
        let error = transport
            .send_message(42, "hello", None, None, &mut |_| Ok(()))
            .unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_connect_failed");
        assert!(
            !result_is_unknown(&error),
            "a failure before the request left must not read uncertain"
        );
        let progress = error.send_progress.expect("no checkpoint reported");
        assert!(!progress.outcome_unknown);
        assert_eq!(progress.next_part, 0);
    }

    #[test]
    fn throttled_status_with_an_incomplete_body_keeps_the_head_classification() {
        // Valid 429 headers arrive, then the chunk framing dies mid
        // body: the body is optional to the classification, never the
        // other way around.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request_body(&mut stream).expect("complete request");
            stream
                .write_all(
                    b"HTTP/1.1 429 X\r\nContent-Type: application/json\r\nRetry-After: 6\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhel",
                )
                .unwrap();
            // Close with the chunk half-sent: framing never completes.
        });
        let transport =
            LiveBotTransport::new_for_test("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_throttled");
        assert_eq!(error.retry_after, Some(6));
    }

    /// A scripted reader whose `read` calls return bounded chunk
    /// sizes — the network delivering the head's tail and the body
    /// inside one read.
    struct ChunkedReader {
        data: Vec<u8>,
        reads: std::collections::VecDeque<usize>,
        offset: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let size = self
                .reads
                .pop_front()
                .unwrap_or(usize::MAX)
                .min(self.data.len().saturating_sub(self.offset))
                .min(buf.len());
            buf[..size].copy_from_slice(&self.data[self.offset..self.offset + size]);
            self.offset += size;
            Ok(size)
        }
    }

    #[test]
    fn a_body_in_the_final_head_read_cannot_hide_a_throttle() {
        // A head just under the bound completes inside one read that
        // also carries enough body to push the buffer past it: the
        // limit is enforced at the terminator, so the valid 429 head
        // is still classified — the buffer size is not the head size.
        let head = format!(
            "HTTP/1.1 429 X\r\nContent-Type: application/json\r\nRetry-After: 6\r\nX-Pad: {}\r\n\r\n",
            "h".repeat(15_000)
        );
        let head_len = head.len();
        assert!(head_len <= MAX_HEAD_BYTES, "fixture head is oversized");
        let body = "b".repeat(9_000);
        let mut response = head.into_bytes();
        response.extend_from_slice(body.as_bytes());
        // Two short head reads, then one read covering the head's tail
        // and most of the body — past the head bound while the
        // terminator is still inside the same read.
        let mut stream = ChunkedReader {
            data: response,
            reads: std::collections::VecDeque::from([8_000, 8_000]),
            offset: 0,
        };
        let parsed = read_response(&mut stream).unwrap();
        assert_eq!(parsed.status, 429);
        assert_eq!(parsed.retry_after, Some(6));
        assert_eq!(parsed.body, body.as_bytes());
    }

    /// A reader that serves its bytes, then fails every read — the
    /// stand-in for a peer's unclean close (a TLS truncation alert)
    /// behind the last response byte.
    struct FailingTailReader {
        data: Vec<u8>,
        offset: usize,
    }

    impl Read for FailingTailReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let size = (self.data.len() - self.offset).min(buf.len());
            if size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "closed without close_notify",
                ));
            }
            buf[..size].copy_from_slice(&self.data[self.offset..self.offset + size]);
            self.offset += size;
            Ok(size)
        }
    }

    #[test]
    fn a_complete_content_length_body_never_waits_for_the_close() {
        // The declared frame ends the read: an unclean close behind
        // the last body byte cannot shadow a response that arrived
        // whole.
        let body = "{\"ok\":true,\"result\":[]}";
        let response = format!(
            "HTTP/1.1 200 X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = FailingTailReader {
            data: response.into_bytes(),
            offset: 0,
        };
        let parsed = read_response(&mut stream).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, body.as_bytes());
    }

    #[test]
    fn a_complete_chunked_body_never_waits_for_the_close() {
        let body = "{\"ok\":true,\"result\":[]}";
        let response = format!(
            "HTTP/1.1 200 X\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        let mut stream = FailingTailReader {
            data: response.into_bytes(),
            offset: 0,
        };
        let parsed = read_response(&mut stream).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, body.as_bytes());
    }

    #[test]
    fn a_short_body_at_clean_eof_is_truncation_not_a_body() {
        // Content-Length declares 40; the connection closes cleanly
        // after 11. A successful send's answer must not read as the
        // shorter slice — the outcome stays unknown rather than
        // evaluated on a partial body.
        let mut stream = ChunkedReader {
            data: b"HTTP/1.1 200 X\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"ok\":true}".to_vec(),
            reads: std::collections::VecDeque::new(),
            offset: 0,
        };
        let error = read_response(&mut stream).err().unwrap();
        assert_eq!(error.code, "a4mc_telegram_read_failed");
    }

    #[test]
    fn an_unterminated_chunked_body_at_eof_is_truncation() {
        // The chunk data completed but the terminal 0-chunk never
        // arrived: the frame is incomplete even at a clean close.
        let mut stream = ChunkedReader {
            data: b"HTTP/1.1 200 X\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n".to_vec(),
            reads: std::collections::VecDeque::new(),
            offset: 0,
        };
        let error = read_response(&mut stream).err().unwrap();
        assert_eq!(error.code, "a4mc_telegram_read_failed");
    }
}
