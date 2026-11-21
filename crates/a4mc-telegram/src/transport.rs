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
    /// for failures outside a multi-part send.
    pub send_progress: Option<SendProgress>,
}

/// Where a chunked `sendMessage` send stopped, kept by the idempotency
/// owner so a retry resumes instead of blindly reposting confirmed parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
        self.send_progress = Some(progress);
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
    /// order. A mid-flight failure carries the updated progress on the
    /// error so the caller can resume or refuse to retry.
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
        resume: Option<&SendProgress>,
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
    ) -> Result<Vec<i64>, TelegramApiError> {
        (**self).send_message(chat_id, text, reply_to_message_id, resume)
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
        .ok_or_else(failed)?;
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
            return Err(failed());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name =
            rustls::pki_types::ServerName::try_from(endpoint.host.clone()).map_err(|_| failed())?;
        let conn =
            rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|_| failed())?;
        let mut stream = rustls::StreamOwned::new(conn, stream);
        write_request(&mut stream)?;
        read_response(&mut stream)
    } else {
        let mut stream = stream;
        write_request(&mut stream)?;
        read_response(&mut stream)
    }
}

/// Read one close-delimited response: status line, the headers that
/// matter (`Retry-After`, `Transfer-Encoding`) and the decoded body,
/// bounded the whole way.
fn read_response(stream: &mut dyn Read) -> Result<HttpResponse, TelegramApiError> {
    let failed =
        || TelegramApiError::new("a4mc_telegram_read_failed", "Bot API response read failed");
    let cap = MAX_HEAD_BYTES + MAX_RESPONSE_BYTES + 1;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if raw.len() > cap {
                    return Err(TelegramApiError::new(
                        "a4mc_telegram_response_too_large",
                        "Bot API response exceeded bound",
                    ));
                }
            }
            Err(_) => return Err(failed()),
        }
    }
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(failed)?;
    if head_end > MAX_HEAD_BYTES {
        return Err(failed());
    }
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(failed)?;
    let mut retry_after = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "retry-after" {
                retry_after = value.parse::<u64>().ok();
            } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }
    let body = if chunked {
        decode_chunked(&raw[head_end..]).ok_or_else(failed)?
    } else {
        raw[head_end..].to_vec()
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(TelegramApiError::new(
            "a4mc_telegram_response_too_large",
            "Bot API response exceeded bound",
        ));
    }
    Ok(HttpResponse {
        status,
        retry_after,
        body,
    })
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
            return Some(body);
        }
        if rest.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&rest[..size]);
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
    ) -> Result<Vec<i64>, TelegramApiError> {
        let chunks = bounded_send_parts(text)?;
        let start = resume.map_or(0, |progress| progress.next_part);
        if start > chunks.len() {
            return Err(TelegramApiError::new(
                "a4mc_telegram_resume_invalid",
                "send resume position is outside the chunked text",
            ));
        }
        let mut sent_ids = Vec::with_capacity(chunks.len() - start);
        for (index, chunk) in chunks.iter().enumerate().skip(start) {
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
                Ok(result) => sent_ids.push(result["message_id"].as_i64().unwrap_or_default()),
                Err(error) => {
                    let confirmed = resume
                        .map(|progress| progress.confirmed.clone())
                        .unwrap_or_default();
                    let outcome_unknown = result_is_unknown(&error);
                    return Err(error.with_send_progress(SendProgress {
                        confirmed: confirmed.into_iter().chain(sent_ids).collect(),
                        next_part: index,
                        outcome_unknown,
                    }));
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
        let mut sent_ids = Vec::with_capacity(parts.len() - start);
        for (index, part) in parts.iter().enumerate().skip(start) {
            if let Some((at, error, unknown)) = self.fail_send_at_part.as_ref()
                && *at == index
                && self.fired_parts.lock().unwrap().insert(index)
            {
                let confirmed = resume
                    .map(|progress| progress.confirmed.clone())
                    .unwrap_or_default();
                return Err(error.clone().with_send_progress(SendProgress {
                    confirmed: confirmed.into_iter().chain(sent_ids).collect(),
                    next_part: index,
                    outcome_unknown: *unknown,
                }));
            }
            self.sent
                .lock()
                .unwrap()
                .push((chat_id, (*part).to_owned()));
            sent_ids.push(self.next_message_id.fetch_add(1, Ordering::SeqCst));
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
            .send_message(42, &markdown, Some(7), None)
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
        let error = transport.send_message(42, "hello", None, None).unwrap_err();
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
}
