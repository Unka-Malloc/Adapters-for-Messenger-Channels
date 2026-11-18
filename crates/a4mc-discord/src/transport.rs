//! Discord REST transport and host-custody credential resolution.
//!
//! The transport speaks Discord's HTTP API on one side and sanitized,
//! bounded errors on the other. The bot token resolves through the
//! host-installed [`a4mc::custody`] port under [`crate::CHANNEL`]; the
//! crate never reads keychains, files or environment itself. Tokens move
//! into an [`a4mc::SecretToken`], which has no `Serialize` and a redacted
//! `Debug`; request failures never echo the token, a request/response
//! body, or a Gateway URL.
//!
//! Discord calls the Gateway's websocket side `Gateway`; the REST side is
//! used for identity and message sends. Gateway framing lives in
//! [`crate::gateway`].

use a4mc::{ChannelError, ChannelId, SecretToken};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// The channel identifier and custody lookup key for Discord.
pub const CHANNEL: &str = "discord";
/// Discord REST API root (v10).
pub const DEFAULT_API_ROOT: &str = "https://discord.com/api/v10";

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 512;

/// One bounded, sanitized Discord API failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscordApiError {
    pub code: String,
    pub message: String,
    /// Discord's `retry_after` hint in whole seconds, when throttled.
    /// `None` on every other failure.
    pub retry_after: Option<u64>,
}

impl DiscordApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn with_retry_after(mut self, retry_after: Option<u64>) -> Self {
        self.retry_after = retry_after;
        self
    }
}

impl fmt::Display for DiscordApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DiscordApiError {}

impl From<DiscordApiError> for ChannelError {
    fn from(error: DiscordApiError) -> Self {
        ChannelError::new(error.code, error.message)
    }
}

/// A Discord bot token sourced from host custody.
///
/// `SecretToken` keeps this redacted in `Debug` and forbids `Serialize`;
/// the value is exposed only at the transport edge that consumes it.
#[derive(Debug)]
pub struct DiscordToken {
    token: SecretToken,
}

impl DiscordToken {
    /// Validate and wrap a token the host already resolved.
    pub fn new(token: SecretToken) -> Result<Self, DiscordApiError> {
        let value = token.expose_utf8().map_err(|_| {
            DiscordApiError::new("a4mc_discord_token_invalid", "Discord token is not UTF-8")
        })?;
        if value.trim().is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || !value.is_ascii()
            || value
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(DiscordApiError::new(
                "a4mc_discord_token_invalid",
                "Discord token failed its shape check",
            ));
        }
        Ok(Self { token })
    }

    /// Resolve the bot token through the installed custody port.
    pub fn from_custody() -> Result<Self, DiscordApiError> {
        let port = a4mc::custody::require().map_err(|error| {
            DiscordApiError::new("a4mc_discord_custody_unavailable", error.to_string())
        })?;
        let token = port
            .channel_token(&ChannelId::from(CHANNEL))
            .map_err(|error| {
                DiscordApiError::new("a4mc_discord_custody_failed", error.to_string())
            })?
            .ok_or_else(|| {
                DiscordApiError::new(
                    "a4mc_discord_bot_token_missing",
                    "custody holds no Discord bot token",
                )
            })?;
        Self::new(token)
    }

    pub fn token(&self) -> &SecretToken {
        &self.token
    }
}

/// The bot identity `GET /users/@me` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscordIdentity {
    pub id: String,
    pub username: String,
    pub global_name: Option<String>,
    pub bot: bool,
}

/// One `POST /channels/{channel_id}/messages` request after contract
/// validation and lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostMessageRequest {
    pub channel_id: String,
    pub content: String,
    /// Discord threads a reply by referencing the parent message id.
    pub reply_to_message_id: Option<String>,
    /// Deterministic Discord-shaped nonce derived from the contract
    /// idempotency key. Discord bounds a nonce to 25 characters.
    pub nonce: String,
}

/// One accepted message create response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostedMessage {
    pub channel_id: String,
    pub id: String,
}

/// The Discord REST surface the dialect needs.
pub trait DiscordApi: Send + Sync {
    fn current_user(&self) -> Result<DiscordIdentity, DiscordApiError>;
    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, DiscordApiError>;
}

impl<T: DiscordApi + ?Sized> DiscordApi for Arc<T> {
    fn current_user(&self) -> Result<DiscordIdentity, DiscordApiError> {
        (**self).current_user()
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, DiscordApiError> {
        (**self).post_message(request)
    }
}

/// Authorities credentialed REST requests may target: the provider's
/// documented API domain family only.
const APPROVED_API_AUTHORITIES: &[&str] = &["discord.com", "discord.gg"];

fn api_root_refused() -> DiscordApiError {
    DiscordApiError::new(
        "a4mc_discord_api_root_refused",
        "Discord REST API root is outside the approved endpoint policy",
    )
}

/// Validate a configured REST API root for credentialed live requests:
/// HTTPS only — plaintext can never carry the token — on the provider's
/// own authority family. Plaintext loopback fixtures go through the
/// test-only construction path; redirects are never followed, so the
/// policy holds for every byte that leaves the process.
fn validate_api_root(root: &str) -> Result<String, DiscordApiError> {
    let rest = root
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .ok_or_else(api_root_refused)?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(api_root_refused());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            port.parse::<u16>().map_err(|_| api_root_refused())?;
            host
        }
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let approved = APPROVED_API_AUTHORITIES
        .iter()
        .any(|authority| host == *authority || host.ends_with(&format!(".{authority}")));
    if host.is_empty() || !approved {
        return Err(api_root_refused());
    }
    Ok(format!("https://{rest}"))
}

/// Live ureq-backed Discord REST client.
pub struct LiveDiscordApi {
    api_root: String,
    token: DiscordToken,
    agent: ureq::Agent,
}

impl LiveDiscordApi {
    /// Build the live client after validating `api_root` against the
    /// credentialed endpoint policy (`https://` on the provider's
    /// authority family). `None` keeps the default [`DEFAULT_API_ROOT`].
    /// The agent never follows redirects, so the validated endpoint is
    /// the only authority a credentialed request can reach.
    pub fn new(token: DiscordToken, api_root: Option<&str>) -> Result<Self, DiscordApiError> {
        Ok(Self {
            api_root: validate_api_root(api_root.unwrap_or(DEFAULT_API_ROOT))?,
            token,
            agent: Self::agent(),
        })
    }

    /// Test-only construction for plaintext loopback fixtures: skips the
    /// endpoint policy so `http://127.0.0.1:{port}` responders can stand
    /// in for the API. Only exists under `cfg(test)` — no production
    /// build can ever select this path.
    #[cfg(test)]
    fn new_for_test(token: DiscordToken, api_root: Option<&str>) -> Self {
        Self {
            api_root: api_root
                .unwrap_or(DEFAULT_API_ROOT)
                .trim_end_matches('/')
                .to_owned(),
            token,
            agent: Self::agent(),
        }
    }

    /// One agent configuration for every construction path: bounded
    /// timeouts and redirects disabled, so a credentialed request can
    /// never be steered onto an authority the endpoint policy refused.
    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .redirects(0)
            .build()
    }

    /// Resolve the bot token through the installed custody port and
    /// build the live client.
    pub fn from_custody(api_root: Option<&str>) -> Result<Self, DiscordApiError> {
        Self::new(DiscordToken::from_custody()?, api_root)
    }

    /// The custody-resolved token, for composing the Gateway loop with
    /// the same client.
    pub fn token(&self) -> &DiscordToken {
        &self.token
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, DiscordApiError> {
        let token = self.token.token.expose_utf8().map_err(|_| {
            DiscordApiError::new("a4mc_discord_token_invalid", "Discord token is not UTF-8")
        })?;
        let authorization = Zeroizing::new(format!("Bot {token}"));
        let request = self
            .agent
            .request(method, &format!("{}/{path}", self.api_root))
            .set("Authorization", authorization.as_str())
            .set("User-Agent", "DiscordBot (https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels, 0.1.0)");
        let response = match body {
            Some(body) => request
                .set("Content-Type", "application/json; charset=utf-8")
                .send_json(body)
                .map_err(|error| map_transport_error(path, error)),
            None => request
                .call()
                .map_err(|error| map_transport_error(path, error)),
        }?;
        let status = response.status();
        let mut buffer = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| {
                DiscordApiError::new(
                    "a4mc_discord_read_failed",
                    format!("{path}: response read failed"),
                )
            })?;
        if buffer.len() > MAX_RESPONSE_BYTES {
            return Err(DiscordApiError::new(
                "a4mc_discord_response_too_large",
                format!("{path}: response exceeded bound"),
            ));
        }
        let value: Value = serde_json::from_slice(&buffer).map_err(|_| {
            DiscordApiError::new(
                "a4mc_discord_json_invalid",
                format!("{path}: response was not valid JSON"),
            )
        })?;
        if status == 401 || status == 403 {
            return Err(DiscordApiError::new(
                "a4mc_discord_unauthorized",
                format!("{path}: Discord rejected the token"),
            ));
        }
        if !(200..300).contains(&status) {
            return Err(DiscordApiError::new(
                "a4mc_discord_api_failed",
                format!("{path}: Discord API returned HTTP {status}"),
            ));
        }
        Ok(value)
    }
}

impl DiscordApi for LiveDiscordApi {
    fn current_user(&self) -> Result<DiscordIdentity, DiscordApiError> {
        let value = self.call("GET", "users/@me", None)?;
        let required = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    DiscordApiError::new(
                        "a4mc_discord_identity_invalid",
                        "users/@me omitted the bot identity",
                    )
                })
        };
        Ok(DiscordIdentity {
            id: required("id")?,
            username: required("username")?,
            global_name: value
                .get("global_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            bot: value.get("bot").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, DiscordApiError> {
        let mut body = json!({
            "content": request.content,
            "nonce": request.nonce,
            "enforce_nonce": true,
            "allowed_mentions": { "parse": [] },
        });
        if let Some(reply_to) = request.reply_to_message_id.as_deref() {
            body["message_reference"] = json!({
                "message_id": reply_to,
                "fail_if_not_exists": false,
            });
        }
        let path = format!("channels/{}/messages", request.channel_id);
        let value = self.call("POST", &path, Some(&body))?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                DiscordApiError::new(
                    "a4mc_discord_message_id_missing",
                    "message create omitted the message id",
                )
            })?;
        let channel_id = value
            .get("channel_id")
            .and_then(Value::as_str)
            .unwrap_or(&request.channel_id)
            .to_owned();
        Ok(PostedMessage { channel_id, id })
    }
}

/// Resolve host custody and build the live Discord REST client.
pub fn live_api(api_root: Option<&str>) -> Result<LiveDiscordApi, DiscordApiError> {
    LiveDiscordApi::from_custody(api_root)
}

fn retry_after_hint(response: ureq::Response) -> Option<u64> {
    let mut body = String::new();
    response
        .into_reader()
        .take(8 * 1024)
        .read_to_string(&mut body)
        .ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    value
        .get("retry_after")
        .and_then(Value::as_f64)
        .map(|seconds| seconds.ceil().max(0.0) as u64)
}

fn map_transport_error(path: &str, error: ureq::Error) -> DiscordApiError {
    match error {
        ureq::Error::Status(401 | 403, _) => DiscordApiError::new(
            "a4mc_discord_unauthorized",
            format!("{path}: Discord rejected the token"),
        ),
        ureq::Error::Status(404, _) => DiscordApiError::new(
            "a4mc_discord_not_found",
            format!("{path}: Discord resource not found"),
        ),
        ureq::Error::Status(429, response) => DiscordApiError::new(
            "a4mc_discord_throttled",
            format!("{path}: Discord API rate limited"),
        )
        .with_retry_after(retry_after_hint(response)),
        ureq::Error::Status(status, _) => {
            DiscordApiError::new("a4mc_discord_api_failed", format!("{path}: HTTP {status}"))
        }
        ureq::Error::Transport(_) => DiscordApiError::new(
            "a4mc_discord_network_failed",
            format!("{path}: transport failure"),
        ),
    }
}

/// In-memory Discord REST fixture for tests and host-side composition
/// checks. No network, no secrets.
#[derive(Debug)]
pub struct MockDiscordApi {
    pub identity: DiscordIdentity,
    pub posted: Mutex<Vec<PostMessageRequest>>,
    pub user_error: Mutex<Option<DiscordApiError>>,
    pub post_error: Mutex<Option<DiscordApiError>>,
    next_id: AtomicU64,
}

impl Default for MockDiscordApi {
    fn default() -> Self {
        Self {
            identity: DiscordIdentity {
                id: "U_FIXTURE".into(),
                username: "a4mc".into(),
                global_name: Some("A4MC Fixture".into()),
                bot: true,
            },
            posted: Mutex::new(Vec::new()),
            user_error: Mutex::new(None),
            post_error: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

impl MockDiscordApi {
    pub fn posted_requests(&self) -> Vec<PostMessageRequest> {
        self.posted.lock().unwrap().clone()
    }
}

impl DiscordApi for MockDiscordApi {
    fn current_user(&self) -> Result<DiscordIdentity, DiscordApiError> {
        if let Some(error) = self.user_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.identity.clone())
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, DiscordApiError> {
        if let Some(error) = self.post_error.lock().unwrap().clone() {
            return Err(error);
        }
        self.posted.lock().unwrap().push(request.clone());
        let next = self.next_id.fetch_add(1, Ordering::SeqCst);
        Ok(PostedMessage {
            channel_id: request.channel_id.clone(),
            id: format!("900000000000000{next:02}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex as StdMutex;

    /// Custody is process-wide; serialize tests that install it.
    static CUSTODY_LOCK: StdMutex<()> = StdMutex::new(());

    fn secret(value: &str) -> SecretToken {
        SecretToken::try_from_string(value.into()).unwrap()
    }

    fn token(value: &str) -> DiscordToken {
        DiscordToken::new(secret(value)).unwrap()
    }

    /// Test credential material is minted per run; no static token
    /// literal is committed.
    fn fixture_token() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
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

    fn serve_once(status: u16, body: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 2048];
            let header_end = loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    return;
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
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse().ok())
                })
                .unwrap_or(0);
            while request.len() < header_end + body_len {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (port, handle)
    }

    /// Answer the first request with a 302 pointing at `location`.
    fn serve_redirect(location: &str) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let location = location.to_owned();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (port, handle)
    }

    /// A listener that reports through the channel if any connection —
    /// e.g. a followed redirect carrying the Authorization header —
    /// ever reaches it.
    fn recording_listener() -> (u16, std::sync::mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if listener.accept().is_ok() {
                let _ = tx.send(());
            }
        });
        (port, rx)
    }

    #[test]
    fn resolves_token_through_custody_channel_key() {
        let _guard = CUSTODY_LOCK.lock().unwrap();
        a4mc::custody::clear();

        let fixture = fixture_token();
        struct FixtureCustody {
            token: String,
        }
        impl a4mc::CustodyPort for FixtureCustody {
            fn channel_token(
                &self,
                channel: &ChannelId,
            ) -> Result<Option<SecretToken>, ChannelError> {
                match channel.as_str() {
                    crate::CHANNEL => Ok(Some(
                        SecretToken::try_from_string(self.token.clone()).unwrap(),
                    )),
                    _ => Ok(None),
                }
            }
        }

        let port: Arc<dyn a4mc::CustodyPort> = Arc::new(FixtureCustody {
            token: fixture.clone(),
        });
        a4mc::custody::install(Arc::clone(&port)).unwrap();
        let resolved = DiscordToken::from_custody().unwrap();
        assert_eq!(resolved.token().expose_utf8().unwrap(), fixture);
        a4mc::custody::clear();
    }

    #[test]
    fn custody_without_a_token_fails_closed() {
        let _guard = CUSTODY_LOCK.lock().unwrap();
        a4mc::custody::clear();
        assert_eq!(
            DiscordToken::from_custody().unwrap_err().code,
            "a4mc_discord_custody_unavailable"
        );
    }

    #[test]
    fn token_debug_is_redacted_and_shape_is_bounded() {
        let value = fixture_token();
        let debug = format!("{:?}", token(&value));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(value.as_str()));
        assert_eq!(
            DiscordToken::new(secret(" ")).unwrap_err().code,
            "a4mc_discord_token_invalid"
        );
        assert_eq!(
            DiscordToken::new(secret(&"a".repeat(MAX_TOKEN_BYTES + 1)))
                .unwrap_err()
                .code,
            "a4mc_discord_token_invalid"
        );
    }

    #[test]
    fn current_user_maps_identity_fields() {
        let body = "{\"id\":\"U1\",\"username\":\"bot\",\"global_name\":\"Bot Name\",\"bot\":true}";
        let (port, handle) = serve_once(200, body);
        let api = LiveDiscordApi::new_for_test(
            token(&fixture_token()),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let identity = api.current_user().unwrap();
        handle.join().unwrap();
        assert_eq!(identity.id, "U1");
        assert_eq!(identity.username, "bot");
        assert_eq!(identity.global_name.as_deref(), Some("Bot Name"));
        assert!(identity.bot);
    }

    #[test]
    fn credentialed_requests_refuse_roots_outside_the_policy() {
        for root in [
            "http://discord.com/api/v10",
            "https://example.com/api",
            "https://discord.com.evil.example/api",
            "wss://discord.com/api",
            "https://token@discord.com/api",
            "https://discord.com:abc/api",
        ] {
            assert_eq!(
                LiveDiscordApi::new(token(&fixture_token()), Some(root))
                    .err()
                    .unwrap()
                    .code,
                "a4mc_discord_api_root_refused",
                "{root} was not refused"
            );
        }
        LiveDiscordApi::new(token(&fixture_token()), None).unwrap();
        LiveDiscordApi::new(token(&fixture_token()), Some("https://discord.com/api/v10")).unwrap();
        LiveDiscordApi::new(
            token(&fixture_token()),
            Some("https://canary.discord.com/api/"),
        )
        .unwrap();
        LiveDiscordApi::new(token(&fixture_token()), Some("https://discord.gg/api")).unwrap();
        LiveDiscordApi::new(
            token(&fixture_token()),
            Some("https://discord.com:8443/api"),
        )
        .unwrap();
    }

    #[test]
    fn redirects_are_never_followed_so_authorization_stays_put() {
        let (target_port, seen) = recording_listener();
        let (port, handle) = serve_redirect(&format!("http://127.0.0.1:{target_port}/"));
        let api = LiveDiscordApi::new_for_test(
            token(&fixture_token()),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.current_user().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_discord_api_failed");
        assert!(
            seen.recv_timeout(Duration::from_millis(500)).is_err(),
            "a redirect moved a credentialed request to another authority"
        );
    }

    #[test]
    fn post_message_maps_reply_and_nonce() {
        let body = "{\"id\":\"M1\",\"channel_id\":\"C1\"}";
        let (port, handle) = serve_once(200, body);
        let api = LiveDiscordApi::new_for_test(
            token(&fixture_token()),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let posted = api
            .post_message(&PostMessageRequest {
                channel_id: "C1".into(),
                content: "hello".into(),
                reply_to_message_id: Some("M0".into()),
                nonce: "nonce-1".into(),
            })
            .unwrap();
        handle.join().unwrap();
        assert_eq!(posted.id, "M1");
        assert_eq!(posted.channel_id, "C1");
    }

    #[test]
    fn http_error_never_leaks_token_or_body() {
        let token_value = fixture_token();
        let body = "{\"message\":\"CANARY_BODY\",\"code\":50035}";
        let (port, handle) = serve_once(400, body);
        let api = LiveDiscordApi::new_for_test(
            token(&token_value),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.current_user().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_discord_api_failed");
        assert!(!error.message.contains(token_value.as_str()));
        assert!(!error.message.contains("CANARY_BODY"));
        assert!(!error.message.contains("127.0.0.1"));
    }

    #[test]
    fn unauthorized_maps_to_bounded_code() {
        let body = "{\"message\":\"401: Unauthorized\",\"code\":0}";
        let (port, handle) = serve_once(401, body);
        let api = LiveDiscordApi::new_for_test(
            token(&fixture_token()),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.current_user().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_discord_unauthorized");
        assert!(!error.message.contains("Unauthorized"));
    }
}
