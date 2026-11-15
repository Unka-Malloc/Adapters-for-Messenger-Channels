//! Slack Web API transport and host-custody credential resolution.
//!
//! The transport speaks Slack's HTTP Web API on one side and sanitized
//! bounded errors on the other. Two credentials are involved and both
//! resolve through the host-installed [`a4mc::custody`] port:
//!
//! * the **app-level token** (Socket Mode `connections:write`) is
//!   requested for the custody channel [`crate::APP_TOKEN_CHANNEL`];
//! * the **bot token** is requested for [`crate::CHANNEL`].
//!
//! The crate never reads keychains, files or environment for either
//! token. Tokens are moved into [`a4mc::SecretToken`], which has no
//! `Serialize` and a redacted `Debug`; request failures never echo the
//! token, a request/response body, or a Socket Mode URL (whose ticket is
//! itself a capability).

use a4mc::{ChannelError, ChannelId, SecretToken};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub const DEFAULT_API_ROOT: &str = "https://slack.com/api";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_SLACK_ERROR_CHARS: usize = 64;

/// One bounded, sanitized Slack API or Socket Mode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackApiError {
    pub code: String,
    pub message: String,
    /// Slack's `Retry-After` hint in seconds, when the call was
    /// throttled. `None` on every other failure.
    pub retry_after: Option<u64>,
}

impl SlackApiError {
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

impl fmt::Display for SlackApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SlackApiError {}

impl From<SlackApiError> for ChannelError {
    fn from(error: SlackApiError) -> Self {
        ChannelError::new(error.code, error.message)
    }
}

/// The two Slack credentials the dialect needs, both sourced from host
/// custody. Debug is redacted by `SecretToken`; neither token is ever
/// serialized.
#[derive(Debug)]
pub struct SlackTokens {
    app: SecretToken,
    bot: SecretToken,
}

impl SlackTokens {
    /// Validate and assemble the two tokens a host already resolved.
    pub fn new(app: SecretToken, bot: SecretToken) -> Result<Self, SlackApiError> {
        validate_token(&app, "app-level")?;
        validate_token(&bot, "bot")?;
        Ok(Self { app, bot })
    }

    /// Resolve both tokens through the installed custody port.
    ///
    /// The host answers [`crate::APP_TOKEN_CHANNEL`] with the app-level
    /// Socket Mode token and [`crate::CHANNEL`] with the bot token. Two
    /// lookup keys are used because Slack issues two independently
    /// scoped credentials; the dialect never guesses one from the other.
    pub fn from_custody() -> Result<Self, SlackApiError> {
        let port = a4mc::custody::require().map_err(|error| {
            SlackApiError::new("a4mc_slack_custody_unavailable", error.to_string())
        })?;
        let app = port
            .channel_token(&ChannelId::from(crate::APP_TOKEN_CHANNEL))
            .map_err(|error| SlackApiError::new("a4mc_slack_custody_failed", error.to_string()))?
            .ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_app_token_missing",
                    "custody holds no Slack app-level token",
                )
            })?;
        let bot = port
            .channel_token(&ChannelId::from(crate::CHANNEL))
            .map_err(|error| SlackApiError::new("a4mc_slack_custody_failed", error.to_string()))?
            .ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_bot_token_missing",
                    "custody holds no Slack bot token",
                )
            })?;
        Self::new(app, bot)
    }

    pub fn app_token(&self) -> &SecretToken {
        &self.app
    }

    pub fn bot_token(&self) -> &SecretToken {
        &self.bot
    }
}

/// Shape check for a custody-provided Slack credential: nonempty,
/// bounded, ASCII, no whitespace or control bytes. Token prefixes are
/// deliberately not required here — Slack treats tokens as opaque
/// values and rejects a wrong scope at the API call, where the failure
/// is sanitized.
fn validate_token(token: &SecretToken, kind: &str) -> Result<(), SlackApiError> {
    let value = token
        .expose_utf8()
        .map_err(|_| SlackApiError::new("a4mc_slack_token_invalid", "Slack token is not UTF-8"))?;
    if value.trim().is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value.is_ascii()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(SlackApiError::new(
            "a4mc_slack_token_invalid",
            format!("{kind} Slack token failed its shape check"),
        ));
    }
    Ok(())
}

/// A one-time Socket Mode URL. Its query carries a connection ticket, so
/// `Debug` is redacted and the value is never serialized.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SocketUrl(String);

impl SocketUrl {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the URL to a connector. The URL is a short-lived
    /// capability: never log it or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SocketUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SocketUrl([redacted])")
    }
}

/// The bot identity `auth.test` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlackIdentity {
    pub team_id: String,
    pub team: Option<String>,
    pub user_id: String,
    pub user: Option<String>,
    pub bot_id: Option<String>,
    pub enterprise_install: bool,
}

/// One `chat.postMessage` request after contract validation and lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostMessageRequest {
    pub channel: String,
    pub text: String,
    /// Slack threads a reply under the parent message's `ts`.
    pub thread_ts: Option<String>,
    /// Deterministic Slack-shaped client id derived from the contract
    /// idempotency key.
    pub client_msg_id: String,
}

/// One accepted `chat.postMessage` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostedMessage {
    pub channel: String,
    pub ts: String,
}

/// The Slack Web API surface the dialect needs.
pub trait SlackApi: Send + Sync {
    fn auth_test(&self) -> Result<SlackIdentity, SlackApiError>;
    /// Ask Slack for a fresh Socket Mode URL. Each call yields a
    /// short-lived, single-use connection ticket.
    fn open_socket(&self) -> Result<SocketUrl, SlackApiError>;
    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, SlackApiError>;
}

impl<T: SlackApi + ?Sized> SlackApi for Arc<T> {
    fn auth_test(&self) -> Result<SlackIdentity, SlackApiError> {
        (**self).auth_test()
    }

    fn open_socket(&self) -> Result<SocketUrl, SlackApiError> {
        (**self).open_socket()
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, SlackApiError> {
        (**self).post_message(request)
    }
}

/// Live ureq-backed Slack Web API client.
pub struct LiveSlackApi {
    api_root: String,
    tokens: SlackTokens,
    agent: ureq::Agent,
}

impl LiveSlackApi {
    pub fn new(tokens: SlackTokens, api_root: Option<&str>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(60))
            .build();
        Self {
            api_root: api_root
                .unwrap_or(DEFAULT_API_ROOT)
                .trim_end_matches('/')
                .to_owned(),
            tokens,
            agent,
        }
    }

    /// Resolve both credentials through the installed custody port and
    /// build the live client.
    pub fn from_custody(api_root: Option<&str>) -> Result<Self, SlackApiError> {
        Ok(Self::new(SlackTokens::from_custody()?, api_root))
    }

    fn call(&self, method: &str, token: &SecretToken, body: Value) -> Result<Value, SlackApiError> {
        let token = token.expose_utf8().map_err(|_| {
            SlackApiError::new("a4mc_slack_token_invalid", "Slack token is not UTF-8")
        })?;
        let authorization = Zeroizing::new(format!("Bearer {token}"));
        let response = self
            .agent
            .post(&format!("{}/{method}", self.api_root))
            .set("Authorization", authorization.as_str())
            .set("Content-Type", "application/json; charset=utf-8")
            .send_json(body)
            .map_err(|error| map_transport_error(method, error))?;
        let status = response.status();
        let mut buffer = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| {
                SlackApiError::new(
                    "a4mc_slack_read_failed",
                    format!("{method}: response read failed"),
                )
            })?;
        if buffer.len() > MAX_RESPONSE_BYTES {
            return Err(SlackApiError::new(
                "a4mc_slack_response_too_large",
                format!("{method}: response exceeded bound"),
            ));
        }
        let value: Value = serde_json::from_slice(&buffer).map_err(|_| {
            SlackApiError::new(
                "a4mc_slack_json_invalid",
                format!("{method}: response was not valid JSON"),
            )
        })?;
        if status == 401 || value.get("error").and_then(Value::as_str) == Some("invalid_auth") {
            return Err(SlackApiError::new(
                "a4mc_slack_unauthorized",
                format!("{method}: Slack rejected the token"),
            ));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let error = sanitize_slack_error(
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("api_failed"),
            );
            return Err(SlackApiError::new(
                format!("a4mc_slack_{error}"),
                format!("{method}: Slack API returned an error"),
            ));
        }
        Ok(value)
    }
}

impl SlackApi for LiveSlackApi {
    fn auth_test(&self) -> Result<SlackIdentity, SlackApiError> {
        let value = self.call("auth.test", self.tokens.bot_token(), json!({}))?;
        let required = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    SlackApiError::new(
                        "a4mc_slack_identity_invalid",
                        "auth.test omitted the bot identity",
                    )
                })
        };
        Ok(SlackIdentity {
            team_id: required("team_id")?,
            team: value.get("team").and_then(Value::as_str).map(str::to_owned),
            user_id: required("user_id")?,
            user: value.get("user").and_then(Value::as_str).map(str::to_owned),
            bot_id: value
                .get("bot_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            enterprise_install: value
                .get("is_enterprise_install")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    fn open_socket(&self) -> Result<SocketUrl, SlackApiError> {
        let value = self.call("apps.connections.open", self.tokens.app_token(), json!({}))?;
        let url = value
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_socket_url_missing",
                    "apps.connections.open omitted the socket URL",
                )
            })?;
        Ok(SocketUrl::new(url))
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, SlackApiError> {
        let mut body = json!({
            "channel": request.channel,
            "text": request.text,
            "client_msg_id": request.client_msg_id,
            "unfurl_links": false,
            "unfurl_media": false,
        });
        if let Some(thread_ts) = request.thread_ts.as_deref() {
            body["thread_ts"] = json!(thread_ts);
        }
        let value = self.call("chat.postMessage", self.tokens.bot_token(), body)?;
        let ts = value
            .get("ts")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                SlackApiError::new(
                    "a4mc_slack_message_ts_missing",
                    "chat.postMessage omitted the message timestamp",
                )
            })?;
        let channel = value
            .get("channel")
            .and_then(Value::as_str)
            .unwrap_or(&request.channel)
            .to_owned();
        Ok(PostedMessage { channel, ts })
    }
}

/// Resolve host custody and build the live Slack Web API client.
pub fn live_api(api_root: Option<&str>) -> Result<LiveSlackApi, SlackApiError> {
    LiveSlackApi::from_custody(api_root)
}

fn sanitize_slack_error(value: &str) -> String {
    let mut out: String = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .take(MAX_SLACK_ERROR_CHARS)
        .collect();
    if out.is_empty() {
        out.push_str("api_failed");
    }
    out
}

fn retry_after_hint(response: ureq::Response) -> Option<u64> {
    if let Some(secs) = response
        .header("retry-after")
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return Some(secs);
    }
    let mut body = String::new();
    response
        .into_reader()
        .take(8 * 1024)
        .read_to_string(&mut body)
        .ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()?
        .get("retry_after")?
        .as_u64()
}

fn map_transport_error(method: &str, error: ureq::Error) -> SlackApiError {
    match error {
        ureq::Error::Status(401, _) => {
            SlackApiError::new("a4mc_slack_unauthorized", format!("{method}: unauthorized"))
        }
        ureq::Error::Status(429, response) => SlackApiError::new(
            "a4mc_slack_throttled",
            format!("{method}: Slack API rate limited"),
        )
        .with_retry_after(retry_after_hint(response)),
        ureq::Error::Status(code, _) => {
            SlackApiError::new("a4mc_slack_api_failed", format!("{method}: HTTP {code}"))
        }
        ureq::Error::Transport(_) => SlackApiError::new(
            "a4mc_slack_network_failed",
            format!("{method}: transport failure"),
        ),
    }
}

/// In-memory Slack Web API fixture for tests and host-side composition
/// checks. No network, no secrets.
#[derive(Debug)]
pub struct MockSlackApi {
    pub identity: SlackIdentity,
    pub socket_url: Mutex<SocketUrl>,
    pub posted: Mutex<Vec<PostMessageRequest>>,
    pub auth_error: Mutex<Option<SlackApiError>>,
    pub open_error: Mutex<Option<SlackApiError>>,
    pub post_error: Mutex<Option<SlackApiError>>,
    next_ts: AtomicU64,
}

impl Default for MockSlackApi {
    fn default() -> Self {
        Self {
            identity: SlackIdentity {
                team_id: "T_FIXTURE".into(),
                team: Some("Fixture".into()),
                user_id: "U_FIXTURE".into(),
                user: Some("a4mc".into()),
                bot_id: Some("B_FIXTURE".into()),
                enterprise_install: false,
            },
            socket_url: Mutex::new(SocketUrl::new("ws://fixture.invalid/socket")),
            posted: Mutex::new(Vec::new()),
            auth_error: Mutex::new(None),
            open_error: Mutex::new(None),
            post_error: Mutex::new(None),
            next_ts: AtomicU64::new(1),
        }
    }
}

impl MockSlackApi {
    pub fn with_socket_url(socket_url: impl Into<String>) -> Self {
        let mock = Self::default();
        *mock.socket_url.lock().unwrap() = SocketUrl::new(socket_url);
        mock
    }

    pub fn posted_requests(&self) -> Vec<PostMessageRequest> {
        self.posted.lock().unwrap().clone()
    }
}

impl SlackApi for MockSlackApi {
    fn auth_test(&self) -> Result<SlackIdentity, SlackApiError> {
        if let Some(error) = self.auth_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.identity.clone())
    }

    fn open_socket(&self) -> Result<SocketUrl, SlackApiError> {
        if let Some(error) = self.open_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.socket_url.lock().unwrap().clone())
    }

    fn post_message(&self, request: &PostMessageRequest) -> Result<PostedMessage, SlackApiError> {
        if let Some(error) = self.post_error.lock().unwrap().clone() {
            return Err(error);
        }
        self.posted.lock().unwrap().push(request.clone());
        let next = self.next_ts.fetch_add(1, Ordering::SeqCst);
        Ok(PostedMessage {
            channel: request.channel.clone(),
            ts: format!("1700000000.{next:06}"),
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
                    line.strip_prefix("Content-Length:")
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

    #[test]
    fn resolves_both_tokens_through_custody_channel_keys() {
        let _guard = CUSTODY_LOCK.lock().unwrap();
        a4mc::custody::clear();

        struct FixtureCustody;
        impl a4mc::CustodyPort for FixtureCustody {
            fn channel_token(
                &self,
                channel: &ChannelId,
            ) -> Result<Option<SecretToken>, ChannelError> {
                match channel.as_str() {
                    crate::APP_TOKEN_CHANNEL => Ok(Some(
                        SecretToken::try_from_string("fixture-app-value".into()).unwrap(),
                    )),
                    crate::CHANNEL => Ok(Some(
                        SecretToken::try_from_string("fixture-bot-value".into()).unwrap(),
                    )),
                    _ => Ok(None),
                }
            }
        }

        let port: Arc<dyn a4mc::CustodyPort> = Arc::new(FixtureCustody);
        a4mc::custody::install(Arc::clone(&port)).unwrap();
        let tokens = SlackTokens::from_custody().unwrap();
        assert_eq!(
            tokens.app_token().expose_utf8().unwrap(),
            "fixture-app-value"
        );
        assert_eq!(
            tokens.bot_token().expose_utf8().unwrap(),
            "fixture-bot-value"
        );
        a4mc::custody::clear();
    }

    #[test]
    fn token_debug_is_redacted() {
        let tokens =
            SlackTokens::new(secret("fixture-app-value"), secret("fixture-bot-value")).unwrap();
        let debug = format!("{tokens:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("fixture-app-value"));
        assert!(!debug.contains("fixture-bot-value"));
    }

    #[test]
    fn token_shape_rejects_bounded_and_whitespace_values() {
        assert!(SlackTokens::new(secret("fixture-app"), secret("fixture-bot")).is_ok());
        assert_eq!(
            SlackTokens::new(secret(" "), secret("fixture-bot"))
                .unwrap_err()
                .code,
            "a4mc_slack_token_invalid"
        );
        assert_eq!(
            SlackTokens::new(
                secret(&"a".repeat(MAX_TOKEN_BYTES + 1)),
                secret("fixture-bot"),
            )
            .unwrap_err()
            .code,
            "a4mc_slack_token_invalid"
        );
        assert_eq!(
            SlackTokens::new(secret("fixture-app"), secret("fixture bot"))
                .unwrap_err()
                .code,
            "a4mc_slack_token_invalid"
        );
    }

    #[test]
    fn socket_url_debug_never_shows_the_ticket() {
        let url = SocketUrl::new("wss://fixture.invalid/link?ticket=CANARY_TICKET");
        let debug = format!("{url:?}");
        assert_eq!(debug, "SocketUrl([redacted])");
        assert!(!debug.contains("CANARY_TICKET"));
    }

    #[test]
    fn http_error_never_leaks_token_body_or_host() {
        let token_value = "fixture-slack-bot-value";
        let body = "{\"ok\":false,\"error\":\"CANARY_BODY\"}";
        let (port, handle) = serve_once(500, body);
        let api = LiveSlackApi::new(
            SlackTokens::new(secret("fixture-app-value"), secret(token_value)).unwrap(),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.auth_test().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_slack_api_failed");
        assert!(!error.message.contains(token_value));
        assert!(!error.message.contains("CANARY_BODY"));
        assert!(!error.message.contains("127.0.0.1"));
    }

    #[test]
    fn slack_error_identifier_is_sanitized_and_bounded() {
        assert_eq!(sanitize_slack_error("invalid_auth"), "invalid_auth");
        assert_eq!(
            sanitize_slack_error("bad/error with spaces"),
            "baderrorwithspaces"
        );
        assert_eq!(sanitize_slack_error("!!!"), "api_failed");
        assert!(
            sanitize_slack_error(&"x".repeat(MAX_SLACK_ERROR_CHARS + 10)).len()
                <= MAX_SLACK_ERROR_CHARS
        );
    }

    #[test]
    fn slack_api_error_maps_to_bounded_code() {
        let body = "{\"ok\":false,\"error\":\"channel_not_found\"}";
        let (port, handle) = serve_once(200, body);
        let api = LiveSlackApi::new(
            SlackTokens::new(secret("fixture-app-value"), secret("fixture-bot-value")).unwrap(),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.auth_test().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_slack_channel_not_found");
        assert!(!error.message.contains("channel_not_found"));
        assert!(!error.message.contains("127.0.0.1"));
    }

    #[test]
    fn invalid_auth_maps_to_unauthorized() {
        let body = "{\"ok\":false,\"error\":\"invalid_auth\"}";
        let (port, handle) = serve_once(200, body);
        let api = LiveSlackApi::new(
            SlackTokens::new(secret("fixture-app-value"), secret("fixture-bot-value")).unwrap(),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let error = api.auth_test().unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_slack_unauthorized");
        assert!(!error.message.contains("invalid_auth"));
    }

    #[test]
    fn auth_test_maps_identity_fields() {
        let body = "{\"ok\":true,\"team_id\":\"T1\",\"team\":\"Team\",\"user_id\":\"U1\",\"user\":\"bot\",\"bot_id\":\"B1\",\"is_enterprise_install\":true}";
        let (port, handle) = serve_once(200, body);
        let api = LiveSlackApi::new(
            SlackTokens::new(secret("fixture-app-value"), secret("fixture-bot-value")).unwrap(),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let identity = api.auth_test().unwrap();
        handle.join().unwrap();
        assert_eq!(identity.team_id, "T1");
        assert_eq!(identity.user_id, "U1");
        assert_eq!(identity.bot_id.as_deref(), Some("B1"));
        assert!(identity.enterprise_install);
    }

    #[test]
    fn post_message_maps_thread_and_client_id() {
        let body = "{\"ok\":true,\"channel\":\"C1\",\"ts\":\"1700000000.000100\"}";
        let (port, handle) = serve_once(200, body);
        let api = LiveSlackApi::new(
            SlackTokens::new(secret("fixture-app-value"), secret("fixture-bot-value")).unwrap(),
            Some(&format!("http://127.0.0.1:{port}")),
        );
        let posted = api
            .post_message(&PostMessageRequest {
                channel: "C1".into(),
                text: "hello".into(),
                thread_ts: Some("1700000000.000001".into()),
                client_msg_id: "client-1".into(),
            })
            .unwrap();
        handle.join().unwrap();
        assert_eq!(posted.ts, "1700000000.000100");
        assert_eq!(posted.channel, "C1");
    }
}
