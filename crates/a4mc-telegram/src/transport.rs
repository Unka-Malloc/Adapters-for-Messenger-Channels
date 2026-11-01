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
use std::io::Read;
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
}

impl TelegramApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retry_after: None,
        }
    }

    /// Attach the platform's `retry_after` hint to a throttled failure.
    pub fn with_retry_after(mut self, retry_after: Option<u64>) -> Self {
        self.retry_after = retry_after;
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
        a4mc::ChannelError::new(error.code, error.message)
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
    /// under `reply_to_message_id`. Returns the platform message ids in
    /// send order, one per transmitted part.
    fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to_message_id: Option<i64>,
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
    ) -> Result<Vec<i64>, TelegramApiError> {
        (**self).send_message(chat_id, text, reply_to_message_id)
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

/// Live ureq-backed Bot API client.
pub struct LiveBotTransport {
    api_root: String,
    token: Zeroizing<String>,
    agent: ureq::Agent,
}

impl LiveBotTransport {
    pub fn new(token: impl Into<String>, api_root: Option<&str>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(90))
            .build();
        Self {
            api_root: api_root
                .unwrap_or(DEFAULT_API_ROOT)
                .trim_end_matches('/')
                .to_owned(),
            token: Zeroizing::new(token.into()),
            agent,
        }
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.api_root, self.token.as_str(), method)
    }

    fn call_json(&self, method: &str, body: Value) -> Result<Value, TelegramApiError> {
        let url = self.method_url(method);
        let response = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|error| map_transport_error(method, error))?;
        let status = response.status();
        let mut buffer = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| {
                TelegramApiError::new("a4mc_telegram_read_failed", "Bot API response read failed")
            })?;
        if buffer.len() > MAX_RESPONSE_BYTES {
            return Err(TelegramApiError::new(
                "a4mc_telegram_response_too_large",
                "Bot API response exceeded bound",
            ));
        }
        let value: Value = serde_json::from_slice(&buffer).map_err(|_| {
            TelegramApiError::new(
                "a4mc_telegram_json_invalid",
                "Bot API response was not valid JSON",
            )
        })?;
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
            let retry_after = value
                .pointer("/parameters/retry_after")
                .and_then(Value::as_u64);
            let code = if status == 429 || value["error_code"].as_i64() == Some(429) {
                "a4mc_telegram_throttled"
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
    ) -> Result<Vec<i64>, TelegramApiError> {
        let chunks = bounded_send_parts(text)?;
        let mut sent_ids = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
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
            let result = self.call_json("sendMessage", body)?;
            sent_ids.push(result["message_id"].as_i64().unwrap_or_default());
        }
        Ok(sent_ids)
    }
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
    Ok(LiveBotTransport::new(token.to_owned(), api_root))
}

/// The platform's wait hint on a throttled response: the `Retry-After`
/// header first, then a bounded peek at the error body's
/// `parameters.retry_after` (never more than a few kilobytes are read).
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
        .pointer("/parameters/retry_after")?
        .as_u64()
}

fn map_transport_error(method: &str, error: ureq::Error) -> TelegramApiError {
    match error {
        ureq::Error::Status(401, _) => TelegramApiError::new(
            "a4mc_telegram_unauthorized",
            format!("{method}: unauthorized"),
        ),
        ureq::Error::Status(409, _) => TelegramApiError::new(
            "a4mc_telegram_conflict",
            "getUpdates conflict: another poller is using this bot token",
        ),
        ureq::Error::Status(429, response) => TelegramApiError::new(
            "a4mc_telegram_throttled",
            format!("{method}: Bot API rate limited"),
        )
        .with_retry_after(retry_after_hint(response)),
        ureq::Error::Status(code, _) => {
            TelegramApiError::new("a4mc_telegram_api_failed", format!("{method}: HTTP {code}"))
        }
        ureq::Error::Transport(_) => TelegramApiError::new(
            "a4mc_telegram_network_failed",
            format!("{method}: transport failure"),
        ),
    }
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

/// Chunk size for one `sendMessage` post: inside the platform's
/// ~4096-char limit, applied on bytes so multi-byte text never
/// overflows a post.
const TELEGRAM_TEXT_CHUNK: usize = 4000;

/// Per-chat send budget: the most `sendMessage` posts one logical send
/// may fan out to. Sized to admit the worst-case UTF-8 expansion of the
/// contract's `MAX_OUTBOUND_TEXT_CHARS` — a contract-valid text always
/// fits unless pathological newline fragmentation would explode it
/// into more posts than the contract maximum can physically need; that
/// runaway is rejected before the first post, never partially posted.
const MAX_SEND_PARTS: usize = a4mc::MAX_OUTBOUND_TEXT_CHARS * 4 / TELEGRAM_TEXT_CHUNK + 1;

/// Bound one outbound text for the wire. Text above the contract's
/// `MAX_OUTBOUND_TEXT_CHARS` is rejected instead of fanning out into an
/// unbounded post sequence; what remains is chunked at the platform
/// limit inside the per-chat part budget.
fn bounded_send_parts(text: &str) -> Result<Vec<&str>, TelegramApiError> {
    if text.chars().count() > a4mc::MAX_OUTBOUND_TEXT_CHARS {
        return Err(TelegramApiError::new(
            "a4mc_telegram_text_too_large",
            "outbound text exceeded bound",
        ));
    }
    let chunks = chunk_telegram_text(text, TELEGRAM_TEXT_CHUNK);
    if chunks.len() > MAX_SEND_PARTS {
        return Err(TelegramApiError::new(
            "a4mc_telegram_part_budget_exceeded",
            "outbound text exceeded the per-chat send part budget",
        ));
    }
    Ok(chunks)
}

pub fn chunk_telegram_text(text: &str, limit: usize) -> Vec<&str> {
    if text.is_empty() {
        return vec![""];
    }
    let mut chunks = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if rest.len() <= limit {
            chunks.push(rest);
            break;
        }
        let mut end = limit;
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(split) = rest[..end].rfind('\n')
            && split > limit / 4
        {
            end = split + 1;
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
    ) -> Result<Vec<i64>, TelegramApiError> {
        self.sent.lock().unwrap().push((chat_id, text.to_owned()));
        Ok(vec![self.next_message_id.fetch_add(1, Ordering::SeqCst)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_once(
        status: u16,
        content_type: &'static str,
        body: &'static str,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Consume the full request (headers plus declared body) so the
            // close below never resets an in-flight client write.
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
                "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (port, handle)
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
    fn send_parts_reject_pathological_newline_fan_out() {
        // Multi-byte text with newlines past the split floor fragments
        // a contract-valid character count into more posts than the
        // part budget allows: the send is refused wholesale rather than
        // partially posted.
        let unit = format!("{}\n", "😀".repeat(275)); // 276 chars, 1101 bytes
        let fragmented = unit.repeat(118); // 32568 chars — inside the bound
        let raw = chunk_telegram_text(&fragmented, TELEGRAM_TEXT_CHUNK);
        assert!(raw.len() > MAX_SEND_PARTS);
        let error = bounded_send_parts(&fragmented).unwrap_err();
        assert_eq!(error.code, "a4mc_telegram_part_budget_exceeded");
    }

    #[test]
    fn http_error_never_leaks_token_or_body() {
        let fixture_ref = ["synthetic", "telegram", "credential"].join("-");
        let body = "{\"description\":\"leak-CANARY_BODY-leak\"}";
        let (port, handle) = serve_once(500, "application/json", body);
        let transport =
            LiveBotTransport::new(&fixture_ref, Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_api_failed");
        assert!(!error.message.contains(fixture_ref.as_str()));
        assert!(!error.message.contains("CANARY_BODY"));
        assert!(!error.message.contains("127.0.0.1"));
    }

    #[test]
    fn api_failure_description_is_not_forwarded() {
        let body = "{\"ok\":false,\"description\":\"CANARY_BODY description\"}";
        let (port, handle) = serve_once(200, "application/json", body);
        let transport = LiveBotTransport::new("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_api_failed");
        assert!(!error.message.contains("CANARY_BODY"));
    }

    #[test]
    fn invalid_json_error_is_sanitized() {
        let body = "CANARY_BODY not json";
        let (port, handle) = serve_once(200, "application/json", body);
        let transport = LiveBotTransport::new("token", Some(&format!("http://127.0.0.1:{port}")));
        let error = transport.get_updates(0, 1).unwrap_err();
        handle.join().unwrap();
        assert_eq!(error.code, "a4mc_telegram_json_invalid");
        assert!(!error.message.contains("CANARY_BODY"));
    }
}
