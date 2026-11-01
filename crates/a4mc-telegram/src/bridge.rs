//! Bridge Telegram turns into the local conversation lane.
//!
//! The composing host installs lane access through `a4mc::lane`;
//! without it the channel fails closed instead of reaching for host
//! internals. The port's answer shape is the lane contract:
//! `scan_targets` returns `{candidates: [...]}`, `conversation_list`
//! returns `{sessions: [...]}`, `open_or_resume` and `dispatch` return
//! the opened session and turn result.

use a4mc::lane;
use anyhow::Result;
use serde_json::{Value, json};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
}

impl BridgeError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BridgeError {}

/// The composing host installs conversation access; without it the channel
/// fails closed instead of reaching for host internals.
fn lane_port() -> Result<lane::LanePort, BridgeError> {
    lane::require()
        .map_err(|error| BridgeError::new("a4mc_telegram_lane_unavailable", error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSummary {
    pub id: String,
    pub label: String,
    pub readiness: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
}

pub fn list_agents() -> Result<Vec<AgentSummary>, BridgeError> {
    let scanned = (lane_port()?.scan_targets)()
        .map_err(|error| BridgeError::new("a4mc_telegram_targets_failed", error.to_string()))?;
    let mut agents = Vec::new();
    if let Some(items) = scanned.get("candidates").and_then(Value::as_array) {
        for item in items {
            if let Some(agent) = agent_summary_if_channel_admissible(item) {
                agents.push(agent);
            }
        }
    }
    agents.sort_by(|left, right| left.id.cmp(&right.id));
    agents.dedup_by(|left, right| left.id == right.id);
    Ok(agents)
}

/// The Telegram channel only offers agents that already passed
/// conversation readiness (`ready`) and declare a detected local
/// executable. Unverified / history-only inventory stays out of the
/// picker — discovery is not admission.
fn agent_summary_if_channel_admissible(item: &Value) -> Option<AgentSummary> {
    let id = item
        .get("target")
        .or_else(|| item.get("id"))
        .or_else(|| item.get("agentId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if id.is_empty() {
        return None;
    }
    let readiness = item
        .pointer("/adapterCapabilities/conversationReadiness")
        .or_else(|| item.get("conversationReadiness"))
        .and_then(Value::as_str)
        .unwrap_or("unverified");
    if readiness != "ready" {
        return None;
    }
    let driver = item
        .pointer("/adapterCapabilities/conversationDriver")
        .or_else(|| item.get("conversationDriver"))
        .and_then(Value::as_str)
        .unwrap_or("unsupported");
    if driver == "unsupported" {
        return None;
    }
    item.get("binaryPath")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let label = item
        .get("label")
        .or_else(|| item.get("displayName"))
        .and_then(Value::as_str)
        .unwrap_or(&id)
        .to_owned();
    Some(AgentSummary {
        id,
        label,
        readiness: readiness.to_owned(),
    })
}

pub fn list_sessions(agent_id: &str) -> Result<Vec<SessionSummary>, BridgeError> {
    let listed = (lane_port()?.conversation_list)(&json!({
        "agent": agent_id,
        "scanMode": "browse",
        "limit": 20,
    }))
    .map_err(|error| BridgeError::new("a4mc_telegram_sessions_failed", error.to_string()))?;
    let mut sessions = Vec::new();
    if let Some(items) = listed.get("sessions").and_then(Value::as_array) {
        for item in items {
            let id = item
                .get("sessionId")
                .or_else(|| item.get("id"))
                .or_else(|| item.get("nativeSessionId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if id.is_empty() {
                continue;
            }
            let title = item
                .get("title")
                .or_else(|| item.get("summary"))
                .or_else(|| item.get("label"))
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_owned();
            sessions.push(SessionSummary { id, title });
        }
    }
    Ok(sessions)
}

pub fn open_session(agent_id: &str, session_id: Option<&str>) -> Result<String, BridgeError> {
    let mut params = json!({ "agent": agent_id });
    if let Some(session_id) = session_id.filter(|value| !value.is_empty()) {
        params["sessionId"] = json!(session_id);
    }
    let opened = (lane_port()?.open_or_resume)(&params)
        .map_err(|error| BridgeError::new("a4mc_telegram_open_failed", error.to_string()))?;
    let resolved = opened
        .get("sessionId")
        .or_else(|| opened.get("nativeSessionId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(resolved)
}

/// Run one agent turn within `deadline`. The lane call is
/// uninterruptible once entered, so it runs on its own thread: on
/// expiry the worker abandons the call — the detached thread finishes
/// into a dropped receiver or dies with the lane — and the user gets a
/// bounded timeout reply instead of a worker pinned forever. The same
/// deadline is forwarded as `timeoutMs` so a cooperative lane bounds
/// itself before the hard cutoff.
pub fn send_turn(
    agent_id: &str,
    session_id: Option<&str>,
    text: &str,
    deadline: Duration,
) -> Result<(String, String), BridgeError> {
    let mut params = json!({
        "agent": agent_id,
        "text": text,
        "timeoutMs": u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
    });
    if let Some(session_id) = session_id.filter(|value| !value.is_empty()) {
        params["sessionId"] = json!(session_id);
    }
    let port = lane_port()?;
    let (done_tx, done_rx) = mpsc::channel();
    thread::Builder::new()
        .name("a4mc-telegram-turn".into())
        .spawn(move || {
            let _ = done_tx.send((port.dispatch)("send", &params));
        })
        .map_err(|_| BridgeError::new("a4mc_telegram_send_failed", "turn worker spawn failed"))?;
    let result = match done_rx.recv_timeout(deadline) {
        Ok(result) => result.map_err(|_| {
            BridgeError::new("a4mc_telegram_send_failed", "conversation lane send failed")
        })?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(BridgeError::new(
                "a4mc_telegram_turn_timeout",
                "agent turn exceeded the configured deadline",
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(BridgeError::new(
                "a4mc_telegram_send_failed",
                "conversation lane send failed",
            ));
        }
    };
    if result.get("ok").and_then(Value::as_bool) == Some(false) {
        let code = result
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("");
        let message = result
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("agent turn failed");
        let detail = if code.is_empty() {
            message.to_owned()
        } else {
            format!("{code}: {message}")
        };
        return Err(BridgeError::new("a4mc_telegram_send_failed", detail));
    }
    let output = result
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    let next_session = result
        .get("sessionId")
        .or_else(|| result.get("nativeSessionId"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .or_else(|| session_id.map(str::to_owned))
        .unwrap_or_default();
    if output.is_empty() {
        return Err(BridgeError::new(
            "a4mc_telegram_empty_reply",
            "agent returned no text",
        ));
    }
    Ok((output, next_session))
}

pub fn format_agent_list(agents: &[AgentSummary]) -> String {
    if agents.is_empty() {
        return "No verified local agents.\n\
             Telegram only lists agents with conversation readiness ready \
             and a detected executable.\n\
             Verify an agent with the host application first, then retry /agent."
            .to_owned();
    }
    let mut lines = vec!["Verified local agents:".to_owned()];
    for agent in agents {
        lines.push(format!("- {} ({})", agent.id, agent.label));
    }
    lines.push("Bind with /agent <id>".to_owned());
    lines.join("\n")
}

pub fn format_session_list(sessions: &[SessionSummary]) -> String {
    if sessions.is_empty() {
        return "No conversations found. Use /new to start one.".to_owned();
    }
    let mut lines = vec!["Conversations:".to_owned()];
    for (index, session) in sessions.iter().enumerate() {
        lines.push(format!(
            "{}. {} — {}",
            index + 1,
            session.id,
            truncate(&session.title, 80)
        ));
    }
    lines.push("Bind with /session <id|index>".to_owned());
    lines.join("\n")
}

pub fn resolve_session_selector<'a>(
    sessions: &'a [SessionSummary],
    selector: &str,
) -> Result<&'a SessionSummary, BridgeError> {
    if let Ok(index) = selector.parse::<usize>()
        && index >= 1
        && index <= sessions.len()
    {
        return Ok(&sessions[index - 1]);
    }
    sessions
        .iter()
        .find(|session| session.id == selector)
        .ok_or_else(|| {
            BridgeError::new(
                "a4mc_telegram_session_not_found",
                format!("session not found: {selector}"),
            )
        })
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        let trimmed: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{trimmed}…")
    }
}

pub fn ensure_known_agent(agent_id: &str) -> Result<(), BridgeError> {
    let agents = list_agents()?;
    if agents.iter().any(|agent| agent.id == agent_id) {
        return Ok(());
    }
    Err(BridgeError::new(
        "a4mc_telegram_agent_not_admitted",
        format!(
            "agent `{agent_id}` is not admitted for Telegram. \
             Only verified (ready) local agents with a detected executable can be bound. \
             Use /agent to list admitted agents."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_ready_detected_agents() {
        let unverified = json!({
            "target": "cursor",
            "label": "Cursor",
            "binaryPath": "/Applications/Cursor.app",
            "adapterCapabilities": {
                "conversationDriver": "native",
                "conversationReadiness": "unverified"
            }
        });
        assert!(agent_summary_if_channel_admissible(&unverified).is_none());

        let history_only = json!({
            "target": "code",
            "label": "VS Code",
            "binaryPath": "/usr/bin/code",
            "adapterCapabilities": {
                "conversationDriver": "history-only",
                "conversationReadiness": "history-only"
            }
        });
        assert!(agent_summary_if_channel_admissible(&history_only).is_none());

        let ready_no_binary = json!({
            "target": "codex",
            "label": "Codex",
            "adapterCapabilities": {
                "conversationDriver": "native",
                "conversationReadiness": "ready"
            }
        });
        assert!(agent_summary_if_channel_admissible(&ready_no_binary).is_none());

        let ready = json!({
            "target": "codex",
            "label": "Codex",
            "binaryPath": "/fixture-root/bin/codex",
            "adapterCapabilities": {
                "conversationDriver": "native",
                "conversationReadiness": "ready"
            }
        });
        let admitted = agent_summary_if_channel_admissible(&ready).unwrap();
        assert_eq!(admitted.id, "codex");
        assert_eq!(admitted.readiness, "ready");
    }

    #[test]
    fn empty_agent_list_explains_verification_gate() {
        let text = format_agent_list(&[]);
        assert!(text.contains("No verified local agents"));
        assert!(text.contains("conversation readiness ready"));
    }
}
