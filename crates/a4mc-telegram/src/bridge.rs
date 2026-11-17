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
use std::collections::HashMap;
use std::sync::{Condvar, LazyLock, Mutex};
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

/// The Telegram channel offers every agent whose inventory declares a
/// runnable conversation driver and a detected local executable. A lane
/// that cannot actually carry a turn surfaces its real error on the send
/// that tries it; verification evidence is never admission and never a
/// channel-facing label.
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
    let driver = item
        .pointer("/adapterCapabilities/conversationDriver")
        .or_else(|| item.get("conversationDriver"))
        .and_then(Value::as_str)
        .unwrap_or("unsupported");
    // A driver declared non-conversational cannot carry a turn at all; a
    // runnable one is offered whatever its evidence state says.
    if matches!(driver, "unsupported" | "blocked" | "history-only") {
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
    Some(AgentSummary { id, label })
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

/// A completed or in-flight turn. A duplicate caller from the same chat
/// waits for the in-flight dispatch and then reuses its reply, so a
/// redelivered update cannot pay for a second lane dispatch.
struct TurnGate {
    done: bool,
    waiters: usize,
    result: Option<TurnResult>,
}

type TurnResult = Result<(String, String), BridgeError>;

/// One table of joinable turns. The lane dispatch is synchronous and
/// uninterruptible; this gate makes duplicate callers share its result
/// instead of starting a second paid dispatch over the same turn.
static TURN_GATES: LazyLock<Mutex<HashMap<String, TurnGate>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TURN_WAKE: Condvar = Condvar::new();

enum TurnJoin {
    Leader(TurnPermit),
    Follower(TurnResult),
}

struct TurnPermit {
    key: String,
}

impl TurnPermit {
    fn acquire(key: String) -> TurnJoin {
        let mut gates = TURN_GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut waited = false;
        loop {
            match gates.get_mut(&key) {
                None => {
                    gates.insert(
                        key.clone(),
                        TurnGate {
                            done: false,
                            waiters: 0,
                            result: None,
                        },
                    );
                    return TurnJoin::Leader(Self { key });
                }
                Some(gate) if gate.done => {
                    let result = gate
                        .result
                        .clone()
                        .expect("a completed turn has a stored result");
                    if waited {
                        gate.waiters = gate.waiters.saturating_sub(1);
                        if gate.waiters == 0 {
                            gates.remove(&key);
                        }
                    }
                    TURN_WAKE.notify_all();
                    return TurnJoin::Follower(result);
                }
                Some(gate) => {
                    if !waited {
                        gate.waiters += 1;
                        waited = true;
                    }
                    gates = TURN_WAKE
                        .wait(gates)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
        }
    }

    /// Publish the turn's result to every waiter, then wake them.
    fn finish(self, result: &TurnResult) {
        let mut gates = TURN_GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(gate) = gates.get_mut(&self.key) {
            gate.done = true;
            gate.result = Some(result.clone());
            if gate.waiters == 0 {
                gates.remove(&self.key);
            }
        }
        drop(gates);
        TURN_WAKE.notify_all();
    }
}

impl Drop for TurnPermit {
    fn drop(&mut self) {
        // Reached only when the leader unwinds before finish: release
        // waiters with a bounded error instead of parking them forever.
        let mut gates = TURN_GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(gate) = gates.get_mut(&self.key)
            && !gate.done
        {
            gate.done = true;
            gate.result = Some(Err(BridgeError::new(
                "a4mc_telegram_send_failed",
                "conversation lane turn aborted",
            )));
            if gate.waiters == 0 {
                gates.remove(&self.key);
            }
        }
        drop(gates);
        TURN_WAKE.notify_all();
    }
}

fn turn_key(chat_id: i64, agent_id: &str, session_id: Option<&str>, text: &str) -> String {
    format!(
        "{chat_id}\u{1f}{agent_id}\u{1f}{}\u{1f}{text}",
        session_id.filter(|value| !value.is_empty()).unwrap_or("")
    )
}

/// Run one agent turn and wait for the lane to finish it.
///
/// The lane call is synchronous: the caller keeps waiting until the lane
/// returns, so no dispatch outlives this call and a caller cannot retry
/// while the original turn still runs. `deadline` is forwarded as
/// `timeoutMs` — bounding a turn is the lane's responsibility, not a
/// local elapsed-time cutoff that abandons viable agent work.
///
/// `chat_id` scopes the in-flight turn table. A redelivered update from
/// the same chat joins the running turn and reuses its reply; two
/// different chats never share a dispatch or a reply even when they
/// address the same agent with the same text.
pub fn send_turn(
    chat_id: i64,
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
    let permit = match TurnPermit::acquire(turn_key(chat_id, agent_id, session_id, text)) {
        TurnJoin::Follower(result) => return result,
        TurnJoin::Leader(permit) => permit,
    };
    let result = (|| -> TurnResult {
        let result = (port.dispatch)("send", &params).map_err(|_| {
            BridgeError::new("a4mc_telegram_send_failed", "conversation lane send failed")
        })?;
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
    })();
    permit.finish(&result);
    result
}

pub fn format_agent_list(agents: &[AgentSummary]) -> String {
    if agents.is_empty() {
        return "No local agents with a conversation driver and a detected \
             executable.\n\
             Install or configure an agent with the host application first, \
             then retry /agent."
            .to_owned();
    }
    let mut lines = vec!["Local agents:".to_owned()];
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
            "agent `{agent_id}` is not available for Telegram. \
             Only local agents with a conversation driver and a detected \
             executable can be bound. Use /agent to list available agents."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use a4mc::ChannelError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    static SLOW_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static SLOW_FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static DISPATCH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ACTIVE_DISPATCHES: AtomicUsize = AtomicUsize::new(0);
    static MAX_ACTIVE_DISPATCHES: AtomicUsize = AtomicUsize::new(0);
    static LAST_TIMEOUT_MS: AtomicUsize = AtomicUsize::new(0);
    static OVERLAP_ENTERED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static OVERLAP_RELEASE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    fn scan() -> Result<Value, ChannelError> {
        Ok(json!({"candidates": []}))
    }

    fn conversations(_: &Value) -> Result<Value, ChannelError> {
        Ok(json!({"sessions": []}))
    }

    fn open(_: &Value) -> Result<Value, ChannelError> {
        Ok(json!({"sessionId": "sess-1"}))
    }

    fn fixture_dispatch(_: &str, params: &Value) -> Result<Value, ChannelError> {
        LAST_TIMEOUT_MS.store(
            params
                .get("timeoutMs")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
            Ordering::SeqCst,
        );
        Ok(json!({
            "ok": true,
            "output": "agent reply",
            "sessionId": "sess-1"
        }))
    }

    fn slow_dispatch(_: &str, _: &Value) -> Result<Value, ChannelError> {
        SLOW_ENTERED.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(150));
        SLOW_FINISHED.store(true, Ordering::SeqCst);
        Ok(json!({
            "ok": true,
            "output": "slow agent reply",
            "sessionId": "sess-slow"
        }))
    }

    fn overlap_dispatch(_: &str, _: &Value) -> Result<Value, ChannelError> {
        DISPATCH_CALLS.fetch_add(1, Ordering::SeqCst);
        let active = ACTIVE_DISPATCHES.fetch_add(1, Ordering::SeqCst) + 1;
        MAX_ACTIVE_DISPATCHES.fetch_max(active, Ordering::SeqCst);
        OVERLAP_ENTERED.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !OVERLAP_RELEASE.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        ACTIVE_DISPATCHES.fetch_sub(1, Ordering::SeqCst);
        Ok(json!({
            "ok": true,
            "output": "overlap fixture reply",
            "sessionId": "sess-overlap"
        }))
    }

    static REPLY_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    /// Answers every dispatch with a distinct reply so a test can tell
    /// whether two callers shared one paid lane call.
    fn sequence_dispatch(_: &str, _: &Value) -> Result<Value, ChannelError> {
        let sequence = REPLY_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
        thread::sleep(Duration::from_millis(120));
        Ok(json!({
            "ok": true,
            "output": format!("reply {sequence}"),
            "sessionId": format!("sess-{sequence}")
        }))
    }

    fn install_lane(
        dispatch: fn(&str, &Value) -> Result<Value, ChannelError>,
    ) -> Result<(), &'static str> {
        lane::clear();
        lane::install(lane::LanePort {
            scan_targets: scan,
            conversation_list: conversations,
            open_or_resume: open,
            dispatch,
        })
    }

    #[test]
    fn admits_agents_with_a_runnable_driver_and_executable() {
        let unverified = json!({
            "target": "cursor",
            "label": "Cursor",
            "binaryPath": "/Applications/Cursor.app",
            "adapterCapabilities": {
                "conversationDriver": "implemented",
                "conversationReadiness": "unverified"
            }
        });
        let admitted = agent_summary_if_channel_admissible(&unverified).unwrap();
        assert_eq!(admitted.id, "cursor");

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

        let blocked = json!({
            "target": "antigravity",
            "label": "Antigravity",
            "binaryPath": "/fixture-root/bin/antigravity",
            "adapterCapabilities": {
                "conversationDriver": "blocked",
                "conversationReadiness": "unverified"
            }
        });
        assert!(agent_summary_if_channel_admissible(&blocked).is_none());

        let ready_no_binary = json!({
            "target": "codex",
            "label": "Codex",
            "adapterCapabilities": {
                "conversationDriver": "implemented",
                "conversationReadiness": "ready"
            }
        });
        assert!(agent_summary_if_channel_admissible(&ready_no_binary).is_none());

        let ready = json!({
            "target": "codex",
            "label": "Codex",
            "binaryPath": "/fixture-root/bin/codex",
            "adapterCapabilities": {
                "conversationDriver": "implemented",
                "conversationReadiness": "ready"
            }
        });
        let admitted = agent_summary_if_channel_admissible(&ready).unwrap();
        assert_eq!(admitted.id, "codex");
    }

    #[test]
    fn admits_without_a_readiness_field_on_the_scan_item() {
        let item = json!({
            "target": "cursor",
            "label": "Cursor",
            "binaryPath": "/Applications/Cursor.app",
            "adapterCapabilities": {
                "conversationDriver": "implemented"
            }
        });
        let admitted = agent_summary_if_channel_admissible(&item).unwrap();
        assert_eq!(admitted.id, "cursor");
    }

    #[test]
    fn empty_agent_list_explains_runnable_driver_requirement() {
        let text = format_agent_list(&[]);
        assert!(text.contains("No local agents"));
        assert!(text.contains("conversation driver"));
    }

    #[test]
    fn send_turn_forward_success_and_deadline_as_timeout() {
        let _guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_lane(fixture_dispatch).unwrap();
        let (output, session) =
            send_turn(42, "codex", Some("sess-1"), "hello", Duration::from_secs(5)).unwrap();
        lane::clear();

        assert_eq!(output, "agent reply");
        assert_eq!(session, "sess-1");
        assert_eq!(
            LAST_TIMEOUT_MS.load(Ordering::SeqCst),
            5_000,
            "the caller deadline must be forwarded as timeoutMs"
        );
    }

    #[test]
    fn send_turn_waits_past_a_local_deadline_instead_of_abandoning_work() {
        let _guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        SLOW_ENTERED.store(false, Ordering::SeqCst);
        SLOW_FINISHED.store(false, Ordering::SeqCst);
        install_lane(slow_dispatch).unwrap();

        let started = Instant::now();
        let (output, session) = send_turn(
            42,
            "codex",
            Some("sess-slow"),
            "long running turn",
            Duration::from_millis(1),
        )
        .unwrap();
        let elapsed = started.elapsed();
        lane::clear();

        assert!(SLOW_ENTERED.load(Ordering::SeqCst));
        assert!(SLOW_FINISHED.load(Ordering::SeqCst));
        assert!(
            elapsed >= Duration::from_millis(100),
            "bridge returned before the dispatch finished: {elapsed:?}"
        );
        assert_eq!(output, "slow agent reply");
        assert_eq!(session, "sess-slow");
    }

    #[test]
    fn duplicate_turn_waits_instead_of_dispatching_concurrently() {
        let _guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        MAX_ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        DISPATCH_CALLS.store(0, Ordering::SeqCst);
        OVERLAP_ENTERED.store(false, Ordering::SeqCst);
        OVERLAP_RELEASE.store(false, Ordering::SeqCst);
        install_lane(overlap_dispatch).unwrap();

        let first = thread::spawn(|| {
            send_turn(
                42,
                "codex",
                Some("sess-overlap"),
                "same turn",
                Duration::from_secs(5),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !OVERLAP_ENTERED.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "first dispatch never started");
            thread::sleep(Duration::from_millis(2));
        }

        let second = thread::spawn(|| {
            send_turn(
                42,
                "codex",
                Some("sess-overlap"),
                "same turn",
                Duration::from_secs(5),
            )
        });
        thread::sleep(Duration::from_millis(40));
        // The first dispatch cannot finish until the fixture is released,
        // so a caller that returned here did not wait for it.
        let second_finished_while_first_active = second.is_finished();
        OVERLAP_RELEASE.store(true, Ordering::SeqCst);

        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        lane::clear();

        assert!(
            !second_finished_while_first_active,
            "a duplicate caller returned while the original dispatch was active"
        );
        assert_eq!(first.0, "overlap fixture reply");
        assert_eq!(
            second.0, "overlap fixture reply",
            "the duplicate caller must reuse the in-flight turn's reply"
        );
        assert_eq!(MAX_ACTIVE_DISPATCHES.load(Ordering::SeqCst), 1);
        assert_eq!(
            DISPATCH_CALLS.load(Ordering::SeqCst),
            1,
            "a duplicate caller must not start a second paid dispatch"
        );
    }

    #[test]
    fn different_chats_never_share_a_turn_dispatch() {
        let _guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        REPLY_SEQUENCE.store(0, Ordering::SeqCst);
        install_lane(sequence_dispatch).unwrap();

        let first = thread::spawn(|| send_turn(1, "codex", None, "hello", Duration::from_secs(5)));
        let second = thread::spawn(|| send_turn(2, "codex", None, "hello", Duration::from_secs(5)));
        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();
        lane::clear();

        assert_eq!(
            REPLY_SEQUENCE.load(Ordering::SeqCst),
            2,
            "two chats must not share one paid lane dispatch"
        );
        assert_ne!(
            first, second,
            "a reply and its returned session belong to exactly one chat"
        );
    }

    #[test]
    fn without_a_lane_port_calls_fail_closed() {
        let _guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lane::clear();
        assert_eq!(
            send_turn(42, "codex", None, "hello", Duration::from_millis(10))
                .unwrap_err()
                .code,
            "a4mc_telegram_lane_unavailable"
        );
    }
}
