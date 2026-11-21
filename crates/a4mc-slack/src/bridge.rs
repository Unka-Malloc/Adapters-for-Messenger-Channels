//! Bridge Slack turns into the local conversation lane.
//!
//! The composing host installs lane access through `a4mc::lane`; without
//! it every call fails closed instead of reaching for host internals.
//! The port's answer shape is the lane contract: `scan_targets` returns
//! `{candidates: [...]}`, `conversation_list` returns `{sessions: [...]}`,
//! `open_or_resume` opens one session, and `dispatch` runs a named lane
//! operation such as `send`.
//!
//! Admission remains host policy. This module only drops inventory that
//! declares no runnable conversation driver or no local executable, and
//! surfaces the lane's own error on the turn that tries it.

use a4mc::lane;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::Duration;

/// One bounded lane failure at the Slack boundary.
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

fn lane_port() -> Result<lane::LanePort, BridgeError> {
    lane::require()
        .map_err(|error| BridgeError::new("a4mc_slack_lane_unavailable", error.to_string()))
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

/// List the local agents a Slack channel may bind.
pub fn list_agents() -> Result<Vec<AgentSummary>, BridgeError> {
    let scanned = (lane_port()?.scan_targets)()
        .map_err(|error| BridgeError::new("a4mc_slack_targets_failed", error.to_string()))?;
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

/// A channel-admissible inventory item declares a runnable conversation
/// driver and a detected local executable. Evidence state is not an
/// admission signal here; a lane that cannot carry a turn reports that
/// on the turn itself.
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

/// List one bound agent's conversations.
pub fn list_sessions(agent_id: &str) -> Result<Vec<SessionSummary>, BridgeError> {
    let listed = (lane_port()?.conversation_list)(&json!({
        "agent": agent_id,
        "scanMode": "browse",
        "limit": 20,
    }))
    .map_err(|error| BridgeError::new("a4mc_slack_sessions_failed", error.to_string()))?;
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

/// Open or resume one conversation and return its session id.
pub fn open_session(agent_id: &str, session_id: Option<&str>) -> Result<String, BridgeError> {
    let mut params = json!({ "agent": agent_id });
    if let Some(session_id) = session_id.filter(|value| !value.is_empty()) {
        params["sessionId"] = json!(session_id);
    }
    let opened = (lane_port()?.open_or_resume)(&params)
        .map_err(|error| BridgeError::new("a4mc_slack_open_failed", error.to_string()))?;
    Ok(opened
        .get("sessionId")
        .or_else(|| opened.get("nativeSessionId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned())
}

/// Coalesces duplicate dispatches of the same platform event.
///
/// The lane dispatch is synchronous and uninterruptible, so returning a
/// local timeout used to leave the original dispatch alive while the
/// caller was free to retry it. Now a turn is keyed by its authorized
/// scope — agent and session — plus the platform's stable event id:
/// a genuinely redelivered event waits for the in-flight dispatch and
/// reuses its result instead of paying a second agent execution, while
/// a distinct event (even with identical text) dispatches on its own.
static TURN_GATE: LazyLock<Mutex<TurnGate>> = LazyLock::new(|| Mutex::new(TurnGate::new()));

/// Bound on finished results retained for late redeliveries; oldest
/// evict FIFO.
const TURN_RESULT_CACHE: usize = 256;

struct TurnGate {
    entries: HashMap<String, Arc<SharedTurn>>,
    /// Keys of retained finished entries, oldest first, for eviction.
    done_order: VecDeque<String>,
}

impl TurnGate {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            done_order: VecDeque::new(),
        }
    }
}

/// One dedupable turn's shared outcome: `Running` until the leader's
/// dispatch returns, then every waiter reuses the finished result.
struct SharedTurn {
    state: Mutex<TurnState>,
    wake: Condvar,
}

enum TurnState {
    Running,
    Finished(Result<(String, String), BridgeError>),
}

/// The caller's role for one turn: leader runs the lane dispatch,
/// waiter reuses its result.
enum TurnEntry {
    Leader {
        shared: Arc<SharedTurn>,
        /// `None` when the turn carries no event id: it is unique and
        /// leaves nothing to dedupe.
        key: Option<String>,
    },
    Waiter(Arc<SharedTurn>),
}

impl SharedTurn {
    fn new() -> Self {
        Self {
            state: Mutex::new(TurnState::Running),
            wake: Condvar::new(),
        }
    }

    /// Block until the leader's dispatch finishes, then reuse its
    /// result — a duplicate event never pays a second execution.
    fn wait_for_result(&self) -> Result<(String, String), BridgeError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match &*state {
                TurnState::Finished(result) => return result.clone(),
                TurnState::Running => {
                    state = self
                        .wake
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
        }
    }

    /// Publish the leader's result and wake every waiter. Successful
    /// results stay dedupable (bounded) so a slightly later redelivery
    /// still reuses them; a failure frees the key so the platform's
    /// retry gets a fresh dispatch.
    fn finish(&self, key: Option<String>, result: Result<(String, String), BridgeError>) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *state = TurnState::Finished(result.clone());
        }
        self.wake.notify_all();
        let Some(key) = key else { return };
        let mut gate = TURN_GATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if result.is_err() {
            gate.entries.remove(&key);
            return;
        }
        gate.done_order.push_back(key.clone());
        while gate.done_order.len() > TURN_RESULT_CACHE {
            if let Some(oldest) = gate.done_order.pop_front() {
                gate.entries.remove(&oldest);
            }
        }
    }
}

/// Reserve the turn for (agent, session, event): the first caller leads
/// and dispatches; later callers of the same event wait and reuse.
fn begin_turn(agent_id: &str, session_id: Option<&str>, event_id: Option<&str>) -> TurnEntry {
    let shared = || Arc::new(SharedTurn::new());
    let Some(event_id) = event_id.map(str::trim).filter(|value| !value.is_empty()) else {
        // No stable event id: nothing can prove this call duplicates
        // another, so it dispatches independently and never reuses.
        return TurnEntry::Leader {
            shared: shared(),
            key: None,
        };
    };
    let key = format!(
        "{agent_id}\u{1f}{}\u{1f}{event_id}",
        session_id.filter(|value| !value.is_empty()).unwrap_or("")
    );
    let mut gate = TURN_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(turn) = gate.entries.get(&key) {
        return TurnEntry::Waiter(Arc::clone(turn));
    }
    let turn = shared();
    gate.entries.insert(key.clone(), Arc::clone(&turn));
    TurnEntry::Leader {
        shared: turn,
        key: Some(key),
    }
}

/// Run one agent turn and wait for the lane to finish it.
///
/// The lane call is synchronous: the caller keeps waiting until the lane
/// returns, so no dispatch outlives this call and a caller cannot retry
/// while the original turn still runs. `deadline` is forwarded as
/// `timeoutMs` — bounding a turn is the lane's responsibility, not a
/// local elapsed-time cutoff that abandons viable agent work.
///
/// `event_id` is the platform's stable event or operation id (Slack's
/// `event_id`, or the envelope id when the payload lacks one). A caller
/// repeating the same event within its agent/session scope reuses the
/// first dispatch's result instead of paying a second execution; a
/// distinct event — even with identical text — always dispatches on
/// its own. `None` marks a unique turn that never reuses.
pub fn send_turn(
    agent_id: &str,
    session_id: Option<&str>,
    text: &str,
    deadline: Duration,
    event_id: Option<&str>,
) -> Result<(String, String), BridgeError> {
    let turn = match begin_turn(agent_id, session_id, event_id) {
        TurnEntry::Waiter(shared) => return shared.wait_for_result(),
        TurnEntry::Leader { shared, key } => (shared, key),
    };
    let result = send_turn_dispatch(agent_id, session_id, text, deadline);
    turn.0.finish(turn.1, result.clone());
    result
}

fn send_turn_dispatch(
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
    let result = (port.dispatch)("send", &params)
        .map_err(|_| BridgeError::new("a4mc_slack_send_failed", "conversation lane send failed"))?;
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
        return Err(BridgeError::new("a4mc_slack_send_failed", detail));
    }
    let output = result
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if output.is_empty() {
        return Err(BridgeError::new(
            "a4mc_slack_empty_reply",
            "agent returned no text",
        ));
    }
    let next_session = result
        .get("sessionId")
        .or_else(|| result.get("nativeSessionId"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .or_else(|| session_id.map(str::to_owned))
        .unwrap_or_default();
    Ok((output, next_session))
}

/// Fail closed when `agent_id` is not in the channel-admissible list.
pub fn ensure_known_agent(agent_id: &str) -> Result<(), BridgeError> {
    let agents = list_agents()?;
    if agents.iter().any(|agent| agent.id == agent_id) {
        return Ok(());
    }
    Err(BridgeError::new(
        "a4mc_slack_agent_not_admitted",
        format!(
            "agent `{agent_id}` is not available for Slack. Use the host \
             application to configure an agent with a conversation driver \
             and a detected executable."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use a4mc::ChannelError;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    /// The lane port is process-wide; serialize tests that install it.
    static LANE_LOCK: Mutex<()> = Mutex::new(());
    static LAST_DISPATCH: Mutex<Option<Value>> = Mutex::new(None);
    static SLOW_ENTERED: AtomicBool = AtomicBool::new(false);
    static SLOW_FINISHED: AtomicBool = AtomicBool::new(false);
    static ACTIVE_DISPATCHES: AtomicUsize = AtomicUsize::new(0);
    static MAX_ACTIVE_DISPATCHES: AtomicUsize = AtomicUsize::new(0);
    static DISPATCH_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn scan() -> Result<Value, ChannelError> {
        Ok(json!({
            "candidates": [
                {
                    "target": "cursor",
                    "label": "Cursor",
                    "binaryPath": "/fixture-root/bin/cursor",
                    "adapterCapabilities": { "conversationDriver": "implemented" }
                },
                {
                    "target": "blocked",
                    "label": "Blocked",
                    "binaryPath": "/fixture-root/bin/blocked",
                    "adapterCapabilities": { "conversationDriver": "blocked" }
                },
                {
                    "target": "no-binary",
                    "label": "No Binary",
                    "adapterCapabilities": { "conversationDriver": "implemented" }
                }
            ]
        }))
    }

    fn conversations(_: &Value) -> Result<Value, ChannelError> {
        Ok(json!({
            "sessions": [
                { "sessionId": "sess-1", "title": "First" },
                { "id": "sess-2", "summary": "Second" }
            ]
        }))
    }

    fn open(_: &Value) -> Result<Value, ChannelError> {
        Ok(json!({ "sessionId": "sess-1" }))
    }

    fn dispatch(operation: &str, params: &Value) -> Result<Value, ChannelError> {
        assert_eq!(operation, "send");
        *LAST_DISPATCH.lock().unwrap() = Some(params.clone());
        Ok(json!({
            "ok": true,
            "output": "agent reply",
            "sessionId": "sess-1"
        }))
    }

    fn install_fixture() {
        let port = lane::LanePort {
            scan_targets: scan,
            conversation_list: conversations,
            open_or_resume: open,
            dispatch,
            outbound_hooks: None,
        };
        lane::clear();
        lane::install(port).unwrap();
    }

    /// A lane that outlives any local deadline the caller passes: the
    /// bridge must wait for it rather than abandon the worker.
    fn slow_dispatch(operation: &str, _: &Value) -> Result<Value, ChannelError> {
        assert_eq!(operation, "send");
        SLOW_ENTERED.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(150));
        SLOW_FINISHED.store(true, Ordering::SeqCst);
        Ok(json!({
            "ok": true,
            "output": "slow agent reply",
            "sessionId": "sess-slow"
        }))
    }

    static BLOCK_GATE: Mutex<bool> = Mutex::new(false);
    static BLOCK_WAKE: Condvar = Condvar::new();

    /// A dispatch parked on `BLOCK_GATE` until the test releases it: the
    /// overlap window is held open deterministically instead of trusting
    /// a wall-clock sleep to outlive an assertion.
    fn dispatch_with_observable_overlap(operation: &str, _: &Value) -> Result<Value, ChannelError> {
        assert_eq!(operation, "send");
        DISPATCH_CALLS.fetch_add(1, Ordering::SeqCst);
        let active = ACTIVE_DISPATCHES.fetch_add(1, Ordering::SeqCst) + 1;
        MAX_ACTIVE_DISPATCHES.fetch_max(active, Ordering::SeqCst);
        {
            let mut gate = BLOCK_GATE.lock().unwrap();
            while !*gate {
                gate = BLOCK_WAKE.wait(gate).unwrap();
            }
        }
        ACTIVE_DISPATCHES.fetch_sub(1, Ordering::SeqCst);
        Ok(json!({
            "ok": true,
            "output": "overlap fixture reply",
            "sessionId": "sess-overlap"
        }))
    }

    fn install_fixture_with_dispatch(dispatch: fn(&str, &Value) -> Result<Value, ChannelError>) {
        lane::clear();
        lane::install(lane::LanePort {
            scan_targets: scan,
            conversation_list: conversations,
            open_or_resume: open,
            dispatch,
            outbound_hooks: None,
        })
        .unwrap();
    }

    #[test]
    fn agent_filter_requires_a_runnable_driver_and_executable() {
        let admitted = agent_summary_if_channel_admissible(&json!({
            "target": "cursor",
            "label": "Cursor",
            "binaryPath": "/fixture-root/bin/cursor",
            "adapterCapabilities": { "conversationDriver": "implemented" }
        }))
        .unwrap();
        assert_eq!(admitted.id, "cursor");

        assert!(
            agent_summary_if_channel_admissible(&json!({
                "target": "blocked",
                "binaryPath": "/fixture-root/bin/blocked",
                "adapterCapabilities": { "conversationDriver": "blocked" }
            }))
            .is_none()
        );
        assert!(
            agent_summary_if_channel_admissible(&json!({
                "target": "history",
                "binaryPath": "/fixture-root/bin/history",
                "adapterCapabilities": { "conversationDriver": "history-only" }
            }))
            .is_none()
        );
        assert!(
            agent_summary_if_channel_admissible(&json!({
                "target": "no-binary",
                "adapterCapabilities": { "conversationDriver": "implemented" }
            }))
            .is_none()
        );
    }

    #[test]
    fn lane_flow_lists_opens_and_dispatches_a_turn() {
        let _guard = LANE_LOCK.lock().unwrap();
        install_fixture();
        *LAST_DISPATCH.lock().unwrap() = None;

        let agents = list_agents().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "cursor");

        let sessions = list_sessions("cursor").unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "sess-1");
        assert_eq!(sessions[1].title, "Second");

        assert_eq!(open_session("cursor", None).unwrap(), "sess-1");
        let (output, session) = send_turn(
            "cursor",
            Some("sess-1"),
            "hello",
            Duration::from_secs(5),
            Some("ev-1"),
        )
        .unwrap();
        assert_eq!(output, "agent reply");
        assert_eq!(session, "sess-1");

        let dispatched = LAST_DISPATCH.lock().unwrap().clone().unwrap();
        assert_eq!(dispatched["agent"], json!("cursor"));
        assert_eq!(dispatched["sessionId"], json!("sess-1"));
        assert_eq!(dispatched["text"], json!("hello"));
        assert!(dispatched["timeoutMs"].as_u64().unwrap() > 0);

        lane::clear();
    }

    #[test]
    fn send_turn_waits_past_a_local_deadline_instead_of_abandoning_work() {
        let _guard = LANE_LOCK.lock().unwrap();
        SLOW_ENTERED.store(false, Ordering::SeqCst);
        SLOW_FINISHED.store(false, Ordering::SeqCst);
        install_fixture_with_dispatch(slow_dispatch);

        let started = Instant::now();
        let (output, session) = send_turn(
            "cursor",
            Some("sess-slow"),
            "long running turn",
            Duration::from_millis(1),
            None,
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
    fn duplicate_event_waits_and_reuses_the_dispatch_result() {
        let _guard = LANE_LOCK.lock().unwrap();
        ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        MAX_ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        DISPATCH_CALLS.store(0, Ordering::SeqCst);
        install_fixture_with_dispatch(dispatch_with_observable_overlap);
        *BLOCK_GATE.lock().unwrap() = false;

        let first = thread::spawn(|| {
            send_turn(
                "cursor",
                Some("sess-overlap"),
                "same turn",
                Duration::from_secs(5),
                Some("ev-dup"),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while DISPATCH_CALLS.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "first dispatch never started");
            thread::sleep(Duration::from_millis(2));
        }

        let second = thread::spawn(|| {
            send_turn(
                "cursor",
                Some("sess-overlap"),
                "same turn",
                Duration::from_secs(5),
                Some("ev-dup"),
            )
        });
        // The leader is provably parked inside the dispatch, so the
        // duplicate can only be waiting on it — no timing margin.
        assert!(
            !second.is_finished(),
            "a duplicate caller returned while the original dispatch was parked"
        );
        *BLOCK_GATE.lock().unwrap() = true;
        BLOCK_WAKE.notify_all();

        let first = first.join().unwrap().unwrap();
        let second = second.join().unwrap().unwrap();

        // One paid execution; both callers of the same event reuse it —
        // and a redelivery arriving after completion reuses it too.
        let third = send_turn(
            "cursor",
            Some("sess-overlap"),
            "same turn",
            Duration::from_secs(5),
            Some("ev-dup"),
        )
        .unwrap();
        assert_eq!(first.0, "overlap fixture reply");
        assert_eq!(second.0, "overlap fixture reply");
        assert_eq!(third.0, "overlap fixture reply");
        assert_eq!(DISPATCH_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(MAX_ACTIVE_DISPATCHES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn distinct_events_with_identical_text_dispatch_independently() {
        let _guard = LANE_LOCK.lock().unwrap();
        ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        MAX_ACTIVE_DISPATCHES.store(0, Ordering::SeqCst);
        DISPATCH_CALLS.store(0, Ordering::SeqCst);
        install_fixture_with_dispatch(dispatch_with_observable_overlap);
        *BLOCK_GATE.lock().unwrap() = true;
        BLOCK_WAKE.notify_all();

        send_turn(
            "cursor",
            Some("sess-overlap"),
            "same turn",
            Duration::from_secs(5),
            Some("ev-a"),
        )
        .unwrap();
        send_turn(
            "cursor",
            Some("sess-overlap"),
            "same turn",
            Duration::from_secs(5),
            Some("ev-b"),
        )
        .unwrap();
        send_turn(
            "cursor",
            Some("sess-other"),
            "same turn",
            Duration::from_secs(5),
            Some("ev-a"),
        )
        .unwrap();
        lane::clear();

        // Same text but different events, and the same event id under a
        // different session scope: three independent dispatches.
        assert_eq!(DISPATCH_CALLS.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn without_a_lane_port_calls_fail_closed() {
        let _guard = LANE_LOCK.lock().unwrap();
        lane::clear();
        assert_eq!(
            list_agents().unwrap_err().code,
            "a4mc_slack_lane_unavailable"
        );
        assert_eq!(
            open_session("cursor", None).unwrap_err().code,
            "a4mc_slack_lane_unavailable"
        );
        assert_eq!(
            send_turn("cursor", None, "hello", Duration::from_millis(10), None)
                .unwrap_err()
                .code,
            "a4mc_slack_lane_unavailable"
        );
    }
}
