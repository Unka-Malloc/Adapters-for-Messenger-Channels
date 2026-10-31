//! Conversation lane port.
//!
//! A channel answers turns by asking the composing host for lane work.
//! The adapter never links host internals; the host registers its four
//! answers once per process, and without them every lane call fails
//! closed.
//!
//! Answer payloads are normalized JSON. `scan_targets` returns the
//! channel-admissible agent candidates the host verified (`candidates`
//! array); `conversation_list` returns a bound agent's sessions;
//! `open_or_resume` opens one conversation; `dispatch` runs a named lane
//! operation such as `send`.

use crate::error::ChannelError;
use serde_json::Value;
use std::sync::RwLock;

/// Host answers for the conversation lane operations a channel needs.
#[derive(Clone, Copy)]
pub struct LanePort {
    /// Verified agent discovery for channel admission.
    pub scan_targets: fn() -> Result<Value, ChannelError>,
    /// Conversation list for a bound agent.
    pub conversation_list: fn(&Value) -> Result<Value, ChannelError>,
    /// Open or resume one conversation session.
    pub open_or_resume: fn(&Value) -> Result<Value, ChannelError>,
    /// Dispatch a named lane operation (send, cancel, cleanup, ...).
    pub dispatch: fn(&str, &Value) -> Result<Value, ChannelError>,
}

static LANE: RwLock<Option<LanePort>> = RwLock::new(None);

/// Install this host's lane answers. One composition owns the port per
/// process; reinstalling the same answers is accepted so repeated
/// startup is harmless.
pub fn install(port: LanePort) -> Result<(), &'static str> {
    let mut guard = LANE.write().map_err(|_| "a4mc_lane_port_lock_failed")?;
    match guard.as_ref() {
        Some(installed) if same_answers(installed, &port) => return Ok(()),
        Some(_) => return Err("a4mc_lane_port_already_installed"),
        None => {}
    }
    *guard = Some(port);
    Ok(())
}

fn same_answers(left: &LanePort, right: &LanePort) -> bool {
    std::ptr::fn_addr_eq(left.scan_targets, right.scan_targets)
        && std::ptr::fn_addr_eq(left.conversation_list, right.conversation_list)
        && std::ptr::fn_addr_eq(left.open_or_resume, right.open_or_resume)
        && std::ptr::fn_addr_eq(left.dispatch, right.dispatch)
}

pub fn installed() -> bool {
    LANE.read().map(|guard| guard.is_some()).unwrap_or(false)
}

/// Drop the installed port. Used by tests that need to prove the
/// fail-closed path; production composition installs once per process.
pub fn clear() {
    if let Ok(mut guard) = LANE.write() {
        *guard = None;
    }
}

/// Consume the installed port; fails closed when nothing is installed.
pub fn require() -> Result<LanePort, ChannelError> {
    LANE.read()
        .ok()
        .and_then(|guard| *guard)
        .ok_or_else(|| ChannelError::new("a4mc_lane_port_unavailable", "lane port not installed"))
}
