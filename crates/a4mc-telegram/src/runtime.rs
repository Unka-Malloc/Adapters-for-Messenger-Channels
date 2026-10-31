//! Long-polling channel loop and bounded per-chat inbound scheduling.
//!
//! The loop long-polls `getUpdates`, admits each message into a globally
//! bounded, fair, per-chat FIFO scheduler, and hands work to the bridge.
//! It is fail-safe: unauthorized tokens and second-poller conflicts end
//! the loop with their error; transient transport failures back off and
//! continue; a handler failure never kills a worker — it is answered
//! with a sanitized error reply.

use super::bridge::{
    ensure_known_agent, format_agent_list, format_session_list, list_agents, list_sessions,
    open_session, resolve_session_selector, send_turn,
};
use super::transport::{BotIdentity, BotTransport, InboundMessage, bot_commands};
use crate::binding::{BindingStore, ChatBinding, PairingRecord};
use crate::control::{
    ControlCommand, ControlOutcome, commands_text, help_text, parse_control_command,
};
use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

pub struct RuntimeConfig {
    pub poll_timeout_secs: u64,
    pub stop: Arc<AtomicBool>,
    pub worker_count: usize,
    pub max_admitted: usize,
    /// Invoked once after the Bot API handshake (`getMe`, webhook clear,
    /// command registration) succeeds — the host's readiness hook for
    /// status files, supervisors or UI. The adapter owns no such state.
    pub on_started: Option<OnStarted>,
}

/// The readiness hook invoked once after a successful Bot API handshake.
pub type OnStarted = Box<dyn FnOnce(&BotIdentity) + Send>;

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            poll_timeout_secs: 25,
            stop: Arc::new(AtomicBool::new(false)),
            worker_count: 4,
            max_admitted: 64,
            on_started: None,
        }
    }
}

struct SchedulerState {
    per_chat: HashMap<i64, VecDeque<InboundMessage>>,
    ready: VecDeque<i64>,
    queued: HashSet<i64>,
    inflight: HashSet<i64>,
    admitted: usize,
}

impl SchedulerState {
    fn new() -> Self {
        Self {
            per_chat: HashMap::new(),
            ready: VecDeque::new(),
            queued: HashSet::new(),
            inflight: HashSet::new(),
            admitted: 0,
        }
    }
}

/// Globally bounded, fair, per-chat FIFO scheduler. A chat has at most one
/// in-flight job; queued plus running jobs never exceed `max_admitted`, and
/// admitted jobs are never dropped.
struct Scheduler {
    state: Mutex<SchedulerState>,
    wake: Condvar,
    stop: Arc<AtomicBool>,
    max_admitted: usize,
}

impl Scheduler {
    fn new(max_admitted: usize, stop: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(SchedulerState::new()),
            wake: Condvar::new(),
            stop,
            max_admitted,
        }
    }

    /// Block until admission capacity is available. Used by the poller so it
    /// never over-admits a fetched batch.
    fn wait_for_capacity(&self) {
        let mut state = self.state.lock().unwrap();
        while state.admitted >= self.max_admitted {
            state = self.wake.wait(state).unwrap();
        }
    }

    fn admitted(&self) -> usize {
        self.state.lock().unwrap().admitted
    }

    fn enqueue(&self, message: InboundMessage) {
        let mut state = self.state.lock().unwrap();
        let chat_id = message.chat_id;
        state
            .per_chat
            .entry(chat_id)
            .or_default()
            .push_back(message);
        state.admitted += 1;
        if !state.queued.contains(&chat_id) && !state.inflight.contains(&chat_id) {
            state.ready.push_back(chat_id);
            state.queued.insert(chat_id);
        }
        self.wake.notify_one();
    }

    fn spawn_workers<F>(
        self: &Arc<Self>,
        worker_count: usize,
        processor: F,
    ) -> Result<Vec<thread::JoinHandle<()>>>
    where
        F: Fn(i64, InboundMessage) -> Result<()> + Send + Sync + 'static,
    {
        let processor = Arc::new(processor);
        let mut handles = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let scheduler = Arc::clone(self);
            let processor = Arc::clone(&processor);
            handles.push(
                thread::Builder::new()
                    .name(format!("a4mc-telegram-worker-{index}"))
                    .spawn(move || worker_loop(scheduler, processor))
                    .map_err(|_| anyhow!("a4mc_telegram_runtime_spawn_failed"))?,
            );
        }
        Ok(handles)
    }

    fn join_workers(&self, handles: Vec<thread::JoinHandle<()>>) -> Result<()> {
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow!("a4mc_telegram_runtime_join_failed"))?;
        }
        Ok(())
    }
}

fn worker_loop<F>(scheduler: Arc<Scheduler>, processor: Arc<F>)
where
    F: Fn(i64, InboundMessage) -> Result<()> + Send + Sync + 'static,
{
    loop {
        let (chat_id, message) = {
            let mut state = scheduler.state.lock().unwrap();
            loop {
                if let Some(chat_id) = state.ready.pop_front() {
                    state.queued.remove(&chat_id);
                    let message = state
                        .per_chat
                        .get_mut(&chat_id)
                        .expect("ready chats have a queued job")
                        .pop_front()
                        .expect("ready chats have a queued job");
                    if state.per_chat.get(&chat_id).is_none_or(VecDeque::is_empty) {
                        state.per_chat.remove(&chat_id);
                    }
                    state.inflight.insert(chat_id);
                    break (chat_id, message);
                }
                if scheduler.stop.load(Ordering::SeqCst) {
                    return;
                }
                state = scheduler.wake.wait(state).unwrap();
            }
        };
        let _ = processor(chat_id, message);
        let mut state = scheduler.state.lock().unwrap();
        state.inflight.remove(&chat_id);
        state.admitted -= 1;
        if state
            .per_chat
            .get(&chat_id)
            .is_some_and(|queue| !queue.is_empty())
        {
            state.ready.push_back(chat_id);
            state.queued.insert(chat_id);
        }
        scheduler.wake.notify_all();
    }
}

pub fn run_channel_loop<T: BotTransport + 'static>(
    transport: T,
    store: BindingStore,
    config: RuntimeConfig,
) -> Result<BotIdentity> {
    let transport = Arc::new(transport);
    let identity = transport
        .get_me()
        .map_err(|error| anyhow!("{}: {}", error.code, error.message))?;
    transport
        .delete_webhook()
        .map_err(|error| anyhow!("{}: {}", error.code, error.message))?;
    transport
        .set_my_commands(&bot_commands())
        .map_err(|error| anyhow!("{}: {}", error.code, error.message))?;
    let mut config = config;
    if let Some(on_started) = config.on_started.take() {
        on_started(&identity);
    }

    let store = Arc::new(Mutex::new(store));
    let scheduler = Arc::new(Scheduler::new(
        config.max_admitted,
        Arc::clone(&config.stop),
    ));

    let processor_transport = Arc::clone(&transport);
    let processor_store = Arc::clone(&store);
    let processor_identity = identity.clone();
    let processor = move |chat_id: i64, message: InboundMessage| match handle_inbound(
        &*processor_transport,
        &processor_store,
        &processor_identity,
        &message,
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = processor_transport.send_message(
                chat_id,
                &sanitize_error(&error),
                Some(message.message_id),
            );
            Ok(())
        }
    };
    let workers = scheduler.spawn_workers(config.worker_count, processor)?;

    let mut offset: i64 = 0;
    let mut pending: VecDeque<InboundMessage> = VecDeque::new();
    let poll_result = poll_updates(&*transport, &scheduler, &config, &mut offset, &mut pending);
    // Fail-closed on every exit: raising stop before drain/join releases
    // workers parked on `wake` — a fatal poll error that left stop unset
    // would deadlock here instead of returning its error. Workers serve
    // `ready` before re-checking stop, so admitted work still drains.
    config.stop.store(true, Ordering::SeqCst);
    scheduler.wake.notify_all();
    drain_pending(&scheduler, &mut pending);
    scheduler.join_workers(workers)?;
    poll_result?;
    Ok(identity)
}

fn poll_updates<T: BotTransport>(
    transport: &T,
    scheduler: &Scheduler,
    config: &RuntimeConfig,
    offset: &mut i64,
    pending: &mut VecDeque<InboundMessage>,
) -> Result<()> {
    while !config.stop.load(Ordering::SeqCst) {
        scheduler.wait_for_capacity();
        if config.stop.load(Ordering::SeqCst) {
            break;
        }
        if pending.is_empty() {
            let updates = match transport.get_updates(*offset, config.poll_timeout_secs) {
                Ok(updates) => updates,
                Err(error) if error.code == "a4mc_telegram_conflict" => {
                    return Err(anyhow!("{}: {}", error.code, error.message));
                }
                Err(error) if error.code == "a4mc_telegram_unauthorized" => {
                    return Err(anyhow!("{}: {}", error.code, error.message));
                }
                Err(_) => {
                    // Recoverable network blip: brief backoff then continue.
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            for update in updates {
                *offset = update.update_id + 1;
                if let Some(message) = update.message {
                    pending.push_back(message);
                }
            }
        }
        admit_available(scheduler, pending);
    }
    Ok(())
}

fn admit_available(scheduler: &Scheduler, pending: &mut VecDeque<InboundMessage>) {
    loop {
        if scheduler.admitted() >= scheduler.max_admitted {
            break;
        }
        let Some(message) = pending.pop_front() else {
            break;
        };
        scheduler.enqueue(message);
    }
}

fn drain_pending(scheduler: &Scheduler, pending: &mut VecDeque<InboundMessage>) {
    while !pending.is_empty() {
        scheduler.wait_for_capacity();
        admit_available(scheduler, pending);
    }
}

fn handle_inbound<T: BotTransport>(
    transport: &T,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
) -> Result<()> {
    if !message.is_private {
        // The channel serves direct chats only; group traffic is ignored.
        return Ok(());
    }
    match parse_control_command(&message.control_text()) {
        ControlOutcome::Command(command) => {
            handle_command(transport, store, identity, message, command)
        }
        ControlOutcome::OrdinaryText(_) => {
            let body = message.agent_text();
            if body.trim().is_empty() {
                return Ok(());
            }
            handle_ordinary(transport, store, message, &body)
        }
    }
}

fn send_reply<T: BotTransport>(transport: &T, message: &InboundMessage, text: &str) -> Result<()> {
    transport
        .send_message(message.chat_id, text, Some(message.message_id))
        .map(|_| ())
        .map_err(api_err)
}

fn handle_command<T: BotTransport>(
    transport: &T,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
    command: ControlCommand,
) -> Result<()> {
    match command {
        ControlCommand::Help => {
            send_reply(transport, message, &help_text(&identity.username))?;
        }
        ControlCommand::Commands => {
            send_reply(transport, message, &commands_text())?;
        }
        ControlCommand::Start | ControlCommand::Pair => {
            handle_pair_request(transport, store, identity, message)?;
        }
        ControlCommand::Whoami => {
            send_reply(transport, message, &whoami_text(message))?;
        }
        ControlCommand::Unpair => {
            let revoked = store_revoke(store, message.chat_id)?;
            send_reply(
                transport,
                message,
                if revoked {
                    "Pairing revoked for this chat. Send /start to pair again."
                } else {
                    "No pairing found for this chat."
                },
            )?;
        }
        ControlCommand::Status => {
            if !store_is_paired(store, message.chat_id, message.user_id)? {
                send_reply(
                    transport,
                    message,
                    "Not paired. Send /start to request a pairing code.",
                )?;
            } else {
                send_reply(
                    transport,
                    message,
                    &status_text(store, identity, message.chat_id)?,
                )?;
            }
        }
        ControlCommand::Agent { agent_id: None } => {
            require_paired(store, message)?;
            let agents = list_agents().map_err(|error| anyhow!(error.to_string()))?;
            send_reply(transport, message, &format_agent_list(&agents))?;
        }
        ControlCommand::Agent {
            agent_id: Some(agent_id),
        } => {
            require_paired(store, message)?;
            ensure_known_agent(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            let binding = store_set_agent(store, message.chat_id, Some(agent_id.clone()))?;
            send_reply(
                transport,
                message,
                &format!(
                    "Bound agent: {}.\nSession cleared. Use /session or /new, then send a message.",
                    binding.agent_id.unwrap_or(agent_id)
                ),
            )?;
        }
        ControlCommand::Session { selector: None } => {
            require_paired(store, message)?;
            let agent_id = require_agent(store, message.chat_id)?;
            let sessions = list_sessions(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            send_reply(transport, message, &format_session_list(&sessions))?;
        }
        ControlCommand::Session {
            selector: Some(selector),
        } => {
            require_paired(store, message)?;
            let agent_id = require_agent(store, message.chat_id)?;
            let sessions = list_sessions(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            let selected = resolve_session_selector(&sessions, &selector)
                .map_err(|error| anyhow!(error.to_string()))?;
            let opened = open_session(&agent_id, Some(&selected.id))
                .map_err(|error| anyhow!(error.to_string()))?;
            let session_id = if opened.is_empty() {
                selected.id.clone()
            } else {
                opened
            };
            store_set_session(store, message.chat_id, Some(session_id.clone()))?;
            send_reply(transport, message, &format!("Bound session: {session_id}"))?;
        }
        ControlCommand::New | ControlCommand::Reset => {
            require_paired(store, message)?;
            let agent_id = require_agent(store, message.chat_id)?;
            let opened =
                open_session(&agent_id, None).map_err(|error| anyhow!(error.to_string()))?;
            store_set_session(
                store,
                message.chat_id,
                if opened.is_empty() {
                    None
                } else {
                    Some(opened.clone())
                },
            )?;
            send_reply(
                transport,
                message,
                &format!(
                    "Started a new conversation{}.",
                    if opened.is_empty() {
                        String::new()
                    } else {
                        format!(": {opened}")
                    }
                ),
            )?;
        }
        ControlCommand::Stop => {
            send_reply(
                transport,
                message,
                "This channel processes one turn at a time. There is no separate in-flight interrupt yet; wait for the current reply, or use /new for a fresh conversation.",
            )?;
        }
        ControlCommand::Unknown { name } => {
            send_reply(
                transport,
                message,
                &format!("Unknown command /{name}. Use /commands for the catalog."),
            )?;
        }
    }
    Ok(())
}

fn handle_pair_request<T: BotTransport>(
    transport: &T,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
) -> Result<()> {
    if store_is_paired(store, message.chat_id, message.user_id)? {
        send_reply(
            transport,
            message,
            &format!(
                "Already paired.\n{}",
                status_text(store, identity, message.chat_id)?
            ),
        )?;
        return Ok(());
    }
    let pending = store_request_pairing(
        store,
        message.chat_id,
        message.user_id,
        message.username.clone(),
    )?;
    send_reply(transport, message, &pairing_code_text(&pending.code))?;
    Ok(())
}

fn handle_ordinary<T: BotTransport>(
    transport: &T,
    store: &Mutex<BindingStore>,
    message: &InboundMessage,
    text: &str,
) -> Result<()> {
    if !store_is_paired(store, message.chat_id, message.user_id)? {
        let pending = store_request_pairing(
            store,
            message.chat_id,
            message.user_id,
            message.username.clone(),
        )?;
        send_reply(
            transport,
            message,
            &format!("Pairing required.\n{}", pairing_code_text(&pending.code)),
        )?;
        return Ok(());
    }
    let binding = store_binding(store, message.chat_id)?
        .ok_or_else(|| anyhow!("a4mc_telegram_not_paired"))?;
    let Some(agent_id) = binding.agent_id.clone() else {
        send_reply(
            transport,
            message,
            "No agent bound. Use /agent to list agents, then /agent <id>.",
        )?;
        return Ok(());
    };
    let (reply, next_session) = send_turn(&agent_id, binding.session_id.as_deref(), text)
        .map_err(|error| anyhow!(error.to_string()))?;
    if !next_session.is_empty() && binding.session_id.as_deref() != Some(next_session.as_str()) {
        let _ = store_set_session(store, message.chat_id, Some(next_session));
    }
    send_reply(transport, message, &reply)?;
    Ok(())
}

fn require_paired(store: &Mutex<BindingStore>, message: &InboundMessage) -> Result<()> {
    if store_is_paired(store, message.chat_id, message.user_id)? {
        Ok(())
    } else {
        Err(anyhow!(
            "Not paired. Send /start to request a pairing code."
        ))
    }
}

fn require_agent(store: &Mutex<BindingStore>, chat_id: i64) -> Result<String> {
    store_binding(store, chat_id)?
        .and_then(|binding| binding.agent_id)
        .ok_or_else(|| anyhow!("No agent bound. Use /agent <id> first."))
}

fn store_is_paired(store: &Mutex<BindingStore>, chat_id: i64, user_id: i64) -> Result<bool> {
    let mut guard = store.lock().unwrap();
    guard.refresh()?;
    Ok(guard.is_paired(chat_id, user_id))
}

fn store_binding(store: &Mutex<BindingStore>, chat_id: i64) -> Result<Option<ChatBinding>> {
    let mut guard = store.lock().unwrap();
    guard.refresh()?;
    Ok(guard.binding(chat_id).cloned())
}

fn store_request_pairing(
    store: &Mutex<BindingStore>,
    chat_id: i64,
    user_id: i64,
    username: Option<String>,
) -> Result<PairingRecord> {
    store
        .lock()
        .unwrap()
        .request_pairing(chat_id, user_id, username)
}

fn store_revoke(store: &Mutex<BindingStore>, chat_id: i64) -> Result<bool> {
    store.lock().unwrap().revoke(chat_id)
}

fn store_set_agent(
    store: &Mutex<BindingStore>,
    chat_id: i64,
    agent_id: Option<String>,
) -> Result<ChatBinding> {
    store.lock().unwrap().set_agent(chat_id, agent_id)
}

fn store_set_session(
    store: &Mutex<BindingStore>,
    chat_id: i64,
    session_id: Option<String>,
) -> Result<ChatBinding> {
    store.lock().unwrap().set_session(chat_id, session_id)
}

fn status_text(
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    chat_id: i64,
) -> Result<String> {
    let mut guard = store.lock().unwrap();
    guard.refresh()?;
    let binding = guard.binding(chat_id).cloned();
    Ok(format!(
        "Bot: @{}\nPaired: {}\nAgent: {}\nSession: {}",
        identity.username,
        binding.as_ref().map(|value| value.paired).unwrap_or(false),
        binding
            .as_ref()
            .and_then(|value| value.agent_id.as_deref())
            .unwrap_or("(none)"),
        binding
            .as_ref()
            .and_then(|value| value.session_id.as_deref())
            .unwrap_or("(none)")
    ))
}

fn whoami_text(message: &InboundMessage) -> String {
    format!(
        "chatId: {}\nuserId: {}\nusername: {}",
        message.chat_id,
        message.user_id,
        message
            .username
            .as_deref()
            .map(|value| format!("@{value}"))
            .unwrap_or_else(|| "(none)".to_owned())
    )
}

fn pairing_code_text(code: &str) -> String {
    format!(
        "Pairing code: {code}\n\
         Approve it in the host application's channel settings."
    )
}

fn api_err(error: super::transport::TelegramApiError) -> anyhow::Error {
    anyhow!("{}: {}", error.code, error.message)
}

/// User-facing error replies keep only the bounded error code; any body or
/// credential content after the first colon is never forwarded.
fn sanitize_error(error: &anyhow::Error) -> String {
    const MAX_ERROR_CHARS: usize = 160;
    let text = error.to_string();
    let code = text
        .split(':')
        .next()
        .unwrap_or("a4mc_telegram_failed")
        .trim();
    let code: String = code.chars().take(MAX_ERROR_CHARS).collect();
    format!("Error: {code}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::InboundKind;
    use crate::transport::{MockBotTransport, TelegramApiError, Update};
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::time::Instant;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-rt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::create_dir_all(&root);
        root
    }

    fn text_message(
        chat_id: i64,
        user_id: i64,
        username: Option<&str>,
        text: &str,
        message_id: i64,
    ) -> InboundMessage {
        InboundMessage {
            update_id: message_id,
            chat_id,
            chat_type: "private".into(),
            user_id,
            username: username.map(str::to_owned),
            from_name: None,
            is_private: true,
            message_id,
            message_thread_id: None,
            edited: false,
            date: None,
            edit_date: None,
            kind: InboundKind::Text,
            text: Some(text.to_owned()),
            caption: None,
            media: Vec::new(),
            reply_to: None,
            forward_label: None,
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        }
    }

    /// The composing host owns conversation access; tests install deterministic
    /// lane answers so the channel admission path stays exercised.
    fn install_synthetic_lane() {
        use a4mc::lane::{self, LanePort};
        use serde_json::json;
        fn scan_targets() -> Result<serde_json::Value, a4mc::ChannelError> {
            Ok(json!({"candidates": [{
                "target": "codex",
                "label": "Codex",
                "binaryPath": "/fixture-root/bin/codex",
                "adapterCapabilities": {
                    "conversationDriver": "native",
                    "conversationReadiness": "ready",
                },
            }]}))
        }
        fn empty(params: &serde_json::Value) -> Result<serde_json::Value, a4mc::ChannelError> {
            let _ = params;
            Ok(json!({"sessions": []}))
        }
        let _ = lane::install(LanePort {
            scan_targets,
            conversation_list: empty,
            open_or_resume: empty,
            dispatch: |operation, params| {
                let _ = (operation, params);
                Ok(json!({"ok": true, "output": "synthetic", "sessionId": "synthetic"}))
            },
        });
    }

    fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn start_issues_pairing_and_approve_enables_agent_command() {
        install_synthetic_lane();
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = MockBotTransport {
            sent: sent.clone(),
            ..MockBotTransport::default()
        };
        let message = text_message(99, 77, Some("bob"), "/start", 1);
        handle_inbound(&transport, &store, &BotIdentity::default(), &message).unwrap();
        let code = store.lock().unwrap().pending_pairings()[0].code.clone();
        store.lock().unwrap().approve(&code).unwrap();
        let list = text_message(99, 77, Some("bob"), "/agent", 2);
        handle_inbound(&transport, &store, &BotIdentity::default(), &list).unwrap();
        let messages = sent.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|(_, body)| body.contains("Pairing code"))
        );
        assert!(messages.iter().any(|(_, body)| {
            body.contains("Verified local agents") || body.contains("No verified local agents")
        }));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn whoami_works_before_pairing_and_unpair_revokes() {
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = MockBotTransport {
            sent: sent.clone(),
            ..MockBotTransport::default()
        };
        let identity = BotIdentity {
            username: "a4mc_bot".into(),
            ..BotIdentity::default()
        };
        handle_inbound(
            &transport,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/whoami", 1),
        )
        .unwrap();
        handle_inbound(
            &transport,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/start", 2),
        )
        .unwrap();
        let code = store.lock().unwrap().pending_pairings()[0].code.clone();
        store.lock().unwrap().approve(&code).unwrap();
        handle_inbound(
            &transport,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/unpair", 3),
        )
        .unwrap();
        assert!(!store.lock().unwrap().is_paired(42, 42));
        let messages = sent.lock().unwrap();
        assert!(messages.iter().any(|(_, body)| body.contains("chatId: 42")));
        assert!(
            messages
                .iter()
                .any(|(_, body)| body.contains("Pairing revoked"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn photo_caption_command_uses_caption_for_control() {
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = MockBotTransport {
            sent: sent.clone(),
            ..MockBotTransport::default()
        };
        let mut message = text_message(5, 5, None, "", 1);
        message.kind = InboundKind::Photo;
        message.text = None;
        message.caption = Some("/whoami".into());
        message.media = vec![crate::inbound::MediaRef {
            kind: "photo".into(),
            file_id: "p".into(),
            file_unique_id: None,
            file_name: None,
            mime_type: None,
            file_size: Some(10),
            width: Some(1),
            height: Some(1),
            duration: None,
            emoji: None,
        }];
        handle_inbound(&transport, &store, &BotIdentity::default(), &message).unwrap();
        let messages = sent.lock().unwrap();
        assert!(messages.iter().any(|(_, body)| body.contains("chatId: 5")));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn channel_loop_polls_admits_and_replies_in_order() {
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            observed_offsets: Arc::clone(&observed_offsets),
            ..MockBotTransport::default()
        };
        transport.updates.lock().unwrap().extend([
            Update {
                update_id: 1,
                message: Some(text_message(42, 42, Some("alice"), "/whoami", 1)),
            },
            Update {
                update_id: 2,
                message: Some(text_message(42, 42, Some("bob"), "/whoami", 2)),
            },
            Update {
                update_id: 3,
                message: Some(text_message(7, 7, Some("carol"), "/help", 5)),
            },
        ]);
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let started_hook = Arc::clone(&started);
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_started: Some(Box::new(move |identity: &BotIdentity| {
                assert_eq!(identity.username, "a4mc_bot");
                started_hook.store(true, Ordering::SeqCst);
            })),
            ..RuntimeConfig::default()
        };
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 3, Duration::from_secs(10));
        wait_until(
            || {
                observed_offsets
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|offset| *offset >= 4)
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert!(started.load(Ordering::SeqCst));

        let messages = sent.lock().unwrap();
        let chat_42: Vec<&str> = messages
            .iter()
            .filter(|(chat, _)| *chat == 42)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(chat_42.len(), 2);
        assert!(chat_42[0].contains("@alice"), "same-chat FIFO violated");
        assert!(chat_42[1].contains("@bob"));
        assert!(
            messages
                .iter()
                .any(|(chat, text)| *chat == 7 && text.contains("Telegram Channel"))
        );
        let offsets = observed_offsets.lock().unwrap();
        assert!(
            offsets.contains(&4),
            "offset never advanced past the last admitted update: {offsets:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scheduler_preserves_fifo_and_runs_cross_chat_concurrently() {
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Arc::new(Scheduler::new(4, Arc::clone(&stop)));
        let records = Arc::new(Mutex::new(Vec::<(i64, i64, String)>::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let chat_11_held = Arc::new(AtomicBool::new(false));
        let chat_11_blocked = Arc::new(AtomicBool::new(false));
        let processor = {
            let records = Arc::clone(&records);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let gate = Arc::clone(&gate);
            let chat_11_held = Arc::clone(&chat_11_held);
            let chat_11_blocked = Arc::clone(&chat_11_blocked);
            move |chat_id: i64, message: InboundMessage| -> Result<()> {
                records.lock().unwrap().push((
                    chat_id,
                    message.message_id,
                    thread::current().name().unwrap_or("").to_owned(),
                ));
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                if chat_id == 11 && !chat_11_held.swap(true, Ordering::SeqCst) {
                    chat_11_blocked.store(true, Ordering::SeqCst);
                    let (mutex, condvar) = &*gate;
                    let mut released = mutex.lock().unwrap();
                    while !*released {
                        released = condvar.wait(released).unwrap();
                    }
                }
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        };
        let workers = scheduler.spawn_workers(4, processor).unwrap();
        scheduler.enqueue(text_message(11, 1, Some("a"), "m1", 1));
        scheduler.enqueue(text_message(11, 1, Some("a"), "m2", 2));
        wait_until(
            || chat_11_blocked.load(Ordering::SeqCst),
            Duration::from_secs(5),
        );
        scheduler.enqueue(text_message(22, 2, Some("b"), "m3", 10));
        wait_until(
            || {
                records
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(chat, id, _)| *chat == 22 && *id == 10)
            },
            Duration::from_secs(5),
        );
        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "cross-chat overlap expected, peak work was {}",
            peak.load(Ordering::SeqCst)
        );
        {
            let (mutex, condvar) = &*gate;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        wait_until(
            || records.lock().unwrap().len() == 3,
            Duration::from_secs(5),
        );
        stop.store(true, Ordering::SeqCst);
        scheduler.wake.notify_all();
        for handle in workers {
            handle.join().unwrap();
        }
        let records = records.lock().unwrap();
        let first = records
            .iter()
            .position(|(chat, id, _)| *chat == 11 && *id == 1)
            .unwrap();
        let second = records
            .iter()
            .position(|(chat, id, _)| *chat == 11 && *id == 2)
            .unwrap();
        assert!(first < second, "same-chat FIFO violated");
        assert!(
            records
                .iter()
                .all(|(_, _, name)| name.starts_with("a4mc-telegram-worker-")),
            "jobs must run on named scheduler workers"
        );
    }

    #[test]
    fn scheduler_never_admits_beyond_capacity_and_drops_nothing() {
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Arc::new(Scheduler::new(2, Arc::clone(&stop)));
        let done = Arc::new(Mutex::new(Vec::<i64>::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let processor = {
            let done = Arc::clone(&done);
            let gate = Arc::clone(&gate);
            move |_chat_id: i64, message: InboundMessage| -> Result<()> {
                done.lock().unwrap().push(message.message_id);
                let (mutex, condvar) = &*gate;
                let mut released = mutex.lock().unwrap();
                while !*released {
                    released = condvar.wait(released).unwrap();
                }
                Ok(())
            }
        };
        let workers = scheduler.spawn_workers(1, processor).unwrap();
        scheduler.enqueue(text_message(1, 1, None, "a", 1));
        scheduler.enqueue(text_message(2, 2, None, "b", 2));
        assert_eq!(scheduler.admitted(), 2);

        let returned = Arc::new(AtomicBool::new(false));
        let waiter = {
            let scheduler = Arc::clone(&scheduler);
            let returned = Arc::clone(&returned);
            thread::spawn(move || {
                scheduler.wait_for_capacity();
                returned.store(true, Ordering::SeqCst);
            })
        };
        thread::sleep(Duration::from_millis(80));
        assert!(
            !returned.load(Ordering::SeqCst),
            "capacity wait returned while admission was full"
        );
        {
            let (mutex, condvar) = &*gate;
            *mutex.lock().unwrap() = true;
            condvar.notify_all();
        }
        wait_until(|| done.lock().unwrap().len() == 2, Duration::from_secs(5));
        waiter.join().unwrap();
        assert!(returned.load(Ordering::SeqCst));

        scheduler.enqueue(text_message(3, 3, None, "c", 3));
        wait_until(|| done.lock().unwrap().len() == 3, Duration::from_secs(5));
        let mut processed = done.lock().unwrap().clone();
        processed.sort_unstable();
        assert_eq!(processed, vec![1, 2, 3]);
        stop.store(true, Ordering::SeqCst);
        scheduler.wake.notify_all();
        for handle in workers {
            handle.join().unwrap();
        }
    }

    #[test]
    fn fatal_poll_error_stops_workers_and_returns_the_error() {
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let transport = MockBotTransport {
            fail_get_updates_with: Some(TelegramApiError::new(
                "a4mc_telegram_conflict",
                "getUpdates conflict: another poller is using this bot token",
            )),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        // Returning at all is the regression proof: before the shutdown
        // path raised `stop`, the join below parked workers on the wake
        // condvar forever and this call never returned.
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_conflict"),
            "unexpected error: {error}"
        );
        assert!(stop.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sanitize_error_strips_body_content_and_bounds_length() {
        let canary = "CANARY_TOKEN_123";
        let error = anyhow!("a4mc_telegram_send_failed: {canary} body text");
        let sanitized = sanitize_error(&error);
        assert!(!sanitized.contains(canary));
        assert!(!sanitized.contains("body text"));
        assert!(sanitized.contains("a4mc_telegram_send_failed"));
        let long = anyhow!("a4mc_telegram_send_failed: {}", "x".repeat(5000));
        assert!(sanitize_error(&long).len() <= 200);
    }
}
