//! Long-polling channel loop and bounded per-chat inbound scheduling.
//!
//! The loop long-polls `getUpdates`, admits each message into a globally
//! bounded, fair, per-chat FIFO scheduler, and hands work to the bridge.
//! The poll cursor is durably recorded in the binding store as it
//! advances, so a restart resumes where the platform's acknowledged
//! offset left off instead of replaying confirmed updates. It is
//! fail-safe: unauthorized tokens and second-poller conflicts end the
//! loop with their error; transient transport failures honor the
//! platform's retry hint, back off with jitter and surface to the host
//! once the failure budget is spent; a handler failure never kills a
//! worker — it is answered with a sanitized error reply.

use super::bridge::{
    ensure_known_agent, format_agent_list, format_session_list, list_agents, list_sessions,
    open_session, resolve_session_selector, send_turn,
};
use super::channel::TelegramChannel;
use super::transport::{BotIdentity, BotTransport, InboundMessage, bot_commands};
use crate::binding::{BindingStore, ChatBinding, DroppedUpdate, PairingRecord};
use crate::control::{
    ControlCommand, ControlOutcome, commands_text, help_text, parse_control_command,
};
use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct RuntimeConfig {
    pub poll_timeout_secs: u64,
    pub stop: Arc<AtomicBool>,
    pub worker_count: usize,
    pub max_admitted: usize,
    /// Forwarded to the lane as `timeoutMs` for one agent turn. The lane
    /// owns bounding the work; the runtime never abandons a paid turn on
    /// a local elapsed-time cutoff.
    pub turn_deadline: Duration,
    /// Consecutive `getUpdates` failures tolerated before the loop
    /// surfaces `a4mc_telegram_poll_failed` to the host — an outage or
    /// a permanently rejected request must not retry silently forever.
    pub max_poll_failures: u32,
    /// How long the update stream may stay silent before the platform
    /// is allowed to restart update identifiers at a random value —
    /// Telegram documents a week. A stored cursor whose sequence is
    /// older than this window is discarded on startup, and in the
    /// running loop the stale high-water mark stops being confirmed so
    /// the new sequence's first ids are not acknowledged unseen.
    pub poll_sequence_idle: Duration,
    /// Invoked once after the Bot API handshake (`getMe`, webhook clear,
    /// command registration) succeeds — the host's readiness hook for
    /// status files, supervisors or UI. The adapter owns no such state.
    pub on_started: Option<OnStarted>,
    /// Host observer for a fetched update that carries no message body
    /// this channel can dispatch (dice/game/service payloads). The
    /// lowered event is passed so the host sees the gap instead of the
    /// cursor silently advancing past it. When no hook is mounted the
    /// runtime persists the update id in the binding store, so the loss
    /// is durable and inspectable rather than silent.
    pub on_event: Option<OnEvent>,
    /// Outbound send policy for every reply this runtime generates —
    /// command replies, agent replies and fallback errors are outbound
    /// sends and run through the same pipeline as host-initiated sends.
    /// `None` resolves the lane port's hook provider; with neither
    /// mounted the sends pass through.
    pub outbound_hooks: Option<Arc<dyn a4mc::OutboundHooks>>,
}

/// The readiness hook invoked once after a successful Bot API handshake.
pub type OnStarted = Box<dyn FnOnce(&BotIdentity) + Send>;
/// The host observer for updates this runtime cannot dispatch as a
/// message. Returning an error leaves the durable cursor before the
/// update, so it is redelivered rather than acknowledged unseen.
pub type OnEvent = Box<dyn FnMut(&a4mc::ChannelEvent) -> Result<()> + Send>;

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            poll_timeout_secs: 25,
            stop: Arc::new(AtomicBool::new(false)),
            worker_count: 4,
            max_admitted: 64,
            turn_deadline: Duration::from_secs(300),
            max_poll_failures: 8,
            poll_sequence_idle: Duration::from_secs(7 * 24 * 60 * 60),
            on_started: None,
            on_event: None,
            outbound_hooks: None,
        }
    }
}

struct SchedulerState {
    per_chat: HashMap<i64, VecDeque<InboundMessage>>,
    ready: VecDeque<i64>,
    queued: HashSet<i64>,
    inflight: HashSet<i64>,
    admitted: usize,
    /// No further work will ever be enqueued. Workers exit only once
    /// this is set *and* the ready queue is empty — `stop` alone never
    /// releases them, because the drain may still be admitting the
    /// fetched remainder after shutdown begins.
    drained: bool,
}

impl SchedulerState {
    fn new() -> Self {
        Self {
            per_chat: HashMap::new(),
            ready: VecDeque::new(),
            queued: HashSet::new(),
            inflight: HashSet::new(),
            admitted: 0,
            drained: false,
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

    /// Block until admission capacity is available or `stop` is raised.
    /// Used by the poller so it never over-admits a fetched batch; a
    /// `false` return means shutdown ended the wait and the poller must
    /// exit instead of parking on a full pipeline.
    fn wait_for_capacity(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        while state.admitted >= self.max_admitted && !self.stop.load(Ordering::SeqCst) {
            state = self.wake.wait(state).unwrap();
        }
        !self.stop.load(Ordering::SeqCst)
    }

    /// Raise `stop` and wake every parked thread under the state lock.
    /// The notify must hold the lock a waiter holds across its
    /// check-then-wait — an unlocked notify can land between a worker's
    /// `stop` check and its `wake.wait()` registration and be lost,
    /// parking that worker forever.
    fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _state = self.state.lock().unwrap();
        self.wake.notify_all();
    }

    /// Mark the fetched queue fully admitted and wake every parked
    /// worker under the state lock. Runs only after `drain_pending`:
    /// marking earlier would let workers exit with the drain's
    /// remainder still unqueued, stranding it behind the admission
    /// bound forever.
    fn mark_drained(&self) {
        let mut state = self.state.lock().unwrap();
        state.drained = true;
        self.wake.notify_all();
    }

    /// Block until admission capacity frees, regardless of `stop`. The
    /// drain path runs only after `stop` is already raised and must
    /// still admit the fetched remainder — admitted work is never
    /// dropped, and workers free capacity as they finish.
    fn wait_for_drain(&self) {
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
                if state.drained {
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

    // Resume where the last process durably confirmed: updates below
    // the stored cursor were already acknowledged to the platform, so
    // restarting from them would replay paid agent turns. The cursor
    // is only trusted while its sequence is live, though — the
    // platform may restart update identifiers at a random value after
    // a long silence, and a stale high-water mark would acknowledge
    // the new sequence's lower first ids before they are delivered.
    let mut cursor = PollCursor {
        sequence_age: SequenceAge::resumed(
            store
                .poll_offset_advanced_at()
                .map(|advanced| Duration::from_secs(now_secs().saturating_sub(advanced)))
                .unwrap_or(Duration::ZERO),
        ),
        offset: 0,
    };
    cursor.offset = if cursor.sequence_age.elapsed() >= config.poll_sequence_idle {
        0
    } else {
        store.poll_offset()
    };
    let store = Arc::new(Mutex::new(store));
    let scheduler = Arc::new(Scheduler::new(
        config.max_admitted,
        Arc::clone(&config.stop),
    ));

    // Every reply the runtime generates — command, agent and fallback
    // error alike — is an outbound send: it runs through the channel's
    // pipeline so a mounted host policy governs it like any other send.
    let channel = TelegramChannel::new(Arc::clone(&transport));
    let channel = Arc::new(match config.outbound_hooks.take() {
        Some(hooks) => channel.with_outbound_hooks(hooks),
        None => channel,
    });

    let processor_channel = Arc::clone(&channel);
    let processor_store = Arc::clone(&store);
    let processor_identity = identity.clone();
    let processor_stop = Arc::clone(&config.stop);
    let turn_deadline = config.turn_deadline;
    let processor = move |chat_id: i64, message: InboundMessage| {
        let update_id = message.update_id;
        match handle_inbound(
            &processor_channel,
            &processor_store,
            &processor_identity,
            &message,
            turn_deadline,
            &processor_stop,
        ) {
            Ok(()) => {
                let _ = processor_store.lock().unwrap().complete_update(update_id);
                Ok(())
            }
            // A reply the host's send policy was still holding when
            // shutdown cut the wait short is not a handler failure: no
            // error reply goes out around the policy, and the
            // unfinished task record stays for the restart drain.
            Err(error) if is_policy_deferral(&error) => Ok(()),
            Err(error) => {
                // The fallback error reply is an outbound send like
                // any other: it waits out a policy deferral rather
                // than being discarded on the first attempt. If the
                // wait ends undelivered — shutdown cut it short, or
                // the channel refused — the report is persisted on
                // the task so the restart drain still delivers it
                // instead of deleting the update unserved.
                let fallback = reply_message(
                    chat_id,
                    message.message_id,
                    update_id,
                    "error",
                    &sanitize_error(&error),
                );
                if send_policy_wait(&processor_channel, &fallback, &processor_stop).is_err() {
                    let _ = processor_store
                        .lock()
                        .unwrap()
                        .record_fallback_reply(update_id, &fallback.text);
                }
                // A task whose finished reply never got delivered keeps
                // its record — restart resumes that stage; anything else
                // was fully handled and settles here.
                let _ = processor_store
                    .lock()
                    .unwrap()
                    .settle_failed_update(update_id);
                Ok(())
            }
        }
    };
    let workers = scheduler.spawn_workers(config.worker_count, processor)?;

    let mut pending: VecDeque<InboundMessage> = VecDeque::new();
    // Resume admitted-but-unfinished work before polling: finished turns
    // only need their recorded reply delivered; unstarted messages are
    // re-queued whole. Records survive only while their stage is
    // unfinished, so nothing paid or already confirmed runs twice. A
    // resend the host's policy is holding retries after the store lock
    // drops — parking on its deferral window under the lock would stall
    // every worker's store access.
    let mut held: Vec<(i64, a4mc::OutboundMessage)> = Vec::new();
    {
        let mut guard = store.lock().unwrap();
        for task in guard.pending_updates() {
            match task.reply {
                Some(reply) => {
                    if let Some(session) = task.next_session.filter(|s| !s.is_empty()) {
                        let _ = guard.set_session(task.message.chat_id, Some(session));
                    }
                    let outbound = reply_message(
                        task.message.chat_id,
                        task.message.message_id,
                        task.update_id,
                        "reply",
                        &reply,
                    );
                    match channel.send(&outbound) {
                        Ok(_) => {
                            let _ = guard.complete_update(task.update_id);
                        }
                        Err(error) if is_outbound_deferral(&error) => {
                            held.push((task.update_id, outbound));
                        }
                        Err(_) => {}
                    }
                }
                None => pending.push_back(task.message),
            }
        }
    }
    for (update_id, outbound) in held {
        if send_policy_wait(&channel, &outbound, &config.stop).is_ok() {
            let _ = store.lock().unwrap().complete_update(update_id);
        }
    }
    let mut on_event = config.on_event.take();
    let poll_result = poll_updates(
        &*transport,
        &scheduler,
        &store,
        &config,
        &mut cursor,
        &mut pending,
        &mut on_event,
    );
    // Fail-closed on every exit: raising stop before drain/join releases
    // the poller's capacity wait — a fatal poll error that left stop
    // unset would park `drain_pending`'s producer side. Workers stay
    // alive on `stop` alone: they serve `ready` first and leave only
    // once `mark_drained` signals nothing more can arrive, so the
    // fetched remainder cannot be stranded behind a full admission
    // bound while the workers it needs are already gone.
    scheduler.shutdown();
    drain_pending(&scheduler, &mut pending);
    scheduler.mark_drained();
    scheduler.join_workers(workers)?;
    poll_result?;
    Ok(identity)
}

/// Ceiling on the adapter-computed backoff only. A platform
/// `retry_after` floor is never capped down: waiting less than the
/// server-specified window means predictably firing a request that is
/// still inside its rate-limit window.
const MAX_RETRY_WAIT_SECS: u64 = 120;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// How long the current confirmed update-id sequence has been silent:
/// the age a resumed cursor carried in, plus the in-process wait since.
/// Once the age reaches `poll_sequence_idle` the platform may have
/// restarted identifiers, so the cursor stops being trusted or
/// confirmed until new updates land.
struct SequenceAge {
    resumed: Duration,
    marked: Instant,
}

impl SequenceAge {
    fn resumed(age: Duration) -> Self {
        Self {
            resumed: age,
            marked: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.resumed + self.marked.elapsed()
    }

    fn reset(&mut self) {
        self.resumed = Duration::ZERO;
        self.marked = Instant::now();
    }
}

/// The polling cursor plus the freshness of the id sequence it
/// confirms: silent past [`RuntimeConfig::poll_sequence_idle`], the
/// stale high-water mark is dropped so a restarted sequence's lower
/// first ids are seen.
struct PollCursor {
    offset: i64,
    sequence_age: SequenceAge,
}

fn poll_updates<T: BotTransport>(
    transport: &T,
    scheduler: &Scheduler,
    store: &Mutex<BindingStore>,
    config: &RuntimeConfig,
    cursor: &mut PollCursor,
    pending: &mut VecDeque<InboundMessage>,
    on_event: &mut Option<OnEvent>,
) -> Result<()> {
    let mut consecutive_failures = 0u32;
    while !config.stop.load(Ordering::SeqCst) {
        if !scheduler.wait_for_capacity() {
            break;
        }
        if pending.is_empty() {
            // A sequence silent past the documented idle window may
            // have restarted its identifiers. Stop confirming the
            // stale high-water mark: polling from zero can only
            // redeliver updates the platform still holds unconfirmed,
            // while passing the stale offset would acknowledge the new
            // sequence's lower first ids unseen.
            if cursor.sequence_age.elapsed() >= config.poll_sequence_idle {
                cursor.offset = 0;
                cursor.sequence_age.reset();
            }
            let updates = match transport.get_updates(cursor.offset, config.poll_timeout_secs) {
                Ok(updates) => {
                    consecutive_failures = 0;
                    updates
                }
                Err(error) if error.code == "a4mc_telegram_conflict" => {
                    return Err(anyhow!("{}: {}", error.code, error.message));
                }
                Err(error) if error.code == "a4mc_telegram_unauthorized" => {
                    return Err(anyhow!("{}: {}", error.code, error.message));
                }
                Err(error) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= config.max_poll_failures.max(1) {
                        return Err(anyhow!("a4mc_telegram_poll_failed: {error}"));
                    }
                    // Recoverable failure: honor the platform's hint,
                    // exponential backoff otherwise; `stop` ends the wait.
                    let wait = retry_wait(consecutive_failures, error.retry_after);
                    if !wait_or_stop(wait, &config.stop) {
                        break;
                    }
                    continue;
                }
            };
            let mut tasks = Vec::new();
            let mut dropped = Vec::new();
            let mut admitted = Vec::new();
            let mut next_offset = cursor.offset;
            for update in updates {
                // The cursor is monotonic: a transport that redelivers an
                // update below the durable cursor must not drag the offset
                // back and replay already-confirmed turns. Telegram sends
                // ascending update ids, so a lower one is a stale replay.
                let next = update.update_id.saturating_add(1);
                if next <= cursor.offset {
                    continue;
                }
                // An update with no dispatchable message body (a
                // dice/game/service payload, or an unmapped update
                // type) is handed to the host hook when one is
                // mounted. Without a hook the id is persisted before
                // the cursor advances, so the gap is durable instead of
                // vanishing silently.
                match unhandled_kind(&update) {
                    Some(raw_kind) => {
                        let event = crate::lower::lower_event(&update);
                        if let Some(on_event) = on_event.as_mut() {
                            on_event(&event).map_err(|error| {
                                anyhow!("a4mc_telegram_unhandled_event: {error}")
                            })?;
                        } else {
                            dropped.push(DroppedUpdate {
                                update_id: update.update_id,
                                raw_kind: raw_kind.to_owned(),
                            });
                        }
                    }
                    None => {
                        if let Some(message) = update.message {
                            // Admit the task BEFORE the cursor confirms
                            // it: a crash after confirmation must find
                            // the work record, not a silent skip.
                            tasks.push(crate::binding::PendingUpdate {
                                update_id: update.update_id,
                                message: message.clone(),
                                reply: None,
                                next_session: None,
                            });
                            admitted.push(message);
                        }
                    }
                }
                next_offset = next;
            }
            if next_offset != cursor.offset {
                // One write confirms the cursor together with the work
                // records of the batch — confirmed updates are never
                // left without their task record, and a write failure
                // surfaces rather than silently recreating the
                // replay-a-restart bug it exists to prevent.
                store
                    .lock()
                    .unwrap()
                    .admit_updates(&tasks, &dropped, next_offset)?;
                cursor.offset = next_offset;
                cursor.sequence_age.reset();
                pending.extend(admitted);
            }
        }
        admit_available(scheduler, pending);
    }
    Ok(())
}

/// Classify an update the message-oriented runtime cannot dispatch.
/// Returns the raw platform kind for the durable record; `None` means a
/// normal message is queued for a worker.
fn unhandled_kind(update: &crate::transport::Update) -> Option<&'static str> {
    let Some(message) = update.message.as_ref() else {
        return Some("unmapped_update");
    };
    if message.kind != crate::inbound::InboundKind::Unsupported {
        return None;
    }
    let blank = |value: &Option<String>| {
        value
            .as_ref()
            .map(|text| text.trim().is_empty())
            .unwrap_or(true)
    };
    if blank(&message.text) && blank(&message.caption) {
        Some(message.kind.as_str())
    } else {
        None
    }
}

/// Next poll retry wait: exponential backoff (2s, doubling, capped)
/// with up-to-half jitter so restart waves don't synchronize. A
/// platform `retry_after` floor is honored at full length — only the
/// self-computed backoff is capped — so a retry never lands inside the
/// rate-limit window it was told to wait out; `stop` still ends the
/// wait early via `wait_or_stop`'s slices.
fn retry_wait(failures: u32, retry_after: Option<u64>) -> Duration {
    let base = 1u64 << failures.min(5);
    let jitter = OsRng.next_u64() % (base / 2 + 1);
    let own = (base + jitter).min(MAX_RETRY_WAIT_SECS);
    Duration::from_secs(own.max(retry_after.unwrap_or(0)))
}

/// Sleep `duration` in short slices so a raised `stop` ends the wait
/// early; returns `false` when `stop` interrupted it.
fn wait_or_stop(duration: Duration, stop: &AtomicBool) -> bool {
    const SLICE: Duration = Duration::from_millis(200);
    let mut remaining = duration;
    while !remaining.is_zero() {
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        let slice = remaining.min(SLICE);
        thread::sleep(slice);
        remaining -= slice;
    }
    !stop.load(Ordering::SeqCst)
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
        scheduler.wait_for_drain();
        admit_available(scheduler, pending);
    }
}

fn handle_inbound<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
    turn_deadline: Duration,
    stop: &AtomicBool,
) -> Result<()> {
    if !message.is_private {
        // The channel serves direct chats only; group traffic is ignored.
        return Ok(());
    }
    match parse_control_command(&message.control_text()) {
        ControlOutcome::Command(command) => {
            handle_command(channel, store, identity, message, command, stop)
        }
        ControlOutcome::OrdinaryText(_) => {
            let body = message.agent_text();
            if body.trim().is_empty() {
                return Ok(());
            }
            handle_ordinary(channel, store, message, &body, turn_deadline, stop)
        }
    }
}

/// The normalized send for one runtime-generated reply. `purpose`
/// distinguishes the reply produced by handling the update (`reply`)
/// from the fallback error report for the same update (`error`), so a
/// recorded agent reply can never be shadowed by an observed error
/// receipt under the same dedupe key.
fn reply_message(
    chat_id: i64,
    reply_to_message_id: i64,
    update_id: i64,
    purpose: &str,
    text: &str,
) -> a4mc::OutboundMessage {
    let mut outbound =
        a4mc::OutboundMessage::new(chat_id.to_string(), text, format!("{purpose}:{update_id}"));
    outbound.reply_to_message_id = Some(a4mc::ExternalMessageId::from(
        reply_to_message_id.to_string(),
    ));
    outbound
}

/// Retry floor for a policy deferral that carries no hint — modest
/// enough to close a batch window promptly, wide enough not to spin on
/// the host's send path.
const DEFERRED_RETRY_WAIT: Duration = Duration::from_secs(1);

/// Whether a channel rejection is the host's outbound policy holding
/// the send — a deferral waits out its hint and retries rather than
/// being reported to the user around the policy.
fn is_outbound_deferral(error: &a4mc::ChannelError) -> bool {
    matches!(
        error.code.as_str(),
        "a4mc_outbound_batched" | "a4mc_outbound_throttled"
    )
}

/// Whether a handler failure is only a policy deferral interrupted by
/// shutdown: no error reply fires around the policy and the unfinished
/// task record stays for the restart drain.
fn is_policy_deferral(error: &anyhow::Error) -> bool {
    matches!(
        error.to_string().split(':').next().map(str::trim),
        Some("a4mc_outbound_batched") | Some("a4mc_outbound_throttled")
    )
}

/// Drive one outbound send under the host's policy. A deferral waits
/// out its hinted window and retries — the policy holds the send, it is
/// not a failure to report; `stop` ends the wait and returns the
/// deferral error itself so the caller can keep the work record.
fn send_policy_wait<T: BotTransport>(
    channel: &TelegramChannel<T>,
    outbound: &a4mc::OutboundMessage,
    stop: &AtomicBool,
) -> Result<(), a4mc::ChannelError> {
    loop {
        match channel.send(outbound) {
            Ok(_) => return Ok(()),
            Err(error) if is_outbound_deferral(&error) => {
                let wait = error
                    .retry_after_ms
                    .map(Duration::from_millis)
                    .unwrap_or(DEFERRED_RETRY_WAIT);
                if !wait_or_stop(wait, stop) {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn send_reply<T: BotTransport>(
    channel: &TelegramChannel<T>,
    message: &InboundMessage,
    text: &str,
    stop: &AtomicBool,
) -> Result<()> {
    send_policy_wait(
        channel,
        &reply_message(
            message.chat_id,
            message.message_id,
            message.update_id,
            "reply",
            text,
        ),
        stop,
    )
    .map_err(channel_err)
}

fn handle_command<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
    command: ControlCommand,
    stop: &AtomicBool,
) -> Result<()> {
    match command {
        ControlCommand::Help => {
            send_reply(channel, message, &help_text(&identity.username), stop)?;
        }
        ControlCommand::Commands => {
            send_reply(channel, message, &commands_text(), stop)?;
        }
        ControlCommand::Start | ControlCommand::Pair => {
            handle_pair_request(channel, store, identity, message, stop)?;
        }
        ControlCommand::Whoami => {
            send_reply(channel, message, &whoami_text(message), stop)?;
        }
        ControlCommand::Unpair => {
            let revoked = store_revoke(store, message.chat_id)?;
            send_reply(
                channel,
                message,
                if revoked {
                    "Pairing revoked for this chat. Send /start to pair again."
                } else {
                    "No pairing found for this chat."
                },
                stop,
            )?;
        }
        ControlCommand::Status => {
            if !store_is_paired(store, message.chat_id, message.user_id)? {
                send_reply(
                    channel,
                    message,
                    "Not paired. Send /start to request a pairing code.",
                    stop,
                )?;
            } else {
                send_reply(
                    channel,
                    message,
                    &status_text(store, identity, message.chat_id)?,
                    stop,
                )?;
            }
        }
        ControlCommand::Agent { agent_id: None } => {
            require_paired(store, message)?;
            let agents = list_agents().map_err(|error| anyhow!(error.to_string()))?;
            send_reply(channel, message, &format_agent_list(&agents), stop)?;
        }
        ControlCommand::Agent {
            agent_id: Some(agent_id),
        } => {
            require_paired(store, message)?;
            ensure_known_agent(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            let binding = store_set_agent(store, message.chat_id, Some(agent_id.clone()))?;
            send_reply(
                channel,
                message,
                &format!(
                    "Bound agent: {}.\nSession cleared. Use /session or /new, then send a message.",
                    binding.agent_id.unwrap_or(agent_id)
                ),
                stop,
            )?;
        }
        ControlCommand::Session { selector: None } => {
            require_paired(store, message)?;
            let agent_id = require_agent(store, message.chat_id)?;
            let sessions = list_sessions(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            send_reply(channel, message, &format_session_list(&sessions), stop)?;
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
            send_reply(
                channel,
                message,
                &format!("Bound session: {session_id}"),
                stop,
            )?;
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
            let confirmation = format!(
                "Started a new conversation{}.",
                if opened.is_empty() {
                    String::new()
                } else {
                    format!(": {opened}")
                }
            );
            // Persist the finished command and its confirmation before
            // waiting on outbound policy: if shutdown interrupts a
            // deferral, recovery resumes delivery of this reply instead
            // of re-running the command and opening a second
            // conversation.
            store_record_reply(store, message.update_id, &confirmation, None)?;
            send_reply(channel, message, &confirmation, stop)?;
        }
        ControlCommand::Stop => {
            send_reply(
                channel,
                message,
                "This channel processes one turn at a time. There is no separate in-flight interrupt yet; wait for the current reply, or use /new for a fresh conversation.",
                stop,
            )?;
        }
        ControlCommand::Unknown { name } => {
            send_reply(
                channel,
                message,
                &format!("Unknown command /{name}. Use /commands for the catalog."),
                stop,
            )?;
        }
    }
    Ok(())
}

fn handle_pair_request<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    message: &InboundMessage,
    stop: &AtomicBool,
) -> Result<()> {
    if store_is_paired(store, message.chat_id, message.user_id)? {
        send_reply(
            channel,
            message,
            &format!(
                "Already paired.\n{}",
                status_text(store, identity, message.chat_id)?
            ),
            stop,
        )?;
        return Ok(());
    }
    let pending = store_request_pairing(
        store,
        message.chat_id,
        message.user_id,
        message.username.clone(),
    )?;
    send_reply(channel, message, &pairing_code_text(&pending.code), stop)?;
    Ok(())
}

fn handle_ordinary<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    message: &InboundMessage,
    text: &str,
    turn_deadline: Duration,
    stop: &AtomicBool,
) -> Result<()> {
    // One refresh, one snapshot: pairing and routing are checked
    // against the same read instead of re-loading the store twice for
    // every paired message.
    let Some(binding) = store_paired_binding(store, message.chat_id, message.user_id)? else {
        let pending = store_request_pairing(
            store,
            message.chat_id,
            message.user_id,
            message.username.clone(),
        )?;
        send_reply(
            channel,
            message,
            &format!("Pairing required.\n{}", pairing_code_text(&pending.code)),
            stop,
        )?;
        return Ok(());
    };
    let Some(agent_id) = binding.agent_id.clone() else {
        send_reply(
            channel,
            message,
            "No agent bound. Use /agent to list agents, then /agent <id>.",
            stop,
        )?;
        return Ok(());
    };
    let (reply, next_session) = send_turn(
        message.chat_id,
        &agent_id,
        binding.session_id.as_deref(),
        text,
        turn_deadline,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    // Record the finished reply on the admitted task before delivery or
    // the session write: an exit after the agent returned still has the
    // result to resend rather than losing paid work.
    let pending_session = if next_session.is_empty()
        || binding.session_id.as_deref() == Some(next_session.as_str())
    {
        None
    } else {
        Some(next_session.clone())
    };
    store_record_reply(store, message.update_id, &reply, pending_session)?;
    // Persist the new session before telling the user the turn
    // succeeded. If the store is unavailable (busy, read-only, full),
    // the next message must not silently route to the old session.
    if !next_session.is_empty() && binding.session_id.as_deref() != Some(next_session.as_str()) {
        store_set_session(store, message.chat_id, Some(next_session))?;
    }
    send_reply(channel, message, &reply, stop)?;
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

/// One refresh, one snapshot: pairing state and the routing binding are
/// read from the same document — no second locked reload per message.
fn store_paired_binding(
    store: &Mutex<BindingStore>,
    chat_id: i64,
    user_id: i64,
) -> Result<Option<ChatBinding>> {
    let mut guard = store.lock().unwrap();
    guard.refresh()?;
    Ok(guard
        .binding(chat_id)
        .filter(|binding| binding.paired && binding.user_id == user_id)
        .cloned())
}

fn store_record_reply(
    store: &Mutex<BindingStore>,
    update_id: i64,
    reply: &str,
    next_session: Option<String>,
) -> Result<()> {
    store
        .lock()
        .unwrap()
        .record_reply(update_id, reply, next_session)
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

fn channel_err(error: a4mc::ChannelError) -> anyhow::Error {
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
    use crate::transport::{MockBotTransport, SendProgress, TelegramApiError, Update};
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::time::Instant;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Turn deadline for handler tests.
    const TEST_DEADLINE: Duration = Duration::from_secs(30);
    /// Text that makes the synthetic lane's dispatch outlive a tiny
    /// caller deadline, so the wait-and-deliver behavior is exercisable.
    const BLOCKING_TURN_TEXT: &str = "a4mc-block-turn";
    static LAST_TURN_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

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
        lane::clear();
        let _ = lane::install(LanePort {
            scan_targets,
            conversation_list: empty,
            open_or_resume: empty,
            dispatch: |operation, params| {
                LAST_TURN_TIMEOUT_MS.store(
                    params
                        .get("timeoutMs")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0),
                    Ordering::SeqCst,
                );
                if params.get("text").and_then(|value| value.as_str()) == Some(BLOCKING_TURN_TEXT) {
                    thread::sleep(Duration::from_millis(150));
                }
                let _ = operation;
                Ok(json!({"ok": true, "output": "synthetic", "sessionId": "synthetic"}))
            },
            outbound_hooks: None,
        });
    }

    /// A host policy that suppresses every outbound send: mounting it
    /// must silence command replies, agent replies and fallback errors
    /// alike, because they all travel the channel's pipeline.
    struct SkipAll;

    impl a4mc::OutboundHooks for SkipAll {
        fn skip(&self, _: &a4mc::SendContext, _: &a4mc::OutboundMessage) -> a4mc::SkipDecision {
            a4mc::SkipDecision::skip("host fixture policy")
        }
    }

    /// A host policy whose throttle budget holds the first `deferrals`
    /// send attempts inside a window of `retry_after_ms`, then allows
    /// the rest — `usize::MAX` deferrals holds every send so shutdown
    /// has to cut the wait short.
    struct DeferringHooks {
        attempts: AtomicUsize,
        deferrals: usize,
        retry_after_ms: u64,
    }

    impl a4mc::OutboundHooks for DeferringHooks {
        fn throttle(
            &self,
            _: &a4mc::SendContext,
            _: &a4mc::OutboundMessage,
        ) -> a4mc::ThrottleDecision {
            if self.attempts.fetch_add(1, Ordering::SeqCst) < self.deferrals {
                a4mc::ThrottleDecision::defer(
                    "send window open",
                    Some(Duration::from_millis(self.retry_after_ms)),
                )
            } else {
                a4mc::ThrottleDecision::Allow
            }
        }
    }

    fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// Fails the first `getUpdates` with a throttled error, then delegates
    /// to the inner mock. Lets the poll loop's 429 backoff and retry be
    /// exercised without a live Bot API.
    struct ThrottleOnceTransport {
        inner: MockBotTransport,
        get_updates_calls: AtomicUsize,
        retry_after: u64,
    }

    impl ThrottleOnceTransport {
        fn new(inner: MockBotTransport, retry_after: u64) -> Self {
            Self {
                inner,
                get_updates_calls: AtomicUsize::new(0),
                retry_after,
            }
        }
    }

    impl BotTransport for ThrottleOnceTransport {
        fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
            self.inner.get_me()
        }
        fn delete_webhook(&self) -> Result<(), TelegramApiError> {
            self.inner.delete_webhook()
        }
        fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
            self.inner.set_my_commands(commands)
        }
        fn get_updates(
            &self,
            offset: i64,
            timeout_secs: u64,
        ) -> Result<Vec<Update>, TelegramApiError> {
            if self.get_updates_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.inner.observed_offsets.lock().unwrap().push(offset);
                return Err(TelegramApiError::new(
                    "a4mc_telegram_throttled",
                    "getUpdates: Bot API rate limited",
                )
                .with_retry_after(Some(self.retry_after)));
            }
            self.inner.get_updates(offset, timeout_secs)
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            reply_to_message_id: Option<i64>,
            resume: Option<&SendProgress>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume)
        }
    }

    /// Replays its queued updates on the first call regardless of the
    /// supplied offset, then delegates. Models a transport/server that
    /// re-delivers below the durable cursor.
    struct ReplayOnceTransport {
        inner: MockBotTransport,
        replayed: AtomicBool,
    }

    impl ReplayOnceTransport {
        fn new(inner: MockBotTransport) -> Self {
            Self {
                inner,
                replayed: AtomicBool::new(false),
            }
        }
    }

    impl BotTransport for ReplayOnceTransport {
        fn get_me(&self) -> Result<BotIdentity, TelegramApiError> {
            self.inner.get_me()
        }
        fn delete_webhook(&self) -> Result<(), TelegramApiError> {
            self.inner.delete_webhook()
        }
        fn set_my_commands(&self, commands: &[(String, String)]) -> Result<(), TelegramApiError> {
            self.inner.set_my_commands(commands)
        }
        fn get_updates(
            &self,
            offset: i64,
            timeout_secs: u64,
        ) -> Result<Vec<Update>, TelegramApiError> {
            if !self.replayed.swap(true, Ordering::SeqCst) {
                self.inner.observed_offsets.lock().unwrap().push(offset);
                return Ok(self.inner.updates.lock().unwrap().drain(..).collect());
            }
            self.inner.get_updates(offset, timeout_secs)
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            reply_to_message_id: Option<i64>,
            resume: Option<&SendProgress>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume)
        }
    }

    #[test]
    fn start_issues_pairing_and_approve_enables_agent_command() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let transport = MockBotTransport {
            sent: sent.clone(),
            ..MockBotTransport::default()
        };
        let channel = TelegramChannel::new(Arc::new(transport));
        let message = text_message(99, 77, Some("bob"), "/start", 1);
        handle_inbound(
            &channel,
            &store,
            &BotIdentity::default(),
            &message,
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
        let code = store.lock().unwrap().pending_pairings()[0].code.clone();
        store.lock().unwrap().approve(&code).unwrap();
        let list = text_message(99, 77, Some("bob"), "/agent", 2);
        handle_inbound(
            &channel,
            &store,
            &BotIdentity::default(),
            &list,
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
        let messages = sent.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|(_, body)| body.contains("Pairing code"))
        );
        assert!(messages.iter().any(|(_, body)| {
            body.contains("Local agents") || body.contains("No local agents")
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
        let channel = TelegramChannel::new(Arc::new(transport));
        let identity = BotIdentity {
            username: "a4mc_bot".into(),
            ..BotIdentity::default()
        };
        handle_inbound(
            &channel,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/whoami", 1),
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
        handle_inbound(
            &channel,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/start", 2),
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
        let code = store.lock().unwrap().pending_pairings()[0].code.clone();
        store.lock().unwrap().approve(&code).unwrap();
        handle_inbound(
            &channel,
            &store,
            &identity,
            &text_message(42, 42, Some("alice"), "/unpair", 3),
            TEST_DEADLINE,
            &AtomicBool::new(false),
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
        let channel = TelegramChannel::new(Arc::new(transport));
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
        handle_inbound(
            &channel,
            &store,
            &BotIdentity::default(),
            &message,
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
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
        scheduler.shutdown();
        scheduler.mark_drained();
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
        scheduler.shutdown();
        scheduler.mark_drained();
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
    fn restart_resumes_the_persisted_poll_cursor() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        {
            let transport = MockBotTransport {
                sent: Arc::clone(&sent),
                ..MockBotTransport::default()
            };
            transport.updates.lock().unwrap().extend([
                Update {
                    update_id: 1,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 1)),
                },
                Update {
                    update_id: 2,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 2)),
                },
            ]);
            let stop = Arc::new(AtomicBool::new(false));
            let store = BindingStore::open_in(&root).unwrap();
            let config = RuntimeConfig {
                poll_timeout_secs: 1,
                stop: Arc::clone(&stop),
                ..RuntimeConfig::default()
            };
            let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
            wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
            stop.store(true, Ordering::SeqCst);
            handle.join().unwrap();
            assert_eq!(
                BindingStore::open_in(&root).unwrap().poll_offset(),
                3,
                "poll cursor was not durably recorded"
            );
        }

        sent.lock().unwrap().clear();
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            observed_offsets: Arc::clone(&observed_offsets),
            ..MockBotTransport::default()
        };
        transport.updates.lock().unwrap().extend([
            // Stale re-delivery below the cursor must not be re-served.
            Update {
                update_id: 1,
                message: Some(text_message(42, 42, Some("alice"), "/whoami", 1)),
            },
            Update {
                update_id: 5,
                message: Some(text_message(9, 9, Some("zed"), "/whoami", 5)),
            },
        ]);
        let stop = Arc::new(AtomicBool::new(false));
        let store = BindingStore::open_in(&root).unwrap();
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let offsets = observed_offsets.lock().unwrap();
        assert_eq!(
            offsets.first(),
            Some(&3),
            "restart polled below the durable cursor: {offsets:?}"
        );
        assert!(
            offsets.iter().all(|offset| *offset >= 3),
            "restart replayed confirmed updates: {offsets:?}"
        );
        let messages = sent.lock().unwrap();
        assert_eq!(
            messages.len(),
            1,
            "stale update was re-served: {messages:?}"
        );
        assert_eq!(messages[0].0, 9);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn restart_reserves_queued_and_recorded_reply_work() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The replies resumed here must not run under a policy another
        // test left mounted on the process-wide lane port.
        a4mc::lane::clear();
        // A crash after the batch write left one admitted-but-unstarted
        // message and one finished-but-undelivered reply behind the
        // durable cursor. Neither may be skipped on the next run.
        let root = temp_root();
        let queued = text_message(42, 42, Some("alice"), "/whoami", 1);
        let recorded = text_message(43, 43, Some("bob"), "hello agent", 2);
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[
                        crate::binding::PendingUpdate {
                            update_id: 1,
                            message: queued,
                            reply: None,
                            next_session: None,
                        },
                        crate::binding::PendingUpdate {
                            update_id: 2,
                            message: recorded,
                            reply: Some("agent reply".to_owned()),
                            next_session: None,
                        },
                    ],
                    &[],
                    3,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let messages = sent.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|(chat, text)| *chat == 42 && text.contains("chatId: 42")),
            "the queued update was skipped on restart: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|(chat, text)| *chat == 43 && text == "agent reply"),
            "the recorded reply was not delivered on restart: {messages:?}"
        );
        drop(messages);
        let reopened = BindingStore::open_in(&root).unwrap();
        assert!(
            reopened.pending_updates().is_empty(),
            "resumed work stayed recorded after delivery"
        );
        assert_eq!(reopened.poll_offset(), 3);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn channel_loop_routes_every_runtime_reply_through_the_mounted_policy() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        // A paired chat bound to an agent, so the "hello" update takes the
        // agent-reply path; /whoami takes the command-reply path; /agent on
        // an unpaired chat takes the fallback error-reply path.
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            observed_offsets: Arc::clone(&observed_offsets),
            updates: Arc::new(Mutex::new(vec![
                Update {
                    update_id: 1,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 1)),
                },
                Update {
                    update_id: 2,
                    message: Some(text_message(7, 7, Some("zed"), "/agent", 2)),
                },
                Update {
                    update_id: 3,
                    message: Some(text_message(42, 42, Some("alice"), "hello", 3)),
                },
            ])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(Arc::new(SkipAll)),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // Every admitted task finishing — replies suppressed — is the
        // signal that all three reply paths ran under the policy. The
        // pending set alone cannot say that: it is also empty before the
        // first batch lands, which would stop the loop before any poll.
        wait_until(
            || {
                let store = BindingStore::open_in(&root).unwrap();
                store.poll_offset() == 4 && store.pending_updates().is_empty()
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(
            sent.lock().unwrap().is_empty(),
            "a mounted skip policy must suppress every runtime reply"
        );
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            4,
            "suppressed replies must not strand admitted work"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_deferred_reply_waits_out_the_policy_window() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(DeferringHooks {
            attempts: AtomicUsize::new(0),
            deferrals: 2,
            retry_after_ms: 20,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || {
                let store = BindingStore::open_in(&root).unwrap();
                store.poll_offset() == 6 && store.pending_updates().is_empty()
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            hooks.attempts.load(Ordering::SeqCst),
            3,
            "the deferred send was not retried after its window"
        );
        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1, "delivered sends: {messages:?}");
        assert_eq!(messages[0].1, "synthetic");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_policy_deferral_interrupted_by_shutdown_keeps_the_task() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(DeferringHooks {
            attempts: AtomicUsize::new(0),
            deferrals: usize::MAX,
            // A window far longer than the test: only `stop` releases
            // the parked send, proving the wait is interruptible.
            retry_after_ms: 60_000,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let started = Instant::now();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // Wait until the reply is parked inside the policy's window,
        // then end the runtime: join must not outlast the wait slices.
        wait_until(
            || hooks.attempts.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "shutdown did not interrupt the deferral wait"
        );

        assert!(
            sent.lock().unwrap().is_empty(),
            "a held reply must not be answered with an error around the policy"
        );
        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the deferred reply's task record was settled: {tasks:?}"
        );
        assert_eq!(tasks[0].reply.as_deref(), Some("synthetic"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_deferred_resumed_reply_retries_off_the_store_lock() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        message: text_message(43, 43, Some("bob"), "hello agent", 2),
                        reply: Some("agent reply".to_owned()),
                        next_session: None,
                    }],
                    &[],
                    3,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(DeferringHooks {
            attempts: AtomicUsize::new(0),
            deferrals: 1,
            retry_after_ms: 20,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(hooks.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(sent.lock().unwrap()[0], (43, "agent reply".to_owned()));
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the resumed reply stayed recorded after its deferred send"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Counts lane `open_or_resume` calls so a restart can be proven
    /// not to open a second conversation for one command.
    static OPEN_SESSION_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn install_open_counting_lane() {
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
        lane::clear();
        OPEN_SESSION_CALLS.store(0, Ordering::SeqCst);
        let _ = lane::install(LanePort {
            scan_targets,
            conversation_list: empty,
            open_or_resume: |params| {
                OPEN_SESSION_CALLS.fetch_add(1, Ordering::SeqCst);
                let _ = params;
                Ok(json!({"sessionId": "counted-session"}))
            },
            dispatch: |_, _| {
                Ok(json!({"ok": true, "output": "synthetic", "sessionId": "synthetic"}))
            },
            outbound_hooks: None,
        });
    }

    #[test]
    fn a_deferred_fallback_reply_is_persisted_and_delivered_on_restart() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        // An unpaired chat's /agent fails admission; the fallback error
        // reply is the only outbound send the update earns.
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 2,
                message: Some(text_message(7, 7, Some("zed"), "/agent", 2)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(DeferringHooks {
            attempts: AtomicUsize::new(0),
            deferrals: usize::MAX,
            retry_after_ms: 60_000,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || hooks.attempts.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(sent.lock().unwrap().is_empty());
        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the interrupted fallback was not persisted: {tasks:?}"
        );
        assert!(
            tasks[0]
                .reply
                .as_deref()
                .is_some_and(|reply| reply.starts_with("Error:")),
            "the recorded reply is not the fallback report: {tasks:?}"
        );

        // Restart with the policy now allowing sends: the drain delivers
        // the recorded fallback instead of dropping the update unserved.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1, "delivered sends: {messages:?}");
        assert_eq!(messages[0].0, 7);
        assert!(
            messages[0].1.starts_with("Error:"),
            "the fallback report was not delivered on restart: {messages:?}"
        );
        drop(messages);
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered fallback stayed recorded"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_deferred_new_command_resumes_delivery_without_a_second_conversation() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_open_counting_lane();
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "/new", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(DeferringHooks {
            attempts: AtomicUsize::new(0),
            deferrals: usize::MAX,
            retry_after_ms: 60_000,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || hooks.attempts.load(Ordering::SeqCst) >= 1,
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            OPEN_SESSION_CALLS.load(Ordering::SeqCst),
            1,
            "the /new command did not open exactly one conversation"
        );
        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the deferred command was settled: {tasks:?}"
        );
        assert_eq!(
            tasks[0].reply.as_deref(),
            Some("Started a new conversation: counted-session."),
            "the finished command's confirmation was not persisted: {tasks:?}"
        );

        // Restart with sends unheld: recovery delivers the recorded
        // confirmation — it must not re-run /new and open a second
        // conversation.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            sent.lock().unwrap()[0],
            (
                42,
                "Started a new conversation: counted-session.".to_owned()
            )
        );
        assert_eq!(
            OPEN_SESSION_CALLS.load(Ordering::SeqCst),
            1,
            "recovery re-ran the command and opened a second conversation"
        );
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered confirmation stayed recorded"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_poll_does_not_advance_the_durable_cursor() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store.set_poll_offset(7).unwrap();
        let transport = MockBotTransport {
            fail_get_updates_with: Some(
                TelegramApiError::new("a4mc_telegram_throttled", "Bot API rate limited")
                    .with_retry_after(Some(1)),
            ),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            max_poll_failures: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_poll_failed"),
            "unexpected error: {error}"
        );
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            7,
            "a failed poll changed the durable cursor"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn throttled_poll_backs_off_then_retries_the_same_cursor() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = ThrottleOnceTransport::new(
            MockBotTransport {
                sent: Arc::clone(&sent),
                observed_offsets: Arc::clone(&observed_offsets),
                updates: Arc::new(Mutex::new(vec![Update {
                    update_id: 9,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 9)),
                }])),
                ..MockBotTransport::default()
            },
            0,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let started = Instant::now();
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(15));
        let elapsed = started.elapsed();
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        assert!(
            elapsed >= Duration::from_secs(2),
            "429 was retried without honoring the backoff: {elapsed:?}"
        );
        let offsets = observed_offsets.lock().unwrap();
        assert_eq!(
            offsets.first().copied(),
            Some(0),
            "initial cursor was not zero: {offsets:?}"
        );
        assert!(
            offsets.iter().take(2).all(|offset| *offset == 0),
            "cursor advanced on a throttled poll: {offsets:?}"
        );
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            10,
            "cursor was not persisted after the retried poll"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn message_less_update_is_reported_to_the_host_before_the_cursor_advances() {
        let root = temp_root();
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            observed_offsets: Arc::clone(&observed_offsets),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 20,
                message: None,
            }])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(Mutex::new(Vec::<a4mc::ChannelEvent>::new()));
        let observed_hook = Arc::clone(&observed);
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_event: Some(Box::new(move |event: &a4mc::ChannelEvent| {
                observed_hook.lock().unwrap().push(event.clone());
                Ok(())
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(
            || observed_offsets.lock().unwrap().contains(&21),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        let events = observed.lock().unwrap();
        assert_eq!(events.len(), 1, "the host did not observe the update");
        assert!(matches!(
            &events[0].update,
            a4mc::InboundUpdate::Unsupported { raw_kind } if raw_kind == "unmapped_update"
        ));
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            21,
            "a message-less update did not advance the cursor"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn message_less_update_is_durably_recorded_without_a_host_hook() {
        let root = temp_root();
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            observed_offsets: Arc::clone(&observed_offsets),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 20,
                message: None,
            }])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(
            || observed_offsets.lock().unwrap().contains(&21),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(reopened.poll_offset(), 21);
        let dropped = reopened.dropped_updates();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].update_id, 20);
        assert_eq!(dropped[0].raw_kind, "unmapped_update");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stale_transport_replay_is_not_served_twice() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store.set_poll_offset(5).unwrap();
        drop(store);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = ReplayOnceTransport::new(MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![
                // Below the durable cursor: a stale re-delivery.
                Update {
                    update_id: 3,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 3)),
                },
                // The only update that is actually new.
                Update {
                    update_id: 8,
                    message: Some(text_message(88, 88, Some("zoe"), "/whoami", 8)),
                },
            ])),
            ..MockBotTransport::default()
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        let messages = sent.lock().unwrap();
        assert_eq!(
            messages.len(),
            1,
            "stale replayed update was served: {messages:?}"
        );
        assert_eq!(messages[0].0, 88);
        drop(messages);
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            9,
            "cursor regressed or failed to advance past the fresh update"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn capacity_wait_unblocks_when_stop_is_raised() {
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Arc::new(Scheduler::new(1, Arc::clone(&stop)));
        // Fill admission without workers so capacity never frees.
        scheduler.enqueue(text_message(1, 1, None, "a", 1));
        let waiter = {
            let scheduler = Arc::clone(&scheduler);
            thread::spawn(move || scheduler.wait_for_capacity())
        };
        thread::sleep(Duration::from_millis(60));
        assert!(
            !waiter.is_finished(),
            "capacity wait returned while admission was full"
        );
        scheduler.shutdown();
        assert!(
            !waiter.join().unwrap(),
            "stop must end the capacity wait even with a full pipeline"
        );
    }

    #[test]
    fn retry_wait_caps_only_the_local_backoff_and_honors_the_server_floor() {
        assert_eq!(retry_wait(0, None), Duration::from_secs(1));
        for (failures, low, high) in [
            (1, 2, 3),
            (2, 4, 6),
            (3, 8, 12),
            (4, 16, 24),
            (5, 32, 48),
            // The exponent is capped: further failures do not grow it.
            (9, 32, 48),
        ] {
            let wait = retry_wait(failures, None);
            assert!(
                wait >= Duration::from_secs(low) && wait <= Duration::from_secs(high),
                "failure {failures} waited {wait:?}, outside {low}..={high}s"
            );
        }
        // The platform's floor raises the wait beyond computed backoff.
        assert!(retry_wait(1, Some(30)) >= Duration::from_secs(30));
        assert_eq!(retry_wait(1, Some(5)), Duration::from_secs(5));
        // A floor longer than the local cap is honored at full length —
        // retrying earlier lands inside the rate-limit window.
        assert!(retry_wait(8, Some(86_400)) >= Duration::from_secs(86_400));
        assert!(retry_wait(9, None) <= Duration::from_secs(MAX_RETRY_WAIT_SECS));
    }

    #[test]
    fn wait_or_stop_ends_the_sleep_early() {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(60));
            flag.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        assert!(!wait_or_stop(Duration::from_secs(30), &stop));
        assert!(started.elapsed() < Duration::from_secs(5));
        handle.join().unwrap();
        assert!(!wait_or_stop(Duration::ZERO, &stop));
    }

    #[test]
    fn persistent_poll_failures_surface_to_the_host() {
        let root = temp_root();
        let store = BindingStore::open_in(&root).unwrap();
        let transport = MockBotTransport {
            fail_get_updates_with: Some(TelegramApiError::new(
                "a4mc_telegram_network_failed",
                "getUpdates: transport failure",
            )),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            max_poll_failures: 2,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        // Before the failure budget the loop retried silently forever;
        // now the host sees `a4mc_telegram_poll_failed`.
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_poll_failed"),
            "unexpected error: {error}"
        );
        assert!(stop.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn turn_deadline_is_forwarded_and_the_lane_output_is_delivered() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
        store.approve(&pending.code).unwrap();
        store.set_agent(42, Some("codex".into())).unwrap();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let channel = TelegramChannel::new(Arc::new(transport));
        let started = Instant::now();
        handle_inbound(
            &channel,
            &store,
            &BotIdentity::default(),
            &text_message(42, 42, Some("alice"), BLOCKING_TURN_TEXT, 1),
            Duration::from_millis(50),
            &AtomicBool::new(false),
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed >= Duration::from_millis(100),
            "the runtime abandoned the lane at the local deadline: {elapsed:?}"
        );
        assert_eq!(
            LAST_TURN_TIMEOUT_MS.load(Ordering::SeqCst),
            50,
            "the deadline must be forwarded as timeoutMs, not enforced locally"
        );
        let messages = sent.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|(chat, text)| *chat == 42 && text == "synthetic"),
            "the lane output was not delivered: {messages:?}"
        );
        drop(messages);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn set_session_write_failure_is_returned_before_the_success_reply() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
        store.approve(&pending.code).unwrap();
        store.set_agent(42, Some("codex".into())).unwrap();
        store.set_session(42, Some("old-session".into())).unwrap();
        store.fail_next_write_for_test();
        let store = Mutex::new(store);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let channel = TelegramChannel::new(Arc::new(transport));

        let error = handle_inbound(
            &channel,
            &store,
            &BotIdentity::default(),
            &text_message(42, 42, Some("alice"), "hello", 1),
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("a4mc_telegram_state_write_failed"),
            "the session write failure was not propagated: {error}"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "the turn reported success before the new session was persisted"
        );
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

    #[test]
    fn an_expired_stored_sequence_accepts_a_lower_first_update_id() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store.set_poll_offset(50).unwrap();
        // The cursor's sequence has been silent past the documented
        // idle window: the platform may have restarted identifiers.
        store.age_poll_offset_for_test(8 * 24 * 60 * 60).unwrap();
        drop(store);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 3,
                message: Some(text_message(42, 42, Some("alice"), "/whoami", 3)),
            }])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        assert_eq!(sent.lock().unwrap().len(), 1);
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            4,
            "the restarted sequence's first id was discarded as stale"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_idle_stream_stops_confirming_the_stale_high_water_mark() {
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let updates = Arc::new(Mutex::new(vec![Update {
            update_id: 9,
            message: Some(text_message(42, 42, Some("alice"), "/whoami", 9)),
        }]));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            observed_offsets: Arc::clone(&observed_offsets),
            updates: Arc::clone(&updates),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            // The platform's documented idle window, compressed for the
            // fixture: past it, a lower id is the restarted sequence's
            // first update, not a stale replay.
            poll_sequence_idle: Duration::from_millis(60),
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        // The new sequence's first id sits below the stale high-water
        // mark; it is only deliverable once the poller stops passing
        // the old offset to the platform.
        updates.lock().unwrap().push(Update {
            update_id: 5,
            message: Some(text_message(88, 88, Some("zoe"), "/whoami", 5)),
        });
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        let offsets = observed_offsets.lock().unwrap();
        assert!(
            offsets.iter().skip(1).any(|offset| *offset == 0),
            "the stale cursor kept being confirmed after the idle window: {offsets:?}"
        );
        drop(offsets);
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            6,
            "the restarted sequence did not advance from its first id"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_rejected_event_holds_the_cursor_while_queued_work_settles() {
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let updates = Arc::new(Mutex::new(vec![Update {
            update_id: 8,
            message: Some(text_message(42, 42, Some("alice"), "/whoami", 8)),
        }]));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::clone(&updates),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_event: Some(Box::new(|_: &a4mc::ChannelEvent| {
                Err(anyhow!("fixture rejection"))
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        // The earlier message settles before the mixed batch arrives:
        // its durable record must complete, not replay.
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        updates.lock().unwrap().extend([
            Update {
                update_id: 20,
                message: Some(text_message(88, 88, Some("zoe"), "/whoami", 20)),
            },
            Update {
                update_id: 21,
                message: None,
            },
        ]);
        let error = handle.join().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_unhandled_event"),
            "unexpected error: {error}"
        );

        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened.poll_offset(),
            9,
            "the rejected update was confirmed past"
        );
        assert!(
            reopened.pending_updates().is_empty(),
            "settled and unadmitted work must leave no record"
        );
        drop(reopened);
        assert_eq!(sent.lock().unwrap().len(), 1);

        // The next run refetches from behind the rejected update: the
        // batched message is admitted then, not lost with its batch.
        let events = Arc::new(Mutex::new(Vec::<a4mc::ChannelEvent>::new()));
        let observed = Arc::clone(&events);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![
                Update {
                    update_id: 20,
                    message: Some(text_message(88, 88, Some("zoe"), "/whoami", 20)),
                },
                Update {
                    update_id: 21,
                    message: None,
                },
            ])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_event: Some(Box::new(move |event: &a4mc::ChannelEvent| {
                observed.lock().unwrap().push(event.clone());
                Ok(())
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        assert_eq!(events.lock().unwrap().len(), 1);
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            22,
            "the refetched batch did not confirm"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shutdown_drain_empties_the_fetched_queue_before_workers_exit() {
        let stop = Arc::new(AtomicBool::new(false));
        // Admission one at a time: the drain has to wait for a worker
        // between every enqueue, so workers leaving early parks it
        // forever.
        let scheduler = Arc::new(Scheduler::new(1, Arc::clone(&stop)));
        let done = Arc::new(Mutex::new(Vec::<i64>::new()));
        let processor = {
            let done = Arc::clone(&done);
            move |_chat_id: i64, message: InboundMessage| -> Result<()> {
                done.lock().unwrap().push(message.message_id);
                Ok(())
            }
        };
        let workers = scheduler.spawn_workers(1, processor).unwrap();
        scheduler.enqueue(text_message(1, 1, None, "a", 1));
        scheduler.shutdown();
        // With `stop` already raised, workers could be gone before this
        // drain admits the fetched remainder: the second message would
        // sit behind a full admission bound with nobody left to free it.
        let mut pending = VecDeque::from([
            text_message(2, 2, None, "b", 2),
            text_message(3, 3, None, "c", 3),
        ]);
        drain_pending(&scheduler, &mut pending);
        scheduler.mark_drained();
        for handle in workers {
            handle.join().unwrap();
        }
        let mut processed = done.lock().unwrap().clone();
        processed.sort_unstable();
        assert_eq!(processed, vec![1, 2, 3]);
    }

    #[test]
    fn an_observer_failure_mid_batch_leaves_every_ordinary_update_for_refetch() {
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // Two ordinary updates followed by an undispatchable one in the
        // same fetched batch: the observer rejection must hold the
        // cursor behind all three without stranding the ordinary work.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![
                Update {
                    update_id: 11,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 11)),
                },
                Update {
                    update_id: 12,
                    message: Some(text_message(43, 43, Some("bob"), "/whoami", 12)),
                },
                Update {
                    update_id: 13,
                    message: None,
                },
            ])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_event: Some(Box::new(|_: &a4mc::ChannelEvent| {
                Err(anyhow!("fixture rejection"))
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        // Returning at all proves the shutdown path did not strand the
        // batch's queue remainder behind workers that had already left.
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_unhandled_event"),
            "unexpected error: {error}"
        );
        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened.poll_offset(),
            0,
            "the rejected batch was confirmed past"
        );
        assert!(reopened.pending_updates().is_empty());
        drop(reopened);
        assert!(
            sent.lock().unwrap().is_empty(),
            "the rejected batch's ordinary updates must be refetched, not served"
        );

        // The next run refetches from behind the rejected update and
        // serves both ordinary messages.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![
                Update {
                    update_id: 11,
                    message: Some(text_message(42, 42, Some("alice"), "/whoami", 11)),
                },
                Update {
                    update_id: 12,
                    message: Some(text_message(43, 43, Some("bob"), "/whoami", 12)),
                },
                Update {
                    update_id: 13,
                    message: None,
                },
            ])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_event: Some(Box::new(|_: &a4mc::ChannelEvent| Ok(()))),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            14,
            "the refetched batch did not confirm past its last update"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
