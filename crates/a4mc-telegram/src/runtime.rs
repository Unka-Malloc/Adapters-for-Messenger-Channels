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
use super::transport::{BotIdentity, BotTransport, InboundMessage, SendProgress, bot_commands};
use crate::binding::{BindingStore, ChatBinding, DroppedUpdate, StrandedReply, TaskKey};
use crate::control::{
    ControlCommand, ControlOutcome, commands_text, help_text, parse_control_command,
};
use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
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
    /// Host observer for a durably-retained reply the runtime cannot
    /// currently deliver or reconcile — an unreadable sidecar, an
    /// ambiguous or mismatched send checkpoint, or a staged completion
    /// that still cannot commit. The hook receives the update id and
    /// the stable refusal code, never reply content; the pending record
    /// is retained for the next restart either way.
    pub on_stuck: Option<OnStuck>,
}

/// The readiness hook invoked once after a successful Bot API handshake.
pub type OnStarted = Box<dyn FnOnce(&BotIdentity) + Send>;
/// The host observer for updates this runtime cannot dispatch as a
/// message. Returning an error leaves the durable cursor before the
/// update, so it is redelivered rather than acknowledged unseen.
pub type OnEvent = Box<dyn FnMut(&a4mc::ChannelEvent) -> Result<()> + Send>;
/// The host observer for a retained reply that needs reconciliation —
/// reported by update id and stable refusal code only.
pub type OnStuck = Box<dyn FnMut(&StrandedReply) + Send>;

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
            on_stuck: None,
        }
    }
}

/// One unit of scheduler work: a fetched message to process, or a
/// durably-recorded reply owed a resend after restart. Both travel
/// the one bounded admission path in the order their records admit —
/// a resend keeps its chat's FIFO position relative to everything
/// older, it can never run ahead of an older message for the same
/// chat, and its deadline and policy waits occupy only its own chat
/// lane and one admission slot.
enum Scheduled {
    /// A polled or recovered message — `key` is the sequence-scoped
    /// claim its durable record committed under.
    Message {
        key: TaskKey,
        message: Box<InboundMessage>,
    },
    /// A recorded reply restart recovery re-queues — only the durable
    /// task record travels: the reply body is loaded once the job
    /// reaches a worker, so a deep backlog of spilled sidecar replies
    /// is never resident in memory at once. The worker waits its
    /// persisted deadline, resumes at the checkpoint and settles the
    /// record on delivery.
    Resend {
        task: Box<crate::binding::PendingUpdate>,
    },
}

struct SchedulerState {
    per_chat: HashMap<i64, VecDeque<Scheduled>>,
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
    /// Test-only: the worker index whose spawn must fail, so the
    /// partial-startup cleanup can be exercised deterministically.
    /// `usize::MAX` means every spawn runs normally.
    #[cfg(test)]
    fail_spawn_at: AtomicUsize,
}

impl Scheduler {
    fn new(max_admitted: usize, stop: Arc<AtomicBool>) -> Self {
        Self {
            state: Mutex::new(SchedulerState::new()),
            wake: Condvar::new(),
            stop,
            max_admitted,
            #[cfg(test)]
            fail_spawn_at: AtomicUsize::new(usize::MAX),
        }
    }

    #[cfg(test)]
    fn fail_spawn_at_for_test(&self, index: usize) {
        self.fail_spawn_at.store(index, Ordering::SeqCst);
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

    fn push(state: &mut SchedulerState, job: Scheduled) {
        let chat_id = match &job {
            Scheduled::Message { message, .. } => message.chat_id,
            Scheduled::Resend { task, .. } => task.message.chat_id,
        };
        state.per_chat.entry(chat_id).or_default().push_back(job);
        state.admitted += 1;
        if !state.queued.contains(&chat_id) && !state.inflight.contains(&chat_id) {
            state.ready.push_back(chat_id);
            state.queued.insert(chat_id);
        }
    }

    /// Tests push straight onto the ready queues to drive worker
    /// behavior; the live producers share `try_enqueue`'s atomic
    /// admission instead.
    #[cfg(test)]
    fn enqueue(&self, job: Scheduled) {
        let mut state = self.state.lock().unwrap();
        Self::push(&mut state, job);
        self.wake.notify_one();
    }

    /// Admit one job only while a slot is free — every producer runs
    /// this same check-and-push under the state lock, so the poller's
    /// backlog drain and a worker's recovered-reply queueing can never
    /// race each other past `max_admitted`. `Err(job)` once the
    /// pipeline is full or drained: the caller keeps the job in its
    /// backlog (or re-stages the record) instead of enqueueing past
    /// the bound.
    fn try_enqueue(&self, job: Scheduled) -> std::result::Result<(), Scheduled> {
        let mut state = self.state.lock().unwrap();
        if state.drained || state.admitted >= self.max_admitted {
            return Err(job);
        }
        Self::push(&mut state, job);
        self.wake.notify_one();
        Ok(())
    }

    /// Spawn the worker pool, reporting processor failures through
    /// `failures` — the first error a worker surfaces is the one the
    /// supervising loop returns. If a later thread fails to spawn, the
    /// workers already started are shut down, drained and joined
    /// before the spawn error returns: returning bare would drop the
    /// handles and leave those workers parked on a scheduler whose
    /// queue is never marked drained.
    fn spawn_workers<F>(
        self: &Arc<Self>,
        worker_count: usize,
        processor: F,
        failures: Arc<Mutex<Option<anyhow::Error>>>,
    ) -> Result<Vec<thread::JoinHandle<()>>>
    where
        F: Fn(i64, Scheduled) -> Result<()> + Send + Sync + 'static,
    {
        let processor = Arc::new(processor);
        let mut handles = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let scheduler = Arc::clone(self);
            let processor = Arc::clone(&processor);
            let failures = Arc::clone(&failures);
            let builder = thread::Builder::new().name(format!("a4mc-telegram-worker-{index}"));
            #[cfg(test)]
            let builder = if self.fail_spawn_at.load(Ordering::SeqCst) == index {
                // An impossible stack reservation fails the spawn the
                // same way an exhausted thread budget does.
                builder.stack_size(usize::MAX)
            } else {
                builder
            };
            let spawned = builder.spawn(move || worker_loop(scheduler, processor, failures));
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    self.shutdown();
                    self.mark_drained();
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(anyhow!("a4mc_telegram_runtime_spawn_failed"));
                }
            }
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

fn worker_loop<F>(
    scheduler: Arc<Scheduler>,
    processor: Arc<F>,
    failures: Arc<Mutex<Option<anyhow::Error>>>,
) where
    F: Fn(i64, Scheduled) -> Result<()> + Send + Sync + 'static,
{
    loop {
        let (chat_id, job) = {
            let mut state = scheduler.state.lock().unwrap();
            loop {
                if let Some(chat_id) = state.ready.pop_front() {
                    state.queued.remove(&chat_id);
                    let job = state
                        .per_chat
                        .get_mut(&chat_id)
                        .expect("ready chats have a queued job")
                        .pop_front()
                        .expect("ready chats have a queued job");
                    if state.per_chat.get(&chat_id).is_none_or(VecDeque::is_empty) {
                        state.per_chat.remove(&chat_id);
                    }
                    state.inflight.insert(chat_id);
                    break (chat_id, job);
                }
                if state.drained {
                    return;
                }
                state = scheduler.wake.wait(state).unwrap();
            }
        };
        // A processor failure is a persistence failure the task's
        // durable record survived: record the first one for the
        // supervising loop and raise stop so the run drains and exits
        // instead of continuing on a store that cannot take writes.
        if let Err(error) = processor(chat_id, job) {
            failures.lock().unwrap().get_or_insert(error);
            scheduler.shutdown();
        }
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
    mut store: BindingStore,
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
        expired_sequence: None,
    };
    cursor.offset = if cursor.sequence_age.elapsed() >= config.poll_sequence_idle {
        // The confirmed id sequence is dead: claims minted under it —
        // settled ids and pending-event markers — retire in one write,
        // while outstanding tasks and staged records keep their
        // dead-sequence keys so a restarted numbering's reused ids can
        // never collide with them.
        cursor.expired_sequence = Some(store.poll_sequence());
        store.expire_sequence()?;
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

    // Host observer for stranded replies — shared between startup
    // recovery and the live workers, so a reply that strands during
    // ordinary processing is surfaced exactly like one found at
    // restart.
    let on_stuck = Arc::new(Mutex::new(config.on_stuck.take()));
    // The first persistence failure a worker surfaces — its durable
    // task record is retained either way — is the error the
    // supervising loop returns after the drain.
    let worker_failure = Arc::new(Mutex::new(None::<anyhow::Error>));
    let processor_channel = Arc::clone(&channel);
    let processor_store = Arc::clone(&store);
    let processor_scheduler = Arc::clone(&scheduler);
    let processor_identity = identity.clone();
    let processor_stop = Arc::clone(&config.stop);
    let processor_stuck = Arc::clone(&on_stuck);
    let turn_deadline = config.turn_deadline;
    let processor = move |chat_id: i64, job: Scheduled| -> Result<()> {
        let result = match job {
            Scheduled::Resend { task } => {
                // Reload the durable record: a queued wait may span
                // another attempt's writes — retrying the stale
                // snapshot would repost confirmed work or skip a
                // deadline the platform just imposed.
                let task = processor_store
                    .lock()
                    .unwrap()
                    .pending_update(task.key())
                    .unwrap_or(*task);
                // One clock reading decides both whether a wait is owed
                // and how long it lasts — a second read between them can
                // never shorten the deadline's tail into a negative
                // wait. Shutdown cutting the wait keeps the record and
                // its deadline for the next restart.
                let now = now_millis();
                if let Some(deadline) = task.reply_retry_at_ms.filter(|at| *at > now)
                    && !wait_or_stop(Duration::from_millis(deadline - now), &processor_stop)
                {
                    return Ok(());
                }
                // The reply body is read only now that the job has a
                // worker: recovery queued the claim alone, so a backlog
                // of large spilled replies is never resident at once. A
                // record whose payload cannot be resolved stays
                // unfinished — settling over a paid result is never
                // allowed — and the host is told it is stuck.
                let resolved = match processor_store.lock().unwrap().resolve_reply(&task) {
                    Ok(Some(resolved)) => resolved,
                    Ok(None) => {
                        notify_stuck(&processor_stuck, task.key(), "a4mc_telegram_reply_lost");
                        return Ok(());
                    }
                    Err(error) => {
                        notify_stuck(&processor_stuck, task.key(), &failure_code(&error));
                        // The resolve can commit durable state — a
                        // lapsed offer's refusal — so its failures are
                        // not all payload reads: a store write failure
                        // reaches the supervising loop exactly like a
                        // delivery persistence failure, instead of
                        // parking the task until a restart.
                        if is_resolve_write_failure(&error) {
                            return Err(error);
                        }
                        return Ok(());
                    }
                };
                let delivery_key = task
                    .reply_key
                    .clone()
                    .unwrap_or_else(|| reply_key(task.key(), "reply"));
                match deliver_recorded_reply(
                    &processor_channel,
                    &processor_store,
                    task.message.chat_id,
                    task.message.message_id,
                    task.key(),
                    &delivery_key,
                    &resolved.text,
                    resolved.sent,
                    resolved.progress.clone(),
                    true,
                    &processor_stop,
                ) {
                    Ok(()) => processor_store.lock().unwrap().complete_update(task.key()),
                    Err(error) if is_interrupted_send_wait(&error) => Ok(()),
                    // A delivery failure keeps its record — and the
                    // checkpoint it earned — for the next restart's
                    // resend; the host is told. A persistence failure
                    // is routed to the supervising loop.
                    Err(error) => {
                        notify_stuck(&processor_stuck, task.key(), &failure_code(&error));
                        if is_store_write_failure(&error) {
                            Err(error)
                        } else {
                            Ok(())
                        }
                    }
                }
            }
            Scheduled::Message { key, message } => {
                match handle_inbound(
                    &processor_channel,
                    &processor_store,
                    &processor_identity,
                    key,
                    &message,
                    turn_deadline,
                    &processor_stop,
                ) {
                    Ok(()) => processor_store.lock().unwrap().complete_update(key),
                    // A reply the host's send policy was still holding when
                    // shutdown cut the wait short is not a handler failure: no
                    // error reply goes out around the policy, and the
                    // unfinished task record stays for the restart drain.
                    Err(error) if is_interrupted_send_wait(&error) => Ok(()),
                    // A persistence failure is not a turn failure: the
                    // fallback path must never write over it — a
                    // settlement write that lands after a reply-record
                    // failure would settle work whose result was never
                    // recorded, and the supervisor would never see the
                    // original error. The task stays claimed for
                    // recovery either way. Exactly one shape stays
                    // nonfatal: a completion whose staged record is
                    // durable but still UNBOUND — it could not fit the
                    // document — since it binds on recovery, so
                    // reporting it and continuing is the established
                    // contract. A state-full refusal on any later write
                    // — a checkpoint or retry deadline that no longer
                    // fits — is a different failure even though the
                    // task's own bound record still sits in the staged
                    // directory as its payload: it reaches the
                    // supervising loop as the resend and fallback paths
                    // surface theirs, because polling must not continue
                    // on a store that cannot take writes.
                    Err(error) if is_persistence_failure(&error) => {
                        report_stranded(
                            &processor_store,
                            &processor_stuck,
                            key,
                            &failure_code(&error),
                        );
                        let durable_staged = failure_code(&error) == "a4mc_telegram_state_full"
                            && processor_store.lock().unwrap().staged_reply_unbound(key);
                        if durable_staged { Ok(()) } else { Err(error) }
                    }
                    Err(error) => handle_failed_inbound(
                        &processor_channel,
                        &processor_store,
                        &processor_stuck,
                        chat_id,
                        key,
                        &message,
                        &error,
                        &processor_stop,
                    ),
                }
            }
        };
        // A mutation this job committed can newly bind a staged reply
        // that could not fit before — a completed task freeing
        // document space is exactly what lets a record stranded since
        // startup land. Each newly bound reply is queued once for
        // resend on its own chat lane, so a reply that became
        // deliverable never waits for a restart; whatever the
        // admission bound cannot take stays re-staged for the
        // poller's backlog drain.
        let mut rest = Vec::new();
        for task in processor_store.lock().unwrap().take_bound_replies() {
            let key = task.key();
            if processor_scheduler
                .try_enqueue(Scheduled::Resend {
                    task: Box::new(task),
                })
                .is_err()
            {
                rest.push(key);
            }
        }
        if !rest.is_empty() {
            processor_store.lock().unwrap().restage_bound_replies(rest);
        }
        result
    };

    let mut pending: VecDeque<Scheduled> = VecDeque::new();
    // Bind staged completions first: a reply whose payload, key and
    // effect were staged but whose document pointer never committed is
    // recovered by its claim key here instead of re-running its work —
    // delivery key and session change come back with it. Whatever
    // could not bind is surfaced to the host while its record stays:
    // it is never silently parked and never re-dispatched.
    // The scrutinee's guard must drop before the fallback can lock
    // again — holding it through the match deadlocks the Err arm.
    let reconciled = store.lock().unwrap().reconcile_staged();
    let stranded: Vec<StrandedReply> = match reconciled {
        Ok(stranded) => stranded,
        Err(_) => store
            .lock()
            .unwrap()
            .staged_update_keys()
            .into_iter()
            .map(|key| StrandedReply {
                update_id: key.update_id,
                sequence: key.sequence,
                code: "a4mc_telegram_state_full".to_owned(),
            })
            .collect(),
    };
    let staged: HashSet<TaskKey> = stranded
        .iter()
        .map(|item| TaskKey::new(item.sequence, item.update_id))
        .collect();
    // Events the cursor confirmed past but whose callbacks never ran —
    // the lowered event cannot be replayed, so each becomes its
    // durable dropped record instead of vanishing on restart. A marker
    // at or above the cursor is still refetchable and stays for the
    // redelivered callback.
    store.lock().unwrap().settle_unconsumed_events()?;
    // Alerts come out of the final recovery state, not the earlier
    // snapshot: the settle's own write can free the room a stranded
    // reply was waiting on and bind it — the resend queue below
    // already carries it — so only a record still unbound reaches the
    // host.
    for item in &stranded {
        let key = TaskKey::new(item.sequence, item.update_id);
        // Only a record still stranded in the final durable state
        // reaches the host: the settle's write can bind the record the
        // earlier snapshot could not — its resend is queued below —
        // and a task already carrying its finished reply is delivered
        // work, not a stranded record. The task's own reply state is
        // the gate — a manifest too corrupt to parse can never bind
        // its payload, so gating on a readable record would suppress
        // exactly the alert the stored code exists to carry.
        let store = store.lock().unwrap();
        if store
            .pending_update(key)
            .is_none_or(|task| !task.has_reply())
        {
            notify_stuck(&on_stuck, key, &item.code);
        }
    }
    // Resume admitted-but-unfinished work before polling — on the same
    // bounded admission path polled messages take: recovered replies
    // and unstarted messages enter the backlog in record order, so
    // recovery cannot exceed the admission bound, cannot leapfrog an
    // older record for the same chat, and a held reply occupies only
    // its own chat lane once a worker takes it. Records survive only
    // while their stage is unfinished, so nothing paid or already
    // confirmed runs twice; the binding's routing is already committed
    // — recovery only re-delivers, it never re-applies a superseded
    // change. Only the claim decides the lane: a finished reply's
    // body — possibly several MiB spilled to a sidecar — is loaded by
    // the worker that takes the job, not eagerly here, so the whole
    // backlog's payloads are never resident at once. Replies bound by
    // the recovery writes above are covered by this same snapshot —
    // drop them from the newly-bound drain so only binds landing
    // after startup reach the resend path.
    let _ = store.lock().unwrap().take_bound_replies();
    let unfinished = store.lock().unwrap().pending_updates();
    for task in unfinished {
        // Only a task whose staged reply is still unbound waits for the
        // space its record needs: one the recovery writes bound — an
        // event settle freeing its room — already holds a finished
        // reply and joins the resend queue like any other recovered
        // work; the earlier stranded snapshot must not keep it out.
        if staged.contains(&task.key()) && !task.has_reply() {
            continue;
        }
        if task.has_reply() {
            pending.push_back(Scheduled::Resend {
                task: Box::new(task),
            });
        } else {
            pending.push_back(Scheduled::Message {
                key: task.key(),
                message: Box::new(task.message.clone()),
            });
        }
    }
    // Workers spawn only after every recovery write has run: a
    // recovery failure that returns early can never strand spawned
    // workers without shutdown and join.
    let workers =
        scheduler.spawn_workers(config.worker_count, processor, Arc::clone(&worker_failure))?;
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
    if let Some(error) = worker_failure.lock().unwrap().take() {
        return Err(error);
    }
    poll_result?;
    Ok(identity)
}

/// A message the handler failed on: the fallback error report is
/// persisted — under the delivery key its first send attempt carries
/// — BEFORE delivery, so a mid-send exit leaves a resumable record
/// the restart drain resends under the same key, and host policy and
/// dedupe see one logical send. The record only lands while the task
/// holds no finished reply — a paid agent result is never shadowed —
/// and every failed write surfaces with the stranded reply still
/// reported to the host first, instead of the error being dropped on
/// the way out.
#[allow(clippy::too_many_arguments)]
fn handle_failed_inbound<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    on_stuck: &Mutex<Option<OnStuck>>,
    chat_id: i64,
    key: TaskKey,
    message: &InboundMessage,
    error: &anyhow::Error,
    stop: &AtomicBool,
) -> Result<()> {
    let delivery_key = reply_key(key, "error");
    let text = sanitize_error(error);
    let recorded = store
        .lock()
        .unwrap()
        .record_fallback_reply(key, &text, &delivery_key);
    let recorded = match recorded {
        Ok(recorded) => recorded,
        Err(write) => {
            report_stranded(store, on_stuck, key, &failure_code(&write));
            return Err(write);
        }
    };
    let delivery = if recorded {
        deliver_recorded_reply(
            channel,
            store,
            chat_id,
            message.message_id,
            key,
            &delivery_key,
            &text,
            0,
            None,
            true,
            stop,
        )
    } else {
        // The slot already holds a finished agent reply the report
        // must not shadow — and must not earn delivery progress on
        // either.
        deliver_sends(
            channel,
            &reply_sends(chat_id, message.message_id, &delivery_key, &text),
            stop,
        )
        .map_err(channel_err)
    };
    // A persistence failure inside delivery — a progress or checkpoint
    // write that could not land — is not a refused send to settle
    // over: the record stays for recovery and the error reaches the
    // supervising loop, rather than being masked by a later
    // settlement write that happened to succeed.
    let delivery = match delivery {
        Err(delivery_error) if is_store_write_failure(&delivery_error) => {
            report_stranded(store, on_stuck, key, &failure_code(&delivery_error));
            return Err(delivery_error);
        }
        other => other,
    };
    // A fallback that was both recorded and delivered ends the task
    // outright; anything else — an undelivered report, or a finished
    // agent reply still owed — keeps its record for the restart
    // drain.
    if recorded && delivery.is_ok() {
        let settled = store.lock().unwrap().complete_update(key);
        if let Err(write) = settled {
            report_stranded(store, on_stuck, key, &failure_code(&write));
            return Err(write);
        }
        return Ok(());
    }
    let settled = store.lock().unwrap().settle_failed_update(key);
    if let Err(write) = settled {
        report_stranded(store, on_stuck, key, &failure_code(&write));
        return Err(write);
    }
    let code = match &delivery {
        Err(delivery_error) if recorded => failure_code(delivery_error),
        _ => failure_code(error),
    };
    report_stranded(store, on_stuck, key, &code);
    Ok(())
}

/// A live stranded outcome — a retained record still holding a
/// finished reply, committed or only staged — surfaces to the host
/// with the stable code, exactly like startup recovery, while its
/// checkpoint stays durable.
fn report_stranded(
    store: &Mutex<BindingStore>,
    on_stuck: &Mutex<Option<OnStuck>>,
    key: TaskKey,
    code: &str,
) {
    let stranded = {
        let store = store.lock().unwrap();
        store
            .pending_update(key)
            .is_some_and(|task| task.has_reply())
            || store.staged_reply_pending(key)
    };
    if stranded {
        notify_stuck(on_stuck, key, code);
    }
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

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
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
/// first ids are seen. Expiry is tracked per sequence — each new
/// numbering earns its own idle check, so a run that already rolled
/// over once still resyncs when the live sequence goes silent past the
/// window again.
struct PollCursor {
    offset: i64,
    sequence_age: SequenceAge,
    /// The sequence last retired — `None` while none has been.
    /// Expiry may fire only for a sequence that has not already been
    /// rolled over, so the check can never loop on a dead numbering.
    expired_sequence: Option<u64>,
}

fn poll_updates<T: BotTransport>(
    transport: &T,
    scheduler: &Scheduler,
    store: &Mutex<BindingStore>,
    config: &RuntimeConfig,
    cursor: &mut PollCursor,
    pending: &mut VecDeque<Scheduled>,
    on_event: &mut Option<OnEvent>,
) -> Result<()> {
    let mut consecutive_failures = 0u32;
    // Admission failures are counted independently of fetch failures:
    // a successful getUpdates must not reset the budget an update that
    // can never fit is burning through.
    let mut admission_failures = 0u32;
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
            let live_sequence = store.lock().unwrap().poll_sequence();
            if cursor.expired_sequence != Some(live_sequence)
                && cursor.offset != 0
                && cursor.sequence_age.elapsed() >= config.poll_sequence_idle
            {
                // The confirmed id sequence is dead and retires in one
                // write: the settled tail and pending-event markers
                // belong to it, and a restarted numbering may lawfully
                // reuse those ids — while dead-sequence tasks and staged
                // records keep their keys so the reused ids can never
                // collide with retained work. Each live sequence earns
                // its own idle check: a cursor this process resynced
                // still rolls over if ITS numbering later goes silent
                // past the window.
                cursor.expired_sequence = Some(live_sequence);
                store.lock().unwrap().expire_sequence()?;
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
            // Update ids the store already durably claimed in the live
            // sequence — admitted and still pending, or settled — must
            // never re-enter the scheduler: a cursor rolled back for a
            // rejected event refetches them, and re-running confirmed
            // work would pay for the same turn twice. Dead-sequence
            // records claim nothing here: a restarted numbering's
            // reused ids admit fresh work under the live sequence.
            let (claimed, sequence) = {
                let store = store.lock().unwrap();
                (store.claimed_update_ids(), store.poll_sequence())
            };
            let mut records = Vec::with_capacity(updates.len());
            let mut next_offset = cursor.offset;
            for update in &updates {
                // The cursor is monotonic: a transport that redelivers an
                // update below the durable cursor must not drag the offset
                // back and replay already-confirmed turns. Telegram sends
                // ascending update ids, so a lower one is a stale replay.
                let next = update.update_id.saturating_add(1);
                if next <= cursor.offset {
                    records.push(BatchRecord::Skip);
                    continue;
                }
                next_offset = next;
                // An update with no dispatchable message body (a
                // dice/game/service payload, or an unmapped update
                // type) is held for the host hook until its record
                // commits — callbacks run at the cursor boundary below,
                // never for an uncommitted suffix that a refetch would
                // replay. Without a hook the id is persisted before the
                // cursor advances, so the gap is durable instead of
                // vanishing silently.
                match unhandled_kind(update) {
                    Some(raw_kind) => {
                        if on_event.is_some() {
                            records.push(BatchRecord::Event {
                                key: TaskKey::new(sequence, update.update_id),
                                raw_kind,
                                event: Box::new(crate::lower::lower_event(update)),
                            });
                        } else {
                            records.push(BatchRecord::Dropped(DroppedUpdate {
                                update_id: update.update_id,
                                sequence,
                                raw_kind: raw_kind.to_owned(),
                            }));
                        }
                    }
                    None => {
                        if let Some(message) = update.message.clone() {
                            // Confirmed work refetched by a cursor
                            // rollback keeps its durable record and is
                            // never re-queued; only its cursor advance
                            // still needs this batch's write.
                            if claimed.contains(&update.update_id) {
                                records.push(BatchRecord::Skip);
                                continue;
                            }
                            // Admit the task BEFORE the cursor confirms
                            // it: a crash after confirmation must find
                            // the work record, not a silent skip. The
                            // record claims its id under the live
                            // sequence — a dead sequence's retained
                            // record can never mask it.
                            records.push(BatchRecord::Task(Box::new(
                                crate::binding::PendingUpdate {
                                    update_id: update.update_id,
                                    sequence,
                                    message,
                                    reply: None,
                                    reply_key: None,
                                    reply_sent: 0,
                                    reply_progress: None,
                                    reply_file: None,
                                    reply_retry_at_ms: None,
                                    reply_refused: false,
                                },
                            )));
                        } else {
                            records.push(BatchRecord::Skip);
                        }
                    }
                }
            }
            if next_offset != cursor.offset {
                // Each write confirms the cursor only through the work
                // records that committed with it — confirmed updates are
                // never left without their task record, and a write
                // failure surfaces rather than silently recreating the
                // replay-a-restart bug it exists to prevent. A batch
                // too big for the bounded document commits its largest
                // fitting prefix instead of stalling: the first
                // unadmitted update stays unconfirmed and is refetched
                // once the backlog drains.
                let mut committed = admit_batch_prefix(store, &updates, &records, next_offset)?;
                if committed == 0 {
                    // A refused admission is itself a mutation: its
                    // reconcile pass can bind a staged reply — or
                    // discover one another store instance committed —
                    // whose delivery frees the document space this
                    // batch needs. That resend joins the backlog BEFORE
                    // the drained check, so "no work left" never parks
                    // a send that could still run.
                    drain_bound_replies(store, pending);
                    // One drained observation controls both decisions:
                    // a worker can free store capacity between the
                    // failed probe and the backlog check — capture the
                    // state once, retry the admit on it, and charge the
                    // permanent-failure budget only when that same
                    // drained store still refuses.
                    let mut drained = scheduler.admitted() == 0 && pending.is_empty();
                    if drained {
                        committed = admit_batch_prefix(store, &updates, &records, next_offset)?;
                        // The retried write can bind or discover work
                        // the first one could not — offer it before
                        // the permanent-failure accounting decides the
                        // store has nothing left to settle.
                        drain_bound_replies(store, pending);
                        drained = scheduler.admitted() == 0 && pending.is_empty();
                    }
                    if committed == 0 && !drained {
                        // Nothing of this batch fits while workers or
                        // the dispatch backlog still hold records —
                        // their completion frees the capacity the store
                        // lacks. Temporary pressure waits for the
                        // backlog to drain instead of spending the
                        // permanent-failure budget, which is reserved
                        // for an update that cannot fit once nothing is
                        // left to drain.
                        let waited = if scheduler.admitted() >= scheduler.max_admitted
                            || !pending.is_empty()
                        {
                            scheduler.wait_for_capacity()
                        } else {
                            wait_or_stop(retry_wait(1, None), &config.stop)
                        };
                        if !waited {
                            break;
                        }
                        continue;
                    }
                    if committed == 0 {
                        // The drained store still refuses the first
                        // update — permanent accounting. Not a
                        // transport failure: the budget is counted
                        // independently so a fetch succeeding does not
                        // reset what an update that can never fit burns
                        // through — the first unconfirmed id is
                        // surfaced instead of polling it forever.
                        admission_failures += 1;
                        if admission_failures >= config.max_poll_failures.max(1) {
                            return Err(anyhow!(
                                "a4mc_telegram_poll_failed: update {} never fits the bounded store (a4mc_telegram_state_full)",
                                updates[0].update_id
                            ));
                        }
                        if !wait_or_stop(retry_wait(admission_failures, None), &config.stop) {
                            break;
                        }
                        continue;
                    }
                }
                admission_failures = 0;
                // The batch boundary this commit earns: the whole
                // batch, or the first update the prefix left
                // unconfirmed.
                let batch_offset = if committed == records.len() {
                    next_offset
                } else {
                    updates[committed].update_id
                };
                pending.extend(
                    records[..committed]
                        .iter()
                        .filter_map(|record| match record {
                            BatchRecord::Task(task) => Some(Scheduled::Message {
                                key: task.key(),
                                message: Box::new(task.message.clone()),
                            }),
                            _ => None,
                        }),
                );
                // Host callbacks run at the cursor boundary: only
                // records the store just durably confirmed reach the
                // hook, so routine capacity backpressure cannot replay
                // a callback for an update still in the uncommitted
                // suffix. The durable cursor never passes an
                // unhandled event before its callback accepts it —
                // `admit_batch` capped the commit at the first event's
                // id — so each consumed event settles its marker and
                // earns the next boundary (the next event's id, or the
                // batch edge) in one atomic write, and a rejection
                // needs no rollback: the event was never confirmed, so
                // a restart refetches and redelivers it instead of
                // recording it dropped unseen. Confirmed work the
                // refetch names is reclaimed by record — settled and
                // still-pending ids are skipped, never re-run.
                for (index, record) in records[..committed].iter().enumerate() {
                    let BatchRecord::Event { key, event, .. } = record else {
                        continue;
                    };
                    let Some(hook) = on_event.as_mut() else {
                        break;
                    };
                    match hook(event) {
                        Ok(()) => {
                            let boundary = records[..committed]
                                .iter()
                                .skip(index + 1)
                                .find_map(|record| match record {
                                    BatchRecord::Event { key, .. } => Some(key.update_id),
                                    _ => None,
                                })
                                .unwrap_or(batch_offset);
                            store
                                .lock()
                                .unwrap()
                                .settle_event_at_cursor(*key, boundary)?;
                        }
                        Err(error) => {
                            return Err(anyhow!("a4mc_telegram_unhandled_event: {error}"));
                        }
                    }
                }
                cursor.offset = batch_offset;
                cursor.sequence_age.reset();
            } else {
                // A fetch that committed nothing is still a chance to
                // notice a bind another store instance committed while
                // this runtime idles: the notification lives only in
                // that instance's memory, so without a reload here a
                // staged reply recovered externally can wait forever.
                // The durable transition is rediscovered on the read;
                // the drain below feeds it into the bounded backlog.
                store.lock().unwrap().refresh()?;
            }
        }
        // Mutations since the last round — the batch writes above and
        // worker commits the scheduler could not take — may have newly
        // bound a staged reply that was stranded for space. Each joins
        // the same bounded backlog recovered work took at startup.
        drain_bound_replies(store, pending);
        admit_available(scheduler, pending);
    }
    Ok(())
}

/// What one fetched update contributes to the store write that
/// confirms the cursor — kept per update so a batch that does not fit
/// the bounded document can still confirm the largest prefix that
/// does.
enum BatchRecord {
    /// Nothing to persist: a stale replay.
    Skip,
    /// An unhandled-update id persisted before the cursor confirms it.
    Dropped(DroppedUpdate),
    /// A dispatched message task admitted with the cursor.
    Task(Box<crate::binding::PendingUpdate>),
    /// An unhandled update awaiting its host callback — admitted as a
    /// pending-event record with the cursor, then settled consumed or
    /// dropped by the callback's outcome.
    Event {
        key: TaskKey,
        raw_kind: &'static str,
        event: Box<a4mc::ChannelEvent>,
    },
}

/// Whether a store write was refused for space — the bounded document
/// or the pending-task cap — a condition that drains as workers
/// settle their records, unlike a corruption or IO failure.
fn is_store_capacity(error: &anyhow::Error) -> bool {
    matches!(
        error.to_string().as_str(),
        "a4mc_telegram_state_full" | "a4mc_telegram_pending_updates_full"
    )
}

/// One durable admit write for a batch prefix: the records of
/// `updates[..records.len()]` commit with the cursor confirmed at
/// `offset` — tasks, dropped-update records, and a pending record for
/// each event whose host callback has not run yet. An event's marker
/// commits with the cursor capped at its own id: the cursor must
/// never confirm an event the callback has not accepted, so a crash —
/// or a refused callback — leaves it refetchable instead of recorded
/// dropped unseen. Each consumed event then advances the cursor to
/// the next boundary in the same write that settles its marker.
fn admit_batch(store: &Mutex<BindingStore>, records: &[BatchRecord], offset: i64) -> Result<()> {
    let mut tasks = Vec::new();
    let mut dropped = Vec::new();
    let mut events = Vec::new();
    for record in records {
        match record {
            BatchRecord::Task(task) => tasks.push(task.as_ref().clone()),
            BatchRecord::Dropped(item) => dropped.push(item.clone()),
            BatchRecord::Event { key, raw_kind, .. } => events.push(DroppedUpdate {
                update_id: key.update_id,
                sequence: key.sequence,
                raw_kind: (*raw_kind).to_owned(),
            }),
            BatchRecord::Skip => {}
        }
    }
    // The durable cursor stops at the first event awaiting its
    // callback — it is confirmed only when the callback accepts it,
    // settled and advanced in one write.
    let offset = events
        .first()
        .map(|event| event.update_id)
        .unwrap_or(offset);
    store
        .lock()
        .unwrap()
        .admit_updates(&tasks, &dropped, &events, offset)
}

/// Confirm as much of the fetched batch as the bounded store can hold,
/// in order: the largest leading run of updates whose records commit.
/// Each successful probe is itself a durable cursor advance, so a
/// crash mid-search loses nothing already admitted. Returns the number
/// of leading updates durably admitted.
fn admit_batch_prefix(
    store: &Mutex<BindingStore>,
    updates: &[crate::transport::Update],
    records: &[BatchRecord],
    next_offset: i64,
) -> Result<usize> {
    match admit_batch(store, records, next_offset) {
        Ok(()) => return Ok(records.len()),
        Err(error) if !is_store_capacity(&error) => return Err(error),
        Err(_) => {}
    }
    // Binary search the largest committable prefix; a write only
    // happens where a prefix actually fits. `updates[k]` is the first
    // update a prefix of length `k` leaves unconfirmed, so its id is
    // exactly the cursor that prefix earns.
    let mut lo = 0usize;
    let mut hi = records.len();
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match admit_batch(store, &records[..mid], updates[mid].update_id) {
            Ok(()) => lo = mid,
            Err(error) if is_store_capacity(&error) => hi = mid,
            Err(error) => return Err(error),
        }
    }
    Ok(lo)
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

/// Offer backlog jobs to the scheduler through the same atomic
/// admission every producer shares: checking capacity and enqueueing
/// as one locked operation, so a worker's recovered-reply offer can
/// never slip into the slot this drain already counted. A refused job
/// goes back on the backlog front in order — admitted work is never
/// dropped.
fn admit_available(scheduler: &Scheduler, pending: &mut VecDeque<Scheduled>) {
    while let Some(job) = pending.pop_front() {
        if let Err(job) = scheduler.try_enqueue(job) {
            pending.push_front(job);
            break;
        }
    }
}

/// Move replies the store newly bound into the scheduler backlog —
/// each a recorded send whose delivery frees the document space a
/// refused admission is waiting on. Drained before every "no work
/// left" decision so a bind landing inside a refused write still
/// reaches a worker.
fn drain_bound_replies(store: &Mutex<BindingStore>, pending: &mut VecDeque<Scheduled>) {
    for task in store.lock().unwrap().take_bound_replies() {
        pending.push_back(Scheduled::Resend {
            task: Box::new(task),
        });
    }
}

fn drain_pending(scheduler: &Scheduler, pending: &mut VecDeque<Scheduled>) {
    while !pending.is_empty() {
        scheduler.wait_for_drain();
        admit_available(scheduler, pending);
    }
}

fn handle_inbound<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    key: TaskKey,
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
            handle_command(channel, store, identity, key, message, command, stop)
        }
        ControlOutcome::OrdinaryText(_) => {
            let body = message.agent_text();
            if body.trim().is_empty() {
                return Ok(());
            }
            handle_ordinary(channel, store, key, message, &body, turn_deadline, stop)
        }
    }
}

/// The delivery key for one runtime-generated reply. `purpose`
/// distinguishes the reply produced by handling the update (`reply`)
/// from the fallback error report for the same update (`error`), so a
/// recorded agent reply can never be shadowed by an observed error
/// receipt under the same dedupe key. The claim's sequence names the
/// key — in a form disjoint from every legacy key, since a bare
/// `purpose:id` or `purpose:id:part` could be re-minted verbatim by a
/// restarted numbering. Sequence `0` keeps the revision-one key shape
/// so records staged before the field existed still resume under the
/// key they wrote.
fn reply_key(key: TaskKey, purpose: &str) -> String {
    match key.sequence {
        0 => format!("{purpose}:{}", key.update_id),
        sequence => format!("{purpose}:s{sequence}:{}", key.update_id),
    }
}

/// One runtime reply as contract-valid sends. Text inside the
/// contract bound is a single send under `key`; a larger lane output
/// fans out at the character bound — part zero keeps `key`, later
/// parts derive `<key>:<index>` — so every part is deliverable and a
/// restarted fan-out repeats the same part keys under the host's
/// dedupe instead of retrying one forever-invalid payload. A
/// whitespace-only chunk is skipped: the contract rejects empty text
/// and it carries nothing.
fn reply_sends(
    chat_id: i64,
    reply_to_message_id: i64,
    key: &str,
    text: &str,
) -> Vec<a4mc::OutboundMessage> {
    const PART_CHARS: usize = a4mc::MAX_OUTBOUND_TEXT_CHARS;
    let mut sends = Vec::new();
    let mut rest = text;
    let mut index = 0usize;
    while !rest.is_empty() {
        let end = if rest.chars().count() <= PART_CHARS {
            rest.len()
        } else {
            rest.char_indices()
                .nth(PART_CHARS)
                .map_or(rest.len(), |(offset, _)| offset)
        };
        let (part, remaining) = rest.split_at(end);
        rest = remaining;
        if !part.trim().is_empty() {
            let key = if index == 0 {
                key.to_owned()
            } else {
                format!("{key}:{index}")
            };
            let mut outbound = a4mc::OutboundMessage::new(chat_id.to_string(), part, key);
            outbound.reply_to_message_id = Some(a4mc::ExternalMessageId::from(
                reply_to_message_id.to_string(),
            ));
            sends.push(outbound);
        }
        index += 1;
    }
    sends
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

/// Whether a handler failure is only a send wait interrupted by
/// shutdown — a policy deferral or a platform-hinted transient retry
/// cut short by `stop`: no error reply fires around the wait and the
/// unfinished task record stays for the restart drain. A transient
/// send failure only escapes the retry loop this way, so seeing one
/// here always means the wait was interrupted.
fn is_interrupted_send_wait(error: &anyhow::Error) -> bool {
    matches!(
        error.to_string().split(':').next().map(str::trim),
        Some("a4mc_outbound_batched")
            | Some("a4mc_outbound_throttled")
            | Some("a4mc_telegram_throttled")
            | Some("a4mc_telegram_connect_failed")
    )
}

/// Whether a resend failure came out of the durable store rather than
/// the delivery path: a persistence write failing means the store
/// cannot take writes — the run drains and reports it instead of
/// treating it like a refused send the record can simply wait out.
fn is_store_write_failure(error: &anyhow::Error) -> bool {
    matches!(
        error.to_string().split(':').next().map(str::trim),
        Some(
            "a4mc_telegram_checkpoint_failed"
                | "a4mc_telegram_state_write_failed"
                | "a4mc_telegram_state_full"
                | "a4mc_telegram_pending_updates_full"
                | "a4mc_telegram_reply_lost"
                | "a4mc_telegram_reply_too_large"
                | "a4mc_telegram_staged_invalid"
                | "a4mc_telegram_bindings_lock_failed"
                | "a4mc_telegram_bindings_invalid"
                | "a4mc_telegram_bindings_schema"
        )
    )
}

/// Whether a live-path failure is a persistence failure the
/// supervising loop must see: the store refused or could not durably
/// record — the task stays claimed for recovery instead of being
/// settled over by the fallback path. A reply refused for its size is
/// the turn's own outcome — the record was never writable — so it
/// keeps the ordinary failure path rather than reporting a dead store.
fn is_persistence_failure(error: &anyhow::Error) -> bool {
    is_store_write_failure(error)
        && error.to_string().split(':').next().map(str::trim)
            != Some("a4mc_telegram_reply_too_large")
}

/// Whether a reply-resolve failure came out of a durable write —
/// the lapsed-offer refusal the resolve commits — rather than the
/// payload read itself: a store that cannot take the write is a
/// persistence failure for the supervising loop, while a reply that
/// cannot be proven is a stranded record to report and retain.
fn is_resolve_write_failure(error: &anyhow::Error) -> bool {
    is_store_write_failure(error)
        && error.to_string().split(':').next().map(str::trim) != Some("a4mc_telegram_reply_lost")
}

/// Whether a failed send is safe to retry from its checkpoint: the
/// platform either never saw the request — a pre-connect failure — or
/// definitively rejected it and said when to come back (429). An
/// outcome that may already be posted is never retried.
fn is_transient_send_failure(error: &a4mc::ChannelError, progress: Option<&SendProgress>) -> bool {
    matches!(
        error.code.as_str(),
        "a4mc_telegram_throttled" | "a4mc_telegram_connect_failed"
    ) && progress.is_none_or(|progress| !progress.outcome_unknown)
}

/// Drive one outbound send under the host's policy. A deferral waits
/// out its hinted window and retries — the policy holds the send, it is
/// not a failure to report; a transient platform failure retries from
/// the channel's cached checkpoint on the same schedule — honoring the
/// platform's hint where one exists. `stop` ends the wait and returns
/// the held error itself so the caller can keep the work record.
fn send_policy_wait<T: BotTransport>(
    channel: &TelegramChannel<T>,
    outbound: &a4mc::OutboundMessage,
    stop: &AtomicBool,
) -> Result<(), a4mc::ChannelError> {
    let mut transient_failures = 0u32;
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
            Err(error) if is_transient_send_failure(&error, None) => {
                transient_failures += 1;
                let wait = error
                    .retry_after_ms
                    .map(Duration::from_millis)
                    .unwrap_or_else(|| retry_wait(transient_failures, None));
                if !wait_or_stop(wait, stop) {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Deliver one reply's contract-valid sends under the host's policy,
/// part after part: a deferral waits out its hint on each part, and the
/// first failure stops the fan-out so the caller keeps the work record.
fn deliver_sends<T: BotTransport>(
    channel: &TelegramChannel<T>,
    parts: &[a4mc::OutboundMessage],
    stop: &AtomicBool,
) -> Result<(), a4mc::ChannelError> {
    for part in parts {
        send_policy_wait(channel, part, stop)?;
    }
    Ok(())
}

/// Deliver one durably-recorded reply's sends, part after part, from
/// its persisted checkpoint: `sent` counts the contract-level sends
/// already confirmed (skipped, never reposted), and the send at `sent`
/// resumes the platform-level progress its last attempt recorded.
/// Every confirmed part and every mid-flight checkpoint lands in the
/// store, so a restart resumes instead of reposting confirmed work or
/// blindly retrying a part whose outcome is uncertain. The observer
/// marks each platform POST in flight before it leaves — a crash after
/// the platform accepts it leaves an honestly-uncertain record to
/// reconcile, never a silent repost. `wait` parks on the host's
/// deferral window and the platform's retry hint; without it the
/// first held send returns so the caller can wait off any lock it
/// holds.
#[allow(clippy::too_many_arguments)]
fn deliver_recorded_reply<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    chat_id: i64,
    reply_to_message_id: i64,
    key: TaskKey,
    delivery_key: &str,
    reply: &str,
    sent: usize,
    progress: Option<SendProgress>,
    wait: bool,
    stop: &AtomicBool,
) -> Result<()> {
    let mut text = reply.to_owned();
    let mut parts = reply_sends(chat_id, reply_to_message_id, delivery_key, &text);
    if sent >= parts.len() {
        return Ok(());
    }
    let mut resume = progress;
    let mut transient_failures = 0u32;
    let mut index = sent;
    while index < parts.len() {
        // Each stale-checkpoint recovery re-arms per part: the reply's
        // own durable checkpoint of THIS part and a foreign cached
        // partial under THIS part's effective key are distinct
        // positions the same retry can meet one after the other, and
        // either that still refuses after its own clearing surfaces as
        // the error it is. Clearing only ever drops the refused part's
        // checkpoint — the confirmed prefix before it stays recorded.
        let mut durable_cleared = false;
        let mut cache_evicted = false;
        loop {
            // Before EVERY attempt it is still safe to reshape — the
            // leading send with no confirmed part and no uncertain
            // outcome outstanding — the recorded text is revalidated
            // against the durable record: a pairing offer whose exact
            // record lapsed while a shutdown, a policy deferral or a
            // platform retry window held the send resolves to its
            // refused variant, so no attempt can publish a dead code.
            // Validation failures — a store the read cannot trust or a
            // payload that no longer resolves — propagate before a send
            // runs on unchecked text; a confirmed part prefix and an
            // uncertain checkpoint keep the text they earned.
            if index == 0
                && resume.as_ref().is_none_or(|progress| {
                    progress.confirmed.is_empty() && !progress.outcome_unknown
                })
            {
                let current = {
                    let mut store = store.lock().unwrap();
                    store.refresh()?;
                    match store.pending_update(key) {
                        Some(task) => store.resolve_reply(&task)?,
                        None => None,
                    }
                };
                if let Some(current) = current.filter(|current| current.text != text) {
                    text = current.text;
                    parts = reply_sends(chat_id, reply_to_message_id, delivery_key, &text);
                    // The attempt the checkpoint was earned on carried
                    // the replaced text — its position can never apply
                    // to this payload. Drop the caller's copy, the
                    // channel's cached partial — under the effective
                    // key the checkpoint names, since a host dedupe
                    // hook may have moved it off the delivery key —
                    // and the durable checkpoint only while it still
                    // equals the position this attempt was resolved
                    // with: that equality is what ties a stored
                    // checkpoint to the superseded payload, and the
                    // resolve guard already proved it carries no
                    // confirmed chunk and no uncertain outcome. What
                    // the record committed on the variant now selected
                    // — confirmed sends and the checkpoint they left —
                    // is adopted instead: the delivery resumes from
                    // the resolved reply's own sent count rather than
                    // erasing earned progress and restarting at the
                    // stale index.
                    durable_cleared = true;
                    let effective = resume
                        .as_ref()
                        .and_then(|progress| progress.binding.as_ref())
                        .map(|binding| binding.dedupe_key.clone());
                    channel.discard_partial(effective.as_deref().unwrap_or(delivery_key));
                    resume = store
                        .lock()
                        .unwrap()
                        .clear_reply_progress(key, resume.as_ref())?;
                    index = current.sent;
                    if index >= parts.len() {
                        return Ok(());
                    }
                    continue;
                }
            }
            let mut observe = |checkpoint: &SendProgress| {
                store
                    .lock()
                    .unwrap()
                    .record_reply_progress(key, index, Some(checkpoint.clone()))
                    .map_err(|_| {
                        crate::transport::TelegramApiError::new(
                            "a4mc_telegram_checkpoint_failed",
                            "reply checkpoint write failed",
                        )
                    })
            };
            match channel.send_tracked(&parts[index], resume.as_ref(), &mut observe) {
                Ok(_) => {
                    resume = None;
                    store
                        .lock()
                        .unwrap()
                        .record_reply_progress(key, index + 1, None)?;
                    break;
                }
                Err(tracked)
                    if !cache_evicted
                        && tracked.error.code == "a4mc_telegram_resume_mismatch"
                        && tracked.progress.as_deref().is_some_and(|stale| {
                            stale.confirmed.is_empty() && !stale.outcome_unknown
                        }) =>
                {
                    // The refused checkpoint came back for inspection —
                    // the partial a foreign send parked under the
                    // effective key this attempt resolved, never this
                    // reply's progress. It provably holds no confirmed
                    // chunk and no uncertain outcome, so it alone is
                    // evicted: the reply's own durable checkpoint is
                    // not the conflict and keeps its confirmed prefix
                    // for the retry. The entry drops under the key its
                    // binding names — a host dedupe hook may have filed
                    // it off the contract's delivery key, and clearing
                    // only that key would leave the foreign position
                    // to refuse the next attempt forever.
                    let effective = tracked
                        .progress
                        .as_deref()
                        .and_then(|stale| stale.binding.as_ref())
                        .map(|binding| binding.dedupe_key.clone());
                    cache_evicted = true;
                    channel.discard_partial(effective.as_deref().unwrap_or(delivery_key));
                    continue;
                }
                Err(tracked)
                    if !durable_cleared
                        && tracked.error.code == "a4mc_telegram_resume_mismatch"
                        && tracked.progress.is_none()
                        && resume.as_ref().is_some_and(|stale| {
                            stale.confirmed.is_empty() && !stale.outcome_unknown
                        }) =>
                {
                    // The reply's own durable checkpoint no longer
                    // applies to the prepared send — a lapsed pairing
                    // offer substituted its refused variant, or a host
                    // hook reshaped the send after earlier parts
                    // already delivered. Clearing is allowed only
                    // here, where the refused checkpoint provably
                    // holds no confirmed chunk and no uncertain
                    // outcome — a mismatch alone never proves the
                    // platform saw nothing, so a checkpoint with
                    // progress is kept intact and surfaces as the
                    // error it is. The part at `index` sends fresh:
                    // the confirmed prefix before it stays recorded,
                    // and the cached position under the checkpoint's
                    // effective key goes with it so the retry cannot
                    // refuse on it again. The durable clear is guarded
                    // by the checkpoint that just refused: progress
                    // another store committed since is adopted for the
                    // retry, never erased under a stale decision.
                    let effective = resume
                        .as_ref()
                        .and_then(|stale| stale.binding.as_ref())
                        .map(|binding| binding.dedupe_key.clone());
                    durable_cleared = true;
                    let expected = resume.take();
                    channel.discard_partial(effective.as_deref().unwrap_or(delivery_key));
                    resume = store
                        .lock()
                        .unwrap()
                        .clear_reply_progress(key, expected.as_ref())?;
                    continue;
                }
                Err(tracked) => {
                    let error = tracked.error;
                    // A resume-mismatch refusal carries the REFUSED
                    // checkpoint — a foreign send's position returned
                    // for inspection, not progress this attempt earned:
                    // adopting or persisting it would repoint the
                    // durable record at another payload's chunks.
                    let progress = if error.code == "a4mc_telegram_resume_mismatch" {
                        None
                    } else {
                        tracked.progress.map(|progress| *progress)
                    };
                    if let Some(progress) = &progress {
                        resume = Some(progress.clone());
                    }
                    // A failure nothing could have posted — or a
                    // definitive rejection carrying its retry hint —
                    // retries from the persisted checkpoint here
                    // instead of stranding the recorded reply until a
                    // restart.
                    let window = if is_outbound_deferral(&error) {
                        Some(
                            error
                                .retry_after_ms
                                .map(Duration::from_millis)
                                .unwrap_or(DEFERRED_RETRY_WAIT),
                        )
                    } else if is_transient_send_failure(&error, resume.as_ref()) {
                        transient_failures += 1;
                        Some(
                            error
                                .retry_after_ms
                                .map(Duration::from_millis)
                                .unwrap_or_else(|| retry_wait(transient_failures, None)),
                        )
                    } else {
                        None
                    };
                    // Persist the checkpoint the attempt left behind —
                    // including the uncertain-outcome flag — together
                    // with the absolute deadline an owed wait ends, in
                    // one durable write BEFORE sleeping: an exit inside
                    // the wait can never leave a retryable checkpoint
                    // missing its deadline, and a persistence failure
                    // surfaces instead of landing an unsafe resend.
                    if progress.is_some() || window.is_some() {
                        store.lock().unwrap().record_reply_checkpoint(
                            key,
                            progress,
                            window.map(|window| {
                                now_millis().saturating_add(
                                    u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
                                )
                            }),
                        )?;
                    }
                    match window {
                        Some(window) => {
                            if !wait || !wait_or_stop(window, stop) {
                                return Err(channel_err(error));
                            }
                            continue;
                        }
                        None => return Err(channel_err(error)),
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}

/// Record a reply the runtime just produced on the admitted task and
/// deliver it through the tracked path — every runtime reply goes
/// through this, so an exit after the platform accepts the send but
/// before the task settles resumes the same logical send on restart
/// instead of re-running the command or reposting a duplicate.
fn record_and_deliver<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    key: TaskKey,
    message: &InboundMessage,
    text: &str,
    stop: &AtomicBool,
) -> Result<()> {
    let delivery_key = reply_key(key, "reply");
    store
        .lock()
        .unwrap()
        .record_reply(key, text, &delivery_key)?;
    deliver_recorded_reply(
        channel,
        store,
        message.chat_id,
        message.message_id,
        key,
        &delivery_key,
        text,
        0,
        None,
        true,
        stop,
    )
}

/// Report one retained reply to the host observer — the claim's
/// update id and sequence plus the stable refusal code, never reply
/// content.
fn notify_stuck(on_stuck: &Mutex<Option<OnStuck>>, key: TaskKey, code: &str) {
    if let Some(hook) = on_stuck.lock().unwrap().as_mut() {
        hook(&StrandedReply {
            update_id: key.update_id,
            sequence: key.sequence,
            code: code.to_owned(),
        });
    }
}

fn handle_command<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    identity: &BotIdentity,
    key: TaskKey,
    message: &InboundMessage,
    command: ControlCommand,
    stop: &AtomicBool,
) -> Result<()> {
    match command {
        ControlCommand::Help => {
            record_and_deliver(
                channel,
                store,
                key,
                message,
                &help_text(&identity.username),
                stop,
            )?;
        }
        ControlCommand::Commands => {
            record_and_deliver(channel, store, key, message, &commands_text(), stop)?;
        }
        ControlCommand::Start | ControlCommand::Pair => {
            handle_pair_request(channel, store, identity, key, message, stop)?;
        }
        ControlCommand::Whoami => {
            record_and_deliver(channel, store, key, message, &whoami_text(message), stop)?;
        }
        ControlCommand::Unpair => {
            // The revocation and the confirmation commit in one write —
            // the same rule /new follows — so an exit after the
            // platform accepted the message but before the task
            // settled resumes the recorded confirmation instead of
            // re-running the command and answering a second time.
            let text = store.lock().unwrap().record_reply_and_revocation(
                message.chat_id,
                key,
                &reply_key(key, "reply"),
                |revoked| {
                    if revoked {
                        "Pairing revoked for this chat. Send /start to pair again.".to_owned()
                    } else {
                        "No pairing found for this chat.".to_owned()
                    }
                },
            )?;
            deliver_recorded_reply(
                channel,
                store,
                message.chat_id,
                message.message_id,
                key,
                &reply_key(key, "reply"),
                &text,
                0,
                None,
                true,
                stop,
            )?;
        }
        ControlCommand::Status => {
            if !store_is_paired(store, message.chat_id, message.user_id)? {
                record_and_deliver(
                    channel,
                    store,
                    key,
                    message,
                    "Not paired. Send /start to request a pairing code.",
                    stop,
                )?;
            } else {
                record_and_deliver(
                    channel,
                    store,
                    key,
                    message,
                    &status_text(store, identity, message.chat_id)?,
                    stop,
                )?;
            }
        }
        ControlCommand::Agent { agent_id: None } => {
            require_paired(store, message)?;
            let agents = list_agents().map_err(|error| anyhow!(error.to_string()))?;
            record_and_deliver(
                channel,
                store,
                key,
                message,
                &format_agent_list(&agents),
                stop,
            )?;
        }
        ControlCommand::Agent {
            agent_id: Some(agent_id),
        } => {
            // Authorization and the routing snapshot are ONE store
            // read: a rebind landing between two refreshes would be
            // adopted as this command's expected revision — and a
            // pairing that disappears between them would leave the
            // guarded write with no precondition at all. Capturing the
            // paired binding once means the guarded write commits only
            // against the revision the command was authorized under —
            // an intervening rebind or re-pairing is refused, never
            // overwritten.
            let Some(expected) = store_paired_binding(store, message.chat_id, message.user_id)?
            else {
                return Err(anyhow!(
                    "Not paired. Send /start to request a pairing code."
                ));
            };
            ensure_known_agent(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            // The rebind and its confirmation commit in one write, so
            // recovery only ever resumes delivery — it never re-runs
            // the bind or re-sends a different confirmation. The
            // confirmation reports what the guarded mutation actually
            // did: a pairing or binding that moved while the command
            // ran gets an honest reply, not a success claim.
            let confirmation = store.lock().unwrap().record_reply_and_agent(
                message.chat_id,
                key,
                agent_id.clone(),
                &reply_key(key, "reply"),
                message.user_id,
                &expected,
                |applied| {
                    if applied {
                        format!(
                            "Bound agent: {agent_id}.\nSession cleared. Use /session or /new, then send a message."
                        )
                    } else {
                        "The chat's pairing moved while the command ran — the agent was not changed."
                            .to_owned()
                    }
                },
            )?;
            deliver_recorded_reply(
                channel,
                store,
                message.chat_id,
                message.message_id,
                key,
                &reply_key(key, "reply"),
                &confirmation,
                0,
                None,
                true,
                stop,
            )?;
        }
        ControlCommand::Session { selector: None } => {
            require_paired(store, message)?;
            let binding = require_agent_binding(store, message.chat_id)?;
            let agent_id = binding.agent_id.clone().expect("agent-checked binding");
            let sessions = list_sessions(&agent_id).map_err(|error| anyhow!(error.to_string()))?;
            record_and_deliver(
                channel,
                store,
                key,
                message,
                &format_session_list(&sessions),
                stop,
            )?;
        }
        ControlCommand::Session {
            selector: Some(selector),
        } => {
            require_paired(store, message)?;
            let binding = require_agent_binding(store, message.chat_id)?;
            let agent_id = binding.agent_id.clone().expect("agent-checked binding");
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
            // The binding change and its confirmation commit in one
            // write — the same rule /new follows — so a restart only
            // ever resumes delivery, never re-opens the selector. The
            // session lands only while the binding the command ran
            // under still holds, and the confirmation reports what the
            // guarded mutation actually did — a binding that moved on
            // gets an honest reply, not a success claim.
            let confirmation = store_record_reply_and_session(
                store,
                message.chat_id,
                key,
                Some(session_id.clone()),
                &binding,
                |applied| {
                    if applied {
                        format!("Bound session: {session_id}")
                    } else {
                        "The chat's binding moved while the command ran — the session was not changed."
                            .to_owned()
                    }
                },
            )?;
            deliver_recorded_reply(
                channel,
                store,
                message.chat_id,
                message.message_id,
                key,
                &reply_key(key, "reply"),
                &confirmation,
                0,
                None,
                true,
                stop,
            )?;
        }
        ControlCommand::New | ControlCommand::Reset => {
            require_paired(store, message)?;
            let binding = require_agent_binding(store, message.chat_id)?;
            let agent_id = binding.agent_id.clone().expect("agent-checked binding");
            let opened =
                open_session(&agent_id, None).map_err(|error| anyhow!(error.to_string()))?;
            let confirmation = format!(
                "Started a new conversation{}.",
                if opened.is_empty() {
                    String::new()
                } else {
                    format!(": {opened}")
                }
            );
            // Commit the new binding session and the finished
            // confirmation in one store mutation before waiting on
            // outbound policy: separate writes let an exit between
            // them leave the committed session on an unfinished task,
            // so restart re-ran the command and opened a second
            // conversation — the single write means recovery only ever
            // resumes delivery of this reply. The confirmation reports
            // what the guarded mutation actually did.
            let session_id = if opened.is_empty() {
                None
            } else {
                Some(opened.clone())
            };
            let confirmation = store_record_reply_and_session(
                store,
                message.chat_id,
                key,
                session_id,
                &binding,
                |applied| {
                    if applied {
                        confirmation.clone()
                    } else {
                        "The chat's binding moved while the command ran — the session was not changed."
                            .to_owned()
                    }
                },
            )?;
            deliver_recorded_reply(
                channel,
                store,
                message.chat_id,
                message.message_id,
                key,
                &reply_key(key, "reply"),
                &confirmation,
                0,
                None,
                true,
                stop,
            )?;
        }
        ControlCommand::Stop => {
            record_and_deliver(
                channel,
                store,
                key,
                message,
                "This channel processes one turn at a time. There is no separate in-flight interrupt yet; wait for the current reply, or use /new for a fresh conversation.",
                stop,
            )?;
        }
        ControlCommand::Unknown { name } => {
            record_and_deliver(
                channel,
                store,
                key,
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
    key: TaskKey,
    message: &InboundMessage,
    stop: &AtomicBool,
) -> Result<()> {
    if store_is_paired(store, message.chat_id, message.user_id)? {
        record_and_deliver(
            channel,
            store,
            key,
            message,
            &format!(
                "Already paired.\n{}",
                status_text(store, identity, message.chat_id)?
            ),
            stop,
        )?;
        return Ok(());
    }
    // The pairing record and the reply carrying its code commit in one
    // write: a restart never re-mints a second code for a confirmation
    // the platform already accepted. The recovered record binds the
    // refused variant when its offer can no longer apply — an
    // intervening approval or a TTL that elapsed during downtime must
    // never deliver a dead code.
    let delivery_key = reply_key(key, "reply");
    let text = store.lock().unwrap().record_pairing_and_reply(
        message.chat_id,
        message.user_id,
        message.username.clone(),
        key,
        &delivery_key,
        |record| pairing_code_text(&record.code),
        "That pairing offer did not hold — send /start to request a fresh code.",
    )?;
    deliver_recorded_reply(
        channel,
        store,
        message.chat_id,
        message.message_id,
        key,
        &delivery_key,
        &text,
        0,
        None,
        true,
        stop,
    )?;
    Ok(())
}

fn handle_ordinary<T: BotTransport>(
    channel: &TelegramChannel<T>,
    store: &Mutex<BindingStore>,
    key: TaskKey,
    message: &InboundMessage,
    text: &str,
    turn_deadline: Duration,
    stop: &AtomicBool,
) -> Result<()> {
    // One refresh, one snapshot: pairing and routing are checked
    // against the same read instead of re-loading the store twice for
    // every paired message.
    let Some(binding) = store_paired_binding(store, message.chat_id, message.user_id)? else {
        // The pairing record and the reply carrying its code commit in
        // one write — recovery resumes this delivery instead of
        // minting a second code.
        let delivery_key = reply_key(key, "reply");
        let text = store.lock().unwrap().record_pairing_and_reply(
            message.chat_id,
            message.user_id,
            message.username.clone(),
            key,
            &delivery_key,
            |record| format!("Pairing required.\n{}", pairing_code_text(&record.code)),
            "Pairing is still required — send /start to request a fresh code.",
        )?;
        deliver_recorded_reply(
            channel,
            store,
            message.chat_id,
            message.message_id,
            key,
            &delivery_key,
            &text,
            0,
            None,
            true,
            stop,
        )?;
        return Ok(());
    };
    let Some(agent_id) = binding.agent_id.clone() else {
        record_and_deliver(
            channel,
            store,
            key,
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
    // Commit the finished reply — and the session the turn produced —
    // in one store write before delivery: the routing change and the
    // resumable result land or fail together, so a restart neither
    // loses paid work nor re-applies a session a later committed
    // command already replaced. The session lands only while the
    // binding this turn ran under still holds — a rebind that raced
    // the turn keeps its newer routing, and the reply record
    // regardless.
    if next_session.is_empty() || binding.session_id.as_deref() == Some(next_session.as_str()) {
        store_record_reply(store, key, &reply)?;
    } else {
        // The reply is the turn's paid output — delivered verbatim
        // whether or not the guarded session change still applies.
        store_record_reply_and_session(
            store,
            message.chat_id,
            key,
            Some(next_session),
            &binding,
            |_| reply.clone(),
        )?;
    }
    deliver_recorded_reply(
        channel,
        store,
        message.chat_id,
        message.message_id,
        key,
        &reply_key(key, "reply"),
        &reply,
        0,
        None,
        true,
        stop,
    )?;
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

/// The chat's binding with an agent bound — the snapshot the
/// command's session change is verified against when it commits, so
/// a rebind landing while the lane call ran keeps its newer routing.
fn require_agent_binding(store: &Mutex<BindingStore>, chat_id: i64) -> Result<ChatBinding> {
    store_binding(store, chat_id)?
        .filter(|binding| binding.agent_id.is_some())
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

fn store_record_reply(store: &Mutex<BindingStore>, key: TaskKey, reply: &str) -> Result<()> {
    store
        .lock()
        .unwrap()
        .record_reply(key, reply, &reply_key(key, "reply"))
}

/// Commit a chat's session change and the finished reply record in one
/// store mutation — see [`BindingStore::record_reply_and_session`].
/// `expected` is the binding the caller ran under; the session lands
/// only while it still matches. `text` renders both outcomes so a
/// recovered record binds the answer matching what the effect
/// committed; the recorded text is returned.
fn store_record_reply_and_session(
    store: &Mutex<BindingStore>,
    chat_id: i64,
    key: TaskKey,
    session_id: Option<String>,
    expected: &ChatBinding,
    text: impl Fn(bool) -> String,
) -> Result<String> {
    store.lock().unwrap().record_reply_and_session(
        chat_id,
        key,
        &reply_key(key, "reply"),
        session_id,
        expected,
        text,
    )
}

fn store_binding(store: &Mutex<BindingStore>, chat_id: i64) -> Result<Option<ChatBinding>> {
    let mut guard = store.lock().unwrap();
    guard.refresh()?;
    Ok(guard.binding(chat_id).cloned())
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

/// The bounded failure code one error carries — host-facing surfaces
/// (stuck reports, user error replies) forward only this prefix; any
/// body or credential content after the first colon is never exposed.
fn failure_code(error: &anyhow::Error) -> String {
    const MAX_ERROR_CHARS: usize = 160;
    error
        .to_string()
        .split(':')
        .next()
        .unwrap_or("a4mc_telegram_failed")
        .trim()
        .chars()
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// User-facing error replies keep only the bounded error code; any body or
/// credential content after the first colon is never forwarded.
fn sanitize_error(error: &anyhow::Error) -> String {
    format!("Error: {}", failure_code(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::PendingUpdate;
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
        let _ = std::fs::remove_dir_all(&root);
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

    /// Optional override for the synthetic lane's turn output —
    /// oversized replies exercise the multi-part send path without a
    /// real agent. `None` answers `"synthetic"`.
    static LANE_TURN_OUTPUT: Mutex<Option<String>> = Mutex::new(None);

    /// Optional override for the synthetic lane's turn session id —
    /// a staged session larger than the bounded document exercises
    /// the uncommittable-completion path. `None` answers
    /// `"synthetic"`.
    static LANE_TURN_SESSION: Mutex<Option<String>> = Mutex::new(None);

    /// A one-shot action the synthetic lane runs inside `dispatch` —
    /// a host rebind landing mid-turn exercises the stale-session
    /// precondition the completion write carries.
    static MID_TURN_ACTION: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

    /// A one-shot action the synthetic lane runs inside `scan_targets`
    /// — a host rebind landing while `/agent` checks admission
    /// exercises the command's pre-captured binding revision.
    static MID_SCAN_ACTION: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

    /// The composing host owns conversation access; tests install deterministic
    /// lane answers so the channel admission path stays exercised.
    fn install_synthetic_lane() {
        use a4mc::lane::{self, LanePort};
        use serde_json::json;
        fn scan_targets() -> Result<serde_json::Value, a4mc::ChannelError> {
            if let Some(action) = MID_SCAN_ACTION.lock().unwrap().take() {
                action();
            }
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
        *MID_TURN_ACTION.lock().unwrap() = None;
        *MID_SCAN_ACTION.lock().unwrap() = None;
        *LANE_TURN_SESSION.lock().unwrap() = None;
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
                if let Some(action) = MID_TURN_ACTION.lock().unwrap().take() {
                    action();
                }
                let _ = operation;
                let output = LANE_TURN_OUTPUT
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "synthetic".to_owned());
                let session_id = LANE_TURN_SESSION
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "synthetic".to_owned());
                Ok(json!({"ok": true, "output": output, "sessionId": session_id}))
            },
            outbound_hooks: None,
        });
    }

    /// Installs the synthetic lane answering each turn with `output`.
    fn install_lane_with_output(output: String) {
        install_synthetic_lane();
        *LANE_TURN_OUTPUT.lock().unwrap() = Some(output);
    }

    fn reset_lane_output() {
        *LANE_TURN_OUTPUT.lock().unwrap() = None;
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

    /// A host policy that records the idempotency key of every send
    /// attempt — including deferred ones — and can hold sends the way
    /// `DeferringHooks` does. Recovery and retry runs assert on the
    /// recorded keys to prove a re-delivered unit keeps its original
    /// key.
    struct KeyRecordingHooks {
        attempts: AtomicUsize,
        deferrals: usize,
        retry_after_ms: u64,
        keys: Mutex<Vec<String>>,
    }

    impl KeyRecordingHooks {
        fn allowing() -> Self {
            Self {
                attempts: AtomicUsize::new(0),
                deferrals: 0,
                retry_after_ms: 0,
                keys: Mutex::new(Vec::new()),
            }
        }

        fn holding(deferrals: usize, retry_after_ms: u64) -> Self {
            Self {
                attempts: AtomicUsize::new(0),
                deferrals,
                retry_after_ms,
                keys: Mutex::new(Vec::new()),
            }
        }

        fn observed_keys(&self) -> Vec<String> {
            self.keys.lock().unwrap().clone()
        }
    }

    impl a4mc::OutboundHooks for KeyRecordingHooks {
        fn throttle(
            &self,
            _: &a4mc::SendContext,
            message: &a4mc::OutboundMessage,
        ) -> a4mc::ThrottleDecision {
            self.keys
                .lock()
                .unwrap()
                .push(message.idempotency_key.clone());
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
            observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume, observe)
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
            observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume, observe)
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
            TaskKey::from(1),
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
            TaskKey::from(2),
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
            TaskKey::from(1),
            &text_message(42, 42, Some("alice"), "/whoami", 1),
            TEST_DEADLINE,
            &AtomicBool::new(false),
        )
        .unwrap();
        handle_inbound(
            &channel,
            &store,
            &identity,
            TaskKey::from(2),
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
            TaskKey::from(3),
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
            TaskKey::from(1),
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
            move |chat_id: i64, job: Scheduled| -> Result<()> {
                let Scheduled::Message { message, .. } = job else {
                    return Ok(());
                };
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
        let workers = scheduler
            .spawn_workers(4, processor, Arc::new(Mutex::new(None)))
            .unwrap();
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(1),
            message: Box::new(text_message(11, 1, Some("a"), "m1", 1)),
        });
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(2),
            message: Box::new(text_message(11, 1, Some("a"), "m2", 2)),
        });
        wait_until(
            || chat_11_blocked.load(Ordering::SeqCst),
            Duration::from_secs(5),
        );
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(10),
            message: Box::new(text_message(22, 2, Some("b"), "m3", 10)),
        });
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
            move |_chat_id: i64, job: Scheduled| -> Result<()> {
                let Scheduled::Message { message, .. } = job else {
                    return Ok(());
                };
                done.lock().unwrap().push(message.message_id);
                let (mutex, condvar) = &*gate;
                let mut released = mutex.lock().unwrap();
                while !*released {
                    released = condvar.wait(released).unwrap();
                }
                Ok(())
            }
        };
        let workers = scheduler
            .spawn_workers(1, processor, Arc::new(Mutex::new(None)))
            .unwrap();
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(1),
            message: Box::new(text_message(1, 1, None, "a", 1)),
        });
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(2),
            message: Box::new(text_message(2, 2, None, "b", 2)),
        });
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

        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(3),
            message: Box::new(text_message(3, 3, None, "c", 3)),
        });
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
                            sequence: 0,
                            message: queued,
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,

                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        crate::binding::PendingUpdate {
                            update_id: 2,
                            sequence: 0,
                            message: recorded,
                            reply: Some("agent reply".to_owned()),
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,

                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                    ],
                    &[],
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
        let mut reopened = BindingStore::open_in(&root).unwrap();
        let tasks = reopened.pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the deferred reply's task record was settled: {tasks:?}"
        );
        assert_eq!(
            reopened.reply_text(&tasks[0]).unwrap().as_deref(),
            Some("synthetic")
        );
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
                        sequence: 0,
                        message: text_message(43, 43, Some("bob"), "hello agent", 2),
                        reply: Some("agent reply".to_owned()),
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
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
        // A short deferral window: its deadline is persisted on the
        // interrupted attempt and honored — not skipped — on restart.
        let hooks = Arc::new(KeyRecordingHooks::holding(usize::MAX, 1_500));
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
        assert_eq!(
            hooks.observed_keys(),
            vec!["error:2".to_owned()],
            "the first fallback attempt did not carry its error key"
        );
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
        assert_eq!(
            tasks[0].reply_key.as_deref(),
            Some("error:2"),
            "the persisted fallback lost its original idempotency key: {tasks:?}"
        );

        // Restart with the policy now allowing sends: the drain delivers
        // the recorded fallback under the same key the first attempt
        // carried, so host dedupe and policy see one logical send.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(KeyRecordingHooks::allowing());
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

        assert_eq!(
            hooks.observed_keys(),
            vec!["error:2".to_owned()],
            "the recovered fallback resent under a different key"
        );
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
            // A short deferral window: the persisted deadline is
            // honored on restart, then delivery proceeds.
            retry_after_ms: 1_500,
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
        let mut reopened = BindingStore::open_in(&root).unwrap();
        let tasks = reopened.pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the deferred command was settled: {tasks:?}"
        );
        assert_eq!(
            reopened.reply_text(&tasks[0]).unwrap().as_deref(),
            Some("Started a new conversation: counted-session."),
            "the finished command's confirmation was not persisted: {tasks:?}"
        );
        assert_eq!(
            BindingStore::open_in(&root)
                .unwrap()
                .binding(42)
                .and_then(|binding| binding.session_id.clone())
                .as_deref(),
            Some("counted-session"),
            "the new session binding did not commit with the confirmation"
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
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(1),
            message: Box::new(text_message(1, 1, None, "a", 1)),
        });
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
            TaskKey::from(1),
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
            TaskKey::from(1),
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
        // The restarted sequence's first commit is confirmed as the
        // live mark on later polls — the durable cursor itself may
        // already have rolled over a second time by the time the run
        // is read back.
        assert!(
            offsets.contains(&6),
            "the restarted sequence did not advance from its first id"
        );
        drop(offsets);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_rejected_event_leaves_the_cursor_before_it_for_redelivery() {
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
        // A task the cursor confirmed AFTER the rejected event: the
        // rollback refetches it, and its durable record keeps the
        // confirmed work from re-entering the scheduler.
        updates.lock().unwrap().extend([
            Update {
                update_id: 20,
                message: None,
            },
            Update {
                update_id: 21,
                message: Some(text_message(88, 88, Some("zoe"), "/whoami", 21)),
            },
        ]);
        let error = handle.join().unwrap().unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_unhandled_event"),
            "unexpected error: {error}"
        );

        // The hook's contract: rejection leaves the cursor before the
        // event so the platform redelivers it — the event is never
        // recorded dropped — while the confirmed task still drains
        // and delivers on shutdown.
        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened.poll_offset(),
            20,
            "a rejected event was acknowledged instead of left for redelivery"
        );
        assert!(
            !reopened
                .dropped_updates()
                .iter()
                .any(|item| item.update_id == 20),
            "a redeliverable event was recorded dropped: {:?}",
            reopened.dropped_updates()
        );
        drop(reopened);
        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "the committed batch's admitted message was not delivered"
        );

        // The next run refetches from the rolled-back cursor: the
        // event reaches the hook again — the redelivery the contract
        // promises — while the already-confirmed task is reclaimed by
        // record and never re-processed.
        let events = Arc::new(Mutex::new(Vec::<a4mc::ChannelEvent>::new()));
        let observed = Arc::clone(&events);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![
                Update {
                    update_id: 20,
                    message: None,
                },
                Update {
                    update_id: 21,
                    message: Some(text_message(88, 88, Some("zoe"), "/whoami", 21)),
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
        // Wait on the durable cursor, not a fixed window: the batch is
        // fully settled — event redelivered, message sent — only once
        // the offset moves past update 21.
        wait_until(
            || {
                BindingStore::open_in(&root)
                    .map(|store| store.poll_offset() == 22)
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        assert_eq!(
            events.lock().unwrap().len(),
            1,
            "the rejected event was not redelivered to its callback"
        );
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            22,
            "the redelivered batch did not advance the cursor"
        );
        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "confirmed work replayed after the cursor rollback"
        );
        let reopened = BindingStore::open_in(&root).unwrap();
        assert!(
            !reopened
                .dropped_updates()
                .iter()
                .any(|item| item.update_id == 20),
            "a consumed event was recorded dropped: {:?}",
            reopened.dropped_updates()
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
            move |_chat_id: i64, job: Scheduled| -> Result<()> {
                let Scheduled::Message { message, .. } = job else {
                    return Ok(());
                };
                done.lock().unwrap().push(message.message_id);
                Ok(())
            }
        };
        let workers = scheduler
            .spawn_workers(1, processor, Arc::new(Mutex::new(None)))
            .unwrap();
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(1),
            message: Box::new(text_message(1, 1, None, "a", 1)),
        });
        scheduler.shutdown();
        // With `stop` already raised, workers could be gone before this
        // drain admits the fetched remainder: the second message would
        // sit behind a full admission bound with nobody left to free it.
        let mut pending = VecDeque::from([
            Scheduled::Message {
                key: TaskKey::from(2),
                message: Box::new(text_message(2, 2, None, "b", 2)),
            },
            Scheduled::Message {
                key: TaskKey::from(3),
                message: Box::new(text_message(3, 3, None, "c", 3)),
            },
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
    fn an_observer_failure_leaves_the_event_for_restart_redelivery() {
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // Two ordinary updates followed by an undispatchable one in the
        // same fetched batch: the batch commits first — callbacks run
        // only at the cursor boundary — but the hook's rejection rolls
        // the durable cursor back before the event instead of
        // acknowledging it unseen.
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
            13,
            "a rejected event was acknowledged instead of left for redelivery"
        );
        assert!(
            !reopened
                .dropped_updates()
                .iter()
                .any(|item| item.update_id == 13),
            "a redeliverable event was recorded dropped: {:?}",
            reopened.dropped_updates()
        );
        assert!(reopened.pending_updates().is_empty());
        drop(reopened);
        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "the committed batch's admitted messages were not delivered"
        );

        // The next run refetches the event — the updates before the
        // rolled-back cursor stay confirmed — and this time the hook
        // accepts it.
        let events = Arc::new(Mutex::new(Vec::<a4mc::ChannelEvent>::new()));
        let observed = Arc::clone(&events);
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
            on_event: Some(Box::new(move |event: &a4mc::ChannelEvent| {
                observed.lock().unwrap().push(event.clone());
                Ok(())
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        // Wait on the durable cursor, not a fixed window: the refetched
        // event reaches the hook and the batch commits before the
        // offset moves to 14.
        wait_until(
            || {
                BindingStore::open_in(&root)
                    .map(|store| store.poll_offset() == 14)
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();
        assert_eq!(
            events.lock().unwrap().len(),
            1,
            "the rejected event was not redelivered to its callback"
        );
        assert_eq!(sent.lock().unwrap().len(), 2, "confirmed work replayed");
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            14,
            "the redelivered batch did not advance the cursor"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_failed_fallback_record_surfaces_instead_of_settling_the_task() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        {
            // An admitted update on an unpaired chat fails admission
            // with the fallback path; the seeded store leaves that
            // record write as the run's first state mutation.
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(7, 7, Some("zed"), "/agent", 2),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
        }
        let mut store = BindingStore::open_in(&root).unwrap();
        store.fail_next_write_for_test();
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
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        // Joining is the barrier: whether the worker processed the
        // update during the run or while the shutdown drain feeds it
        // queued work, the record write was attempted before exit.
        stop.store(true, Ordering::SeqCst);
        let error = handle.join().unwrap().unwrap_err();
        assert_eq!(
            error.to_string().split(':').next().map(str::trim),
            Some("a4mc_telegram_state_write_failed"),
            "the worker's persistence failure did not reach the caller: {error}"
        );

        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the failed fallback record was settled over: {tasks:?}"
        );
        assert!(
            !tasks[0].has_reply(),
            "the failed write still recorded a reply: {tasks:?}"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "an unpersisted fallback report was delivered anyway"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_resumed_reply_delivery_never_reverts_a_newer_session_binding() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
            // A later command already moved the binding forward; the
            // recorded reply's own session change committed with it.
            // Recovery must deliver the reply only — re-applying the
            // older routing would send every later message back to
            // the stale conversation.
            store.set_session(42, Some("session-newer".into())).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 1,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello agent", 1),
                        reply: Some("agent reply".into()),
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    2,
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
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened
                .binding(42)
                .and_then(|binding| binding.session_id.clone())
                .as_deref(),
            Some("session-newer"),
            "recovery reverted the chat binding to an older session"
        );
        assert!(
            reopened.pending_updates().is_empty(),
            "the delivered reply stayed pending"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_oversized_turn_reply_is_split_into_contract_valid_sends() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let big = "x".repeat(a4mc::MAX_OUTBOUND_TEXT_CHARS + 5_000);
        install_lane_with_output(big.clone());
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
                message: Some(text_message(42, 42, Some("alice"), "hello agent", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(KeyRecordingHooks::allowing());
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
            || hooks.attempts.load(Ordering::SeqCst) >= 2,
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        // One oversized lane output becomes contract-bound parts, each
        // under its own stable key; the platform chunker then posts
        // each part in order, so the concatenation is the full reply.
        assert_eq!(
            hooks.observed_keys(),
            vec!["reply:5".to_owned(), "reply:5:1".to_owned()],
            "the oversized reply was not split under stable part keys"
        );
        let reassembled: String = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(reassembled, big, "the delivered parts lost reply text");
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered multi-part reply stayed pending"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_oversized_recorded_reply_delivers_as_stable_keyed_parts_on_restart() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // A reply recorded above the contract bound used to be retried
        // as one invalid send forever. The restart drain now fans it
        // out into contract-valid parts under the recorded key's
        // derived part keys.
        let big = "x".repeat(a4mc::MAX_OUTBOUND_TEXT_CHARS + 5_000);
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(43, 43, Some("bob"), "hello agent", 2),
                        reply: Some(big.clone()),
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
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
        let hooks = Arc::new(KeyRecordingHooks::allowing());
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
            || hooks.attempts.load(Ordering::SeqCst) >= 2,
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            hooks.observed_keys(),
            vec!["reply:2".to_owned(), "reply:2:1".to_owned()],
            "the recorded reply did not resend under its stable part keys"
        );
        let reassembled: String = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(reassembled, big, "the delivered parts lost reply text");
        let reopened = BindingStore::open_in(&root).unwrap();
        assert!(
            reopened.pending_updates().is_empty(),
            "the fully delivered recorded reply stayed pending"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_restart_resumes_a_recorded_reply_from_its_persisted_checkpoint() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // One contract send whose platform fan-out stopped after part
        // zero: the checkpoint is durable, so the drain must post only
        // the unconfirmed tail — never the confirmed prefix again.
        let big = "x".repeat(5_000);
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(43, 43, Some("bob"), "hello agent", 2),
                        reply: Some(big.clone()),
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: Some(SendProgress {
                            confirmed: vec![91],
                            next_part: 1,
                            outcome_unknown: false,
                            binding: None,
                        }),
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
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
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.len(),
            1,
            "the confirmed prefix was reposted: {posts:?}"
        );
        assert_eq!(
            posts[0].1.len(),
            5_000 - 4096,
            "the resumed send did not continue at the checkpoint"
        );
        drop(posts);
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the resumed reply stayed pending after delivery"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_restart_never_reposts_a_recorded_replys_uncertain_part() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // The stopping part's outcome never reached the last run — it
        // may already be posted, so the drain refuses to resend it
        // rather than duplicate a delivered message. The record stays
        // for an operator decision instead of silently settling.
        let big = "x".repeat(5_000);
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(43, 43, Some("bob"), "hello agent", 2),
                        reply: Some(big.clone()),
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: Some(SendProgress {
                            confirmed: vec![91],
                            next_part: 1,
                            outcome_unknown: true,
                            binding: None,
                        }),
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
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
        // The drain's refusal is immediate; give it one beat, then end.
        thread::sleep(Duration::from_millis(200));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(
            sent.lock().unwrap().is_empty(),
            "a part with an uncertain outcome was reposted"
        );
        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert_eq!(
            tasks.len(),
            1,
            "the ambiguous send was settled without delivery: {tasks:?}"
        );
        assert!(tasks[0].reply.is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_stopped_reply_persists_its_checkpoint_for_the_next_restart() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_lane_with_output("x".repeat(5_000));
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // The platform fan-out of the recorded reply stops at part 1
        // with a definitive rejection: the run must persist that
        // checkpoint so a restart resumes instead of reposting.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello agent", 5)),
            }])),
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_api_failed", "fixture rejection"),
                false,
            )),
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
        wait_until(
            || {
                BindingStore::open_in(&root)
                    .unwrap()
                    .pending_updates()
                    .first()
                    .is_some_and(|task| task.reply_progress.is_some())
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        let task = BindingStore::open_in(&root).unwrap().pending_updates()[0].clone();
        assert_eq!(task.reply_sent, 0);
        let progress = task.reply_progress.expect("checkpoint not persisted");
        assert_eq!(progress.next_part, 1);
        assert!(!progress.outcome_unknown);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Redelivers its batch on every poll at or above the updates' ids:
    /// the platform's at-least-once model for updates the cursor never
    /// confirmed.
    struct RedeliveringTransport {
        inner: MockBotTransport,
        batch: Vec<Update>,
    }

    impl BotTransport for RedeliveringTransport {
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
            _timeout_secs: u64,
        ) -> Result<Vec<Update>, TelegramApiError> {
            self.inner.observed_offsets.lock().unwrap().push(offset);
            Ok(self
                .batch
                .iter()
                .filter(|update| update.update_id >= offset)
                .cloned()
                .collect())
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            reply_to_message_id: Option<i64>,
            resume: Option<&SendProgress>,
            observe: &mut dyn FnMut(&SendProgress) -> Result<(), TelegramApiError>,
        ) -> Result<Vec<i64>, TelegramApiError> {
            self.inner
                .send_message(chat_id, text, reply_to_message_id, resume, observe)
        }
    }

    #[test]
    fn an_oversized_batch_commits_its_largest_fitting_prefix() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // The first update's record nearly fills the bounded document,
        // so the pair cannot be confirmed in one write. The loop must
        // commit the prefix, advance the cursor only to the first
        // unadmitted update, and redeliver the rest once the admitted
        // work settles — never stall on the same batch.
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = RedeliveringTransport {
            inner: MockBotTransport {
                sent: Arc::clone(&sent),
                observed_offsets: Arc::clone(&observed_offsets),
                ..MockBotTransport::default()
            },
            batch: vec![
                Update {
                    update_id: 1,
                    message: Some(text_message(42, 42, Some("alice"), &"x".repeat(200_000), 1)),
                },
                Update {
                    update_id: 2,
                    message: Some(text_message(43, 43, Some("bob"), &"z".repeat(200_000), 2)),
                },
            ],
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // Both updates are answered — each unpaired chat earns its
        // pairing reply — proving the prefix committed and the
        // remainder arrived on a later poll.
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(20));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened.poll_offset(),
            3,
            "the cursor did not reach past the whole batch"
        );
        assert!(
            reopened.pending_updates().is_empty(),
            "admitted work stayed pending"
        );
        assert!(
            observed_offsets.lock().unwrap().contains(&2),
            "the unadmitted update was never refetched: {:?}",
            observed_offsets.lock().unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_reply_too_large_for_the_document_is_still_recorded_and_delivered() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A lane output that could never fit the 256 KiB document: the
        // completed outcome still has to land somewhere durable before
        // the task may settle — the finding's exact loss.
        let big = "y".repeat(300_000);
        install_lane_with_output(big.clone());
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
                message: Some(text_message(42, 42, Some("alice"), "hello agent", 5)),
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
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // Wait on delivery evidence — the recorded reply's platform
        // parts — rather than the record set, which is empty before
        // admission too.
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .map(|(_, text)| text.len())
                    .sum::<usize>()
                    == big.len()
            },
            Duration::from_secs(60),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered reply's task never settled"
        );
        let posts = sent.lock().unwrap();
        let reassembled: String = posts.iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(
            reassembled.len(),
            big.len(),
            "the delivered reply lost bytes: {} posts",
            posts.len()
        );
        assert_eq!(reassembled, big);
        let document_bytes = std::fs::metadata(root.join("bindings.json")).unwrap().len() as usize;
        assert!(
            document_bytes < 256 * 1024,
            "the finished reply stayed inside the bounded document"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_pre_send_failure_retries_the_checkpoint_instead_of_stranding() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_lane_with_output("x".repeat(5_000));
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // A failure before any request byte leaves: nothing can have
        // reached the platform, so the send retries from its
        // checkpoint inside the same run instead of stranding the
        // recorded reply until a restart.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello agent", 5)),
            }])),
            fail_send_at_part: Some((
                0,
                TelegramApiError::new("a4mc_telegram_connect_failed", "Bot API connection failure"),
                false,
            )),
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
        // Wait on delivery evidence, not the record set — it is empty
        // before admission too.
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(15));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        assert_eq!(
            sent.lock().unwrap().len(),
            2,
            "the retried send did not post both platform parts"
        );
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered reply's task never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_throttled_reply_retries_from_the_checkpoint_honoring_the_hint() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_lane_with_output("x".repeat(5_000));
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // Part 0 is confirmed; part 1 is definitively rate-limited with
        // a retry hint. The run must wait the hint out and resume at
        // the rejected part — never repost the confirmed prefix and
        // never strand the reply until a restart.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello agent", 5)),
            }])),
            fail_send_at_part: Some((
                1,
                TelegramApiError::new(
                    "a4mc_telegram_throttled",
                    "sendMessage: Bot API rate limited",
                )
                .with_retry_after(Some(0)),
                false,
            )),
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
        // Wait on delivery evidence, not the record set — it is empty
        // before admission too.
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(15));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.len(),
            2,
            "the throttled send reposted its confirmed prefix: {posts:?}"
        );
        assert_eq!(posts[1].1.len(), 5_000 - 4096);
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the delivered reply's task never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_restart_honors_the_persisted_reply_deadline() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 3),
                        reply: Some("recorded reply".to_owned()),
                        reply_key: Some("reply:3".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        // The interrupted pass earned a Retry-After far
                        // in the future: recovery must keep waiting,
                        // not post immediately.
                        reply_retry_at_ms: Some(now_millis() + 3_600_000),
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    4,
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
        thread::sleep(Duration::from_millis(400));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(
            sent.lock().unwrap().is_empty(),
            "the persisted deadline was skipped on restart"
        );
        let task = BindingStore::open_in(&root).unwrap().pending_updates()[0].clone();
        assert!(
            task.reply_retry_at_ms.is_some(),
            "the retry deadline was dropped"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unreadable_reply_sidecar_is_surfaced_to_the_host() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 2),
                        // The record names a payload file that is not
                        // there: recovery cannot prove the reply — it
                        // must surface, not silently retain.
                        reply: None,
                        reply_key: Some("reply:2".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: Some("reply-2.txt".to_owned()),
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stranded.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(2, "a4mc_telegram_reply_lost".to_owned())],
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a reply that cannot be proven was posted"
        );
        assert_eq!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .len(),
            1,
            "the stranded record was dropped"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_corrupt_staged_manifest_is_surfaced_to_the_host() {
        let root = temp_root();
        let replies = root.join("bindings.json.replies");
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 2),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
            // A staged manifest that cannot be parsed can never bind
            // its payload: startup recovery still owes the host the
            // stored alert — the task stays parked, never silently.
            std::fs::create_dir_all(&replies).unwrap();
            std::fs::write(replies.join("reply-2.json"), "{ not json").unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stranded.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(2, "a4mc_telegram_staged_invalid".to_owned())],
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a task whose staged record cannot be parsed was dispatched"
        );
        assert_eq!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .len(),
            1,
            "the stranded record was dropped"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_ambiguous_checkpoint_is_surfaced_to_the_host() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 2),
                        reply: Some("x".repeat(5_000)),
                        reply_key: Some("reply:2".to_owned()),
                        reply_sent: 0,
                        // A part's outcome never arrived: retrying could
                        // duplicate a delivered message — the refusal is
                        // surfaced, the record retained.
                        reply_progress: Some(SendProgress {
                            confirmed: vec![91],
                            next_part: 1,
                            outcome_unknown: true,
                            binding: None,
                        }),
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stranded.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(2, "a4mc_telegram_send_ambiguous".to_owned())],
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "an uncertain part was reposted"
        );
        assert_eq!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .len(),
            1,
            "the stranded record was dropped"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_unadmittable_update_surfaces_without_replaying_callbacks() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = temp_root();
        // The first update's record can never fit the bounded document
        // — its task alone exceeds the limit. Refetches count toward
        // the failure limit even though every fetch succeeds, and the
        // trailing event's callback never runs: it was never committed.
        let events = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&events);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = RedeliveringTransport {
            inner: MockBotTransport {
                sent: Arc::clone(&sent),
                ..MockBotTransport::default()
            },
            batch: vec![
                Update {
                    update_id: 1,
                    message: Some(text_message(42, 42, Some("alice"), &"x".repeat(300_000), 1)),
                },
                Update {
                    update_id: 2,
                    message: None,
                },
            ],
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            max_poll_failures: 2,
            on_event: Some(Box::new(move |_: &a4mc::ChannelEvent| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error.to_string().contains("a4mc_telegram_poll_failed"),
            "the unadmittable update never surfaced: {error}"
        );
        assert_eq!(
            events.load(Ordering::SeqCst),
            0,
            "an event callback ran for an update that was never committed"
        );
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            0,
            "the cursor advanced past unadmitted work"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_recovered_unpair_redelivers_its_recorded_confirmation() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 9,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "/unpair", 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    10,
                )
                .unwrap();
            // The crash window the finding names: the command's outcome
            // and the revocation committed together; the process died
            // before delivery. Recovery must redeliver the recorded
            // confirmation — never re-run the command (which would now
            // report "No pairing found" on the already-revoked chat).
            store
                .record_reply_and_revocation(42, 9, "reply:9", |removed| {
                    if removed {
                        "Pairing revoked for this chat. Send /start to pair again.".to_owned()
                    } else {
                        "No pairing found for this chat.".to_owned()
                    }
                })
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.len(),
            1,
            "the recorded confirmation was not delivered exactly once"
        );
        assert_eq!(
            posts[0].1,
            "Pairing revoked for this chat. Send /start to pair again."
        );
        let reopened = BindingStore::open_in(&root).unwrap();
        assert!(reopened.binding(42).is_none(), "the chat stayed paired");
        assert!(
            reopened.pending_updates().is_empty(),
            "the delivered command reply's task never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn temporary_store_pressure_waits_for_the_backlog_to_drain() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // The first update's record fills most of the bounded document:
        // while its worker holds it, the second cannot fit. With
        // `max_poll_failures` at one, counting that temporary pressure
        // as a permanent refusal would end polling on the spot — the
        // backlog must drain and the second update must still be
        // served.
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = RedeliveringTransport {
            inner: MockBotTransport {
                sent: Arc::clone(&sent),
                ..MockBotTransport::default()
            },
            batch: vec![
                Update {
                    update_id: 1,
                    message: Some(text_message(42, 42, Some("alice"), &"x".repeat(180_000), 1)),
                },
                Update {
                    update_id: 2,
                    message: Some(text_message(42, 42, Some("alice"), &"y".repeat(120_000), 2)),
                },
            ],
        };
        // Send deferrals keep the first worker busy long enough that
        // the second fetch's admission attempt lands inside the
        // pressure window.
        let hooks = Arc::new(KeyRecordingHooks::holding(8, 60));
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            max_poll_failures: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(20));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(
            BindingStore::open_in(&root).unwrap().poll_offset(),
            3,
            "temporary pressure stranded the second update"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_live_stranded_reply_is_reported_to_the_host() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        a4mc::lane::clear();
        let root = temp_root();
        // A reply recorded during ordinary processing whose delivery
        // fails strands its task exactly like a record found at
        // startup: the host is told the update id and the stable
        // refusal code, and the durable reply with its checkpoint
        // stays for the restart drain.
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            fail_send_with: Arc::new(Mutex::new(Some(TelegramApiError::new(
                "a4mc_telegram_api_failed",
                "sendMessage: Bot API request failed",
            )))),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello there", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stranded.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(5, "a4mc_telegram_api_failed".to_owned())],
            "the live stranded reply never reached on_stuck"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a failed send was still posted"
        );
        let task = BindingStore::open_in(&root)
            .unwrap()
            .pending_update(5)
            .expect("the stranded reply's record was dropped");
        assert!(task.has_reply(), "the durable reply was discarded");
        assert_eq!(task.reply_key.as_deref(), Some("reply:5"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_in_flight_turn_keeps_its_reply_off_a_newer_binding() {
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
            store.set_session(42, Some("s-old".into())).unwrap();
        }
        // The host rebinds the chat while the turn is in flight: the
        // session the lane returns must never land on the newer
        // binding — the finished reply still delivers.
        let rebind_root = root.clone();
        *MID_TURN_ACTION.lock().unwrap() = Some(Box::new(move || {
            let mut store = BindingStore::open_in(&rebind_root).unwrap();
            store.set_agent(42, Some("claude".into())).unwrap();
        }));
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello", 5)),
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
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let reopened = BindingStore::open_in(&root).unwrap();
        let binding = reopened.binding(42).cloned().unwrap();
        assert_eq!(binding.agent_id.as_deref(), Some("claude"));
        assert_eq!(
            binding.session_id, None,
            "a stale turn's session overwrote the newer binding"
        );
        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1, "delivered sends: {messages:?}");
        assert_eq!(messages[0].1, "synthetic");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_oversized_staged_completion_is_reported_not_blocking() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        // A session id that fits the staged record but can never fit
        // the bounded document: the completion stays staged and
        // reported instead of failing every mutation that replays it.
        *LANE_TURN_SESSION.lock().unwrap() = Some("x".repeat(512 * 1024));
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(42, Some("codex".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 5,
                message: Some(text_message(42, 42, Some("alice"), "hello", 5)),
            }])),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stranded.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(5, "a4mc_telegram_state_full".to_owned())],
            "the uncommittable completion never reached on_stuck"
        );
        let mut reopened = BindingStore::open_in(&root).unwrap();
        // Retained and reported — not blocking: the record stays on
        // disk for its task, the binding is untouched, and unrelated
        // mutations proceed.
        assert!(reopened.staged_reply_pending(5));
        assert!(reopened.pending_update(5).is_some());
        assert_eq!(reopened.binding(42).unwrap().session_id, None);
        reopened.set_poll_offset(9).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_startup_event_settle_failure_surfaces_before_workers_run() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        // A pending event marker a previous run left behind the
        // cursor: startup settles it into its durable dropped record.
        store
            .admit_updates(
                &[],
                &[],
                &[DroppedUpdate {
                    update_id: 6,
                    sequence: 0,
                    raw_kind: "reaction".to_owned(),
                }],
                7,
            )
            .unwrap();
        // The settle's durable write fails — the error must surface
        // from recovery, before any worker exists to be leaked by an
        // early return.
        store.fail_next_write_for_test();
        let transport = MockBotTransport {
            updates: Arc::new(Mutex::new(Vec::new())),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop,
            ..RuntimeConfig::default()
        };
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a4mc_telegram_state_write_failed"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_restart_waits_out_a_sub_second_persisted_deadline() {
        let root = temp_root();
        let staged = Instant::now();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 3),
                        reply: Some("recorded reply".to_owned()),
                        reply_key: Some("reply:3".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        // A sub-second deadline a whole-second encoding
                        // would have truncated to "due now": recovery
                        // waits it out instead of reposting early
                        // inside the platform's rate-limit window.
                        reply_retry_at_ms: Some(now_millis() + 400),
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    4,
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
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        // The reply's post only proves the deadline was honored if it
        // lands after it — a fixed sleep cannot measure that under
        // load, the elapsed clock can (millis truncation: 10ms leeway).
        assert!(
            staged.elapsed() >= Duration::from_millis(390),
            "the persisted deadline was cut short on restart"
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(sent.lock().unwrap()[0].1, "recorded reply");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_drained_backlog_retries_admission_before_a_permanent_failure() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        // The probe's stale capacity answer — the shape a worker
        // freeing store space between the failed admit and the
        // scheduler check takes — is retried once the backlog is seen
        // drained, not charged to the permanent budget.
        store.fail_next_admit_capacity_for_test();
        let store = Mutex::new(store);
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Scheduler::new(8, Arc::clone(&stop));
        let transport = MockBotTransport {
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 2,
                message: Some(text_message(42, 42, Some("alice"), "hello", 2)),
            }])),
            ..MockBotTransport::default()
        };
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            max_poll_failures: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let mut cursor = PollCursor {
            offset: 0,
            sequence_age: SequenceAge::resumed(Duration::ZERO),
            expired_sequence: None,
        };
        let mut pending = VecDeque::new();
        let mut on_event = None;
        let stopper = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            stopper.store(true, Ordering::SeqCst);
        });
        poll_updates(
            &transport,
            &scheduler,
            &store,
            &config,
            &mut cursor,
            &mut pending,
            &mut on_event,
        )
        .unwrap();
        assert_eq!(store.lock().unwrap().poll_offset(), 3);
        assert_eq!(
            scheduler.admitted(),
            1,
            "the refetched update was never admitted"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_expired_sequence_retires_the_settled_tail() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            // A task durably claimed and settled in the old sequence:
            // its id joins the tail that suppresses refetches.
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "/whoami", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            store.complete_update(7).unwrap();
            store.age_poll_offset_for_test(8 * 24 * 60 * 60).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // The restarted sequence lawfully reuses id 7 for a fresh
        // message: the dead sequence's settled tail must not suppress
        // it as already-handled.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 7,
                message: Some(text_message(88, 88, Some("zoe"), "/whoami", 7)),
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

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].0, 88,
            "the reused id was suppressed: {messages:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A host policy that holds sends under one idempotency key while
    /// letting every other send through — a held resend can be proven
    /// to block only its own lane.
    struct HoldKeyHooks {
        held_key: &'static str,
        attempts: AtomicUsize,
    }

    impl a4mc::OutboundHooks for HoldKeyHooks {
        fn throttle(
            &self,
            _: &a4mc::SendContext,
            message: &a4mc::OutboundMessage,
        ) -> a4mc::ThrottleDecision {
            if message.idempotency_key == self.held_key {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                return a4mc::ThrottleDecision::defer(
                    "fixture hold",
                    Some(Duration::from_millis(50)),
                );
            }
            a4mc::ThrottleDecision::Allow
        }
    }

    #[test]
    fn a_held_recovered_reply_holds_only_its_own_chat() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            // A finished reply owed a resend: recovery schedules it as
            // worker work rather than waiting it out inline.
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello agent", 2),
                        reply: Some("stuck reply".to_owned()),
                        reply_key: Some("reply:2".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // The resend's key is held by host policy forever; an unrelated
        // chat's /whoami still has to reach a worker and deliver.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 9,
                message: Some(text_message(88, 88, Some("zoe"), "/whoami", 9)),
            }])),
            ..MockBotTransport::default()
        };
        let hooks = Arc::new(HoldKeyHooks {
            held_key: "reply:2",
            attempts: AtomicUsize::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(hooks.clone()),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        wait_until(
            || sent.lock().unwrap().iter().any(|(chat, _)| *chat == 88),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap().unwrap();

        assert!(
            hooks.attempts.load(Ordering::SeqCst) > 0,
            "the resend was never attempted"
        );
        assert!(
            !sent.lock().unwrap().iter().any(|(chat, _)| *chat == 42),
            "the held reply was delivered around the policy"
        );
        let tasks = BindingStore::open_in(&root).unwrap().pending_updates();
        assert!(
            tasks.iter().any(|task| task.update_id == 2),
            "the held reply's durable record was dropped: {tasks:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_recovered_reply_queues_behind_an_older_unfinished_message() {
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
            // Same chat, record order: an unfinished message ahead of a
            // finished reply owed a resend. Recovery feeds both through
            // the one bounded admission path in per-chat order, so the
            // newer reply can never run before the older turn.
            store
                .admit_updates(
                    &[
                        crate::binding::PendingUpdate {
                            update_id: 3,
                            sequence: 0,
                            message: text_message(42, 42, Some("alice"), "hello agent", 3),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        crate::binding::PendingUpdate {
                            update_id: 4,
                            sequence: 0,
                            message: text_message(42, 42, Some("alice"), "again", 4),
                            reply: Some("stuck reply".to_owned()),
                            reply_key: Some("reply:4".to_owned()),
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                    ],
                    &[],
                    &[],
                    5,
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
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .filter(|(chat, _)| *chat == 42)
                    .count()
                    == 2
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        let chat_replies: Vec<&str> = posts
            .iter()
            .filter(|(chat, _)| *chat == 42)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(
            chat_replies,
            ["synthetic", "stuck reply"],
            "the resend overtook the older unfinished turn in its own chat"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_failed_reply_record_propagates_and_the_task_survives_for_recovery() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
        store.approve(&pending.code).unwrap();
        store.set_agent(42, Some("codex".into())).unwrap();
        store
            .admit_updates(
                &[crate::binding::PendingUpdate {
                    update_id: 9,
                    sequence: 0,
                    message: text_message(42, 42, Some("alice"), "hello agent", 9),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                10,
            )
            .unwrap();
        // The first write inside the run is the worker's reply record.
        // It must surface to the supervising loop — a fallback or
        // settlement write that lands afterwards can never be allowed
        // to mask the original failure or settle the unrecorded turn.
        store.fail_next_write_for_test();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        // Stop is already raised: the drained backlog still runs, so
        // the worker hits the poisoned write without any polling.
        let stop = Arc::new(AtomicBool::new(true));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a4mc_telegram_state_write_failed"),
            "the record failure never reached the supervisor: {error}"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "an unrecorded reply was delivered"
        );
        // Nothing was settled: the task keeps its claim — no reply —
        // so the next run re-dispatches the turn instead of resending
        // a reply that was never recorded.
        {
            let reopened = BindingStore::open_in(&root).unwrap();
            let task = reopened
                .pending_update(9)
                .expect("the failed turn's record was dropped or settled");
            assert!(!task.has_reply());
        }
        // Recovery re-runs the turn and delivers its reply: the failed
        // record write costs one restart, not the paid result.
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(
            sent.lock().unwrap()[0].1,
            "synthetic",
            "the retained task never re-ran its turn"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_agent_rebind_during_the_admission_call_is_not_overwritten() {
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
        // The host's own rebind lands while `/agent` checks admission:
        // a second handle on the same root moves the binding's revision
        // mid-command, and the guarded write must refuse it — the
        // revision the command captured was taken BEFORE the host
        // call, so the intervening change is not adopted as the
        // command's own precondition.
        let racing_root = root.clone();
        *MID_SCAN_ACTION.lock().unwrap() = Some(Box::new(move || {
            BindingStore::open_in(&racing_root)
                .unwrap()
                .set_agent(42, Some("claude".into()))
                .unwrap();
        }));
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 9,
                message: Some(text_message(42, 42, Some("alice"), "/agent codex", 9)),
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
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            sent.lock().unwrap()[0].1,
            "The chat's pairing moved while the command ran — the agent was not changed.",
            "the command confirmed a rebind it did not commit"
        );
        let reopened = BindingStore::open_in(&root).unwrap();
        assert_eq!(
            reopened.binding(42).unwrap().agent_id.as_deref(),
            Some("claude"),
            "the racing rebind was overwritten by the command"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_delivery_key_namespaces_the_claims_sequence() {
        // A restarted id sequence mints keys in its own namespace, so a
        // retained dead-sequence delivery can never collide with the
        // fresh sequence's reply for the same update id. Sequence zero
        // keeps the revision-one shape older records resume under. The
        // sequenced form carries a non-numeric marker so it can never
        // re-mint a legacy multipart key — `reply:1:1` is update 1's
        // second part, and a bare `reply:1:1` minted for sequence 1,
        // update 1 would read as exactly that.
        assert_eq!(reply_key(TaskKey::from(7), "reply"), "reply:7");
        assert_eq!(reply_key(TaskKey::new(1, 7), "reply"), "reply:s1:7");
        assert_eq!(reply_key(TaskKey::new(1, 7), "error"), "error:s1:7");
        assert_ne!(reply_key(TaskKey::new(1, 1), "reply"), "reply:1:1");
    }

    #[test]
    fn a_partial_worker_spawn_failure_shuts_down_and_joins_the_started_workers() {
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Arc::new(Scheduler::new(4, Arc::clone(&stop)));
        // The third spawn fails; the two workers already started must
        // be shut down and joined rather than dropped still parked.
        scheduler.fail_spawn_at_for_test(2);
        let ran = Arc::new(AtomicUsize::new(0));
        let processor = {
            let ran = Arc::clone(&ran);
            move |_chat_id: i64, _job: Scheduled| -> Result<()> {
                ran.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };
        let error = scheduler
            .spawn_workers(4, processor, Arc::new(Mutex::new(None)))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "a4mc_telegram_runtime_spawn_failed",
            "unexpected error: {error}"
        );
        assert!(
            stop.load(Ordering::SeqCst),
            "the spawn failure did not raise shutdown"
        );
        // Work enqueued after the failure can never be picked up: the
        // workers that survived the partial spawn are gone — had their
        // handles been dropped parked, this job would still run.
        scheduler.enqueue(Scheduled::Message {
            key: TaskKey::from(1),
            message: Box::new(text_message(1, 1, None, "a", 1)),
        });
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "a worker survived the failed spawn"
        );
    }

    #[test]
    fn a_legacy_multipart_resend_and_a_fresh_update_share_one_dedupe_pipeline() {
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
            // A dead-sequence reply too large for one send: its parts
            // deliver under `reply:1` and `reply:1:1` — the second
            // being exactly the key a bare `purpose:sequence:id`
            // format would mint for sequence 1, update 1.
            let oversized = "d".repeat(a4mc::MAX_OUTBOUND_TEXT_CHARS + 200);
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 1,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "hello", 1),
                        reply: Some(oversized),
                        reply_key: Some("reply:1".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    2,
                )
                .unwrap();
            // The sequence rolls over and the restarted numbering
            // lawfully reuses update id 1 for a fresh turn — its reply
            // must post under a key no dead-sequence part key can
            // equal, or the dedupe cache suppresses it as a repeat.
            store.expire_sequence().unwrap();
            store
                .admit_updates(
                    &[crate::binding::PendingUpdate {
                        update_id: 1,
                        sequence: 0,
                        message: text_message(42, 42, Some("alice"), "again", 1),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    2,
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
        // The first contract part (32K) chunks at the platform bound
        // into 8 posts, its tail posts under `reply:1:1`, and the fresh
        // turn posts its own reply: 10 sends in all.
        wait_until(|| sent.lock().unwrap().len() == 10, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert!(
            posts
                .iter()
                .any(|(_, text)| text.len() == 200 && text.chars().all(|c| c == 'd')),
            "the legacy resend's second part never posted: {:?}",
            posts.iter().map(|(_, text)| text.len()).collect::<Vec<_>>()
        );
        assert_eq!(
            posts.iter().filter(|(_, text)| text == "synthetic").count(),
            1,
            "the fresh sequence's reply was suppressed by the dead sequence's part key"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn each_live_sequence_earns_its_own_idle_check() {
        let root = temp_root();
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let updates = Arc::new(Mutex::new(vec![Update {
            update_id: 9,
            message: Some(text_message(42, 42, Some("alice"), "/whoami", 9)),
        }]));
        let observed_offsets = Arc::new(Mutex::new(Vec::<i64>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::clone(&updates),
            observed_offsets: Arc::clone(&observed_offsets),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            poll_sequence_idle: Duration::from_millis(60),
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        // A second handle watches the sequence counter: the first
        // rollover is not the last — a cursor this run resynced is the
        // live mark, and ITS silent numbering must roll over too.
        let watcher = Arc::new(Mutex::new(BindingStore::open_in(&root).unwrap()));
        let sequence = |watcher: &Mutex<BindingStore>| {
            let mut store = watcher.lock().unwrap();
            store.refresh().unwrap();
            store.poll_sequence()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| sent.lock().unwrap().len() == 1, Duration::from_secs(10));
        wait_until(|| sequence(&watcher) == 1, Duration::from_secs(10));
        // The restarted numbering reuses a lower id — only deliverable
        // while the poller passes the restarted cursor.
        updates.lock().unwrap().push(Update {
            update_id: 4,
            message: Some(text_message(88, 88, Some("zoe"), "/whoami", 4)),
        });
        wait_until(|| sent.lock().unwrap().len() == 2, Duration::from_secs(10));
        // The second idle window must roll the second sequence too —
        // a once-per-run latch would keep confirming this cursor's
        // high-water mark instead.
        wait_until(|| sequence(&watcher) == 2, Duration::from_secs(10));
        updates.lock().unwrap().push(Update {
            update_id: 3,
            message: Some(text_message(99, 99, Some("max"), "/whoami", 3)),
        });
        wait_until(|| sent.lock().unwrap().len() == 3, Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        // Every cursor the poller confirmed after a commit is a live
        // mark: each rollover is a nonzero-to-zero transition, and two
        // committed sequences rolling over in one run is the fix under
        // test — a once-per-run latch would show exactly one.
        let offsets = observed_offsets.lock().unwrap();
        let resets = offsets
            .windows(2)
            .filter(|window| window[0] != 0 && window[1] == 0)
            .count();
        assert!(
            resets >= 2,
            "the second rollover never reset the cursor: {offsets:?}"
        );
        assert!(
            BindingStore::open_in(&root).unwrap().poll_sequence() >= 2,
            "the second rollover never fired"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_checkpoint_write_failure_reaches_the_supervisor() {
        let _lane_guard = crate::LANE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        install_synthetic_lane();
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
        store.approve(&pending.code).unwrap();
        store.set_agent(42, Some("codex".into())).unwrap();
        store
            .admit_updates(
                &[crate::binding::PendingUpdate {
                    update_id: 9,
                    sequence: 0,
                    message: text_message(42, 42, Some("alice"), "hello agent", 9),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                10,
            )
            .unwrap();
        // The reply record lands; the first checkpoint write — the
        // in-flight marker ahead of the platform post — fails. A store
        // that cannot take writes must reach the supervising loop,
        // never be treated as handled because the task has a reply.
        store.fail_next_write_after_for_test(1);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(true));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a4mc_telegram_checkpoint_failed"),
            "the checkpoint failure never reached the supervisor: {error}"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a send posted after its checkpoint write failed"
        );
        {
            let reopened = BindingStore::open_in(&root).unwrap();
            let task = reopened
                .pending_update(9)
                .expect("the recorded reply was settled over");
            assert!(task.has_reply());
        }
        // Recovery resends the retained reply — the failed checkpoint
        // costs one restart, not the paid result.
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        assert_eq!(sent.lock().unwrap()[0].1, "synthetic");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_refusal_commit_failure_reaches_the_supervisor() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store
            .admit_updates(
                &[PendingUpdate {
                    update_id: 7,
                    sequence: 0,
                    message: text_message(9, 9, Some("alice"), "/start", 7),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                8,
            )
            .unwrap();
        store
            .record_pairing_and_reply(
                9,
                9,
                Some("alice".into()),
                7,
                "reply:7",
                |record| format!("Pairing code: {}", record.code),
                "That pairing offer did not hold — send /start to request a fresh code.",
            )
            .unwrap();
        // The exact offer the reply carries lapses: the resend's
        // resolve must commit the refusal — a durable write, not a
        // read. Its failure is a persistence failure for the
        // supervising loop, never a resolved payload to report and
        // park until a restart.
        store.request_pairing(9, 9, Some("alice".into())).unwrap();
        // Startup's own event-settle write stays healthy; the
        // refusal's commit is the one that fails.
        store.fail_next_write_after_for_test(1);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(true));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            ..RuntimeConfig::default()
        };
        let error = run_channel_loop(transport, store, config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("a4mc_telegram_state_write_failed"),
            "the refusal commit failure never reached the supervisor: {error}"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a send posted while its refusal commit failed"
        );
        let task = BindingStore::open_in(&root)
            .unwrap()
            .pending_update(7)
            .expect("the recorded reply was settled over");
        assert!(task.has_reply());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_agent_command_refuses_after_its_authorized_pairing_vanishes() {
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
        // The pairing the command was authorized under disappears while
        // `ensure_known_agent` runs, and the user re-pairs fresh: the
        // command's captured revision must refuse the write — a `None`
        // snapshot would commit over the subsequent pairing instead.
        let racing_root = root.clone();
        *MID_SCAN_ACTION.lock().unwrap() = Some(Box::new(move || {
            let mut store = BindingStore::open_in(&racing_root).unwrap();
            store.revoke(42).unwrap();
            let pending = store.request_pairing(42, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
        }));
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::new(Mutex::new(vec![Update {
                update_id: 9,
                message: Some(text_message(42, 42, Some("alice"), "/agent codex", 9)),
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
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            sent.lock().unwrap()[0].1,
            "The chat's pairing moved while the command ran — the agent was not changed.",
            "the command confirmed a rebind it did not commit"
        );
        let reopened = BindingStore::open_in(&root).unwrap();
        let binding = reopened.binding(42).unwrap();
        assert!(binding.paired);
        assert_eq!(
            binding.agent_id, None,
            "the vanished pairing's re-pairing was overwritten"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_replaced_pairing_offer_resends_its_refused_reply() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("alice"), "/start", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            // The offer and the reply carrying its code commit bound,
            // then a newer request replaces the exact offer before the
            // recorded reply ever sends: the restart resend must
            // publish the refused variant, never the dead code.
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    "That pairing offer did not hold — send /start to request a fresh code.",
                )
                .unwrap();
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts[0].1, "That pairing offer did not hold — send /start to request a fresh code.",
            "the resend published a replaced offer's dead code: {posts:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_reply_bound_after_capacity_frees_is_resent_without_a_restart() {
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
            // Task 1's record fills the bounded document, so task 2's
            // staged completion — a session change too big to land
            // alongside it — cannot commit and stays durable but
            // unbound. Unknown commands keep both neighbors on the
            // session-neutral reply path, so the stranded record's
            // session precondition still holds when space frees.
            store
                .admit_updates(
                    &[
                        PendingUpdate {
                            update_id: 1,
                            sequence: 0,
                            message: text_message(
                                42,
                                42,
                                Some("alice"),
                                &format!("/noopcmd {}", "x".repeat(200_000)),
                                1,
                            ),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        PendingUpdate {
                            update_id: 2,
                            sequence: 0,
                            message: text_message(42, 42, Some("alice"), "waiting", 2),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        PendingUpdate {
                            update_id: 3,
                            sequence: 0,
                            message: text_message(42, 42, Some("alice"), "/noopcmd", 3),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                    ],
                    &[],
                    &[],
                    4,
                )
                .unwrap();
            // The record's own commit is refused for document space:
            // the manifest is already durable — the crash-window shape
            // startup reconciliation owns — while its session change
            // cannot land alongside task 1's record.
            let expected = store.binding(42).unwrap().clone();
            let error = store
                .record_reply_and_session(
                    42,
                    2,
                    "reply:2",
                    Some("s".repeat(150_000)),
                    &expected,
                    |_| "staged reply body".to_owned(),
                )
                .unwrap_err();
            assert_eq!(
                error.to_string().as_str(),
                "a4mc_telegram_state_full",
                "the oversized record committed instead of stranding: {error}"
            );
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .any(|(_, text)| text == "staged reply body")
            },
            Duration::from_secs(20),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        // Startup reported the record stranded for space, but the
        // reply still delivered once the settling work freed it — no
        // restart needed.
        assert_eq!(
            *stranded.lock().unwrap(),
            vec![(2, "a4mc_telegram_state_full".to_owned())],
            "the oversized record was never reported stranded"
        );
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the newly bound reply never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_last_settling_task_recovers_the_reply_its_space_frees() {
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
            // The same shape as the three-task variant, minus the third
            // task: the ONLY runnable work left is the task whose
            // settlement frees the room task 2's staged record needs —
            // if the settling write itself does not reconcile, nothing
            // else ever schedules the reply.
            store
                .admit_updates(
                    &[
                        PendingUpdate {
                            update_id: 1,
                            sequence: 0,
                            message: text_message(
                                42,
                                42,
                                Some("alice"),
                                &format!("/noopcmd {}", "x".repeat(200_000)),
                                1,
                            ),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        PendingUpdate {
                            update_id: 2,
                            sequence: 0,
                            message: text_message(42, 42, Some("alice"), "waiting", 2),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                    ],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
            let expected = store.binding(42).unwrap().clone();
            let error = store
                .record_reply_and_session(
                    42,
                    2,
                    "reply:2",
                    Some("s".repeat(150_000)),
                    &expected,
                    |_| "staged reply body".to_owned(),
                )
                .unwrap_err();
            assert_eq!(
                error.to_string().as_str(),
                "a4mc_telegram_state_full",
                "the oversized record committed instead of stranding: {error}"
            );
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
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .any(|(_, text)| text == "staged reply body")
            },
            Duration::from_secs(20),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        reset_lane_output();

        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the reply the last settlement freed never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_reply_bound_inside_a_refused_admission_still_delivers() {
        let root = temp_root();
        let replies = root.join("bindings.json.replies");
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            // Task 2's staged record cannot bind while the document is
            // full, so startup recovery excludes the task instead of
            // dispatching its message again.
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(9, 9, Some("bob"), "waiting", 2),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
            // One huge pending pairing pins the document near the read
            // bound — it is never approved, so nothing else can claim
            // its space while the test runs.
            store
                .request_pairing(7, 7, Some("u".repeat(240_000)))
                .unwrap();
            // An approved chat's agent field takes arbitrary text, so
            // measured padding parks the slack under the pointer size a
            // bound record needs.
            let pad = store.request_pairing(6, 6, Some("pad".into())).unwrap();
            store.approve(&pad.code).unwrap();
            let bound_file = root.join("bindings.json");
            const MAX_DOC_BYTES: usize = 256 * 1024;
            for _ in 0..4 {
                let remaining = MAX_DOC_BYTES - std::fs::read(&bound_file).unwrap().len();
                if remaining <= 4 {
                    break;
                }
                let agent = store
                    .binding(6)
                    .and_then(|binding| binding.agent_id.as_deref())
                    .map_or(0, str::len);
                store
                    .set_agent(6, Some("a".repeat(agent + remaining - 4)))
                    .unwrap();
            }
            std::fs::create_dir_all(&replies).unwrap();
            std::fs::write(
                replies.join("reply-2.json"),
                serde_json::to_string(&serde_json::json!({
                    "updateId": 2,
                    "sequence": 0,
                    "payload": "reply-2.json",
                    "key": "reply:2",
                    "effect": { "kind": "reply" },
                    "text": "recovered reply",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let updates = Arc::new(Mutex::new(Vec::<Update>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            updates: Arc::clone(&updates),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            worker_count: 1,
            // One permanently-refused admission exhausts the budget —
            // the shape that used to exit the loop with the discovered
            // bind still undrained.
            max_poll_failures: 1,
            ..RuntimeConfig::default()
        };
        let root_for_host = root.clone();
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config));
        // A second store instance — the host revoking a binding — frees
        // the pinned space and binds task 2's record in the same write.
        // Its notification lives only in that instance's memory, so the
        // running poller must rediscover the durable transition inside
        // the admission that still refuses the fetched batch — and
        // drain it before the drained check decides nothing is left.
        thread::sleep(Duration::from_millis(300));
        {
            let mut host = BindingStore::open_in(&root_for_host).unwrap();
            host.revoke(6).unwrap();
        }
        updates.lock().unwrap().push(Update {
            update_id: 3,
            message: Some(text_message(9, 9, Some("bob"), &"b".repeat(60_000), 3)),
        });
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .any(|(_, text)| text == "recovered reply")
            },
            Duration::from_secs(15),
        );
        stop.store(true, Ordering::SeqCst);
        // Either exit is lawful: the poller may still be waiting out the
        // unadmittable update when stop lands, or — once the discovered
        // bind has fully drained and the store still refuses — it may
        // already have surfaced the permanent refusal the failure
        // budget exists for. What this test pins is that the reply
        // bound inside the refused admission delivered either way.
        match handle.join().unwrap() {
            Ok(_) => {}
            Err(error) => assert!(
                error.to_string().contains("a4mc_telegram_poll_failed"),
                "unexpected loop error: {error}"
            ),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn producers_share_one_atomic_admission_bound() {
        let stop = Arc::new(AtomicBool::new(false));
        let scheduler = Scheduler::new(1, Arc::clone(&stop));
        let job = |update_id: i64| Scheduled::Message {
            key: TaskKey::new(0, update_id),
            message: Box::new(text_message(9, 9, Some("bob"), "work", update_id)),
        };
        // A worker-side recovered-reply offer takes the only slot.
        assert!(scheduler.try_enqueue(job(1)).is_ok());
        assert_eq!(scheduler.admitted(), 1);
        // The poller's backlog drain must bounce off the bound — not
        // overrun it — and keep the refused job for the next round.
        let mut pending = VecDeque::from([job(2)]);
        admit_available(&scheduler, &mut pending);
        assert_eq!(
            scheduler.admitted(),
            1,
            "the poller admitted past the bound a worker already held"
        );
        assert_eq!(pending.len(), 1, "a refused job left the poller's backlog");
        // And a second worker offer is refused with the job returned —
        // never dropped.
        assert!(
            scheduler.try_enqueue(job(3)).is_err(),
            "a producer admitted past the bound"
        );
        scheduler.shutdown();
    }

    #[test]
    fn a_deferred_pairing_reply_resolves_the_refused_variant_on_retry() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("alice"), "/start", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            // The offer and its code reply commit bound while the offer
            // is still current — the lapse lands only inside the send
            // policy's deferral window, the gap the old check never
            // revisited.
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    "That pairing offer did not hold — send /start to request a fresh code.",
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
            outbound_hooks: Some(Arc::new(DeferringHooks {
                attempts: AtomicUsize::new(0),
                deferrals: 1,
                retry_after_ms: 1_500,
            })),
            ..RuntimeConfig::default()
        };
        let root_for_lapse = root.clone();
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // Mid-wait, a newer request replaces the exact offer the
        // recorded reply carries.
        thread::sleep(Duration::from_millis(400));
        BindingStore::open_in(&root_for_lapse)
            .unwrap()
            .request_pairing(9, 9, Some("alice".into()))
            .unwrap();
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.as_slice(),
            &[(
                9,
                "That pairing offer did not hold — send /start to request a fresh code.".to_owned()
            )],
            "a deferred retry published the lapsed offer's dead code: {posts:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_lapsed_offer_resend_clears_the_stale_checkpoint_and_delivers() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("alice"), "/start", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    "That pairing offer did not hold — send /start to request a fresh code.",
                )
                .unwrap();
            // A definitively-rejected first attempt left a checkpoint
            // bound to the code text — nothing confirmed, so swapping
            // payloads is safe, but the old position can never apply to
            // the refused variant. Its foreign digest stands in for the
            // digest the original text prepared.
            store
                .record_reply_checkpoint(
                    7,
                    Some(crate::transport::SendProgress {
                        confirmed: vec![],
                        next_part: 0,
                        outcome_unknown: false,
                        binding: Some(crate::transport::SendBinding {
                            dedupe_key: "reply:7".to_owned(),
                            chat_id: 9,
                            payload_digest: "0".repeat(64),
                        }),
                    }),
                    None,
                )
                .unwrap();
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.as_slice(),
            &[(
                9,
                "That pairing offer did not hold — send /start to request a fresh code.".to_owned()
            )],
            "the replaced payload still sent under its stale checkpoint: {posts:?}"
        );
        // The cleared position is durable: nothing about the old
        // payload's checkpoint survives into the settled record.
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the substituted reply never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_confirmed_checkpoint_is_never_dropped_on_a_resume_mismatch() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("bob"), "waiting", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            store.record_reply(7, "deliver me", "reply:7").unwrap();
            // Two chunks of contract part zero were confirmed on a
            // prepared send whose digest no longer matches — a host
            // hook reshaped the payload or the dedupe key on retry.
            // Contract part zero proves nothing about platform
            // progress, so this position is terminal, never resettable.
            store
                .record_reply_checkpoint(
                    7,
                    Some(crate::transport::SendProgress {
                        confirmed: vec![11, 12],
                        next_part: 2,
                        outcome_unknown: false,
                        binding: Some(crate::transport::SendBinding {
                            dedupe_key: "reply:7".to_owned(),
                            chat_id: 9,
                            payload_digest: "0".repeat(64),
                        }),
                    }),
                    None,
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stuck = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stuck);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        wait_until(
            || !stuck.lock().unwrap().is_empty(),
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(
            stuck.lock().unwrap().as_slice(),
            &[(7, "a4mc_telegram_resume_mismatch".to_owned())],
            "the foreign checkpoint was kept but never reported"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "a reset confirmed position reposted its chunks: {:?}",
            sent.lock().unwrap()
        );
        // The checkpoint survives intact: confirmed platform progress
        // is never dropped to make a reshaped retry fit.
        let progress = BindingStore::open_in(&root)
            .unwrap()
            .pending_update(7)
            .and_then(|task| task.reply_progress)
            .expect("the confirmed checkpoint was dropped");
        assert_eq!(progress.confirmed, vec![11, 12]);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A host policy that derives one fixed dedupe key off the
    /// contract's delivery key — the shape that parks a retryable
    /// partial where a `delivery_key`-keyed cleanup never looks.
    struct FixedKeyHooks;

    impl a4mc::OutboundHooks for FixedKeyHooks {
        fn dedupe_key(&self, _: &a4mc::SendContext, _: &a4mc::OutboundMessage) -> Option<String> {
            Some("host-derived-key".to_owned())
        }
    }

    #[test]
    fn a_host_keyed_partial_clears_and_the_refusal_delivers() {
        let root = temp_root();
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("alice"), "/start", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    "That pairing offer did not hold — send /start to request a fresh code.",
                )
                .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            // The first attempt dies at part zero, definitively
            // retryable — leaving a cached partial the host hook filed
            // under its own derived key, not the delivery key.
            fail_send_at_part: Some((
                0,
                TelegramApiError::new("a4mc_telegram_throttled", "Bot API rate limited")
                    .with_retry_after(Some(1)),
                false,
            )),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            outbound_hooks: Some(Arc::new(FixedKeyHooks)),
            ..RuntimeConfig::default()
        };
        let root_for_lapse = root.clone();
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // The offer lapses inside the retry window: the refusal's send
        // must clear the host-keyed partial its own checkpoint names —
        // clearing the contract key leaves the stale position to
        // refuse every later attempt.
        thread::sleep(Duration::from_millis(300));
        BindingStore::open_in(&root_for_lapse)
            .unwrap()
            .request_pairing(9, 9, Some("alice".into()))
            .unwrap();
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(15));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.as_slice(),
            &[(
                9,
                "That pairing offer did not hold — send /start to request a fresh code.".to_owned()
            )],
            "the host-keyed partial stayed cached and blocked the refusal: {posts:?}"
        );
        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the substituted reply never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_refusal_send_resumes_its_own_checkpoint_on_restart() {
        let root = temp_root();
        // The refusal carries more than one platform chunk so a
        // mid-flight stop leaves real confirmed progress behind.
        let refused = format!(
            "That pairing offer did not hold — send /start to request a fresh code.\n{}",
            "x".repeat(4_200)
        );
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: text_message(9, 9, Some("alice"), "/start", 7),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    &refused,
                )
                .unwrap();
            // The exact offer the reply carries lapses before the send
            // starts, so the recorded reply already resolves refused.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // First run: the refusal's second chunk is rejected
        // definitively — the checkpoint commits chunk zero's confirmed
        // id against the refusal's digest and the task stays open.
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_bad_request", "rejected"),
                false,
            )),
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
        wait_until(|| !sent.lock().unwrap().is_empty(), Duration::from_secs(10));
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
        let first_part = sent.lock().unwrap()[0].1.clone();

        // Second run on the same durable state: the restarted resend
        // must resolve the same refusal payload its checkpoint
        // describes and continue from chunk one — never fall back to
        // the lapsed offer's code and never repost chunk zero.
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
        wait_until(
            || {
                BindingStore::open_in(&root)
                    .map(|store| store.pending_updates().is_empty())
                    .unwrap_or(false)
            },
            Duration::from_secs(10),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        let posts = sent.lock().unwrap();
        assert_eq!(
            posts.len(),
            2,
            "the refusal reposted a confirmed chunk or never resumed: {posts:?}"
        );
        assert!(
            format!("{}{}", posts[0].1, posts[1].1) == refused,
            "the restarted send posted a different payload than its checkpoint earned: {posts:?}"
        );
        assert!(
            !posts.iter().any(|(_, text)| text.contains("Pairing code")),
            "the restarted send published the lapsed offer's dead code: {posts:?}"
        );
        assert_eq!(posts[0].1, first_part);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_reply_bound_during_event_cleanup_joins_the_startup_queue() {
        let root = temp_root();
        let replies = root.join("bindings.json.replies");
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 5,
                        sequence: 0,
                        message: text_message(9, 9, Some("bob"), "waiting", 5),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    // A full dropped history whose oldest record is
                    // large: the settle below pushes one entry past the
                    // cap and this record drains — that is the space
                    // the stranded reply binds into.
                    &(0..256)
                        .map(|id| DroppedUpdate {
                            update_id: 300 + id,
                            raw_kind: if id == 0 {
                                "d".repeat(8 * 1024)
                            } else {
                                "d".to_owned()
                            },
                            sequence: 0,
                        })
                        .collect::<Vec<_>>(),
                    // A marker the cursor already moved past: the
                    // startup settle turns it into dropped history,
                    // and that same write drains the cap and reconciles
                    // the staged reply it frees.
                    &[DroppedUpdate {
                        update_id: 2,
                        raw_kind: "e".to_owned(),
                        sequence: 0,
                    }],
                    8,
                )
                .unwrap();
            // Pin the document near the read bound so the reply cannot
            // bind until the settle frees its room — the seeded
            // history already holds ~20 KiB and pairing writes keep a
            // 16 KiB lifecycle reserve, so the offer is sized to leave
            // the total under both limits.
            store
                .request_pairing(7, 7, Some("u".repeat(210_000)))
                .unwrap();
            let pad = store.request_pairing(6, 6, Some("pad".into())).unwrap();
            store.approve(&pad.code).unwrap();
            let bound_file = root.join("bindings.json");
            const MAX_DOC_BYTES: usize = 256 * 1024;
            for _ in 0..4 {
                let remaining = MAX_DOC_BYTES - std::fs::read(&bound_file).unwrap().len();
                if remaining <= 4 {
                    break;
                }
                let agent = store
                    .binding(6)
                    .and_then(|binding| binding.agent_id.as_deref())
                    .map_or(0, str::len);
                store
                    .set_agent(6, Some("a".repeat(agent + remaining - 4)))
                    .unwrap();
            }
            std::fs::create_dir_all(&replies).unwrap();
            std::fs::write(
                replies.join("reply-5.json"),
                serde_json::to_string(&serde_json::json!({
                    "updateId": 5,
                    "sequence": 0,
                    "payload": "reply-5.json",
                    "key": "reply:5",
                    "effect": { "kind": "reply" },
                    "text": "cleanup reply",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let stranded = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let observed = Arc::clone(&stranded);
        let transport = MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let config = RuntimeConfig {
            poll_timeout_secs: 1,
            stop: Arc::clone(&stop),
            on_stuck: Some(Box::new(move |item: &StrandedReply| {
                observed
                    .lock()
                    .unwrap()
                    .push((item.update_id, item.code.clone()));
            })),
            ..RuntimeConfig::default()
        };
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // The reply binds inside the event settle's own write — after
        // the stranded set was captured — and must still reach the
        // resend queue the startup snapshot builds.
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .any(|(_, text)| text == "cleanup reply")
            },
            Duration::from_secs(15),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the reply event cleanup bound never settled"
        );
        assert!(
            stranded.lock().unwrap().is_empty(),
            "a reply the recovery settle bound was still reported stuck: {:?}",
            *stranded.lock().unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_idle_poll_discovers_a_bind_another_store_committed() {
        let root = temp_root();
        let replies = root.join("bindings.json.replies");
        {
            let mut store = BindingStore::open_in(&root).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 2,
                        sequence: 0,
                        message: text_message(9, 9, Some("bob"), "waiting", 2),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    3,
                )
                .unwrap();
            store
                .request_pairing(7, 7, Some("u".repeat(240_000)))
                .unwrap();
            let pad = store.request_pairing(6, 6, Some("pad".into())).unwrap();
            store.approve(&pad.code).unwrap();
            let bound_file = root.join("bindings.json");
            const MAX_DOC_BYTES: usize = 256 * 1024;
            for _ in 0..4 {
                let remaining = MAX_DOC_BYTES - std::fs::read(&bound_file).unwrap().len();
                if remaining <= 4 {
                    break;
                }
                let agent = store
                    .binding(6)
                    .and_then(|binding| binding.agent_id.as_deref())
                    .map_or(0, str::len);
                store
                    .set_agent(6, Some("a".repeat(agent + remaining - 4)))
                    .unwrap();
            }
            std::fs::create_dir_all(&replies).unwrap();
            std::fs::write(
                replies.join("reply-2.json"),
                serde_json::to_string(&serde_json::json!({
                    "updateId": 2,
                    "sequence": 0,
                    "payload": "reply-2.json",
                    "key": "reply:2",
                    "effect": { "kind": "reply" },
                    "text": "recovered reply",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        // Nothing ever arrives: the poller stays idle the whole run —
        // the bind it must discover is committed entirely outside it.
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
        let root_for_host = root.clone();
        let store = BindingStore::open_in(&root).unwrap();
        let handle = thread::spawn(move || run_channel_loop(transport, store, config).unwrap());
        // A second instance frees the pinned space and binds task 2's
        // record in one write; the notification stays in its own
        // memory. Only an idle-cycle state reload can discover the
        // durable transition — no update, mutation or restart ever
        // lands on the polling instance.
        thread::sleep(Duration::from_millis(300));
        {
            let mut host = BindingStore::open_in(&root_for_host).unwrap();
            host.revoke(6).unwrap();
        }
        wait_until(
            || {
                sent.lock()
                    .unwrap()
                    .iter()
                    .any(|(_, text)| text == "recovered reply")
            },
            Duration::from_secs(15),
        );
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert!(
            BindingStore::open_in(&root)
                .unwrap()
                .pending_updates()
                .is_empty(),
            "the externally bound reply never settled"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_foreign_cached_partial_yields_to_the_durable_checkpoint() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store
            .admit_updates(
                &[PendingUpdate {
                    update_id: 7,
                    sequence: 0,
                    message: text_message(9, 9, Some("bob"), "waiting", 7),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                8,
            )
            .unwrap();
        // Two platform chunks inside one contract send: the first is
        // confirmed, the second definitively rejected — the durable
        // checkpoint that must survive the foreign collision.
        let text = "x".repeat(9_000);
        store.record_reply(7, &text, "reply:7").unwrap();
        let store = Mutex::new(store);
        let stop = AtomicBool::new(false);

        // Earn the real checkpoint on a scratch channel so its binding
        // carries this payload's genuine digest.
        let earning = TelegramChannel::new(Arc::new(MockBotTransport {
            fail_send_at_part: Some((
                1,
                TelegramApiError::new("a4mc_telegram_bad_request", "rejected"),
                false,
            )),
            ..MockBotTransport::default()
        }));
        let mut outbound = a4mc::OutboundMessage::new("9", &text, "reply:7");
        outbound.reply_to_message_id = Some(a4mc::ExternalMessageId::from("7"));
        let checkpoint = earning
            .send_tracked(&outbound, None, &mut |_| Ok(()))
            .unwrap_err()
            .progress
            .map(|progress| *progress)
            .expect("the stopped send carried no checkpoint");
        assert_eq!(checkpoint.confirmed.len(), 1);
        store
            .lock()
            .unwrap()
            .record_reply_checkpoint(7, Some(checkpoint.clone()), None)
            .unwrap();

        // A foreign send parked its own safe-empty partial under the
        // same effective key: it refuses this reply's resume, but it is
        // not the reply's progress — evicting it must not cost the
        // durable checkpoint its confirmed chunk.
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let channel = TelegramChannel::new(Arc::new(MockBotTransport {
            sent: Arc::clone(&sent),
            fail_send_at_part: Some((
                0,
                TelegramApiError::new("a4mc_telegram_bad_request", "rejected"),
                false,
            )),
            ..MockBotTransport::default()
        }));
        assert!(
            channel
                .send_tracked(
                    &a4mc::OutboundMessage::new("9", "a different payload", "reply:7"),
                    None,
                    &mut |_| Ok(()),
                )
                .is_err(),
            "the foreign send must stop mid-flight to park its partial"
        );

        deliver_recorded_reply(
            &channel,
            &store,
            9,
            7,
            TaskKey::new(0, 7),
            "reply:7",
            &text,
            0,
            Some(checkpoint),
            true,
            &stop,
        )
        .unwrap();

        // The foreign entry was evicted alone: the resend continued
        // from the durable checkpoint's next_part instead of reposting
        // the confirmed leading chunk.
        let posts = sent.lock().unwrap().clone();
        assert_eq!(
            posts
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<String>(),
            text[4_096..],
            "the durable confirmed chunk was reposted: {posts:?}"
        );
        let task = store.lock().unwrap().pending_update(7).unwrap();
        assert_eq!(task.reply_sent, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_safe_mismatch_after_the_prefix_clears_only_that_part() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store
            .admit_updates(
                &[PendingUpdate {
                    update_id: 7,
                    sequence: 0,
                    message: text_message(9, 9, Some("bob"), "waiting", 7),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                8,
            )
            .unwrap();
        // Two contract parts: the first is confirmed delivered, the
        // second's durable checkpoint was earned before the host
        // reshaped the send — zero confirmed chunks and a known
        // rejection, safe to clear without touching the prefix.
        let text = format!("{}{}", "a".repeat(32 * 1024), "tail");
        store.record_reply(7, &text, "reply:7").unwrap();
        store
            .record_reply_progress(
                7,
                1,
                Some(SendProgress {
                    confirmed: vec![],
                    next_part: 0,
                    outcome_unknown: false,
                    binding: Some(crate::transport::SendBinding {
                        dedupe_key: "reply:7:1".to_owned(),
                        chat_id: 9,
                        payload_digest: "0".repeat(64),
                    }),
                }),
            )
            .unwrap();
        let store = Mutex::new(store);
        let stop = AtomicBool::new(false);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let channel = TelegramChannel::new(Arc::new(MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        }));

        let progress = store
            .lock()
            .unwrap()
            .pending_update(7)
            .and_then(|task| task.reply_progress);
        deliver_recorded_reply(
            &channel,
            &store,
            9,
            7,
            TaskKey::new(0, 7),
            "reply:7",
            &text,
            1,
            progress,
            true,
            &stop,
        )
        .unwrap();

        // Only the mismatched part resent: the confirmed first part is
        // never reposted and never lost.
        let posts = sent.lock().unwrap().clone();
        assert_eq!(
            posts.as_slice(),
            &[(9, "tail".to_owned())],
            "the delivered prefix was reposted or the part never recovered: {posts:?}"
        );
        let task = store.lock().unwrap().pending_update(7).unwrap();
        assert_eq!(task.reply_sent, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_resend_resumes_the_refusals_own_delivery_progress() {
        let root = temp_root();
        let mut store = BindingStore::open_in(&root).unwrap();
        store
            .admit_updates(
                &[PendingUpdate {
                    update_id: 7,
                    sequence: 0,
                    message: text_message(9, 9, Some("alice"), "/start", 7),
                    reply: None,
                    reply_key: None,
                    reply_sent: 0,
                    reply_progress: None,
                    reply_file: None,
                    reply_retry_at_ms: None,
                    reply_refused: false,
                }],
                &[],
                &[],
                8,
            )
            .unwrap();
        // Two contract parts of refusal text: a resend that finds the
        // refusal already committed must continue where its durable
        // record stopped, not restart the payload.
        let refused = format!("{}{}", "r".repeat(32 * 1024), "t".repeat(5_000));
        store
            .record_pairing_and_reply(
                9,
                9,
                Some("alice".into()),
                7,
                "reply:7",
                |record| format!("Pairing code: {}", record.code),
                &refused,
            )
            .unwrap();
        let task = store.pending_update(7).unwrap();
        let live = store
            .reply_text(&task)
            .unwrap()
            .expect("the offer's live text was not recorded");
        // The offer lapsed while the resend waited: another store
        // selected the refusal and its delivery already confirmed the
        // first contract part plus one platform chunk of the second.
        store.request_pairing(9, 9, Some("alice".into())).unwrap();
        let task = store.pending_update(7).unwrap();
        let resolved = store.resolve_reply(&task).unwrap().unwrap();
        assert_eq!(resolved.text, refused, "the lapsed offer did not refuse");
        store
            .record_reply_progress(
                7,
                1,
                Some(SendProgress {
                    confirmed: vec![91],
                    next_part: 1,
                    outcome_unknown: false,
                    binding: None,
                }),
            )
            .unwrap();
        let store = Mutex::new(store);
        let stop = AtomicBool::new(false);
        let sent = Arc::new(Mutex::new(Vec::<(i64, String)>::new()));
        let channel = TelegramChannel::new(Arc::new(MockBotTransport {
            sent: Arc::clone(&sent),
            ..MockBotTransport::default()
        }));

        // The resend still carries the stale offer text and the
        // provably-safe checkpoint it was resolved with — the only
        // position a clear may drop. The refusal's own confirmed
        // progress is adopted, never erased.
        deliver_recorded_reply(
            &channel,
            &store,
            9,
            7,
            TaskKey::new(0, 7),
            "reply:7",
            &live,
            0,
            Some(SendProgress {
                confirmed: vec![],
                next_part: 0,
                outcome_unknown: false,
                binding: None,
            }),
            true,
            &stop,
        )
        .unwrap();

        // Resumed at contract part one from platform chunk one: only
        // the unconfirmed tail posts — no confirmed chunk reposted and
        // no earned checkpoint erased.
        let posts = sent.lock().unwrap().clone();
        assert_eq!(
            posts.as_slice(),
            &[(9, "t".repeat(904))],
            "the resend erased confirmed progress or reposted it: {posts:?}"
        );
        let task = store.lock().unwrap().pending_update(7).unwrap();
        assert_eq!(task.reply_sent, 2);
        let _ = std::fs::remove_dir_all(root);
    }
}
