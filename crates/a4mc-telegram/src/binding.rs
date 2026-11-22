//! Pairing and per-chat agent/session binding store.
//!
//! The store is channel state the adapter persists where the host points
//! it: pairing codes waiting for host-side approval, each chat's bound
//! agent/session, and the durable getUpdates poll cursor so a restart
//! resumes polling instead of replaying already-confirmed updates.
//! Approval and revocation decisions are host policy; the store only
//! records and serves them. Mutations run under one advisory file lock
//! across reload-merge-write so concurrent writers never silently
//! overwrite each other.

use crate::inbound::InboundMessage;
use crate::private_io::{
    atomic_write_private_text, ensure_private_dir, open_private_lock_file,
    read_private_text_bounded,
};
use anyhow::{Result, anyhow, ensure};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STATE_FILE: &str = "bindings.json";
const MAX_STATE_BYTES: usize = 256 * 1024;
/// Bound on one spilled reply payload — beyond it a completed outcome
/// is refused rather than consuming unbounded state space.
const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
/// Bound on one staged-completion record — a self-contained record
/// carries the payload itself, so the bound must cover a full reply
/// plus key, effect and encoding overhead.
const MAX_STAGED_BYTES: usize = 8 * 1024 * 1024;
/// Headroom admission reserves in the bounded document for the
/// lifecycle metadata an admitted task still has to record — the reply
/// pointer, its delivery key, a session change and delivery
/// checkpoints — so completing admitted work never competes with new
/// admissions for the last bytes.
const LIFECYCLE_RESERVE_BYTES: usize = 16 * 1024;
const MAX_DROPPED_UPDATES: usize = 256;
/// Bound on the settled-id tail: comfortably beyond one long-poll
/// batch, which is the widest window a cursor rollback can refetch.
const MAX_SETTLED_UPDATES: usize = 512;
/// Bound on admitted-but-unfinished tasks: far beyond one long-poll
/// batch; a fuller backlog cannot be confirmed anyway, so a new admit
/// is refused rather than silently confirmed.
const MAX_PENDING_UPDATES: usize = 4096;
const MAX_RAW_KIND_CHARS: usize = 64;
const PAIRING_TTL: Duration = Duration::from_secs(60 * 60);
pub const BINDING_SCHEMA: &str = "a4mc.telegram-bindings.v1";

/// The durable identity of a fetched update's record: the polling
/// sequence it was fetched under plus its platform update id. Update
/// ids are only unique within one id sequence — the platform may
/// restart numbering after a long silence — so a claim, a staged
/// record or a task lookup must name both to never confuse a fresh
/// update for an earlier sequence's unfinished work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskKey {
    pub sequence: u64,
    pub update_id: i64,
}

impl TaskKey {
    pub fn new(sequence: u64, update_id: i64) -> Self {
        Self {
            sequence,
            update_id,
        }
    }
}

/// Bare ids name sequence-0 records — the namespace documents written
/// before sequences existed, and any store that has never expired a
/// sequence, live in.
impl From<i64> for TaskKey {
    fn from(update_id: i64) -> Self {
        Self::new(0, update_id)
    }
}

impl From<(u64, i64)> for TaskKey {
    fn from((sequence, update_id): (u64, i64)) -> Self {
        Self::new(sequence, update_id)
    }
}

/// One platform update this runtime received but could not hand to the
/// host as a message (a dice/game/service payload, or any update with no
/// message body). Persisting the id makes the gap durable even when the
/// host mounts no `on_event` hook, so advancing the poll cursor never
/// silently discards it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DroppedUpdate {
    pub update_id: i64,
    pub raw_kind: String,
    /// The polling sequence the update was fetched under. `0` predates
    /// the field.
    #[serde(default)]
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRecord {
    pub code: String,
    pub chat_id: i64,
    pub user_id: i64,
    pub username: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    /// The document revision the offer was minted at — compared against
    /// the chat's revocation tombstone so an offer recorded before a
    /// revocation stays refused once the guard that refused it is gone.
    /// `0` predates the field.
    #[serde(default)]
    pub minted_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChatBinding {
    pub chat_id: i64,
    pub user_id: i64,
    pub username: Option<String>,
    pub paired: bool,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    pub updated_at: u64,
    /// Revision this binding's routing was last changed at — drawn
    /// from the document's monotone counter and advanced by every
    /// write that changes how the chat routes. Recorded-work
    /// preconditions compare it so a turn started under one routing
    /// can never install its result onto a binding that moved and
    /// came back: A→B→A leaves a different revision even though
    /// user, agent and session values match.
    #[serde(default)]
    pub revision: u64,
}

/// One fetched message update admitted for processing: persisted in the
/// same write that confirms the poll cursor, keyed by update id so a
/// restart resumes exactly its unfinished stage instead of re-running
/// or skipping paid work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingUpdate {
    pub update_id: i64,
    /// The polling sequence this task was admitted under — part of its
    /// claim identity, so a restarted sequence's reused update id can
    /// never shadow this record. `0` predates the field.
    #[serde(default)]
    pub sequence: u64,
    pub message: InboundMessage,
    /// The finished turn's reply, recorded before delivery so an exit
    /// after the agent returned still has the result to resend. `None`
    /// means the message was admitted but never processed.
    #[serde(default)]
    pub reply: Option<String>,
    /// The idempotency key the recorded reply is delivered under —
    /// persisted with the text so a restart resend repeats the first
    /// attempt's key instead of minting a different one (a fallback
    /// error report keeps `error:<id>` rather than being resent as
    /// `reply:<id>`). `None` predates the field; recovery derives the
    /// ordinary `reply:` key for it.
    #[serde(default)]
    pub reply_key: Option<String>,
    /// How many of the recorded reply's contract-level sends were
    /// confirmed delivered, in order. Recovery resends only the tail —
    /// the confirmed prefix is never reposted.
    #[serde(default)]
    pub reply_sent: usize,
    /// The platform-level checkpoint of the send that stopped the last
    /// delivery attempt: the confirmed part prefix and whether the
    /// stopping part's outcome is uncertain. Recovery seeds the channel
    /// with it so the resend continues the same logical send; an
    /// uncertain outcome is refused rather than blindly reposted.
    #[serde(default)]
    pub reply_progress: Option<crate::transport::SendProgress>,
    /// File name of the finished reply's payload record inside the
    /// store's sidecar replies directory. Completed outcomes live
    /// there so a large reply never has to fit the bounded document;
    /// `None` means the reply (if any) is inline in `reply`.
    #[serde(default)]
    pub reply_file: Option<String>,
    /// Unix milliseconds before which the recorded reply must not be
    /// attempted again — the durable form of a platform `Retry-After`
    /// or policy deferral a delivery attempt escaped with. `None`
    /// means no wait is owed. Millisecond precision keeps a restart
    /// from retrying inside the sub-second the whole-second form
    /// truncated away.
    #[serde(default)]
    pub reply_retry_at_ms: Option<u64>,
    /// Whether the bound reply is the staged record's refused-effect
    /// variant: a command whose routing change did not commit records
    /// both outcomes, and recovery selects by what the guarded effect
    /// actually did — never the success text the original stage hoped
    /// to commit.
    #[serde(default)]
    pub reply_refused: bool,
}

impl PendingUpdate {
    /// The task's full claim identity — sequence plus update id.
    pub fn key(&self) -> TaskKey {
        TaskKey::new(self.sequence, self.update_id)
    }

    /// Whether a finished reply is durably recorded — inline in the
    /// document or spilled to its sidecar file.
    pub fn has_reply(&self) -> bool {
        self.reply.is_some() || self.reply_file.is_some()
    }
}

/// A resolved reply payload and the durable delivery checkpoint the
/// same locked read observed — the pair is coherent only together, so
/// a resend never drives a freshly committed variant off a checkpoint
/// an older snapshot happened to hold.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedReply {
    /// The deliverable text — the live or committed refused variant.
    pub text: String,
    /// Contract-level sends confirmed so far — the resume prefix.
    pub sent: usize,
    /// The platform checkpoint of the send that stopped, if any.
    pub progress: Option<crate::transport::SendProgress>,
}

/// The reply delivery state a conditional checkpoint clear leaves
/// behind — confirmed part count, the platform checkpoint still held
/// and the retry deadline it carries — all read inside the same locked
/// write that ran the clear. A resend adopts the triple whole:
/// progress another store committed between the caller's resolve and
/// this write governs the resume, so the next attempt neither reposts
/// a part that store confirmed nor retries inside the deadline it was
/// still owed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReplyResumeState {
    /// Contract-level sends confirmed so far — the resume prefix.
    pub sent: usize,
    /// The platform checkpoint still governing the next attempt —
    /// `None` when the expected checkpoint cleared or none is held.
    pub progress: Option<crate::transport::SendProgress>,
    /// Unix milliseconds before which the reply must not be attempted
    /// again — surviving only with a checkpoint that was adopted, not
    /// cleared.
    pub retry_at_ms: Option<u64>,
}

impl DroppedUpdate {
    /// The record's full claim identity — sequence plus update id.
    fn key(&self) -> TaskKey {
        TaskKey::new(self.sequence, self.update_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BindingDocument {
    schema_version: String,
    pairings: Vec<PairingRecord>,
    chats: BTreeMap<String, ChatBinding>,
    /// Durable getUpdates cursor: the next offset this runtime
    /// confirmed to the platform. Defaults to 0 for documents written
    /// before the cursor existed; older readers ignore the field.
    #[serde(default)]
    poll_offset: i64,
    /// Unix seconds when the cursor last advanced. The platform may
    /// restart update identifiers at a random value after a long
    /// silence, so the runtime expires a sequence older than its idle
    /// window. `None` for documents written before the field existed;
    /// an unknown-age cursor is honored, since expiring it could replay
    /// confirmed turns.
    #[serde(default)]
    poll_offset_advanced_at: Option<u64>,
    /// Bounded record of fetched updates the runtime did not turn into
    /// host-visible messages. Older readers ignore the field.
    #[serde(default)]
    dropped_updates: Vec<DroppedUpdate>,
    /// Fetched updates awaiting their host callback — the durable
    /// cursor reaches an event only after its callback accepted it,
    /// so a marker always sits at or above the cursor and stays
    /// refetchable until it settles. A consumed event's marker is
    /// released in the same write that confirms its boundary; a
    /// rejected one keeps its marker while the cursor stays before
    /// it for redelivery; only a marker the cursor has moved past on
    /// restart — one committed under an earlier scheme — is settled
    /// as dropped, since that lowered event cannot be replayed.
    #[serde(default)]
    pending_events: Vec<DroppedUpdate>,
    /// Admitted-but-unfinished message updates: the durable inbox every
    /// confirmed update goes through before the cursor advances.
    #[serde(default)]
    pending_updates: Vec<PendingUpdate>,
    /// Bounded tail of update ids whose task record was settled —
    /// completed or dropped. A cursor rollback for a rejected event
    /// refetches them, and the remembered id keeps confirmed work from
    /// re-entering the scheduler. The tail is scoped to the polling
    /// sequence it was written under: when that sequence expires the
    /// ids lose their meaning — a restarted sequence may lawfully
    /// reuse them — and `retire_settled` clears it.
    #[serde(default)]
    settled_updates: Vec<i64>,
    /// Monotone counter backing `ChatBinding::revision` — persisted so
    /// revisions stay unique across restarts.
    #[serde(default)]
    revision_counter: u64,
    /// The current update-id sequence: bumped each time the confirmed
    /// id sequence expires, so claims, staged records and fresh delivery
    /// keys from a restarted sequence can never collide with retained
    /// work from a dead one. `0` predates the field.
    #[serde(default)]
    poll_sequence: u64,
    /// Chats whose pairing/binding was revoked — chat id to the
    /// document revision the revocation committed at. A staged offer
    /// minted at or before the tombstone must never re-publish: the
    /// binding whose removal freed document space is exactly the guard
    /// that kept the older offer refused.
    #[serde(default)]
    revoked_chats: BTreeMap<String, u64>,
}

/// A staged reply completion: one atomic record carrying the payload,
/// the delivery key and the document effect the finished work commits
/// with. It is written as a single rename *before* the parent document
/// commits, so a crash at any point leaves either nothing (the result
/// was never durable) or the whole recoverable record — never a
/// payload on disk that no manifest recognizes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StagedCompletion {
    update_id: i64,
    /// The polling sequence the record was staged under — part of the
    /// claim identity, verified against both the file name and the
    /// task it binds to. `0` predates the field.
    #[serde(default)]
    sequence: u64,
    /// The file inside the replies directory holding the payload.
    /// Self-contained records name themselves; manifests written by
    /// the separate-files revision name their `reply-<id>.txt`
    /// sidecar.
    payload: String,
    /// The delivery key the reply's sends carry.
    key: String,
    /// The document change the completion committed with.
    effect: StagedEffect,
    /// The reply payload of a self-contained record — bound when the
    /// record's effect applies. `None` marks a manifest written by the
    /// revision that staged payload and manifest as two files; its
    /// payload lives in the named file.
    #[serde(default)]
    text: Option<String>,
    /// The alternative outcome bound when the record's effect is
    /// refused at recovery — a staged command reply names both what it
    /// hoped to commit and what an intervening binding change turns it
    /// into, so recovery never binds a success the refused effect did
    /// not earn. `None` means one text serves both outcomes.
    #[serde(default)]
    refused_text: Option<String>,
}

/// The document mutation a staged completion re-applies on recovery —
/// the same effect the record's own commit performed, guarded by the
/// binding it was staged against: a precondition field `None` marks a
/// record written before it existed, which applies unverifiable,
/// exactly as it did when staged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum StagedEffect {
    /// Only the reply pointer binds; no other document change.
    Reply,
    /// A session change on the chat's binding lands with the reply —
    /// only while the binding it was recorded under still holds.
    ReplySession {
        chat_id: i64,
        session_id: Option<String>,
        #[serde(default)]
        user_id: Option<i64>,
        #[serde(default)]
        agent_id: Option<String>,
        /// The session the binding carried when the turn ran: `Some`
        /// records the precondition, `None` marks a record staged
        /// before it existed, which applies unverifiable.
        #[serde(default)]
        prior_session: Option<Option<String>>,
        /// The binding revision the task ran under: `Some` records the
        /// precondition, `None` marks a record staged before it
        /// existed, which applies unverifiable. User, agent and
        /// session values alone cannot distinguish A→B→A — the
        /// revision can.
        #[serde(default)]
        binding_revision: Option<u64>,
    },
    /// The chat's pairing/binding revocation lands with the reply —
    /// only against the binding it was recorded for, never a pairing
    /// a different user established since.
    ReplyRevoke {
        chat_id: i64,
        #[serde(default)]
        user_id: Option<i64>,
    },
    /// An agent rebind lands with the reply — a changed agent clears
    /// the session, exactly as `set_agent` does — only while the chat
    /// is still bound for the user the command ran for.
    ReplyAgent {
        chat_id: i64,
        agent_id: String,
        #[serde(default)]
        user_id: Option<i64>,
        /// The binding revision observed when the command ran: `Some`
        /// records the precondition, `None` marks a record staged
        /// before it existed, which applies unverifiable.
        #[serde(default)]
        binding_revision: Option<u64>,
    },
    /// A new pairing record lands with the reply carrying its code —
    /// skipped once that user already holds a full pairing.
    ReplyPairing { record: PairingRecord },
}

/// One staged completion that could not be applied durably — reported
/// with the stable refusal code and its update id so the runtime can
/// surface it to the host while the record stays. No reply content
/// crosses this surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrandedReply {
    pub update_id: i64,
    /// The polling sequence the record was staged under.
    pub sequence: u64,
    pub code: String,
}

#[derive(Debug)]
pub struct BindingStore {
    path: PathBuf,
    lock: File,
    document: BindingDocument,
    /// Tasks a committed mutation newly bound a staged reply onto —
    /// records that could not fit earlier and became deliverable when
    /// another write freed document space. In-memory only: the
    /// runtime drains it to queue each recovered reply once for
    /// resend; anything left at exit stays durable on disk for the
    /// next restart's reconciliation.
    bound_replies: Vec<TaskKey>,
    /// Every task key this instance already queued a recovered reply
    /// for — own binds and binds discovered on a document another
    /// store instance committed. A task binds its staged reply exactly
    /// once, so the set lives for the store's lifetime: a stale
    /// document re-read after a failed write can never report the same
    /// transition twice.
    bound_seen: HashSet<TaskKey>,
    #[cfg(test)]
    fail_next_write: bool,
    /// Mutations allowed to succeed before `fail_next_write` fires —
    /// so a test can poison a write in the middle of a sequence.
    #[cfg(test)]
    healthy_writes: usize,
    #[cfg(test)]
    fail_next_admit_capacity: bool,
}

impl BindingStore {
    /// Open the store at `dir/bindings.json` — the conventional layout a
    /// host picks when it hands the adapter a state directory.
    pub fn open_in(dir: &Path) -> Result<Self> {
        Self::open(dir.join(STATE_FILE))
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        let lock = open_private_lock_file(&lock_path(&path))?;
        let document = read_document(&path)?;
        let store = Self {
            path,
            lock,
            document,
            bound_replies: Vec::new(),
            bound_seen: HashSet::new(),
            #[cfg(test)]
            fail_next_write: false,
            #[cfg(test)]
            healthy_writes: 0,
            #[cfg(test)]
            fail_next_admit_capacity: false,
        };
        Ok(store)
    }

    /// Reload the latest on-disk document so external (CLI or another
    /// runtime) writes become visible before reads.
    pub fn refresh(&mut self) -> Result<()> {
        self.lock
            .lock_exclusive()
            .map_err(|_| anyhow!("a4mc_telegram_bindings_lock_failed"))?;
        let result = read_document(&self.path).map(|document| {
            self.note_externally_bound(&document);
            self.document = document;
        });
        let _ = self.lock.unlock();
        result
    }

    /// Queue one newly bound task for the runtime's resend drain —
    /// deduplicated so a reply is offered exactly once even when a
    /// stale document could report its transition again.
    fn note_bound(&mut self, key: TaskKey) {
        if self.bound_seen.insert(key) {
            self.bound_replies.push(key);
        }
    }

    /// Discover binds another store instance committed: a task this
    /// document knows without a finished reply that the freshly read
    /// document shows holding one. The bind notification lives only in
    /// the committing instance's memory, so durable transitions are
    /// rediscovered here on every lock-reload — each queued once.
    fn note_externally_bound(&mut self, fresh: &BindingDocument) {
        for task in &fresh.pending_updates {
            if !task.has_reply() {
                continue;
            }
            let key = task.key();
            if self
                .document
                .pending_updates
                .iter()
                .any(|held| held.key() == key && !held.has_reply())
            {
                self.note_bound(key);
            }
        }
    }

    /// Apply one mutation atomically: hold the advisory lock across reload,
    /// merge, and atomic save so concurrent writers never silently overwrite
    /// each other's changes.
    fn mutate<R>(&mut self, change: impl FnOnce(&mut BindingDocument) -> Result<R>) -> Result<R> {
        self.mutate_bounded(0, change)
    }

    /// One lock-read-merge-write cycle that must leave `headroom`
    /// bytes of document slack beyond the write — admission reserves
    /// lifecycle space this way so completing admitted work never
    /// competes with new admissions for the last bytes.
    ///
    /// Staged completions reconcile BEFORE the change runs: finished
    /// work that never reached the document lands first, so a newer
    /// mutation always overtakes it and a staged effect can never
    /// overwrite a binding committed or staged after it. When the
    /// candidate exceeds the bound the reconciled document still
    /// commits on its own — newer work waits for slack rather than
    /// overtaking a staged record; the on-disk records remain
    /// authoritative for what has been finished but not yet committed
    /// (fallback and settle checks consult them directly).
    ///
    /// Staged completions reconcile AGAIN on the changed candidate: a
    /// mutation that frees document space — a task settling, a record
    /// dropped — is exactly what lets a record stranded for size land,
    /// and waiting for an unrelated later write would leave finished
    /// work parked. A record whose guarded effect the change already
    /// superseded binds its refused variant instead of the outcome the
    /// newer write displaced.
    fn mutate_bounded<R>(
        &mut self,
        headroom: usize,
        change: impl FnOnce(&mut BindingDocument) -> Result<R>,
    ) -> Result<R> {
        #[cfg(test)]
        if self.healthy_writes > 0 {
            self.healthy_writes -= 1;
        } else if std::mem::take(&mut self.fail_next_write) {
            return Err(anyhow!("a4mc_telegram_state_write_failed"));
        }
        self.lock
            .lock_exclusive()
            .map_err(|_| anyhow!("a4mc_telegram_bindings_lock_failed"))?;
        let result = (|| {
            let dir = replies_dir(&self.path);
            let document = read_document(&self.path)?;
            // A bind another instance committed lands only in that
            // instance's drain — rediscover the durable transition
            // against this instance's last seen document.
            self.note_externally_bound(&document);
            // The snapshot then tracks the durable read outright: a
            // mutation refused or failed below must not leave it
            // stale, because the transitions noted above resolve
            // against it when the bound-reply drain runs.
            self.document = document;
            let mut staged = self.document.clone();
            let bound = apply_staged(&mut staged, &dir);
            let mut candidate = staged.clone();
            let value = change(&mut candidate)?;
            // Reconcile on the changed candidate: space the change
            // freed can bind a record the pre-change pass could not.
            // Binds landing here commit only with the candidate — the
            // fallback path below replays them on its own next write.
            let bound_after = apply_staged(&mut candidate, &dir);
            // A revocation tombstone is owed only while a staged offer
            // minted at or before it can still be replayed — reclaim
            // each entry the replies directory no longer guards before
            // the size check, so a drained history cannot strand the
            // write on space its own dead entries hold.
            if !candidate.revoked_chats.is_empty() {
                reclaim_revocations(&mut candidate, &dir);
            }
            // The file must stay readable under its own bound: a
            // mutation whose result would exceed the read limit is
            // refused before it replaces the document, so the store can
            // never land in a shape the next open rejects. Callers
            // treat the refusal like a full disk — work it could not
            // hold stays unconfirmed until the backlog drains.
            let raw = serde_json::to_string_pretty(&candidate)?;
            if raw.len() + headroom <= MAX_STATE_BYTES {
                atomic_write_private_text(&self.path, &raw)?;
                self.document = candidate;
                for key in bound.into_iter().chain(bound_after) {
                    self.note_bound(key);
                }
                return Ok(value);
            }
            // The change does not fit — its work stays uncommitted,
            // but the reconciled document still commits on its own so
            // the staged record is never overtaken by a newer write.
            if staged != self.document {
                if !staged.revoked_chats.is_empty() {
                    reclaim_revocations(&mut staged, &dir);
                }
                let raw = serde_json::to_string_pretty(&staged)?;
                if raw.len() <= MAX_STATE_BYTES {
                    atomic_write_private_text(&self.path, &raw)?;
                    self.document = staged;
                    for key in bound {
                        self.note_bound(key);
                    }
                }
            }
            Err(anyhow!("a4mc_telegram_state_full"))
        })();
        // Sweep spilled reply files under the same lock that wrote the
        // document: a file is live exactly while a pending task or an
        // unapplied staged completion references it, so completed
        // tasks, settled records and orphans from a mutation that died
        // mid-write are all collected here — and a file being written
        // inside another mutation can never be reached for deletion
        // before its document lands.
        if result.is_ok() {
            sweep_reply_files(&self.path, &self.document);
        }
        let _ = self.lock.unlock();
        result
    }

    pub fn binding(&self, chat_id: i64) -> Option<&ChatBinding> {
        self.document.chats.get(&chat_id.to_string())
    }

    pub fn is_paired(&self, chat_id: i64, user_id: i64) -> bool {
        self.document
            .chats
            .get(&chat_id.to_string())
            .is_some_and(|binding| binding.paired && binding.user_id == user_id)
    }

    pub fn request_pairing(
        &mut self,
        chat_id: i64,
        user_id: i64,
        username: Option<String>,
    ) -> Result<PairingRecord> {
        self.mutate(|document| {
            let now = now_secs();
            document.pairings.retain(|record| record.expires_at > now);
            ensure!(
                !document
                    .chats
                    .get(&chat_id.to_string())
                    .is_some_and(|binding| binding.paired && binding.user_id == user_id),
                "a4mc_telegram_already_paired"
            );
            document
                .pairings
                .retain(|record| record.chat_id != chat_id || record.user_id != user_id);
            let record = PairingRecord {
                code: generate_pairing_code(),
                chat_id,
                user_id,
                username,
                created_at: now,
                expires_at: now + PAIRING_TTL.as_secs(),
                minted_revision: next_revision(document),
            };
            document.pairings.push(record.clone());
            Ok(record)
        })
    }

    pub fn approve(&mut self, code: &str) -> Result<ChatBinding> {
        let normalized = code.trim().to_uppercase();
        ensure!(!normalized.is_empty(), "a4mc_telegram_pairing_code_invalid");
        self.mutate(|document| {
            let now = now_secs();
            document.pairings.retain(|record| record.expires_at > now);
            let index = document
                .pairings
                .iter()
                .position(|record| record.code == normalized)
                .ok_or_else(|| anyhow!("a4mc_telegram_pairing_not_found"))?;
            let record = document.pairings.remove(index);
            let binding = ChatBinding {
                chat_id: record.chat_id,
                user_id: record.user_id,
                username: record.username,
                paired: true,
                agent_id: None,
                session_id: None,
                updated_at: now,
                revision: next_revision(document),
            };
            document
                .chats
                .insert(record.chat_id.to_string(), binding.clone());
            Ok(binding)
        })
    }

    pub fn revoke(&mut self, chat_id: i64) -> Result<bool> {
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let now = now_secs();
            let removed = document.chats.remove(&chat_id.to_string()).is_some();
            // Only a live offer counts toward the result: an expired
            // code still listed here is dead already — the next
            // mutation touching the pairings prunes it — so removing
            // its row is cleanup, never a revocation the host should
            // confirm.
            let live = document
                .pairings
                .iter()
                .any(|record| record.chat_id == chat_id && record.expires_at > now);
            document.pairings.retain(|record| record.chat_id != chat_id);
            // An offer whose record never fit the document lives only
            // in its sidecar — nothing here names it, yet the next
            // write that frees space would still bind and publish its
            // code. The revocation recognizes and tombstones it like
            // the offers the document can show — while the offer is
            // still live. An offer whose TTL already ran out binds its
            // own refusal on the next write, so it is neither revocable
            // nor in need of a tombstone.
            let chat = chat_id.to_string();
            let guarded_at = document.revoked_chats.get(&chat).copied();
            let staged = staged_pairing_offers(&dir).into_iter().any(|record| {
                record.chat_id == chat_id
                    && record.expires_at > now
                    && guarded_at.is_none_or(|at| record.minted_revision > at)
            });
            let revoked = removed || live || staged;
            if revoked {
                // Tombstone the revocation at its own revision: a
                // staged offer minted before it can never re-publish
                // now that the binding that refused it is gone.
                let revision = next_revision(document);
                document.revoked_chats.insert(chat, revision);
            }
            Ok(revoked)
        })
    }

    pub fn paired_chats(&self) -> Vec<ChatBinding> {
        self.document
            .chats
            .values()
            .filter(|binding| binding.paired)
            .cloned()
            .collect()
    }

    pub fn set_agent(&mut self, chat_id: i64, agent_id: Option<String>) -> Result<ChatBinding> {
        self.mutate(|document| {
            let mut binding = document
                .chats
                .get(&chat_id.to_string())
                .cloned()
                .ok_or_else(|| anyhow!("a4mc_telegram_not_paired"))?;
            ensure!(binding.paired, "a4mc_telegram_not_paired");
            if binding.agent_id.as_deref() != agent_id.as_deref() {
                binding.session_id = None;
            }
            binding.agent_id = agent_id;
            binding.updated_at = now_secs();
            binding.revision = next_revision(document);
            document.chats.insert(chat_id.to_string(), binding.clone());
            Ok(binding)
        })
    }

    pub fn set_session(&mut self, chat_id: i64, session_id: Option<String>) -> Result<ChatBinding> {
        self.mutate(|document| {
            let mut binding = document
                .chats
                .get(&chat_id.to_string())
                .cloned()
                .ok_or_else(|| anyhow!("a4mc_telegram_not_paired"))?;
            ensure!(binding.paired, "a4mc_telegram_not_paired");
            ensure!(binding.agent_id.is_some(), "a4mc_telegram_agent_required");
            binding.session_id = session_id;
            binding.updated_at = now_secs();
            binding.revision = next_revision(document);
            document.chats.insert(chat_id.to_string(), binding.clone());
            Ok(binding)
        })
    }

    pub fn pending_pairings(&self) -> Vec<PairingRecord> {
        self.document.pairings.clone()
    }

    /// Drop expired pairing codes under the same lock protocol used by
    /// mutations (used by read-facing listing).
    pub fn prune_expired(&mut self) -> Result<()> {
        let now = now_secs();
        self.mutate(|document| {
            document.pairings.retain(|record| record.expires_at > now);
            Ok(())
        })
    }

    /// The last durably recorded poll cursor — where the next
    /// `getUpdates` call resumes after a restart.
    pub fn poll_offset(&self) -> i64 {
        self.document.poll_offset
    }

    /// Unix seconds when the stored cursor last advanced — the input
    /// for the runtime's sequence-expiry check. `None` predates the
    /// field and is treated as a live sequence.
    pub fn poll_offset_advanced_at(&self) -> Option<u64> {
        self.document.poll_offset_advanced_at
    }

    /// Backdate the cursor's last-advance instant so sequence-expiry
    /// paths run without waiting out the real idle window.
    #[cfg(test)]
    pub fn age_poll_offset_for_test(&mut self, secs: u64) -> Result<()> {
        self.mutate(|document| {
            document.poll_offset_advanced_at = Some(now_secs().saturating_sub(secs));
            Ok(())
        })
    }

    /// Expire every stored pairing offer's TTL in place — the shape a
    /// code takes once it lapses while its row still sits in the
    /// document, so revocation accounting can be checked against
    /// dead-code cleanup without waiting out the real TTL.
    #[cfg(test)]
    pub fn expire_pairings_for_test(&mut self) -> Result<()> {
        self.mutate(|document| {
            for record in &mut document.pairings {
                record.expires_at = 0;
            }
            Ok(())
        })
    }

    /// Fail the next mutation, so a caller's error path can be exercised
    /// without relying on OS permissions that root can bypass.
    #[cfg(test)]
    pub fn fail_next_write_for_test(&mut self) {
        self.fail_next_write = true;
    }

    /// Let `healthy` mutations succeed, then fail one — a write in the
    /// middle of a sequence can be poisoned without timing a real
    /// failure.
    #[cfg(test)]
    pub fn fail_next_write_after_for_test(&mut self, healthy: usize) {
        self.healthy_writes = healthy;
        self.fail_next_write = true;
    }

    /// Make the next admission answer a capacity refusal without
    /// writing — the shape a probe against a momentarily full document
    /// takes, so a caller's drain-and-retry path can be exercised
    /// without timing a real backlog.
    #[cfg(test)]
    pub fn fail_next_admit_capacity_for_test(&mut self) {
        self.fail_next_admit_capacity = true;
    }

    /// Persist the poll cursor under the same lock-reload-merge-write
    /// protocol as every mutation. A crash before this write replays at
    /// most the in-flight batch; after it, a restart resumes instead of
    /// re-running paid turns for already-confirmed updates.
    pub fn set_poll_offset(&mut self, offset: i64) -> Result<()> {
        self.mutate(|document| {
            document.poll_offset = offset;
            document.poll_offset_advanced_at = Some(now_secs());
            Ok(())
        })
    }

    /// Persist one fetched batch atomically: newly admitted message
    /// tasks, unhandled-update records and event records awaiting
    /// their host callback all land in the same write that confirms
    /// the poll cursor, so a crash can never leave a confirmed update
    /// without its work record. Admission reserves
    /// `LIFECYCLE_RESERVE_BYTES` of slack beyond the write so the
    /// lifecycle metadata an admitted task still has to record — reply
    /// pointer, delivery key, session change, checkpoints — always has
    /// room to commit.
    pub fn admit_updates(
        &mut self,
        tasks: &[PendingUpdate],
        dropped: &[DroppedUpdate],
        events: &[DroppedUpdate],
        offset: i64,
    ) -> Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_admit_capacity) {
            return Err(anyhow!("a4mc_telegram_state_full"));
        }
        self.mutate_bounded(LIFECYCLE_RESERVE_BYTES, |document| {
            // Records claim their update id in the sequence that was
            // live when the batch was fetched — the store stamps it so
            // a dead sequence's retained record can never block a
            // restarted sequence's fresh admit of the same id.
            let sequence = document.poll_sequence;
            for task in tasks {
                // Re-admission keeps the existing record: a finished
                // reply must survive a stale transport redelivery.
                if !document
                    .pending_updates
                    .iter()
                    .any(|held| held.key() == TaskKey::new(sequence, task.update_id))
                {
                    let mut task = task.clone();
                    task.sequence = sequence;
                    document.pending_updates.push(task);
                }
            }
            ensure!(
                document.pending_updates.len() <= MAX_PENDING_UPDATES,
                "a4mc_telegram_pending_updates_full"
            );
            for dropped in dropped {
                let mut dropped = dropped.clone();
                dropped.sequence = sequence;
                document
                    .dropped_updates
                    .retain(|item| item.key() != dropped.key());
                document.dropped_updates.push(dropped);
            }
            let excess = document
                .dropped_updates
                .len()
                .saturating_sub(MAX_DROPPED_UPDATES);
            if excess > 0 {
                document.dropped_updates.drain(..excess);
            }
            for event in events {
                let mut event = event.clone();
                event.sequence = sequence;
                document
                    .pending_events
                    .retain(|item| item.key() != event.key());
                document.pending_events.push(event);
            }
            document.poll_offset = offset;
            document.poll_offset_advanced_at = Some(now_secs());
            Ok(())
        })
    }

    /// Settle an event the host callback consumed — the durable marker
    /// committed with the cursor is released without a dropped record.
    pub fn settle_event(&mut self, key: impl Into<TaskKey>) -> Result<()> {
        let key = key.into();
        self.mutate(|document| {
            document.pending_events.retain(|item| item.key() != key);
            Ok(())
        })
    }

    /// Settle an event the host callback consumed and confirm the batch
    /// boundary its acceptance earned in the same write: the marker is
    /// released and the cursor advances to `offset` — the first update
    /// whose outcome is not yet durable — atomically, so a crash can
    /// never leave a confirmed cursor on an unsettled marker.
    pub fn settle_event_at_cursor(&mut self, key: impl Into<TaskKey>, offset: i64) -> Result<()> {
        let key = key.into();
        self.mutate(|document| {
            document.pending_events.retain(|item| item.key() != key);
            document.poll_offset = offset;
            document.poll_offset_advanced_at = Some(now_secs());
            Ok(())
        })
    }

    /// Settle the events a restart found still pending — but only the
    /// ones the stored cursor already confirmed: a marker at or above
    /// the cursor is still refetchable — the platform will redeliver
    /// its update and the callback gets its chance — so it stays
    /// pending. A marker the cursor has moved past cannot be replayed
    /// and becomes its durable dropped record. Nothing stale means
    /// nothing to write.
    pub fn settle_unconsumed_events(&mut self) -> Result<()> {
        if self
            .document
            .pending_events
            .iter()
            .all(|item| item.update_id >= self.document.poll_offset)
        {
            return Ok(());
        }
        self.mutate(|document| {
            let ids: Vec<i64> = document
                .pending_events
                .iter()
                .filter(|item| item.update_id < document.poll_offset)
                .map(|item| item.update_id)
                .collect();
            for update_id in ids {
                let event = document
                    .pending_events
                    .iter()
                    .position(|item| item.update_id == update_id)
                    .map(|index| document.pending_events.remove(index));
                if let Some(event) = event {
                    document.dropped_updates.push(event);
                }
            }
            let excess = document
                .dropped_updates
                .len()
                .saturating_sub(MAX_DROPPED_UPDATES);
            if excess > 0 {
                document.dropped_updates.drain(..excess);
            }
            Ok(())
        })
    }

    /// The polling sequence currently live — the namespace new claims,
    /// staged records and delivery keys are minted under.
    pub fn poll_sequence(&self) -> u64 {
        self.document.poll_sequence
    }

    /// Retire the confirmed id sequence in one durable write: the
    /// sequence counter advances, the settled-id tail is released, the
    /// pending event markers — records only meaningful inside the dead
    /// sequence — become their durable dropped records under their
    /// original sequence, and the cursor restarts so a restarted
    /// numbering's lower first ids are fetched instead of acknowledged
    /// unseen. Outstanding tasks and staged records keep their
    /// dead-sequence keys: their replies still deliver under the keys
    /// they recorded, but they no longer claim the id a fresh sequence
    /// may reuse.
    pub fn expire_sequence(&mut self) -> Result<()> {
        self.mutate(|document| {
            document.poll_sequence += 1;
            document.settled_updates.clear();
            // A marker whose sequence died can neither be refetched for
            // a callback nor settled by one — moving it into the bounded
            // dropped history keeps the event visible instead of erasing
            // it with the claims it hung on.
            let dead: Vec<DroppedUpdate> = document
                .pending_events
                .extract_if(.., |item| item.sequence != document.poll_sequence)
                .collect();
            for event in dead {
                document
                    .dropped_updates
                    .retain(|item| item.key() != event.key());
                document.dropped_updates.push(event);
            }
            let excess = document
                .dropped_updates
                .len()
                .saturating_sub(MAX_DROPPED_UPDATES);
            if excess > 0 {
                document.dropped_updates.drain(..excess);
            }
            document.poll_offset = 0;
            document.poll_offset_advanced_at = Some(now_secs());
            Ok(())
        })
    }

    /// The admitted-but-unfinished work, oldest first — sequence before
    /// update id, so a dead sequence's retained work precedes whatever
    /// a restarted numbering admitted later.
    pub fn pending_updates(&self) -> Vec<PendingUpdate> {
        let mut tasks = self.document.pending_updates.clone();
        tasks.sort_by_key(|task| (task.sequence, task.update_id));
        tasks
    }

    /// Record a finished turn's reply — and the delivery key its first
    /// send attempt carries — on the admitted task *before* delivery,
    /// so an exit between the lane returning and the send completing
    /// leaves a resumable result under the same key instead of losing
    /// paid agent work. The payload spills to a sidecar file inside
    /// the mutation's lock: the bounded document only keeps the file
    /// name, so a reply larger than the remaining store capacity is
    /// still preserved before the task can settle.
    ///
    /// The payload and a manifest naming its update id, key and state
    /// effect are written before the document commit, so an exit
    /// between the sidecar rename and the document write is reconciled
    /// on recovery instead of re-running finished work.
    pub fn record_reply(
        &mut self,
        key: impl Into<TaskKey>,
        reply: &str,
        delivery_key: &str,
    ) -> Result<()> {
        ensure!(
            reply.len() <= MAX_REPLY_BYTES,
            "a4mc_telegram_reply_too_large"
        );
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            stage_reply(
                document,
                &dir,
                key,
                reply,
                None,
                true,
                delivery_key,
                StagedEffect::Reply,
            )
        })
    }

    /// Commit a chat's session change and one finished reply record in
    /// the same write: the binding change routing subsequent messages
    /// and the resumable result land or fail together, so a restart
    /// never finds a committed session change on an unfinished task
    /// and re-runs it — or reapplies a session a later committed write
    /// already replaced. `expected` is the binding the caller's turn
    /// ran under: the session lands only while the current binding
    /// still matches it — user, agent, session and revision — so a
    /// rebind that raced an in-flight turn can never have the stale
    /// session written over it, even one that moved the binding and
    /// moved it back. `text` is rendered for both outcomes — applied
    /// and refused — so a record recovered after the binding moved
    /// binds the answer matching what its effect actually commits, not
    /// the success it was staged hoping for. The reply record itself
    /// never depends on the effect: a refused routing change still
    /// keeps its finished reply. Returns the reply text.
    pub fn record_reply_and_session(
        &mut self,
        chat_id: i64,
        key: impl Into<TaskKey>,
        delivery_key: &str,
        session_id: Option<String>,
        expected: &ChatBinding,
        text: impl Fn(bool) -> String,
    ) -> Result<String> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let effect = StagedEffect::ReplySession {
                chat_id,
                session_id,
                user_id: Some(expected.user_id),
                agent_id: expected.agent_id.clone(),
                prior_session: Some(expected.session_id.clone()),
                binding_revision: Some(expected.revision),
            };
            let applied = apply_effect(document, &dir, &effect);
            let (applied_text, refused_text) = (text(true), text(false));
            let reply = if applied {
                applied_text.clone()
            } else {
                refused_text.clone()
            };
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            let refused_text = (refused_text != applied_text).then_some(refused_text);
            stage_reply(
                document,
                &dir,
                key,
                &applied_text,
                refused_text.as_deref(),
                applied,
                delivery_key,
                effect,
            )?;
            Ok(reply)
        })
    }

    /// Commit a chat's revocation — its binding and every pending
    /// pairing record — and the reply confirming it in one write, so a
    /// restart never replays a mutating command whose confirmation was
    /// already accepted by the platform. `text` is rendered for both
    /// outcomes so a recovered record binds the answer matching what
    /// its effect commits. Returns the reply text.
    pub fn record_reply_and_revocation(
        &mut self,
        chat_id: i64,
        key: impl Into<TaskKey>,
        delivery_key: &str,
        text: impl Fn(bool) -> String,
    ) -> Result<String> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let effect = StagedEffect::ReplyRevoke {
                chat_id,
                user_id: document
                    .chats
                    .get(&chat_id.to_string())
                    .map(|binding| binding.user_id),
            };
            let removed = apply_effect(document, &dir, &effect);
            let (applied_text, refused_text) = (text(true), text(false));
            let reply = if removed {
                applied_text.clone()
            } else {
                refused_text.clone()
            };
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            let refused_text = (refused_text != applied_text).then_some(refused_text);
            stage_reply(
                document,
                &dir,
                key,
                &applied_text,
                refused_text.as_deref(),
                removed,
                delivery_key,
                effect,
            )?;
            Ok(reply)
        })
    }

    /// Commit a chat's agent rebind and the reply confirming it in one
    /// write — a changed agent clears the session exactly as
    /// `set_agent` does. The rebind is applied only while the chat is
    /// still paired for the user the command ran for and while the
    /// revision of `expected` — the binding the command was authorized
    /// under — still holds. `text` is rendered for both outcomes, so a
    /// recovered record binds the answer matching what the guarded
    /// rebind actually commits; the reply record never depends on it.
    /// Returns the reply text.
    #[allow(clippy::too_many_arguments)]
    pub fn record_reply_and_agent(
        &mut self,
        chat_id: i64,
        key: impl Into<TaskKey>,
        agent_id: String,
        delivery_key: &str,
        user_id: i64,
        expected: &ChatBinding,
        text: impl Fn(bool) -> String,
    ) -> Result<String> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let effect = StagedEffect::ReplyAgent {
                chat_id,
                agent_id,
                user_id: Some(user_id),
                binding_revision: Some(expected.revision),
            };
            let applied = apply_effect(document, &dir, &effect);
            let (applied_text, refused_text) = (text(true), text(false));
            let reply = if applied {
                applied_text.clone()
            } else {
                refused_text.clone()
            };
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            let refused_text = (refused_text != applied_text).then_some(refused_text);
            stage_reply(
                document,
                &dir,
                key,
                &applied_text,
                refused_text.as_deref(),
                applied,
                delivery_key,
                effect,
            )?;
            Ok(reply)
        })
    }

    /// Commit a fresh pairing record and the reply carrying its code in
    /// one write — same admission rules as `request_pairing` — so the
    /// code a user receives always has its durable record. `text`
    /// receives the record minted for the document; `refused_text` is
    /// the outcome bound instead when recovery finds the offer refused
    /// — an intervening approval or a TTL that elapsed during downtime
    /// must never deliver the staged code. Returns the reply text.
    #[allow(clippy::too_many_arguments)]
    pub fn record_pairing_and_reply(
        &mut self,
        chat_id: i64,
        user_id: i64,
        username: Option<String>,
        key: impl Into<TaskKey>,
        delivery_key: &str,
        text: impl FnOnce(&PairingRecord) -> String,
        refused_text: &str,
    ) -> Result<String> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let now = now_secs();
            document.pairings.retain(|record| record.expires_at > now);
            ensure!(
                !document
                    .chats
                    .get(&chat_id.to_string())
                    .is_some_and(|binding| binding.paired && binding.user_id == user_id),
                "a4mc_telegram_already_paired"
            );
            let record = PairingRecord {
                code: generate_pairing_code(),
                chat_id,
                user_id,
                username,
                created_at: now,
                expires_at: now + PAIRING_TTL.as_secs(),
                minted_revision: next_revision(document),
            };
            let reply = text(&record);
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            let effect = StagedEffect::ReplyPairing {
                record: record.clone(),
            };
            apply_effect(document, &dir, &effect);
            stage_reply(
                document,
                &dir,
                key,
                &reply,
                Some(refused_text),
                true,
                delivery_key,
                effect,
            )?;
            Ok(reply)
        })
    }

    /// Record an undelivered fallback error report on the admitted
    /// task — only when it holds no finished reply already, whether
    /// committed or merely staged: a paid agent result is never
    /// shadowed by an error report. The report keeps the delivery key
    /// its first send attempt carried, so the restart drain resends
    /// the same logical send instead of minting a second key for one
    /// delivery. `Ok(true)` means the report was recorded;
    /// `Ok(false)` means a finished reply already held the slot (or
    /// the task is gone) and nothing was written.
    pub fn record_fallback_reply(
        &mut self,
        key: impl Into<TaskKey>,
        reply: &str,
        delivery_key: &str,
    ) -> Result<bool> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.key() == key)
                && !task.has_reply()
                && !staged_exists(&dir, key)
            {
                task.reply = Some(reply.to_owned());
                task.reply_file = None;
                task.reply_key = Some(delivery_key.to_owned());
                task.reply_sent = 0;
                task.reply_progress = None;
                task.reply_retry_at_ms = None;
                task.reply_refused = false;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Advance a recorded reply's durable delivery checkpoint: `sent`
    /// counts the contract-level sends confirmed so far, `progress` is
    /// the platform-level checkpoint of the send that stopped (cleared
    /// once the reply's fan-out completes a part). The confirmed prefix
    /// only ever moves forward — a stale write can never drag it back.
    pub fn record_reply_progress(
        &mut self,
        key: impl Into<TaskKey>,
        sent: usize,
        progress: Option<crate::transport::SendProgress>,
    ) -> Result<()> {
        let key = key.into();
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.key() == key)
            {
                task.reply_sent = task.reply_sent.max(sent);
                task.reply_progress = progress;
                task.reply_retry_at_ms = None;
            }
            Ok(())
        })
    }

    /// Clear a reply's durable platform checkpoint only while the
    /// stored progress still equals `expected` — the checkpoint the
    /// caller's resolve paired with the reply's variant. Progress a
    /// store committed after that read belongs to the payload now
    /// recorded and is adopted, never erased under a stale decision.
    /// Returns the delivery state the same locked write leaves behind
    /// — confirmed part count, remaining checkpoint and the retry
    /// deadline it carries — so the resend continues from one coherent
    /// record instead of mixing an older resolve's sent count with the
    /// checkpoint a newer write earned. `None` means the durable
    /// record no longer holds the task at all.
    pub fn clear_reply_progress(
        &mut self,
        key: impl Into<TaskKey>,
        expected: Option<&crate::transport::SendProgress>,
    ) -> Result<Option<ReplyResumeState>> {
        let key = key.into();
        self.mutate(|document| {
            Ok(document
                .pending_updates
                .iter_mut()
                .find(|task| task.key() == key)
                .map(|task| {
                    if task.reply_progress.as_ref() == expected {
                        task.reply_progress = None;
                        task.reply_retry_at_ms = None;
                    }
                    ReplyResumeState {
                        sent: task.reply_sent,
                        progress: task.reply_progress.clone(),
                        retry_at_ms: task.reply_retry_at_ms,
                    }
                }))
        })
    }

    /// Persist a delivery attempt's checkpoint and owed retry deadline
    /// as one durable write: `progress` replaces the stored checkpoint
    /// (`None` leaves it untouched — a failure before the transport
    /// ran has none to record), `not_before` sets the Unix-millisecond
    /// instant the reply must not be attempted before. Persisting both
    /// together before the wait means an exit inside it can never
    /// leave a retryable checkpoint missing its deadline.
    pub fn record_reply_checkpoint(
        &mut self,
        key: impl Into<TaskKey>,
        progress: Option<crate::transport::SendProgress>,
        not_before: Option<u64>,
    ) -> Result<()> {
        let key = key.into();
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.key() == key)
            {
                if let Some(progress) = progress {
                    task.reply_progress = Some(progress);
                }
                if let Some(deadline) = not_before {
                    task.reply_retry_at_ms = Some(deadline);
                }
            }
            Ok(())
        })
    }

    /// One admitted-but-unfinished task by its sequence-scoped key,
    /// if it exists — the durable record a retried delivery reloads
    /// before it resumes, so a later attempt continues the latest
    /// checkpoint rather than a stale snapshot.
    pub fn pending_update(&self, key: impl Into<TaskKey>) -> Option<PendingUpdate> {
        let key = key.into();
        self.document
            .pending_updates
            .iter()
            .find(|task| task.key() == key)
            .cloned()
    }

    /// The staged keys on disk — the replies whose payload and manifest
    /// exist but whose document pointer may not have committed yet.
    /// Filename-derived; no content is read.
    pub fn staged_update_keys(&self) -> Vec<TaskKey> {
        staged_update_keys(&replies_dir(&self.path))
    }

    /// Whether a recoverable staged completion for the task is still
    /// waiting to bind — the durable reply exists, so the task counts
    /// as holding a finished reply even while its document pointer has
    /// not committed.
    pub fn staged_reply_pending(&self, key: impl Into<TaskKey>) -> bool {
        staged_exists(&replies_dir(&self.path), key.into())
    }

    /// Whether a staged completion for the task is still waiting to
    /// bind — the durable record exists but the task does not yet
    /// carry its pointer. A bound completion is the task's reply
    /// payload itself, not an outstanding bind: a capacity failure on
    /// a later write — a checkpoint or retry deadline the document no
    /// longer fits — is not the nonfatal staged-record case the
    /// runtime tolerates and must surface as the write failure it is.
    pub fn staged_reply_unbound(&self, key: impl Into<TaskKey>) -> bool {
        let key = key.into();
        let dir = replies_dir(&self.path);
        let Some(manifest) = read_staged_manifest(&dir, key) else {
            return false;
        };
        !self.document.pending_updates.iter().any(|task| {
            task.key() == key && task.reply_file.as_deref() == Some(manifest.payload.as_str())
        })
    }

    /// The tasks a committed mutation newly bound a staged reply onto
    /// since the last drain — replies that became deliverable when a
    /// write freed the document space they were waiting for. Drained
    /// once so the runtime queues each for resend exactly once; a key
    /// whose task already settled drops out here instead of queueing
    /// stale work.
    pub fn take_bound_replies(&mut self) -> Vec<PendingUpdate> {
        std::mem::take(&mut self.bound_replies)
            .into_iter()
            .filter_map(|key| {
                self.document
                    .pending_updates
                    .iter()
                    .find(|task| task.key() == key && task.has_reply())
                    .cloned()
            })
            .collect()
    }

    /// Return keys the scheduler could not admit yet — the poller's
    /// backlog drain offers them again once capacity frees, so a
    /// newly deliverable reply is never lost between the store and a
    /// full lane.
    pub fn restage_bound_replies(&mut self, keys: Vec<TaskKey>) {
        self.bound_replies.extend(keys);
    }

    /// The update ids this store already durably claimed — settled ids
    /// plus the live-sequence ids of pending tasks. Settled records and
    /// claims mean nothing outside the sequence they were confirmed
    /// under, so a restarted sequence's reused ids must not name a dead
    /// sequence's retained work; the runtime filters live-sequence
    /// claims itself once the fetched batch names its own sequence.
    pub fn claimed_update_ids(&self) -> std::collections::HashSet<i64> {
        let sequence = self.document.poll_sequence;
        self.document
            .pending_updates
            .iter()
            .filter(|task| task.sequence == sequence)
            .map(|task| task.update_id)
            .chain(self.document.settled_updates.iter().copied())
            .collect()
    }

    /// Apply every staged completion that commits, then report the
    /// ones still waiting — with the stable refusal code — so the
    /// runtime can surface them instead of silently retaining them.
    /// Runs the same lock-reload-merge-write cycle as every mutation;
    /// with nothing staged it is a pure no-op, never a rewrite.
    pub fn reconcile_staged(&mut self) -> Result<Vec<StrandedReply>> {
        let dir = replies_dir(&self.path);
        if staged_update_keys(&dir).is_empty() {
            return Ok(Vec::new());
        }
        self.mutate(|document| {
            // Apply on this candidate so the report reflects what this
            // write commits; the cycle's own merge pass is idempotent.
            apply_staged(document, &dir);
            Ok(stranded_staged(document, &dir))
        })
    }

    /// Drop an admitted task once it is fully processed. Its id stays
    /// on the bounded settled tail: a cursor rollback that refetches
    /// the update skips it instead of re-running confirmed work. Only
    /// a live-sequence claim settles — the tail's ids name the live
    /// numbering alone.
    pub fn complete_update(&mut self, key: impl Into<TaskKey>) -> Result<()> {
        let key = key.into();
        self.mutate(|document| {
            document.pending_updates.retain(|task| task.key() != key);
            if key.sequence == document.poll_sequence {
                note_settled(document, key.update_id);
            }
            Ok(())
        })
    }

    /// Settle a task whose handling failed: the record is dropped
    /// unless it still holds an undelivered finished reply — committed
    /// or staged — since that result is the only unfinished stage and
    /// is resumed on restart instead of re-running the turn. A
    /// retained record stays claimed; a removed one's id joins the
    /// settled tail so a refetch skips it either way.
    pub fn settle_failed_update(&mut self, key: impl Into<TaskKey>) -> Result<()> {
        let key = key.into();
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let before = document.pending_updates.len();
            document
                .pending_updates
                .retain(|task| task.key() != key || task.has_reply() || staged_exists(&dir, key));
            if document.pending_updates.len() != before && key.sequence == document.poll_sequence {
                note_settled(document, key.update_id);
            }
            Ok(())
        })
    }

    /// Resolve a task's finished reply text: small records carry it
    /// inline; a spilled record's payload lives in its sidecar file.
    /// A task marked `reply_refused` resolves the manifest's refused
    /// variant — for a pointer manifest that text lives in the `.json`
    /// record, not the payload sidecar. A bound self-contained record
    /// is revalidated against the document it sits on: a pairing offer
    /// whose exact record no longer holds — elapsed during downtime,
    /// approved, or replaced by a newer request — resolves to its
    /// refused variant, so a recovered resend can never publish a dead
    /// code. `Ok(None)` means no finished reply is recorded.
    ///
    /// The lapsed-offer substitution applies only while the send is
    /// still safe to reshape: no contract part confirmed and no
    /// platform checkpoint holding confirmed parts or an uncertain
    /// outcome. A send the platform may already have seen keeps the
    /// text its checkpoint was earned on — substituting under it would
    /// restart the remaining parts as a different message and strand
    /// the resume. A substitution the resolver selects is committed
    /// before it can be sent: the first checkpoint the reply earns must
    /// resolve the same payload on the next read, or recovery would
    /// resume the refusal's progress against the recorded offer text
    /// and refuse the send forever.
    pub fn reply_text(&mut self, task: &PendingUpdate) -> Result<Option<String>> {
        Ok(self.resolve_reply(task)?.map(|resolved| resolved.text))
    }

    /// Resolve a recorded reply's deliverable payload together with the
    /// durable delivery checkpoint the same document state holds: the
    /// text and the progress governing it come out of one locked
    /// read — and, for a refusal the resolve commits, one locked
    /// write — so a caller can never pair a freshly selected variant
    /// with a checkpoint read from a different write, nor erase
    /// progress another store landed under it.
    pub fn resolve_reply(&mut self, task: &PendingUpdate) -> Result<Option<ResolvedReply>> {
        if task.reply.is_none() && task.reply_file.is_none() {
            return Ok(None);
        }
        let staged = match task.reply_file.as_deref() {
            Some(name) if name.ends_with(".json") => Some(
                read_staged_record(&self.path, name, task.key())?
                    .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))?,
            ),
            _ => None,
        };
        // The variant and the checkpoint come out of the task the
        // document reloads under the lock — never the caller's
        // snapshot: a refusal or a progress record another store
        // committed in between is answered by the durable state, so a
        // resolve can never pair a freshly selected variant with a
        // checkpoint read from a different write, nor serve a variant
        // the document does not carry.
        let (refused, sent, progress) =
            self.resolve_reply_variant(task, staged.as_ref().map(|staged| &staged.effect))?;
        let text = if let Some(reply) = &task.reply {
            reply.clone()
        } else if let Some(staged) = staged {
            if refused {
                staged.refused_text.or(staged.text)
            } else {
                staged.text
            }
            .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))?
        } else if refused {
            let manifest = manifest_file_name(task.key());
            read_reply_payload(&self.path, &manifest, task.key(), true)?
                .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))?
        } else {
            read_reply_payload(
                &self.path,
                task.reply_file.as_deref().expect("reply is file-backed"),
                task.key(),
                false,
            )?
            .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))?
        };
        Ok(Some(ResolvedReply {
            text,
            sent,
            progress,
        }))
    }

    /// The variant and the delivery checkpoint a resolve answers with,
    /// decided from the task the document reloads under the lock. A
    /// live lapsed-offer substitution commits its refusal inside the
    /// same locked write that re-validates it; every other case answers
    /// the flag the durable record already carries, so a refusal is
    /// served only while the document holds it. A task the durable
    /// record no longer knows falls back to the caller's snapshot —
    /// nothing durable governs it.
    fn resolve_reply_variant(
        &mut self,
        task: &PendingUpdate,
        effect: Option<&StagedEffect>,
    ) -> Result<(bool, usize, Option<crate::transport::SendProgress>)> {
        self.refresh()?;
        let Some(held) = self
            .document
            .pending_updates
            .iter()
            .find(|held| held.key() == task.key())
            .cloned()
        else {
            return Ok((
                task.reply_refused,
                task.reply_sent,
                task.reply_progress.clone(),
            ));
        };
        let substitutable = held.reply_sent == 0
            && held
                .reply_progress
                .as_ref()
                .is_none_or(|progress| progress.confirmed.is_empty() && !progress.outcome_unknown);
        if held.reply_refused || !substitutable {
            return Ok((held.reply_refused, held.reply_sent, held.reply_progress));
        }
        let Some(effect) = effect else {
            return Ok((held.reply_refused, held.reply_sent, held.reply_progress));
        };
        if !pairing_offer_lapsed(&self.document, effect) {
            return Ok((held.reply_refused, held.reply_sent, held.reply_progress));
        }
        self.persist_refused_reply(task, effect)
    }

    /// Commit the durable form of a lapsed offer's refused-variant
    /// selection — re-validated against the reloaded document so a
    /// checkpoint another store instance earned between the resolve
    /// and this write keeps the text it was earned on instead of being
    /// repointed under it. Returns the variant and the checkpoint the
    /// committed document holds: progress landed in between leaves the
    /// original offer selected, so the resolver answers with the
    /// payload that checkpoint was earned on rather than the stale
    /// snapshot's refusal.
    fn persist_refused_reply(
        &mut self,
        task: &PendingUpdate,
        effect: &StagedEffect,
    ) -> Result<(bool, usize, Option<crate::transport::SendProgress>)> {
        let key = task.key();
        let stale = (
            task.reply_refused,
            task.reply_sent,
            task.reply_progress.clone(),
        );
        self.mutate(|document| {
            let lapsed = pairing_offer_lapsed(document, effect);
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.key() == key)
                && task.reply_sent == 0
                && task.reply_progress.as_ref().is_none_or(|progress| {
                    progress.confirmed.is_empty() && !progress.outcome_unknown
                })
                && lapsed
            {
                task.reply_refused = true;
            }
            Ok(document
                .pending_updates
                .iter()
                .find(|task| task.key() == key)
                .map(|task| {
                    (
                        task.reply_refused,
                        task.reply_sent,
                        task.reply_progress.clone(),
                    )
                }))
        })
        .map(|found| found.unwrap_or(stale))
    }

    /// Persist one update id the runtime could not hand to the host as a
    /// message, bounded to the newest [`MAX_DROPPED_UPDATES`] entries.
    /// Writing this record before the cursor advances is what keeps a
    /// dice/game/service payload from vanishing without a trace.
    pub fn record_dropped_update(&mut self, update_id: i64, raw_kind: &str) -> Result<()> {
        let raw_kind: String = raw_kind.chars().take(MAX_RAW_KIND_CHARS).collect();
        self.mutate(|document| {
            let sequence = document.poll_sequence;
            let key = TaskKey::new(sequence, update_id);
            document.dropped_updates.retain(|item| item.key() != key);
            document.dropped_updates.push(DroppedUpdate {
                update_id,
                sequence,
                raw_kind,
            });
            let excess = document
                .dropped_updates
                .len()
                .saturating_sub(MAX_DROPPED_UPDATES);
            if excess > 0 {
                document.dropped_updates.drain(..excess);
            }
            Ok(())
        })
    }

    /// The bounded durable record of updates the runtime could not turn
    /// into host-visible messages, newest last.
    pub fn dropped_updates(&self) -> Vec<DroppedUpdate> {
        self.document.dropped_updates.clone()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn generate_pairing_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[(*byte as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Remember a task's update id on the bounded settled tail: a cursor
/// rollback for a rejected event refetches it, and the remembered id
/// keeps confirmed work out of the scheduler.
fn note_settled(document: &mut BindingDocument, update_id: i64) {
    document.settled_updates.retain(|id| *id != update_id);
    document.settled_updates.push(update_id);
    let excess = document
        .settled_updates
        .len()
        .saturating_sub(MAX_SETTLED_UPDATES);
    if excess > 0 {
        document.settled_updates.drain(..excess);
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "bindings.json".into());
    name.push(".lock");
    path.with_file_name(name)
}

/// Sidecar directory holding spilled reply payloads and staged
/// records next to the state file: `<full state file
/// name>.replies/reply-<update_id>.txt` and
/// `reply-<update_id>.json`. The directory name derives from the
/// entire file name, not an extension substitution — `bot.json` and
/// `bot.state` are distinct stores with distinct locks and must never
/// share reply files. Finished outcomes live there so a large reply
/// never has to fit the bounded document.
fn replies_dir(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "bindings.json".into());
    name.push(".replies");
    path.with_file_name(name)
}

/// The sidecar directory the preceding revision spilled payloads
/// into — `<state stem>.replies`, an extension substitution two
/// distinct state files can collide on. Payloads a pending record
/// still points at are resolved there so work finished before the
/// layout change stays discoverable. Read-only: this store never
/// creates, deletes or sweeps inside it, because the same directory
/// may hold a sibling state file's legacy payloads.
fn legacy_replies_dir(path: &Path) -> PathBuf {
    path.with_extension("replies")
}

/// Resolve a record's payload: the store's sidecar directory first,
/// then the legacy directory the preceding revision used. A `.json`
/// name is a self-contained staged record whose text is the reply —
/// verified against the task it is read for; any other name is raw
/// payload text.
fn read_reply_payload(
    path: &Path,
    name: &str,
    key: TaskKey,
    refused: bool,
) -> Result<Option<String>> {
    for dir in [replies_dir(path), legacy_replies_dir(path)] {
        let bound = if name.ends_with(".json") {
            MAX_STAGED_BYTES
        } else {
            MAX_REPLY_BYTES
        };
        let Some(raw) = read_private_text_bounded(&dir.join(name), bound)? else {
            continue;
        };
        return decode_reply_payload(name, &raw, key, refused).map(Some);
    }
    Ok(None)
}

/// Read one bound self-contained record by the file name the task
/// points at — the store's sidecar directory first, then the legacy
/// directory. Identity is verified against the task exactly as
/// discovery verifies it; a record that cannot parse is lost, not
/// skipped, matching the payload resolution callers replaced.
fn read_staged_record(path: &Path, name: &str, key: TaskKey) -> Result<Option<StagedCompletion>> {
    for dir in [replies_dir(path), legacy_replies_dir(path)] {
        let Some(raw) = read_private_text_bounded(&dir.join(name), MAX_STAGED_BYTES)? else {
            continue;
        };
        return serde_json::from_str::<StagedCompletion>(&raw)
            .ok()
            .filter(|staged| staged.update_id == key.update_id && staged.sequence == key.sequence)
            .map(Some)
            .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"));
    }
    Ok(None)
}

/// Whether a pairing offer a staged effect recorded no longer holds —
/// its TTL elapsed, an approval paired the user it was minted for, or
/// a newer request replaced its code — so the reply publishing it must
/// resolve to the refused variant instead of a dead code. Revalidated
/// on the live document at send time: an offer that still holds
/// delivers its recorded text unchanged.
fn pairing_offer_lapsed(document: &BindingDocument, effect: &StagedEffect) -> bool {
    let StagedEffect::ReplyPairing { record } = effect else {
        return false;
    };
    let now = now_secs();
    record.expires_at <= now
        || document
            .chats
            .get(&record.chat_id.to_string())
            .is_some_and(|binding| binding.paired && binding.user_id == record.user_id)
        || document
            .revoked_chats
            .get(&record.chat_id.to_string())
            .is_some_and(|revoked_at| record.minted_revision <= *revoked_at)
        || !document.pairings.iter().any(|held| {
            held.code == record.code
                && held.chat_id == record.chat_id
                && held.user_id == record.user_id
                && held.expires_at > now
        })
}

fn decode_reply_payload(name: &str, raw: &str, key: TaskKey, refused: bool) -> Result<String> {
    if !name.ends_with(".json") {
        return Ok(raw.to_owned());
    }
    let staged = serde_json::from_str::<StagedCompletion>(raw)
        .ok()
        .filter(|staged| staged.update_id == key.update_id && staged.sequence == key.sequence)
        .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))?;
    if refused {
        staged.refused_text.or(staged.text)
    } else {
        staged.text
    }
    .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))
}

fn reply_file_name(key: TaskKey) -> String {
    match key.sequence {
        0 => format!("reply-{}.txt", key.update_id),
        sequence => format!("reply-s{sequence}-{}.txt", key.update_id),
    }
}

/// The staged-completion manifest for one task key — payload, key
/// and effect recorded before the document commits. Sequence `0`
/// keeps the revision-one file name so records staged before the
/// field existed stay discoverable under the key they decode to.
fn manifest_file_name(key: TaskKey) -> String {
    match key.sequence {
        0 => format!("reply-{}.json", key.update_id),
        sequence => format!("reply-s{sequence}-{}.json", key.update_id),
    }
}

/// Parse `reply-<update_id>.<suffix>` and `reply-s<seq>-<update_id>.<suffix>`
/// names — the only file names this store owns inside its replies
/// directory. The unsequenced form decodes to sequence `0`.
fn staged_file_name_id(name: &str) -> Option<(TaskKey, &str)> {
    let body = name.strip_prefix("reply-")?;
    let (id, suffix) = body.rsplit_once('.')?;
    let key = if let Some(rest) = id.strip_prefix('s') {
        let (sequence, id) = rest.split_once('-')?;
        TaskKey::new(sequence.parse().ok()?, id.parse().ok()?)
    } else {
        TaskKey::from(id.parse::<i64>().ok()?)
    };
    Some((key, suffix))
}

/// Whether a recoverable staged completion exists for the task —
/// the on-disk record stays authoritative until a document write
/// binds its pointer. A self-contained record always qualifies; a
/// pointer manifest does only while its payload file exists.
fn staged_exists(dir: &Path, key: TaskKey) -> bool {
    read_staged_manifest(dir, key)
        .is_some_and(|staged| staged.text.is_some() || dir.join(&staged.payload).is_file())
}

/// Whether a staged record's declared payload name matches the files
/// this store owns for its task key — the self-contained record's
/// own name or a pointer manifest's `.txt` sidecar.
fn staged_payload_name_ok(staged: &StagedCompletion, key: TaskKey) -> bool {
    staged.payload == reply_file_name(key) || staged.payload == manifest_file_name(key)
}

fn staged_update_keys(dir: &Path) -> Vec<TaskKey> {
    let mut keys = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return keys;
    };
    for entry in entries.flatten() {
        if let Some((key, "json")) = entry.file_name().to_str().and_then(staged_file_name_id) {
            keys.push(key);
        }
    }
    keys
}

/// Read one staged manifest by its task key — the file name, declared
/// identity and declared payload name verified exactly as directory
/// discovery verified them. `None` covers a missing, unreadable or
/// disagreeing record, which callers report as invalid. Manifests are
/// read one at a time wherever staged work is reconciled or swept, so
/// a deep backlog of self-contained records — each carrying its full
/// reply body — is never resident in memory at once.
fn read_staged_manifest(dir: &Path, key: TaskKey) -> Option<StagedCompletion> {
    read_private_text_bounded(&dir.join(manifest_file_name(key)), MAX_STAGED_BYTES)
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<StagedCompletion>(&raw).ok())
        .filter(|staged: &StagedCompletion| {
            staged.update_id == key.update_id
                && staged.sequence == key.sequence
                && staged_payload_name_ok(staged, key)
        })
}

/// The document's serialized size — the bound every commit is checked
/// against. `None` means serialization failed, treated as uncommittable.
fn serialized_len(document: &BindingDocument) -> Option<usize> {
    serde_json::to_string_pretty(document)
        .ok()
        .map(|raw| raw.len())
}

/// The pairing offers still living only in staged reply records —
/// each returned as minted so a revocation can tombstone an offer the
/// document itself cannot show.
fn staged_pairing_offers(dir: &Path) -> Vec<PairingRecord> {
    staged_update_keys(dir)
        .into_iter()
        .filter_map(|key| read_staged_manifest(dir, key))
        .filter_map(|staged| match staged.effect {
            StagedEffect::ReplyPairing { record } => Some(record),
            _ => None,
        })
        .collect()
}

/// Reclaim revocation tombstones no staged offer can still need: a
/// tombstone guards the replies directory's records minted at or
/// before it, so once every such offer has expired or settled — its
/// own refusal is already certain without the tombstone — the entry
/// would only consume the bounded document forever. Runs inside the
/// mutation's lock, so a record being written by another mutation is
/// either already durable in the scan or lands after it.
fn reclaim_revocations(document: &mut BindingDocument, dir: &Path) {
    let now = now_secs();
    let guarded: Vec<(String, u64)> = staged_pairing_offers(dir)
        .into_iter()
        .filter(|record| {
            record.expires_at > now
                && !document
                    .chats
                    .get(&record.chat_id.to_string())
                    .is_some_and(|binding| binding.paired && binding.user_id == record.user_id)
        })
        .map(|record| (record.chat_id.to_string(), record.minted_revision))
        .collect();
    document.revoked_chats.retain(|chat_id, revoked_at| {
        guarded
            .iter()
            .any(|(chat, minted)| chat == chat_id && minted <= revoked_at)
    });
}

/// Bind every applicable staged completion on the candidate document:
/// the declared effect re-applies exactly as the record's own commit
/// performed it, and the task gains the payload pointer and delivery
/// key. Manifests are read under the caller's lock, so a completion
/// being written by another mutation is either already durable here or
/// still staging — never half-read. Returns the keys this call newly
/// bound — each a reply that became deliverable, reported so the
/// runtime can queue it for resend once. A task already holding its
/// bound reply never re-enters the list.
fn apply_staged(document: &mut BindingDocument, dir: &Path) -> Vec<TaskKey> {
    let mut bound = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return bound;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some((key, "json")) = entry.file_name().to_str().and_then(staged_file_name_id) else {
            continue;
        };
        // A task already holding its bound reply can never re-apply
        // this record — the manifest's only remaining job is the
        // sweep, so its (potentially large) payload is not re-read and
        // re-parsed on every mutation.
        let Some(index) = document
            .pending_updates
            .iter()
            .position(|task| task.key() == key)
        else {
            continue;
        };
        if document.pending_updates[index].has_reply() {
            continue;
        }
        let staged = read_private_text_bounded(&path, MAX_STAGED_BYTES)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<StagedCompletion>(&raw).ok())
            .filter(|staged: &StagedCompletion| {
                staged.update_id == key.update_id
                    && staged.sequence == key.sequence
                    && staged_payload_name_ok(staged, key)
            });
        let Some(staged) = staged else { continue };
        // The record must be readable end to end: a self-contained
        // record carries its payload; a pointer manifest is only
        // recoverable while its payload file exists — a pointer whose
        // payload never landed marks a stage that died mid-write,
        // not finished work.
        if staged.text.is_none() && !dir.join(&staged.payload).is_file() {
            continue;
        }
        // Bind tentatively, then keep the record only while the whole
        // serialized document still fits the read bound: an effect
        // that fits in isolation can overflow against live bindings,
        // and records that each fit can overflow together. A record
        // that cannot land is reverted, retained on disk and reported
        // by `stranded_staged` — instead of letting every mutation
        // that replays it fail on a document it can never commit.
        let before = document.clone();
        let applied = apply_effect(document, dir, &staged.effect);
        let task = &mut document.pending_updates[index];
        task.reply = None;
        task.reply_file = Some(staged.payload.clone());
        task.reply_key = Some(staged.key.clone());
        task.reply_sent = 0;
        task.reply_progress = None;
        task.reply_retry_at_ms = None;
        // The bound text names what the effect actually committed: a
        // refused effect binds the record's refused variant, never the
        // success text the stage hoped for.
        task.reply_refused = !applied && staged.refused_text.is_some();
        if serialized_len(document).is_none_or(|len| len > MAX_STATE_BYTES) {
            *document = before;
        } else {
            bound.push(key);
        }
    }
    bound
}

/// The staged completions a document still has not bound — each with
/// the code naming why it waits, for host surfacing. A manifest whose
/// task is gone is ignored: the sweep reclaims it.
fn stranded_staged(document: &BindingDocument, dir: &Path) -> Vec<StrandedReply> {
    let mut out = Vec::new();
    for key in staged_update_keys(dir) {
        let staged = read_staged_manifest(dir, key);
        let applied = document
            .pending_updates
            .iter()
            .find(|task| task.key() == key)
            .is_some_and(|task| {
                task.has_reply()
                    && staged.as_ref().is_some_and(|staged| {
                        task.reply_file.as_deref() == Some(staged.payload.as_str())
                    })
            });
        if applied {
            continue;
        }
        let Some(task) = document
            .pending_updates
            .iter()
            .find(|task| task.key() == key)
        else {
            continue;
        };
        let recoverable = staged
            .as_ref()
            .is_some_and(|staged| staged.text.is_some() || dir.join(&staged.payload).is_file());
        out.push(StrandedReply {
            update_id: task.update_id,
            sequence: task.sequence,
            code: if recoverable {
                "a4mc_telegram_state_full".to_owned()
            } else {
                "a4mc_telegram_staged_invalid".to_owned()
            },
        });
    }
    out
}

/// Write one finished reply's recoverable record into the sidecar
/// directory and bind its pointer on the admitted task. The record
/// carries payload, delivery key and state effect in a single atomic
/// rename before the caller's document commit: a crash before it
/// leaves nothing durable, a crash after it leaves the whole
/// recoverable completion — never a payload no record recognizes.
/// `refused_text` is the outcome bound instead when recovery finds
/// the record's effect refused; `applied` is what this commit's own
/// effect did, so the pointer binds the matching variant.
#[allow(clippy::too_many_arguments)]
fn stage_reply(
    document: &mut BindingDocument,
    dir: &Path,
    key: TaskKey,
    reply: &str,
    refused_text: Option<&str>,
    applied: bool,
    delivery_key: &str,
    effect: StagedEffect,
) -> Result<()> {
    let Some(task) = document
        .pending_updates
        .iter_mut()
        .find(|task| task.key() == key)
    else {
        return Ok(());
    };
    ensure_private_dir(dir)?;
    let record_name = manifest_file_name(key);
    let manifest = StagedCompletion {
        update_id: key.update_id,
        sequence: key.sequence,
        payload: record_name.clone(),
        key: delivery_key.to_owned(),
        effect,
        text: Some(reply.to_owned()),
        refused_text: refused_text.map(str::to_owned),
    };
    let raw = serde_json::to_string(&manifest)
        .map_err(|_| anyhow!("a4mc_telegram_state_write_failed"))?;
    ensure!(
        raw.len() <= MAX_STAGED_BYTES,
        "a4mc_telegram_reply_too_large"
    );
    atomic_write_private_text(&dir.join(&record_name), &raw)?;
    task.reply = None;
    task.reply_file = Some(record_name);
    task.reply_key = Some(delivery_key.to_owned());
    task.reply_sent = 0;
    task.reply_progress = None;
    task.reply_retry_at_ms = None;
    task.reply_refused = !applied && refused_text.is_some();
    Ok(())
}

/// The next binding revision from the document's monotone counter —
/// every write that changes how a chat routes draws one, so a stale
/// precondition can never match a binding that moved and came back.
fn next_revision(document: &mut BindingDocument) -> u64 {
    document.revision_counter += 1;
    document.revision_counter
}

/// Apply one staged effect to the document — the same change the
/// record's own commit performed, refused when the binding it was
/// staged against no longer holds. Returns whether the effect's state
/// change landed: for the revocation that is whether anything was
/// removed; for the routing effects whether the guarded write applied.
fn apply_effect(document: &mut BindingDocument, dir: &Path, effect: &StagedEffect) -> bool {
    match effect {
        StagedEffect::Reply => true,
        StagedEffect::ReplySession {
            chat_id,
            session_id,
            user_id,
            agent_id,
            prior_session,
            binding_revision,
        } => {
            let applies = document
                .chats
                .get(&chat_id.to_string())
                .is_some_and(|binding| {
                    binding.agent_id.is_some()
                        && user_id.is_none_or(|held| binding.user_id == held)
                        && agent_id
                            .as_ref()
                            .is_none_or(|held| binding.agent_id.as_ref() == Some(held))
                        && prior_session
                            .as_ref()
                            .is_none_or(|held| binding.session_id == *held)
                        && binding_revision.is_none_or(|held| binding.revision == held)
                });
            if applies {
                let revision = next_revision(document);
                let binding = document
                    .chats
                    .get_mut(&chat_id.to_string())
                    .expect("checked binding");
                binding.session_id = session_id.clone();
                binding.revision = revision;
                binding.updated_at = now_secs();
            }
            applies
        }
        StagedEffect::ReplyRevoke { chat_id, user_id } => {
            let removable = document
                .chats
                .get(&chat_id.to_string())
                .is_none_or(|binding| user_id.is_none_or(|held| binding.user_id == held));
            if !removable {
                return false;
            }
            let now = now_secs();
            let removed = document.chats.remove(&chat_id.to_string()).is_some();
            // The same live-only accounting `revoke` applies: an
            // expired code's row still sitting in the document is dead
            // already, so dropping it here is cleanup and must not turn
            // the recorded /unpair reply into a revocation that never
            // happened.
            let live = document.pairings.iter().any(|record| {
                record.chat_id == *chat_id
                    && user_id.is_none_or(|held| record.user_id == held)
                    && record.expires_at > now
            });
            document.pairings.retain(|record| {
                record.chat_id != *chat_id || user_id.is_some_and(|held| record.user_id != held)
            });
            // A staged offer that never fit the document leaves no
            // pairing to remove — recognize and tombstone it anyway,
            // scoped to the revoking user exactly like the pairing
            // records are, so reconciliation cannot publish the
            // pre-revocation code once unrelated space frees. An offer
            // whose TTL already ran out binds its own refusal, so it
            // is neither revocable nor owed a tombstone.
            let chat = chat_id.to_string();
            let guarded_at = document.revoked_chats.get(&chat).copied();
            let staged = staged_pairing_offers(dir).into_iter().any(|record| {
                record.chat_id == *chat_id
                    && user_id.is_none_or(|held| record.user_id == held)
                    && record.expires_at > now
                    && guarded_at.is_none_or(|at| record.minted_revision > at)
            });
            let revoked = removed || live || staged;
            if revoked {
                // Tombstone the revocation like `revoke` does: a staged
                // offer minted before it can never re-publish through
                // the space the removal freed.
                let revision = next_revision(document);
                document.revoked_chats.insert(chat, revision);
            }
            revoked
        }
        StagedEffect::ReplyAgent {
            chat_id,
            agent_id,
            user_id,
            binding_revision,
        } => {
            let applies = document
                .chats
                .get(&chat_id.to_string())
                .is_some_and(|binding| {
                    binding.paired
                        && user_id.is_none_or(|held| binding.user_id == held)
                        && binding_revision.is_none_or(|held| binding.revision == held)
                });
            if applies {
                let revision = next_revision(document);
                let binding = document
                    .chats
                    .get_mut(&chat_id.to_string())
                    .expect("checked binding");
                if binding.agent_id.as_deref() != Some(agent_id.as_str()) {
                    binding.session_id = None;
                }
                binding.agent_id = Some(agent_id.clone());
                binding.revision = revision;
                binding.updated_at = now_secs();
            }
            applies
        }
        StagedEffect::ReplyPairing { record } => {
            let now = now_secs();
            document.pairings.retain(|held| held.expires_at > now);
            if record.expires_at <= now {
                // The offer's TTL elapsed while it waited to bind —
                // replaying it would publish a dead code, so the
                // record binds its refused variant instead.
                return false;
            }
            if document
                .chats
                .get(&record.chat_id.to_string())
                .is_some_and(|binding| binding.paired && binding.user_id == record.user_id)
            {
                // The user holds a full pairing now — the staged code
                // offer is superseded, never re-published.
                return false;
            }
            if document
                .revoked_chats
                .get(&record.chat_id.to_string())
                .is_some_and(|revoked_at| record.minted_revision <= *revoked_at)
            {
                // The chat was revoked after this offer was minted —
                // the space its revocation freed must never restore an
                // offer minted before it.
                return false;
            }
            document
                .pairings
                .retain(|held| held.chat_id != record.chat_id || held.user_id != record.user_id);
            document.pairings.push(record.clone());
            true
        }
    }
}

/// Remove sidecar files no serialized record still references. Runs
/// inside `mutate`'s lock after the document lands. Only `reply-*`
/// files this store owns inside its own directory are touched — a
/// payload is live while a task or an unapplied record names it, and
/// a record is live while its task may still bind it. The legacy
/// directory is never swept: a sibling state file's payloads may live
/// there too.
fn sweep_reply_files(path: &Path, document: &BindingDocument) {
    let dir = replies_dir(path);
    let mut live: HashSet<String> = document
        .pending_updates
        .iter()
        .filter_map(|task| task.reply_file.clone())
        .collect();
    for key in staged_update_keys(&dir) {
        let staged = read_staged_manifest(&dir, key);
        let task = document
            .pending_updates
            .iter()
            .find(|task| task.key() == key);
        let bound = task.is_some_and(|task| {
            staged
                .as_ref()
                .is_some_and(|staged| task.reply_file.as_deref() == Some(staged.payload.as_str()))
        });
        if bound {
            // The pointer committed — a self-contained record stays
            // live as the payload itself; a pointer manifest has
            // served and is reclaimed.
            if staged.as_ref().is_some_and(|staged| staged.text.is_none()) {
                let _ = std::fs::remove_file(dir.join(manifest_file_name(key)));
            }
            continue;
        }
        match staged {
            Some(staged) => {
                let recoverable = staged.text.is_some() || dir.join(&staged.payload).is_file();
                if task.is_none() || !recoverable {
                    // Orphaned, or a stage that died before its
                    // payload landed — nothing left to recover.
                    let _ = std::fs::remove_file(dir.join(manifest_file_name(key)));
                } else {
                    // Still waiting to bind: hold the record and the
                    // payload it names.
                    live.insert(staged.payload);
                }
            }
            None => {
                // An unreadable record is held for reporting while its
                // task is unbound; once the task is gone it is swept.
                if task.is_none() {
                    let _ = std::fs::remove_file(dir.join(manifest_file_name(key)));
                } else {
                    live.insert(reply_file_name(key));
                }
            }
        }
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if entry.file_type().is_ok_and(|kind| kind.is_file())
            && name.to_str().is_some_and(|name| {
                staged_file_name_id(name)
                    .is_some_and(|(_, suffix)| suffix == "txt" && !live.contains(name))
            })
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn read_document(path: &Path) -> Result<BindingDocument> {
    match read_private_text_bounded(path, MAX_STATE_BYTES)? {
        Some(raw) => {
            let document: BindingDocument = serde_json::from_str(&raw)
                .map_err(|_| anyhow!("a4mc_telegram_bindings_invalid"))?;
            // The document pins its schema. Unlike disposable counters, a
            // bindings file records approvals — a schema this build does
            // not recognize is refused rather than silently emptied (which
            // would unpair chats and overwrite their records on the next
            // mutation). The file is left untouched for migration.
            ensure!(
                document.schema_version == BINDING_SCHEMA,
                "a4mc_telegram_bindings_schema"
            );
            Ok(document)
        }
        None => Ok(BindingDocument {
            schema_version: BINDING_SCHEMA.to_owned(),
            pairings: Vec::new(),
            chats: BTreeMap::new(),
            poll_offset: 0,
            poll_offset_advanced_at: None,
            dropped_updates: Vec::new(),
            pending_events: Vec::new(),
            pending_updates: Vec::new(),
            settled_updates: Vec::new(),
            revision_counter: 0,
            poll_sequence: 0,
            revoked_chats: BTreeMap::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Instant;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_store<F: FnOnce(BindingStore)>(body: F) {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-bind-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let store = BindingStore::open_in(&root).unwrap();
        body(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pairing_approve_and_agent_switch_clears_session() {
        temp_store(|mut store| {
            let pending = store.request_pairing(11, 22, Some("alice".into())).unwrap();
            let binding = store.approve(&pending.code).unwrap();
            assert!(binding.paired);
            store.set_agent(11, Some("cursor".into())).unwrap();
            store.set_session(11, Some("sess-1".into())).unwrap();
            let switched = store.set_agent(11, Some("codex".into())).unwrap();
            assert_eq!(switched.agent_id.as_deref(), Some("codex"));
            assert_eq!(switched.session_id, None);
        });
    }

    #[test]
    fn revoke_persists_when_only_pending_pairing_exists() {
        temp_store(|mut store| {
            let pending = store.request_pairing(33, 44, Some("bob".into())).unwrap();
            assert_eq!(store.pending_pairings().len(), 1);
            assert!(store.revoke(pending.chat_id).unwrap());
            assert!(store.pending_pairings().is_empty());
            let reopened = BindingStore::open(store.path.clone()).unwrap();
            assert!(reopened.pending_pairings().is_empty());
        });
    }

    #[test]
    fn approved_chats_are_listed() {
        temp_store(|mut store| {
            let pending = store.request_pairing(55, 66, Some("carol".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.refresh().unwrap();
            store.prune_expired().unwrap();
            assert!(store.pending_pairings().is_empty());
            let chats = store.paired_chats();
            assert_eq!(chats.len(), 1);
            assert_eq!(chats[0].chat_id, 55);
        });
    }

    #[test]
    fn separate_handles_merge_without_silent_overwrite() {
        temp_store(|store| {
            let path = store.path.clone();
            let mut first = store;
            let mut second = BindingStore::open(path).unwrap();

            let pending = first.request_pairing(11, 22, Some("alice".into())).unwrap();
            first.approve(&pending.code).unwrap();
            let generation = first
                .set_agent(11, Some("cursor".into()))
                .unwrap()
                .updated_at;

            let pending = second.request_pairing(33, 44, Some("bob".into())).unwrap();
            second.approve(&pending.code).unwrap();
            second.set_agent(33, Some("codex".into())).unwrap();
            let merged = second.set_session(33, Some("sess-9".into())).unwrap();

            assert!(merged.updated_at >= generation);
            let binding = first.binding(11).cloned().unwrap();
            assert_eq!(binding.agent_id.as_deref(), Some("cursor"));
            assert_eq!(binding.session_id, None);
            first.refresh().unwrap();
            let other = first.binding(33).cloned().unwrap();
            assert_eq!(other.session_id.as_deref(), Some("sess-9"));
            assert!(other.updated_at >= generation);
        });
    }

    #[test]
    fn poll_cursor_persists_across_reopen() {
        temp_store(|mut store| {
            assert_eq!(store.poll_offset(), 0);
            store.set_poll_offset(41).unwrap();
            let reopened = BindingStore::open(store.path.clone()).unwrap();
            assert_eq!(reopened.poll_offset(), 41);
            // A later writer merging on an older in-memory document
            // still preserves the cursor.
            let mut other = BindingStore::open(store.path.clone()).unwrap();
            other.request_pairing(11, 22, Some("alice".into())).unwrap();
            let reread = BindingStore::open(store.path.clone()).unwrap();
            assert_eq!(reread.poll_offset(), 41);
        });
    }

    #[test]
    fn legacy_document_without_poll_offset_opens_at_zero_and_keeps_state() {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-bind-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let path = root.join(STATE_FILE);
        let legacy = serde_json::json!({
            "schemaVersion": BINDING_SCHEMA,
            "pairings": [],
            "chats": {
                "9": {
                    "chatId": 9,
                    "userId": 9,
                    "username": null,
                    "paired": true,
                    "agentId": "codex",
                    "sessionId": "sess-9",
                    "updatedAt": 1
                }
            }
        });
        std::fs::write(&path, serde_json::to_string(&legacy).unwrap()).unwrap();
        let mut store = BindingStore::open(path.clone()).unwrap();
        assert_eq!(
            store.poll_offset(),
            0,
            "a pre-cursor document must resume at the platform start"
        );
        assert_eq!(
            store.binding(9).and_then(|b| b.agent_id.as_deref()),
            Some("codex")
        );
        store.set_poll_offset(12).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"pollOffset\": 12"),
            "cursor not persisted: {raw}"
        );
        let reopened = BindingStore::open(path).unwrap();
        assert_eq!(reopened.poll_offset(), 12);
        assert_eq!(
            reopened.binding(9).and_then(|b| b.session_id.as_deref()),
            Some("sess-9"),
            "cursor write clobbered the chat binding"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stale_schema_file_is_refused_and_left_untouched() {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-bind-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let path = root.join(STATE_FILE);
        std::fs::write(
            &path,
            "{\"schemaVersion\":\"a4mc.telegram-bindings.v0\",\"pairings\":[],\"chats\":{}}",
        )
        .unwrap();
        let error = BindingStore::open(path.clone()).unwrap_err();
        assert_eq!(error.to_string(), "a4mc_telegram_bindings_schema");
        // The foreign document survives for inspection or migration.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("a4mc.telegram-bindings.v0"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn advisory_lock_serializes_refresh() {
        temp_store(|store| {
            let path = store.path.clone();
            drop(store);
            let held = open_private_lock_file(&lock_path(&path)).unwrap();
            FileExt::lock_exclusive(&held).unwrap();

            let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_started = Arc::clone(&started);
            let thread_finished = Arc::clone(&finished);
            let handle = thread::spawn(move || {
                let mut store = BindingStore::open(path).unwrap();
                thread_started.store(true, Ordering::SeqCst);
                store.refresh().unwrap();
                thread_finished.store(true, Ordering::SeqCst);
            });

            let deadline = Instant::now() + Duration::from_secs(2);
            while !started.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "refresh thread never started");
                thread::sleep(Duration::from_millis(2));
            }
            thread::sleep(Duration::from_millis(80));
            assert!(
                !finished.load(Ordering::SeqCst),
                "refresh completed while the advisory lock was held"
            );
            FileExt::unlock(&held).unwrap();
            handle.join().unwrap();
            assert!(finished.load(Ordering::SeqCst));
        });
    }

    fn inbound_message(update_id: i64, chat_id: i64) -> InboundMessage {
        InboundMessage {
            update_id,
            chat_id,
            chat_type: "private".into(),
            user_id: chat_id,
            username: Some("alice".into()),
            from_name: None,
            is_private: true,
            message_id: update_id,
            message_thread_id: None,
            edited: false,
            date: None,
            edit_date: None,
            kind: crate::inbound::InboundKind::Text,
            text: Some("hello".into()),
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

    #[test]
    fn reply_and_session_commit_lands_or_fails_as_one_write() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // A failed commit must leave neither half applied: a moved
            // binding on an unfinished task is exactly the state that
            // let a restart re-run the command or revert a later
            // session.
            let expected = store.binding(9).cloned().unwrap();
            store.fail_next_write_for_test();
            store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("s2".into()),
                    &expected,
                    |applied| {
                        if applied {
                            "Started a new conversation: s2".to_owned()
                        } else {
                            "The session could not move.".to_owned()
                        }
                    },
                )
                .unwrap_err();
            assert_eq!(store.binding(9).unwrap().session_id, None);
            assert!(!store.pending_updates()[0].has_reply());
            let reply = store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("s2".into()),
                    &expected,
                    |applied| {
                        if applied {
                            "Started a new conversation: s2".to_owned()
                        } else {
                            "The session could not move.".to_owned()
                        }
                    },
                )
                .unwrap();
            assert_eq!(reply, "Started a new conversation: s2");
            assert_eq!(store.binding(9).unwrap().session_id.as_deref(), Some("s2"));
            let task = &store.pending_updates()[0];
            assert_eq!(
                store.reply_text(task).unwrap().as_deref(),
                Some("Started a new conversation: s2")
            );
            assert_eq!(task.reply_key.as_deref(), Some("reply:7"));
        });
    }

    #[test]
    fn a_mutation_over_the_read_limit_is_refused_before_replacing_the_file() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message: inbound_message(3, 9),
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
                    4,
                )
                .unwrap();
            // An admitted update larger than the bounded read limit
            // must be refused outright: the file it would have replaced
            // stays readable, so the unacknowledged work can still
            // drain.
            let mut oversized = inbound_message(4, 9);
            oversized.text = Some("x".repeat(MAX_STATE_BYTES));
            let error = store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 4,
                        sequence: 0,
                        message: oversized,
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
                    5,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "a4mc_telegram_state_full");
            let reopened = BindingStore::open(store.path.clone()).unwrap();
            assert_eq!(reopened.poll_offset(), 4);
            assert!(!reopened.pending_updates()[0].has_reply());
            // Shrinking work still commits after the refusal.
            store.complete_update(3).unwrap();
            assert!(store.pending_updates().is_empty());
        });
    }

    #[test]
    fn a_completed_reply_survives_in_its_sidecar_file_until_the_task_settles() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 5,
                        sequence: 0,
                        message: inbound_message(5, 9),
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
                    6,
                )
                .unwrap();
            // A reply larger than the whole bounded document is the
            // case the inline field could never hold.
            let reply = "r".repeat(MAX_STATE_BYTES);
            store.record_reply(5, &reply, "reply:5").unwrap();
            let task = store.pending_updates().pop().unwrap();
            assert!(task.has_reply());
            assert!(task.reply.is_none());
            let mut reopened = BindingStore::open(store.path.clone()).unwrap();
            assert_eq!(
                reopened.reply_text(&task).unwrap().as_deref(),
                Some(&*reply)
            );
            let document_bytes = std::fs::metadata(&store.path).unwrap().len() as usize;
            assert!(
                document_bytes < MAX_STATE_BYTES,
                "the payload must not live inside the bounded document"
            );
            store.complete_update(5).unwrap();
            let task_file = replies_dir(&store.path).join("reply-5.txt");
            assert!(
                !task_file.exists(),
                "settling the task collects its payload file"
            );
        });
    }

    #[test]
    fn a_staged_completion_binds_reply_key_and_effect_on_recovery() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The crash window the finding names: the payload landed on
            // disk and the manifest was staged, but the document never
            // committed its pointer — a restart must still bind it.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("reply-7.txt"), "staged reply body").unwrap();
            let manifest = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.txt".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplySession {
                    chat_id: 9,
                    session_id: Some("staged-session".to_owned()),
                    user_id: None,
                    agent_id: None,
                    prior_session: None,
                    binding_revision: None,
                },
                text: None,
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&manifest).unwrap(),
            )
            .unwrap();

            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded.is_empty(),
                "a complete staged record stranded: {stranded:?}"
            );
            let task = store.pending_updates().pop().unwrap();
            assert_eq!(task.reply_key.as_deref(), Some("reply:7"));
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("staged reply body")
            );
            assert_eq!(
                store.binding(9).unwrap().session_id.as_deref(),
                Some("staged-session"),
                "the staged session change did not commit"
            );
            assert!(
                !dir.join("reply-7.json").exists(),
                "the applied manifest was left staged"
            );
        });
    }

    #[test]
    fn an_unreadable_staged_manifest_is_retained_and_reported() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 9,
                        sequence: 0,
                        message: inbound_message(9, 9),
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
            // A manifest whose bytes cannot be parsed cannot be
            // recovered — it must surface with a stable code and stay
            // on disk for inspection rather than being swept.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("reply-9.txt"), "staged body").unwrap();
            std::fs::write(dir.join("reply-9.json"), "{ not json").unwrap();

            let stranded = store.reconcile_staged().unwrap();
            assert_eq!(stranded.len(), 1);
            assert_eq!(stranded[0].update_id, 9);
            assert_eq!(stranded[0].code, "a4mc_telegram_staged_invalid");
            assert!(
                dir.join("reply-9.json").exists(),
                "an unreconciled manifest must not be discarded"
            );
            assert!(
                dir.join("reply-9.txt").exists(),
                "an unreconciled payload must not be discarded"
            );
        });
    }

    #[test]
    fn an_orphaned_staged_completion_is_swept_on_the_next_commit() {
        temp_store(|mut store| {
            // A manifest whose task settled already carries nothing
            // recoverable: it is never bound onto another record and
            // the sweep reclaims it with the next committed write.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("reply-9.txt"), "orphan body").unwrap();
            let manifest = StagedCompletion {
                update_id: 9,
                sequence: 0,
                payload: "reply-9.txt".to_owned(),
                key: "reply:9".to_owned(),
                effect: StagedEffect::Reply,
                text: None,
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-9.json"),
                serde_json::to_string(&manifest).unwrap(),
            )
            .unwrap();

            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded.is_empty(),
                "a settled task's manifest was reported stranded: {stranded:?}"
            );
            assert!(
                !dir.join("reply-9.json").exists() && !dir.join("reply-9.txt").exists(),
                "the orphan manifest and payload survived the sweep"
            );
            assert!(store.pending_updates().is_empty());
        });
    }

    #[test]
    fn distinct_state_files_get_distinct_replies_directories() {
        // `bot.json` and `bot.state` must not share a sidecar
        // directory: equal update ids would overwrite each other's
        // payloads and each store's sweep could collect the other's
        // referenced files.
        assert_ne!(
            replies_dir(Path::new("/d/bot.json")),
            replies_dir(Path::new("/d/bot.state")),
        );
        assert_eq!(
            replies_dir(Path::new("/d/bot.json")),
            Path::new("/d/bot.json.replies")
        );
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 5,
                        sequence: 0,
                        message: inbound_message(5, 9),
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
                    6,
                )
                .unwrap();
            let reply = "r".repeat(MAX_STATE_BYTES);
            store.record_reply(5, &reply, "reply:5").unwrap();
            // A foreign file inside the store's own directory and an
            // unreferenced store-owned file: only the latter is swept.
            let dir = replies_dir(&store.path);
            std::fs::write(dir.join("notes.txt"), "foreign").unwrap();
            std::fs::write(dir.join("reply-999.txt"), "stale").unwrap();
            store.complete_update(5).unwrap();
            assert!(
                dir.join("notes.txt").exists(),
                "the sweep collected a file it does not own"
            );
            assert!(
                !dir.join("reply-999.txt").exists(),
                "an unreferenced store-owned reply was left behind"
            );
        });
    }

    #[test]
    fn admission_reserves_lifecycle_space_for_a_recorded_reply() {
        temp_store(|mut store| {
            // An admission that lands within the lifecycle reserve is
            // refused even though the record itself would still fit
            // the document — the room is held for the reply pointer,
            // key, session and checkpoints the completed turn needs.
            let mut message = inbound_message(3, 9);
            message.text = Some("x".repeat(MAX_STATE_BYTES - LIFECYCLE_RESERVE_BYTES - 2_000));
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message,
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
                    4,
                )
                .unwrap();
            let mut crowded = inbound_message(4, 9);
            crowded.text = Some("y".repeat(8_000));
            let error = store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 4,
                        sequence: 0,
                        message: crowded,
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
                    5,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "a4mc_telegram_state_full");
            // The lifecycle write itself is not reserve-gated: the
            // admitted task's reply still commits into the held room.
            store.record_reply(3, "done", "reply:3").unwrap();
            let task = store.pending_updates().pop().unwrap();
            assert_eq!(store.reply_text(&task).unwrap().as_deref(), Some("done"));
        });
    }

    #[test]
    fn an_oversized_reply_is_refused_at_the_record_boundary() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message: inbound_message(3, 9),
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
                    4,
                )
                .unwrap();
            // Above the payload ceiling the reply is refused with its
            // own code — the store boundary, not a silent drop.
            let oversized = "r".repeat(MAX_REPLY_BYTES + 1);
            let error = store.record_reply(3, &oversized, "reply:3").unwrap_err();
            assert_eq!(error.to_string(), "a4mc_telegram_reply_too_large");
            assert!(!store.pending_updates()[0].has_reply());
            assert!(
                !replies_dir(&store.path).join("reply-3.txt").exists(),
                "a refused reply left a staged payload"
            );
        });
    }

    #[test]
    fn the_revocation_and_its_reply_commit_as_one_write() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 8,
                        sequence: 0,
                        message: inbound_message(8, 9),
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
                    9,
                )
                .unwrap();
            // A failed commit must leave neither half applied: no
            // revocation without its reply, no reply without the
            // revocation.
            store.fail_next_write_for_test();
            store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    if removed {
                        "Pairing revoked for this chat.".to_owned()
                    } else {
                        "This chat was not paired.".to_owned()
                    }
                })
                .unwrap_err();
            assert!(
                store.binding(9).is_some(),
                "the revocation committed without its reply"
            );
            assert!(!store.pending_updates()[0].has_reply());
            let reply = store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    if removed {
                        "Pairing revoked for this chat.".to_owned()
                    } else {
                        "This chat was not paired.".to_owned()
                    }
                })
                .unwrap();
            assert_eq!(reply, "Pairing revoked for this chat.");
            assert!(store.binding(9).is_none(), "the chat stayed paired");
            let task = &store.pending_updates()[0];
            assert_eq!(task.reply_key.as_deref(), Some("reply:8"));
            assert_eq!(
                store.reply_text(task).unwrap().as_deref(),
                Some("Pairing revoked for this chat.")
            );
        });
    }

    #[test]
    fn a_self_contained_staged_record_binds_on_recovery() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The record the runtime now stages: payload, delivery key
            // and effect in one file — a crash leaves the whole record
            // or nothing, never a payload whose record never landed.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplySession {
                    chat_id: 9,
                    session_id: Some("staged-session".to_owned()),
                    user_id: Some(42),
                    agent_id: None,
                    prior_session: None,
                    binding_revision: None,
                },
                text: Some("self-contained reply".to_owned()),
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();

            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded.is_empty(),
                "a self-contained record stranded: {stranded:?}"
            );
            let task = store.pending_updates().pop().unwrap();
            assert_eq!(task.reply_file.as_deref(), Some("reply-7.json"));
            assert_eq!(task.reply_key.as_deref(), Some("reply:7"));
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("self-contained reply")
            );
            assert_eq!(
                store.binding(9).unwrap().session_id.as_deref(),
                Some("staged-session")
            );
        });
    }

    #[test]
    fn a_payload_file_without_its_record_is_never_bound() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The crash window: the payload landed but the record that
            // would make it a reply never did. A bare payload names no
            // key and no effect — it is never bound and the next
            // committed write sweeps it.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("reply-7.txt"), "unrecorded payload").unwrap();

            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded.is_empty(),
                "a bare payload produced a binding or a report: {stranded:?}"
            );
            let task = store.pending_update(7).unwrap();
            assert!(!task.has_reply(), "a bare payload bound a reply: {task:?}");
            store.set_poll_offset(9).unwrap();
            assert!(
                !dir.join("reply-7.txt").exists(),
                "an unrecorded payload survived the sweep"
            );
        });
    }

    #[test]
    fn a_staged_effect_never_overtakes_a_newer_binding() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 42, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // A session staged while "codex" held the binding.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplySession {
                    chat_id: 9,
                    session_id: Some("staged-session".to_owned()),
                    user_id: Some(42),
                    agent_id: Some("codex".to_owned()),
                    prior_session: None,
                    binding_revision: None,
                },
                text: Some("reply body".to_owned()),
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            // A newer write moved the binding forward before the staged
            // record reached the document. Reconciliation runs BEFORE
            // that change lands, so the staged session applies to its
            // own binding and the newer agent switch still clears it —
            // the stale session can never attach to the new agent.
            store.set_agent(9, Some("claude".into())).unwrap();
            let binding = store.binding(9).unwrap();
            assert_eq!(binding.agent_id.as_deref(), Some("claude"));
            assert_eq!(
                binding.session_id, None,
                "the staged session attached to the newer binding"
            );
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                task.reply_key.as_deref(),
                Some("reply:7"),
                "the finished reply did not survive its staged effect"
            );
        });
    }

    #[test]
    fn a_confirmed_event_settles_consumed_or_dropped() {
        temp_store(|mut store| {
            // The cursor confirms an event with its pending record in
            // one write.
            store
                .admit_updates(
                    &[],
                    &[],
                    &[DroppedUpdate {
                        update_id: 5,
                        sequence: 0,
                        raw_kind: "edited_message".to_owned(),
                    }],
                    6,
                )
                .unwrap();
            // A restart settles an unconsumed event into its durable
            // dropped record — the confirmed update is never lost.
            let mut reopened = BindingStore::open(store.path.clone()).unwrap();
            reopened.settle_unconsumed_events().unwrap();
            let dropped = reopened.dropped_updates();
            assert_eq!(dropped.len(), 1);
            assert_eq!(dropped[0].update_id, 5);
            assert_eq!(dropped[0].raw_kind, "edited_message");

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
            store.settle_event(6).unwrap();
            assert!(
                !store
                    .dropped_updates()
                    .iter()
                    .any(|item| item.update_id == 6),
                "a consumed event was recorded dropped"
            );

            // A rejected event rolls the cursor back before it for
            // redelivery: its marker stays pending — never recorded
            // dropped — and a restart settles only markers the cursor
            // has moved past.
            store
                .admit_updates(
                    &[],
                    &[],
                    &[DroppedUpdate {
                        update_id: 7,
                        sequence: 0,
                        raw_kind: "reaction".to_owned(),
                    }],
                    8,
                )
                .unwrap();
            store.set_poll_offset(7).unwrap();
            let mut reopened = BindingStore::open(store.path.clone()).unwrap();
            reopened.settle_unconsumed_events().unwrap();
            assert!(
                !reopened
                    .dropped_updates()
                    .iter()
                    .any(|item| item.update_id == 7),
                "a redeliverable event was recorded dropped on restart"
            );
            reopened.settle_event(7).unwrap();
            assert!(
                !reopened
                    .dropped_updates()
                    .iter()
                    .any(|item| item.update_id == 7),
                "a consumed event was recorded dropped"
            );
        });
    }

    #[test]
    fn a_checkpoint_and_its_deadline_commit_as_one_write() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
                        reply: Some("held reply".to_owned()),
                        reply_key: Some("reply:7".to_owned()),
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
            let progress = crate::transport::SendProgress {
                confirmed: vec![91],
                next_part: 1,
                outcome_unknown: true,
                binding: None,
            };
            store
                .record_reply_checkpoint(7, Some(progress), Some(1_700_000_000))
                .unwrap();
            let task = BindingStore::open(store.path.clone())
                .unwrap()
                .pending_update(7)
                .unwrap();
            let progress = task.reply_progress.expect("checkpoint lost");
            assert!(progress.outcome_unknown);
            assert_eq!(progress.confirmed, vec![91]);
            assert_eq!(
                task.reply_retry_at_ms,
                Some(1_700_000_000),
                "the retry deadline did not commit with its checkpoint"
            );
        });
    }

    #[test]
    fn a_turn_reply_never_overwrites_a_binding_that_moved_on() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store.set_session(9, Some("s-old".into())).unwrap();
            // The binding the turn ran under.
            let expected = store.binding(9).cloned().unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The host rebinds mid-turn: the agent switch clears the
            // session, so the in-flight turn's session effect is stale.
            store.set_agent(9, Some("claude".into())).unwrap();
            let reply = store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("turn-session".into()),
                    &expected,
                    |applied| {
                        if applied {
                            "session moved".to_owned()
                        } else {
                            "turn reply".to_owned()
                        }
                    },
                )
                .unwrap();
            assert_eq!(reply, "turn reply", "the stale effect still applied");
            let binding = store.binding(9).cloned().unwrap();
            assert_eq!(binding.agent_id.as_deref(), Some("claude"));
            assert_eq!(
                binding.session_id, None,
                "a stale turn's session overwrote the newer binding"
            );
            // The finished reply is retained regardless: its record
            // never depends on the routing effect applying.
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("turn reply")
            );
            assert_eq!(task.reply_key.as_deref(), Some("reply:7"));
        });
    }

    #[test]
    fn an_uncommittable_staged_record_is_reported_while_mutations_proceed() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            let expected = store.binding(9).cloned().unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // A session id that fits the staged record but can never
            // fit the bounded document: the record is retained while
            // its document contribution is refused.
            let error = store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("x".repeat(MAX_STATE_BYTES)),
                    &expected,
                    |_| "reply body".to_owned(),
                )
                .unwrap_err();
            assert_eq!(error.to_string(), "a4mc_telegram_state_full");
            // Unrelated mutations are not blocked by the record every
            // replay would otherwise force into the document.
            store.set_poll_offset(9).unwrap();
            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded
                    .iter()
                    .any(|item| item.update_id == 7 && item.code == "a4mc_telegram_state_full"),
                "the uncommittable completion was not reported: {stranded:?}"
            );
            // Retained: the record stays on disk for its task and the
            // binding is untouched by the oversized session.
            assert!(store.staged_reply_pending(7));
            assert!(store.pending_update(7).is_some());
            assert_eq!(store.binding(9).unwrap().session_id, None);
        });
    }

    #[test]
    fn a_pending_payload_in_the_legacy_replies_dir_is_found() {
        temp_store(|mut store| {
            // A record written by the preceding revision: the pointer
            // names a payload spilled under `<stem>.replies`, not the
            // current full-filename directory.
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: Some("reply:7".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: Some("reply-7.txt".to_owned()),
                        reply_retry_at_ms: None,
                        reply_refused: false,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            let legacy = store.path.with_extension("replies");
            std::fs::create_dir_all(&legacy).unwrap();
            std::fs::write(legacy.join("reply-7.txt"), "legacy payload").unwrap();

            let mut reopened = BindingStore::open(store.path.clone()).unwrap();
            let task = reopened.pending_update(7).unwrap();
            assert_eq!(
                reopened.reply_text(&task).unwrap().as_deref(),
                Some("legacy payload"),
                "a pending payload in the legacy directory was lost"
            );
            // A commit must never sweep inside the shared legacy
            // directory — a sibling state file's payloads may live
            // there too.
            let mut store = reopened;
            store.set_poll_offset(9).unwrap();
            assert!(
                legacy.join("reply-7.txt").exists(),
                "the legacy payload was swept by the new store"
            );
        });
    }

    #[test]
    fn a_stale_revision_cannot_reinstall_a_session_after_a_round_trip() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store.set_session(9, Some("s-old".into())).unwrap();
            // The binding the turn ran under — captured before the host
            // moved routing away and back.
            let expected = store.binding(9).cloned().unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // A→B→A: user, agent and session values end up identical
            // to the snapshot the turn ran under, so only the revision
            // still tells the binding moved.
            store.set_agent(9, Some("claude".into())).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            store.set_session(9, Some("s-old".into())).unwrap();
            let binding = store.binding(9).unwrap();
            assert_eq!(binding.agent_id.as_deref(), Some("codex"));
            assert_eq!(binding.session_id.as_deref(), Some("s-old"));

            let reply = store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("turn-session".into()),
                    &expected,
                    |applied| {
                        if applied {
                            "Bound session: turn-session".to_owned()
                        } else {
                            "The binding moved — the session was not applied.".to_owned()
                        }
                    },
                )
                .unwrap();
            assert_eq!(
                reply, "The binding moved — the session was not applied.",
                "the stale turn's session was confirmed as applied"
            );
            assert_eq!(
                store.binding(9).unwrap().session_id.as_deref(),
                Some("s-old"),
                "the stale turn's session overwrote the newer binding"
            );
            // The finished reply is retained regardless: its record
            // never depends on the routing effect applying.
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("The binding moved — the session was not applied.")
            );
        });
    }

    #[test]
    fn a_staged_record_that_overflows_the_document_is_retained_until_it_fits() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            // One task fills most of the bounded document; a second
            // small task carries the staged completion whose session
            // effect cannot land beside the first — though it fits
            // the bound alone once room frees.
            let mut big = inbound_message(7, 9);
            big.text = Some("x".repeat(MAX_STATE_BYTES - 20_000));
            store
                .admit_updates(
                    &[
                        PendingUpdate {
                            update_id: 7,
                            sequence: 0,
                            message: big,
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                            reply_refused: false,
                        },
                        PendingUpdate {
                            update_id: 8,
                            sequence: 0,
                            message: inbound_message(8, 9),
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
                    9,
                )
                .unwrap();
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 8,
                sequence: 0,
                payload: "reply-8.json".to_owned(),
                key: "reply:8".to_owned(),
                effect: StagedEffect::ReplySession {
                    chat_id: 9,
                    session_id: Some("y".repeat(30_000)),
                    user_id: None,
                    agent_id: None,
                    prior_session: None,
                    binding_revision: None,
                },
                text: Some("staged reply".to_owned()),
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-8.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();

            // The record does not fit beside the admitted work: every
            // unrelated mutation still commits — the record is
            // retained and reported instead of blocking the store.
            store.set_poll_offset(9).unwrap();
            let stranded = store.reconcile_staged().unwrap();
            assert!(
                stranded
                    .iter()
                    .any(|item| item.update_id == 8 && item.code == "a4mc_telegram_state_full"),
                "the overflowing record was not reported: {stranded:?}"
            );
            assert!(store.pending_update(8).unwrap().reply_file.is_none());
            assert_eq!(store.binding(9).unwrap().session_id, None);

            // Once the document frees, the next mutation binds the
            // same record — finished work is never discarded.
            store.complete_update(7).unwrap();
            store.set_poll_offset(10).unwrap();
            let task = store.pending_update(8).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("staged reply")
            );
            assert_eq!(
                store.binding(9).unwrap().session_id.as_deref(),
                Some("y".repeat(30_000).as_str()),
                "the staged session did not commit once it fit"
            );
        });
    }

    #[test]
    fn a_restarted_sequence_claims_a_reused_update_id_for_fresh_work() {
        temp_store(|mut store| {
            // A dead sequence's retained task claims its id only under
            // its own sequence: after expiry the same update id admits
            // fresh work instead of being skipped as already claimed.
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
                        reply: Some("old reply".to_owned()),
                        reply_key: Some("reply:7".to_owned()),
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
            store.expire_sequence().unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            let tasks = store.pending_updates();
            assert_eq!(tasks.len(), 2, "the reused id dropped fresh work");
            assert_eq!(tasks[0].key(), TaskKey::new(0, 7));
            assert_eq!(tasks[1].key(), TaskKey::new(1, 7));
            assert!(
                !tasks[1].has_reply(),
                "the fresh task inherited the dead record's reply"
            );
            // Each record settles on its own key: the fresh task can
            // complete while the dead record's reply stays owed.
            store.complete_update(TaskKey::new(1, 7)).unwrap();
            let tasks = store.pending_updates();
            assert_eq!(tasks.len(), 1);
            assert_eq!(tasks[0].key(), TaskKey::new(0, 7));
        });
    }

    #[test]
    fn a_recovered_record_binds_the_variant_its_effect_committed() {
        temp_store(|mut store| {
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store.set_agent(9, Some("codex".into())).unwrap();
            let expected = store.binding(9).cloned().unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The binding moves before recovery — while the durable
            // record only exists as its manifest — so the guarded
            // session write is stale by the time any mutation can
            // pick the record up.
            store.set_agent(9, Some("claude".into())).unwrap();
            // The crash window the finding names: a staged record that
            // carries both outcome variants survived on disk while the
            // document write that would have committed the session and
            // the reply pointer never landed.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplySession {
                    chat_id: 9,
                    session_id: Some("s2".into()),
                    user_id: Some(expected.user_id),
                    agent_id: expected.agent_id.clone(),
                    prior_session: Some(expected.session_id.clone()),
                    binding_revision: Some(expected.revision),
                },
                text: Some("Bound session: s2".to_owned()),
                refused_text: Some("The chat moved on — the session was not applied.".to_owned()),
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            assert!(store.staged_reply_pending(7));
            store.reconcile_staged().unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(task.reply_refused);
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("The chat moved on — the session was not applied."),
                "recovery delivered the success text of a refused effect"
            );
            let binding = store.binding(9).unwrap();
            assert_eq!(binding.agent_id.as_deref(), Some("claude"));
            assert_eq!(binding.session_id, None);
        });
    }

    #[test]
    fn an_expired_sequence_moves_pending_events_into_dropped_history() {
        temp_store(|mut store| {
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
            assert_eq!(store.poll_sequence(), 0);
            store.expire_sequence().unwrap();
            assert_eq!(store.poll_sequence(), 1);
            // The dead sequence's marker can neither be refetched for a
            // callback nor settled by one — it must survive as its
            // dropped record under the sequence it was claimed in, not
            // be erased with the claims it hung on.
            let dropped = store.dropped_updates();
            assert!(
                dropped.iter().any(|item| item.update_id == 6
                    && item.sequence == 0
                    && item.raw_kind == "reaction"),
                "the dead sequence's marker was erased instead of dropped: {dropped:?}"
            );
        });
    }

    #[test]
    fn an_expired_pairing_offer_binds_its_refused_variant() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The offer's TTL elapsed during downtime while only the
            // durable record existed: replaying its effect must never
            // re-publish the dead code.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplyPairing {
                    record: PairingRecord {
                        code: "ABCD-EFGH".to_owned(),
                        chat_id: 9,
                        user_id: 9,
                        username: Some("alice".to_owned()),
                        created_at: 1,
                        expires_at: 2,
                        minted_revision: 0,
                    },
                },
                text: Some("Pairing code: ABCD-EFGH".to_owned()),
                refused_text: Some(
                    "That pairing offer did not hold — send /start to request a fresh code."
                        .to_owned(),
                ),
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            store.reconcile_staged().unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(task.reply_refused);
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("That pairing offer did not hold — send /start to request a fresh code."),
                "recovery delivered a pairing code whose TTL elapsed"
            );
            assert!(
                store.pending_pairings().is_empty(),
                "an expired offer was re-published: {:?}",
                store.pending_pairings()
            );
        });
    }

    #[test]
    fn a_superseded_pairing_offer_binds_its_refused_variant() {
        temp_store(|mut store| {
            // The user fully paired while only the durable record of a
            // code offer existed: replaying the offer must never
            // re-publish it over the live pairing.
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplyPairing {
                    record: PairingRecord {
                        code: "WXYZ-1234".to_owned(),
                        chat_id: 9,
                        user_id: 9,
                        username: Some("alice".to_owned()),
                        created_at: now_secs(),
                        expires_at: now_secs() + PAIRING_TTL.as_secs(),
                        minted_revision: 0,
                    },
                },
                text: Some("Pairing code: WXYZ-1234".to_owned()),
                refused_text: Some(
                    "That pairing offer did not hold — send /start to request a fresh code."
                        .to_owned(),
                ),
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            store.reconcile_staged().unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(task.reply_refused);
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("That pairing offer did not hold — send /start to request a fresh code."),
                "recovery re-published an offer a full pairing superseded"
            );
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .all(|record| record.code != "WXYZ-1234"),
                "a superseded offer was re-published: {:?}",
                store.pending_pairings()
            );
            assert!(store.binding(9).unwrap().paired);
        });
    }

    #[test]
    fn a_replaced_pairing_offer_resolves_its_refused_variant_at_send_time() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            // The offer and the reply carrying its code commit bound:
            // revalidation at send time must leave a still-current
            // offer's text untouched.
            let refused = "That pairing offer did not hold — send /start to request a fresh code.";
            let reply = store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    refused,
                )
                .unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(!task.reply_refused);
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(reply.as_str()),
                "a current offer's recorded text resolved refused"
            );
            // A newer request replaces the exact offer while the reply
            // waits to send: the recorded code is dead, so the send
            // resolves the refused variant instead of publishing it.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(refused),
                "a replaced offer's send resolved its recorded code"
            );
            // An approval landing while the reply waits lapses the
            // offer the same way.
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(refused),
                "an approved user's send resolved its recorded code"
            );
        });
    }

    #[test]
    fn a_bound_record_is_not_an_unbound_staged_reply() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            assert!(
                !store.staged_reply_unbound(7),
                "nothing staged is not an unbound completion"
            );
            // A self-contained record still waiting for its document
            // pointer is the only shape the nonfatal exception covers.
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::Reply,
                text: Some("staged reply".to_owned()),
                refused_text: None,
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            assert!(
                store.staged_reply_unbound(7),
                "a record whose pointer never committed is unbound"
            );
            // Once bound the manifest file remains as the task's own
            // payload: it is still a staged record on disk, but a
            // capacity refusal on a LATER write — a checkpoint or retry
            // deadline — is not the stranded-completion case and must
            // not be classified as one.
            store.reconcile_staged().unwrap();
            assert!(
                store.staged_reply_pending(7),
                "the bound payload record no longer reads as staged"
            );
            assert!(
                !store.staged_reply_unbound(7),
                "a bound record classified as unbound masks checkpoint failures"
            );
        });
    }

    /// A pending task whose record fills most of the bounded document —
    /// the remaining slack is smaller than a reply pointer.
    fn admit_filler(store: &mut BindingStore, update_id: i64) {
        store
            .admit_updates(
                &[PendingUpdate {
                    update_id,
                    sequence: 0,
                    message: inbound_message(update_id, 9),
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
                update_id + 1,
            )
            .unwrap();
    }

    /// A self-contained staged record for the task, written straight to
    /// the sidecar directory the way a mutation that died between the
    /// record rename and the document commit leaves it.
    fn stage_manifest(dir: &Path, key: TaskKey, text: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let record = StagedCompletion {
            update_id: key.update_id,
            sequence: key.sequence,
            payload: manifest_file_name(key),
            key: format!("reply:{}", key.update_id),
            effect: StagedEffect::Reply,
            text: Some(text.to_owned()),
            refused_text: None,
        };
        std::fs::write(
            dir.join(manifest_file_name(key)),
            serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    }

    /// Park the document inside `headroom` bytes of the read bound: an
    /// approved chat's agent field takes arbitrary text, so one
    /// measured padding write lands the slack exactly — no staged
    /// pointer smaller than `headroom` can bind until space frees.
    fn fill_document(store: &mut BindingStore, chat_id: i64, headroom: usize) {
        let pending = store
            .request_pairing(chat_id, chat_id, Some("filler".into()))
            .unwrap();
        store.approve(&pending.code).unwrap();
        for _ in 0..4 {
            let remaining = MAX_STATE_BYTES - serialized_len(&store.document).unwrap();
            if remaining <= headroom {
                return;
            }
            let agent = store
                .binding(chat_id)
                .and_then(|binding| binding.agent_id.as_deref())
                .map_or(0, str::len);
            store
                .set_agent(chat_id, Some("a".repeat(agent + remaining - headroom)))
                .unwrap();
        }
        panic!("document did not fill to the brim");
    }

    #[test]
    fn a_settling_mutation_binds_the_reply_its_space_frees() {
        temp_store(|mut store| {
            admit_filler(&mut store, 1);
            admit_filler(&mut store, 2);
            // Every reply field serializes `default`-style, so a bound
            // record adds only the null→value delta — a couple dozen
            // bytes. Four bytes of slack guarantees the manifest stays
            // durable but unapplied.
            fill_document(&mut store, 6, 4);
            let dir = replies_dir(&store.path);
            stage_manifest(&dir, TaskKey::from(2), "staged reply body");
            assert!(
                store.staged_reply_unbound(2),
                "the record bound before any space was freed"
            );
            // Settling the last task frees its record — the same write
            // must reconcile the stranded reply instead of parking it
            // for an unrelated later mutation.
            store.complete_update(1).unwrap();
            let bound = store.take_bound_replies();
            assert!(
                store.pending_update(2).unwrap().has_reply(),
                "the freed space never reconciled the staged reply"
            );
            assert_eq!(
                bound.iter().map(PendingUpdate::key).collect::<Vec<_>>(),
                vec![TaskKey::from(2)],
                "the newly bound reply was not queued for resend"
            );
        });
    }

    #[test]
    fn a_bind_committed_by_another_store_is_discovered_and_queued_once() {
        let root = std::env::temp_dir().join(format!(
            "a4mc-tg-bind-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let mut first = BindingStore::open_in(&root).unwrap();
        admit_filler(&mut first, 2);
        let dir = replies_dir(&first.path);
        stage_manifest(&dir, TaskKey::from(2), "staged reply body");
        // A second instance on the same file binds the record through
        // an unrelated mutation — the notification lives only in that
        // instance's memory.
        let mut second = BindingStore::open_in(&root).unwrap();
        second.set_poll_offset(4).unwrap();
        assert_eq!(
            second
                .take_bound_replies()
                .iter()
                .map(PendingUpdate::key)
                .collect::<Vec<_>>(),
            vec![TaskKey::from(2)],
            "the binding instance did not report its own bind"
        );
        // The first instance's next mutation must discover the durable
        // transition instead of skipping the already-bound task.
        first.set_poll_offset(5).unwrap();
        assert!(
            first.pending_update(2).unwrap().has_reply(),
            "the discovered document still lacks the bound reply"
        );
        assert_eq!(
            first
                .take_bound_replies()
                .iter()
                .map(PendingUpdate::key)
                .collect::<Vec<_>>(),
            vec![TaskKey::from(2)],
            "the externally bound reply was never discovered"
        );
        assert!(
            first.take_bound_replies().is_empty(),
            "the same bind was queued twice"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_refused_admission_still_commits_the_bind_it_reconciled() {
        temp_store(|mut store| {
            admit_filler(&mut store, 2);
            // Room for the reply pointer but not for another task on
            // top of it.
            fill_document(&mut store, 6, 400);
            let dir = replies_dir(&store.path);
            stage_manifest(&dir, TaskKey::from(2), "staged reply body");
            let mut big = inbound_message(3, 9);
            big.text = Some("b".repeat(8 * 1024));
            let error = store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 3,
                        sequence: 0,
                        message: big,
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
                    4,
                )
                .unwrap_err();
            assert_eq!(
                error.to_string().as_str(),
                "a4mc_telegram_state_full",
                "the oversized batch committed instead of being refused"
            );
            // The refused write still landed the staged bind its
            // reconcile pass earned — the recovered reply is queued so
            // its delivery can free the space the batch needs.
            assert!(
                store.pending_update(2).unwrap().has_reply(),
                "the refused admission dropped the bind it reconciled"
            );
            assert_eq!(
                store
                    .take_bound_replies()
                    .iter()
                    .map(PendingUpdate::key)
                    .collect::<Vec<_>>(),
                vec![TaskKey::from(2)],
                "the bind a refused admission committed was not drained"
            );
        });
    }

    #[test]
    fn a_lapsed_offer_keeps_its_text_behind_confirmed_or_uncertain_progress() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            let refused = "That pairing offer did not hold — send /start to request a fresh code.";
            let reply = store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    refused,
                )
                .unwrap();
            // A newer request lapses the exact offer the reply carries.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            let progress = |confirmed: Vec<i64>, unknown: bool| {
                let next_part = confirmed.len();
                Some(crate::transport::SendProgress {
                    confirmed,
                    next_part,
                    outcome_unknown: unknown,
                    binding: None,
                })
            };
            // Confirmed transport progress: the platform already holds
            // part of the original text — the resend continues it, it
            // does not substitute a different message.
            store
                .record_reply_checkpoint(7, progress(vec![11], false), None)
                .unwrap();
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(reply.as_str()),
                "a confirmed send had its recorded text substituted"
            );
            // An uncertain stopping outcome likewise keeps the text
            // the platform may already have posted.
            store
                .record_reply_checkpoint(7, progress(vec![], true), None)
                .unwrap();
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(reply.as_str()),
                "an uncertain send had its recorded text substituted"
            );
            // A confirmed contract part is the same rule at the
            // coarser checkpoint.
            store.record_reply_progress(7, 1, None).unwrap();
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(reply.as_str()),
                "a partly-delivered reply had its recorded text substituted"
            );
        });
    }

    #[test]
    fn a_lapsed_offer_substitutes_only_at_zero_progress() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            let refused = "That pairing offer did not hold — send /start to request a fresh code.";
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    refused,
                )
                .unwrap();
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            // A definitive rejection left a checkpoint with nothing
            // confirmed: substitution stays safe — nothing was posted.
            store
                .record_reply_checkpoint(
                    7,
                    Some(crate::transport::SendProgress {
                        confirmed: vec![],
                        next_part: 0,
                        outcome_unknown: false,
                        binding: None,
                    }),
                    None,
                )
                .unwrap();
            let task = store.pending_update(7).unwrap();
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(refused),
                "a zero-progress send kept its lapsed offer's dead code"
            );
        });
    }

    #[test]
    fn a_lapsed_offer_marks_its_refusal_before_the_first_send() {
        temp_store(|mut store| {
            store
                .admit_updates(
                    &[PendingUpdate {
                        update_id: 7,
                        sequence: 0,
                        message: inbound_message(7, 9),
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
            let refused = "That pairing offer did not hold — send /start to request a fresh code.";
            store
                .record_pairing_and_reply(
                    9,
                    9,
                    Some("alice".into()),
                    7,
                    "reply:7",
                    |record| format!("Pairing code: {}", record.code),
                    refused,
                )
                .unwrap();
            // A newer request lapses the exact offer the reply carries.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(!task.reply_refused);
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(refused),
                "the lapsed offer's send did not resolve its refusal"
            );
            // The selection is durable on the task before the first
            // send: a checkpoint the refusal earns — even confirmed
            // progress — resolves the same payload on the next read,
            // never the lapsed offer's dead code.
            store
                .record_reply_progress(
                    7,
                    0,
                    Some(crate::transport::SendProgress {
                        confirmed: vec![11],
                        next_part: 1,
                        outcome_unknown: false,
                        binding: None,
                    }),
                )
                .unwrap();
            let task = store.pending_update(7).unwrap();
            assert!(task.reply_refused, "the lapsed selection never committed");
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(refused),
                "a checkpointed refusal resolved the lapsed offer's code"
            );
        });
    }

    #[test]
    fn a_revoked_chat_keeps_its_older_offer_refused_after_the_space_frees() {
        temp_store(|mut store| {
            // Minted exactly as a staged reply commit mints it — while
            // the chat was still unpaired.
            let minted_revision = store
                .request_pairing(5, 5, Some("earlier".into()))
                .unwrap()
                .minted_revision;
            // The user then pairs fully: the approved binding is the
            // guard that refuses the staged offer — and the record
            // that pins the document full.
            let pending = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.approve(&pending.code).unwrap();
            admit_filler(&mut store, 7);
            fill_document(&mut store, 6, 4);
            let dir = replies_dir(&store.path);
            std::fs::create_dir_all(&dir).unwrap();
            let record = StagedCompletion {
                update_id: 7,
                sequence: 0,
                payload: "reply-7.json".to_owned(),
                key: "reply:7".to_owned(),
                effect: StagedEffect::ReplyPairing {
                    record: PairingRecord {
                        code: "WXYZ-1234".to_owned(),
                        chat_id: 9,
                        user_id: 9,
                        username: Some("alice".to_owned()),
                        created_at: now_secs(),
                        expires_at: now_secs() + PAIRING_TTL.as_secs(),
                        minted_revision,
                    },
                },
                text: Some("Pairing code: WXYZ-1234".to_owned()),
                refused_text: Some(
                    "That pairing offer did not hold — send /start to request a fresh code."
                        .to_owned(),
                ),
            };
            std::fs::write(
                dir.join("reply-7.json"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
            assert!(store.staged_reply_unbound(7));
            // The revocation frees the binding whose guard refused the
            // offer — its tombstone keeps the older offer refused: the
            // reply binds its refusal text and the dead code is never
            // re-published through the freed space.
            assert!(store.revoke(9).unwrap());
            let task = store.pending_update(7).unwrap();
            assert!(
                task.reply_refused,
                "a revoked chat's older offer bound its live variant"
            );
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("That pairing offer did not hold — send /start to request a fresh code."),
                "a revoked chat's older offer resolved its code"
            );
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .all(|held| held.code != "WXYZ-1234"),
                "a revoked chat's older offer was re-published: {:?}",
                store.pending_pairings()
            );
            // An offer minted after the revocation binds normally —
            // free the padding chat first so the fresh record has room.
            assert!(store.revoke(6).unwrap());
            let fresh = store.request_pairing(9, 9, Some("alice".into())).unwrap();
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .any(|held| held.code == fresh.code),
                "a post-revocation offer was refused with the old ones"
            );
        });
    }

    #[test]
    fn a_lapsed_resolve_returns_the_variant_the_committed_state_holds() {
        temp_store(|mut store| {
            let path = store.path.clone();
            admit_filler(&mut store, 7);
            let applied = store
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
            // The exact offer the reply carries lapses on this same
            // store, then the snapshot is read — still showing no send
            // progress.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            let task = store.pending_update(7).unwrap();
            // Another store instance commits the reply's first
            // confirmed chunk between the snapshot read and the
            // resolve's locked write: the refusal selection can no
            // longer commit under it.
            let mut other = BindingStore::open(path).unwrap();
            other
                .record_reply_checkpoint(
                    7,
                    Some(crate::transport::SendProgress {
                        confirmed: vec![11],
                        next_part: 1,
                        outcome_unknown: false,
                        binding: None,
                    }),
                    None,
                )
                .unwrap();
            // The resolver answers with the payload that checkpoint
            // was earned on — not the stale snapshot's refusal.
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some(applied.as_str()),
                "a checkpointed send was repointed at the refusal"
            );
            let held = BindingStore::open(store.path.clone())
                .unwrap()
                .pending_update(7)
                .unwrap();
            assert!(
                !held.reply_refused,
                "the committed state selected the refusal under live progress"
            );
        });
    }

    #[test]
    fn a_revocation_tombstone_is_reclaimed_once_no_guarded_offer_remains() {
        temp_store(|mut store| {
            // No staged offer exists for the chat: the tombstone the
            // revocation writes is reclaimed inside the same write
            // instead of spending document space forever.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            assert!(store.revoke(9).unwrap());
            assert!(
                store.document.revoked_chats.is_empty(),
                "an unguarded tombstone was retained: {:?}",
                store.document.revoked_chats
            );

            // A staged offer minted before the revocation keeps its
            // tombstone while the record can still be replayed.
            admit_filler(&mut store, 7);
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
            assert!(store.revoke(9).unwrap());
            assert!(
                store.document.revoked_chats.contains_key("9"),
                "the guarded offer's tombstone was reclaimed early"
            );
            // The task settles and its record is swept: the next
            // mutation finds nothing left to guard and reclaims the
            // tombstone — the freed admission space actually frees.
            store.complete_update(7).unwrap();
            store.prune_expired().unwrap();
            assert!(
                store.document.revoked_chats.is_empty(),
                "the settled offer's tombstone outlived its record"
            );
        });
    }

    /// A sidecar-only pairing offer for the revocation tests: the
    /// record is durable in the replies directory but deliberately
    /// unbound — the oversized username keeps its pairings entry from
    /// fitting the slack the filler leaves, so the document shows the
    /// chat neither a binding nor a pairing. `expires_at` controls
    /// whether the offer is still live or has already lapsed.
    fn stage_sidecar_only_offer(
        store: &mut BindingStore,
        chat_id: i64,
        update_id: i64,
        expires_at: u64,
    ) {
        let minted_revision = store
            .request_pairing(5, 5, Some("earlier".into()))
            .unwrap()
            .minted_revision;
        admit_filler(store, update_id);
        fill_document(store, 6, 300);
        let dir = replies_dir(&store.path);
        std::fs::create_dir_all(&dir).unwrap();
        let record = StagedCompletion {
            update_id,
            sequence: 0,
            payload: manifest_file_name(TaskKey::new(0, update_id)),
            key: format!("reply:{update_id}"),
            effect: StagedEffect::ReplyPairing {
                record: PairingRecord {
                    code: "WXYZ-1234".to_owned(),
                    chat_id,
                    user_id: 9,
                    username: Some("x".repeat(2048)),
                    created_at: now_secs(),
                    expires_at,
                    minted_revision,
                },
            },
            text: Some("Pairing code: WXYZ-1234".to_owned()),
            refused_text: Some(
                "That pairing offer did not hold — send /start to request a fresh code.".to_owned(),
            ),
        };
        std::fs::write(
            dir.join(manifest_file_name(TaskKey::new(0, update_id))),
            serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn a_revocation_tombstones_an_offer_that_lives_only_in_its_sidecar() {
        temp_store(|mut store| {
            stage_sidecar_only_offer(&mut store, 9, 7, now_secs() + PAIRING_TTL.as_secs());
            assert!(store.staged_reply_unbound(7));
            // The chat has no binding and no visible pairing — the
            // revocation still recognizes the sidecar-only offer and
            // tombstones it: before, this returned false and left the
            // code free to publish once any write freed space.
            assert!(store.revoke(9).unwrap());
            assert!(
                store.document.revoked_chats.contains_key("9"),
                "a sidecar-only offer escaped the revocation's tombstone"
            );
            // An unrelated freeing write reconciles the record: the
            // tombstoned offer binds its refused variant instead of
            // the pre-revocation code.
            assert!(store.revoke(6).unwrap());
            let task = store.pending_update(7).unwrap();
            assert!(
                task.reply_refused,
                "a revoked sidecar-only offer bound its live variant"
            );
            assert_eq!(
                store.reply_text(&task).unwrap().as_deref(),
                Some("That pairing offer did not hold — send /start to request a fresh code."),
                "a revoked sidecar-only offer published its dead code"
            );
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .all(|held| held.chat_id != 9),
                "a revoked sidecar-only offer reached the pairings list"
            );
        });
    }

    #[test]
    fn a_staged_revocation_tombstones_the_sidecar_only_offer() {
        temp_store(|mut store| {
            // Task 8 is admitted before the document fills — the
            // filler deliberately leaves no room for new entries.
            admit_filler(&mut store, 8);
            stage_sidecar_only_offer(&mut store, 9, 7, now_secs() + PAIRING_TTL.as_secs());
            // The confirmation commit's revocation effect meets the
            // same gap: nothing in the document names chat 9, yet its
            // sidecar-only offer is still invalidated and tombstoned.
            let reply = store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    format!("revoked={removed}")
                })
                .unwrap();
            assert_eq!(
                reply, "revoked=true",
                "a sidecar-only offer was not counted as revoked"
            );
            assert!(
                store.document.revoked_chats.contains_key("9"),
                "the staged revocation left no tombstone for the sidecar offer"
            );
            // The freeing write cannot publish the pre-revocation code.
            assert!(store.revoke(6).unwrap());
            let task = store.pending_update(7).unwrap();
            assert!(
                task.reply_refused,
                "a sidecar-only offer outlived the staged revocation"
            );
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .all(|held| held.chat_id != 9),
                "a revoked sidecar-only offer reached the pairings list"
            );
        });
    }

    #[test]
    fn an_expired_sidecar_only_offer_reports_no_revocation() {
        temp_store(|mut store| {
            // Task 8 is admitted before the document fills — the
            // filler deliberately leaves no room for new entries.
            admit_filler(&mut store, 8);
            // The sidecar-only offer's TTL already ran out: nothing it
            // carries can still be revoked — the host revoke and the
            // recorded /unpair path must both answer that there was
            // nothing to revoke instead of reporting success over a
            // lapsed offer.
            stage_sidecar_only_offer(&mut store, 9, 7, 1);
            assert!(
                !store.revoke(9).unwrap(),
                "an expired sidecar-only offer counted as revoked"
            );
            assert!(
                !store.document.revoked_chats.contains_key("9"),
                "a lapsed offer earned a tombstone"
            );
            let reply = store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    format!("revoked={removed}")
                })
                .unwrap();
            assert_eq!(
                reply, "revoked=false",
                "the recorded /unpair reported a revocation over a lapsed offer"
            );
            assert!(
                !store.document.revoked_chats.contains_key("9"),
                "the staged revocation tombstoned a lapsed offer"
            );
        });
    }

    #[test]
    fn an_expired_stored_code_reports_no_revocation() {
        temp_store(|mut store| {
            // A pairing offer whose reply already delivered can leave
            // its code in `document.pairings` past the TTL — nothing
            // prunes it until the next pairing write. Removing that
            // dead row is cleanup: the host revoke and the recorded
            // /unpair must both answer there was nothing to revoke
            // instead of confirming a lapsed code's removal.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.expire_pairings_for_test().unwrap();
            admit_filler(&mut store, 8);
            assert!(
                !store.revoke(9).unwrap(),
                "an expired stored code counted as revoked"
            );
            assert!(
                !store.document.revoked_chats.contains_key("9"),
                "a lapsed stored code earned a tombstone"
            );
            assert!(
                store
                    .pending_pairings()
                    .iter()
                    .all(|held| held.chat_id != 9),
                "the expired row survived the cleanup"
            );
            // The recorded /unpair meets the same shape: a fresh code
            // lapses while its row is still listed — the confirmation
            // it binds must report nothing revoked, not success.
            store.request_pairing(9, 9, Some("alice".into())).unwrap();
            store.expire_pairings_for_test().unwrap();
            let reply = store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    format!("revoked={removed}")
                })
                .unwrap();
            assert_eq!(
                reply, "revoked=false",
                "the recorded /unpair reported a revocation over a lapsed code"
            );
            assert!(
                !store.document.revoked_chats.contains_key("9"),
                "the staged revocation tombstoned a lapsed code"
            );
        });
    }

    #[test]
    fn a_checkpoint_clear_preserves_progress_committed_after_the_resolve() {
        temp_store(|mut store| {
            admit_filler(&mut store, 7);
            store.record_reply(7, "done", "reply:7").unwrap();
            let first = crate::transport::SendProgress {
                confirmed: vec![],
                next_part: 0,
                outcome_unknown: false,
                binding: None,
            };
            store
                .record_reply_checkpoint(7, Some(first.clone()), None)
                .unwrap();
            // The checkpoint moved under the resolver: progress a
            // write landed since the read decided to clear is adopted,
            // not erased — and the confirmed count, checkpoint and
            // deadline the resume needs come back as one coherent
            // state, never mixed from separate reads.
            let second = crate::transport::SendProgress {
                confirmed: vec![11],
                next_part: 1,
                outcome_unknown: false,
                binding: None,
            };
            store
                .record_reply_progress(7, 1, Some(second.clone()))
                .unwrap();
            store
                .record_reply_checkpoint(7, None, Some(1_700_000_000))
                .unwrap();
            let adopted = store
                .clear_reply_progress(7, Some(&first))
                .unwrap()
                .expect("the task's resume state was lost");
            assert_eq!(
                adopted.progress.as_ref(),
                Some(&second),
                "progress committed after the resolve was erased"
            );
            assert_eq!(
                adopted.sent, 1,
                "a part confirmed after the resolve was not adopted"
            );
            assert_eq!(
                adopted.retry_at_ms,
                Some(1_700_000_000),
                "the adopted checkpoint's deadline was dropped"
            );
            assert_eq!(
                store.pending_update(7).unwrap().reply_progress,
                Some(second.clone())
            );
            // The checkpoint the resolve actually paired with the
            // variant clears — its owed deadline with it.
            let cleared = store
                .clear_reply_progress(7, Some(&second))
                .unwrap()
                .expect("the task's resume state was lost");
            assert!(cleared.progress.is_none());
            assert_eq!(cleared.sent, 1);
            assert!(cleared.retry_at_ms.is_none());
            let held = store.pending_update(7).unwrap();
            assert!(held.reply_progress.is_none());
            assert!(held.reply_retry_at_ms.is_none());
        });
    }
}
