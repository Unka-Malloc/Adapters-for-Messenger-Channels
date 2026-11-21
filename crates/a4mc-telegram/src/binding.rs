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
}

impl PendingUpdate {
    /// Whether a finished reply is durably recorded — inline in the
    /// document or spilled to its sidecar file.
    pub fn has_reply(&self) -> bool {
        self.reply.is_some() || self.reply_file.is_some()
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
    /// The file inside the replies directory holding the payload.
    /// Self-contained records name themselves; manifests written by
    /// the separate-files revision name their `reply-<id>.txt`
    /// sidecar.
    payload: String,
    /// The delivery key the reply's sends carry.
    key: String,
    /// The document change the completion committed with.
    effect: StagedEffect,
    /// The reply payload of a self-contained record. `None` marks a
    /// manifest written by the revision that staged payload and
    /// manifest as two files; its payload lives in the named file.
    #[serde(default)]
    text: Option<String>,
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
    pub code: String,
}

#[derive(Debug)]
pub struct BindingStore {
    path: PathBuf,
    lock: File,
    document: BindingDocument,
    #[cfg(test)]
    fail_next_write: bool,
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
            #[cfg(test)]
            fail_next_write: false,
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
        let result = read_document(&self.path).map(|document| self.document = document);
        let _ = self.lock.unlock();
        result
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
    fn mutate_bounded<R>(
        &mut self,
        headroom: usize,
        change: impl FnOnce(&mut BindingDocument) -> Result<R>,
    ) -> Result<R> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_write) {
            return Err(anyhow!("a4mc_telegram_state_write_failed"));
        }
        self.lock
            .lock_exclusive()
            .map_err(|_| anyhow!("a4mc_telegram_bindings_lock_failed"))?;
        let result = (|| {
            let dir = replies_dir(&self.path);
            let document = read_document(&self.path)?;
            let mut staged = document.clone();
            apply_staged(&mut staged, &dir);
            let mut candidate = staged.clone();
            let value = change(&mut candidate)?;
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
                return Ok(value);
            }
            // The change does not fit — its work stays uncommitted,
            // but the reconciled document still commits on its own so
            // the staged record is never overtaken by a newer write.
            if staged != document {
                let raw = serde_json::to_string_pretty(&staged)?;
                if raw.len() <= MAX_STATE_BYTES {
                    atomic_write_private_text(&self.path, &raw)?;
                    self.document = staged;
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
        self.mutate(|document| {
            let removed = document.chats.remove(&chat_id.to_string()).is_some();
            let before = document.pairings.len();
            document.pairings.retain(|record| record.chat_id != chat_id);
            Ok(removed || document.pairings.len() != before)
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

    /// Fail the next mutation, so a caller's error path can be exercised
    /// without relying on OS permissions that root can bypass.
    #[cfg(test)]
    pub fn fail_next_write_for_test(&mut self) {
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
            for task in tasks {
                // Re-admission keeps the existing record: a finished
                // reply must survive a stale transport redelivery.
                if !document
                    .pending_updates
                    .iter()
                    .any(|held| held.update_id == task.update_id)
                {
                    document.pending_updates.push(task.clone());
                }
            }
            ensure!(
                document.pending_updates.len() <= MAX_PENDING_UPDATES,
                "a4mc_telegram_pending_updates_full"
            );
            for dropped in dropped {
                document
                    .dropped_updates
                    .retain(|item| item.update_id != dropped.update_id);
                document.dropped_updates.push(dropped.clone());
            }
            let excess = document
                .dropped_updates
                .len()
                .saturating_sub(MAX_DROPPED_UPDATES);
            if excess > 0 {
                document.dropped_updates.drain(..excess);
            }
            for event in events {
                document
                    .pending_events
                    .retain(|item| item.update_id != event.update_id);
                document.pending_events.push(event.clone());
            }
            document.poll_offset = offset;
            document.poll_offset_advanced_at = Some(now_secs());
            Ok(())
        })
    }

    /// Settle an event the host callback consumed — the durable marker
    /// committed with the cursor is released without a dropped record.
    pub fn settle_event(&mut self, update_id: i64) -> Result<()> {
        self.mutate(|document| {
            document
                .pending_events
                .retain(|item| item.update_id != update_id);
            Ok(())
        })
    }

    /// Settle an event the host callback consumed and confirm the batch
    /// boundary its acceptance earned in the same write: the marker is
    /// released and the cursor advances to `offset` — the first update
    /// whose outcome is not yet durable — atomically, so a crash can
    /// never leave a confirmed cursor on an unsettled marker.
    pub fn settle_event_at_cursor(&mut self, update_id: i64, offset: i64) -> Result<()> {
        self.mutate(|document| {
            document
                .pending_events
                .retain(|item| item.update_id != update_id);
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

    /// Clear the settled-id tail: the remembered ids belong to the
    /// polling sequence that just expired, and a restarted sequence may
    /// lawfully reuse them — keeping the tail would suppress fresh work
    /// as already-settled. An empty tail means nothing to write.
    pub fn retire_settled(&mut self) -> Result<()> {
        if self.document.settled_updates.is_empty() {
            return Ok(());
        }
        self.mutate(|document| {
            document.settled_updates.clear();
            Ok(())
        })
    }

    /// The admitted-but-unfinished work, oldest update first.
    pub fn pending_updates(&self) -> Vec<PendingUpdate> {
        let mut tasks = self.document.pending_updates.clone();
        tasks.sort_by_key(|task| task.update_id);
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
    pub fn record_reply(&mut self, update_id: i64, reply: &str, key: &str) -> Result<()> {
        ensure!(
            reply.len() <= MAX_REPLY_BYTES,
            "a4mc_telegram_reply_too_large"
        );
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            stage_reply(document, &dir, update_id, reply, key, StagedEffect::Reply)
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
    /// moved it back. `text` receives whether the guarded session
    /// change applied, so the confirmation reports what the mutation
    /// actually did. The reply record itself never depends on the
    /// effect: a refused routing change still keeps its finished
    /// reply. Returns the reply text.
    pub fn record_reply_and_session(
        &mut self,
        chat_id: i64,
        update_id: i64,
        key: &str,
        session_id: Option<String>,
        expected: &ChatBinding,
        text: impl FnOnce(bool) -> String,
    ) -> Result<String> {
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
            let applied = apply_effect(document, &effect);
            let reply = text(applied);
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            stage_reply(document, &dir, update_id, &reply, key, effect)?;
            Ok(reply)
        })
    }

    /// Commit a chat's revocation — its binding and every pending
    /// pairing record — and the reply confirming it in one write, so a
    /// restart never replays a mutating command whose confirmation was
    /// already accepted by the platform. `text` receives whether any
    /// state was actually removed. Returns the reply text.
    pub fn record_reply_and_revocation(
        &mut self,
        chat_id: i64,
        update_id: i64,
        key: &str,
        text: impl FnOnce(bool) -> String,
    ) -> Result<String> {
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let effect = StagedEffect::ReplyRevoke {
                chat_id,
                user_id: document
                    .chats
                    .get(&chat_id.to_string())
                    .map(|binding| binding.user_id),
            };
            let removed = apply_effect(document, &effect);
            let reply = text(removed);
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            stage_reply(document, &dir, update_id, &reply, key, effect)?;
            Ok(reply)
        })
    }

    /// Commit a chat's agent rebind and the reply confirming it in one
    /// write — a changed agent clears the session exactly as
    /// `set_agent` does. The rebind is applied only while the chat is
    /// still paired for the user the command ran for and, when
    /// `expected` carries the binding the command observed, while that
    /// binding's revision still holds. `text` receives whether the
    /// guarded rebind applied, so the confirmation reports what the
    /// mutation actually did; the reply record never depends on it.
    /// Returns the reply text.
    #[allow(clippy::too_many_arguments)]
    pub fn record_reply_and_agent(
        &mut self,
        chat_id: i64,
        update_id: i64,
        agent_id: String,
        key: &str,
        user_id: i64,
        expected: Option<&ChatBinding>,
        text: impl FnOnce(bool) -> String,
    ) -> Result<String> {
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let effect = StagedEffect::ReplyAgent {
                chat_id,
                agent_id,
                user_id: Some(user_id),
                binding_revision: expected.map(|binding| binding.revision),
            };
            let applied = apply_effect(document, &effect);
            let reply = text(applied);
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            stage_reply(document, &dir, update_id, &reply, key, effect)?;
            Ok(reply)
        })
    }

    /// Commit a fresh pairing record and the reply carrying its code in
    /// one write — same admission rules as `request_pairing` — so the
    /// code a user receives always has its durable record. `text`
    /// receives the record minted for the document. Returns the reply
    /// text.
    pub fn record_pairing_and_reply(
        &mut self,
        chat_id: i64,
        user_id: i64,
        username: Option<String>,
        update_id: i64,
        key: &str,
        text: impl FnOnce(&PairingRecord) -> String,
    ) -> Result<String> {
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
            };
            let reply = text(&record);
            ensure!(
                reply.len() <= MAX_REPLY_BYTES,
                "a4mc_telegram_reply_too_large"
            );
            let effect = StagedEffect::ReplyPairing {
                record: record.clone(),
            };
            apply_effect(document, &effect);
            stage_reply(document, &dir, update_id, &reply, key, effect)?;
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
        update_id: i64,
        reply: &str,
        key: &str,
    ) -> Result<bool> {
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.update_id == update_id)
                && !task.has_reply()
                && !staged_exists(&dir, update_id)
            {
                task.reply = Some(reply.to_owned());
                task.reply_file = None;
                task.reply_key = Some(key.to_owned());
                task.reply_sent = 0;
                task.reply_progress = None;
                task.reply_retry_at_ms = None;
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
        update_id: i64,
        sent: usize,
        progress: Option<crate::transport::SendProgress>,
    ) -> Result<()> {
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.update_id == update_id)
            {
                task.reply_sent = task.reply_sent.max(sent);
                task.reply_progress = progress;
                task.reply_retry_at_ms = None;
            }
            Ok(())
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
        update_id: i64,
        progress: Option<crate::transport::SendProgress>,
        not_before: Option<u64>,
    ) -> Result<()> {
        self.mutate(|document| {
            if let Some(task) = document
                .pending_updates
                .iter_mut()
                .find(|task| task.update_id == update_id)
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

    /// One admitted-but-unfinished task by update id, if it exists —
    /// the durable record a retried delivery reloads before it
    /// resumes, so a later attempt continues the latest checkpoint
    /// rather than a stale snapshot.
    pub fn pending_update(&self, update_id: i64) -> Option<PendingUpdate> {
        self.document
            .pending_updates
            .iter()
            .find(|task| task.update_id == update_id)
            .cloned()
    }

    /// The update ids with a staged completion on disk — the replies
    /// whose payload and manifest exist but whose document pointer may
    /// not have committed yet. Filename-derived; no content is read.
    pub fn staged_update_ids(&self) -> Vec<i64> {
        staged_update_ids(&replies_dir(&self.path))
    }

    /// Whether a recoverable staged completion for the update is still
    /// waiting to bind — the durable reply exists, so the task counts
    /// as holding a finished reply even while its document pointer has
    /// not committed.
    pub fn staged_reply_pending(&self, update_id: i64) -> bool {
        staged_exists(&replies_dir(&self.path), update_id)
    }

    /// The update ids this store already durably claimed — admitted
    /// tasks still pending, and tasks already settled. A refetched
    /// update naming one is confirmed work, never re-queued.
    pub fn claimed_update_ids(&self) -> std::collections::HashSet<i64> {
        self.document
            .pending_updates
            .iter()
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
        if staged_manifests(&dir).is_empty() {
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
    /// the update skips it instead of re-running confirmed work.
    pub fn complete_update(&mut self, update_id: i64) -> Result<()> {
        self.mutate(|document| {
            document
                .pending_updates
                .retain(|task| task.update_id != update_id);
            note_settled(document, update_id);
            Ok(())
        })
    }

    /// Settle a task whose handling failed: the record is dropped
    /// unless it still holds an undelivered finished reply — committed
    /// or staged — since that result is the only unfinished stage and
    /// is resumed on restart instead of re-running the turn. A
    /// retained record stays claimed; a removed one's id joins the
    /// settled tail so a refetch skips it either way.
    pub fn settle_failed_update(&mut self, update_id: i64) -> Result<()> {
        let dir = replies_dir(&self.path);
        self.mutate(|document| {
            let before = document.pending_updates.len();
            document.pending_updates.retain(|task| {
                task.update_id != update_id || task.has_reply() || staged_exists(&dir, update_id)
            });
            if document.pending_updates.len() != before {
                note_settled(document, update_id);
            }
            Ok(())
        })
    }

    /// Resolve a task's finished reply text: small records carry it
    /// inline; a spilled record's payload lives in its sidecar file.
    /// `Ok(None)` means no finished reply is recorded.
    pub fn reply_text(&self, task: &PendingUpdate) -> Result<Option<String>> {
        if let Some(reply) = &task.reply {
            return Ok(Some(reply.clone()));
        }
        let Some(name) = &task.reply_file else {
            return Ok(None);
        };
        read_reply_payload(&self.path, name, task.update_id)?
            .map(Some)
            .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))
    }

    /// Persist one update id the runtime could not hand to the host as a
    /// message, bounded to the newest [`MAX_DROPPED_UPDATES`] entries.
    /// Writing this record before the cursor advances is what keeps a
    /// dice/game/service payload from vanishing without a trace.
    pub fn record_dropped_update(&mut self, update_id: i64, raw_kind: &str) -> Result<()> {
        let raw_kind: String = raw_kind.chars().take(MAX_RAW_KIND_CHARS).collect();
        self.mutate(|document| {
            document
                .dropped_updates
                .retain(|item| item.update_id != update_id);
            document.dropped_updates.push(DroppedUpdate {
                update_id,
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
fn read_reply_payload(path: &Path, name: &str, update_id: i64) -> Result<Option<String>> {
    for dir in [replies_dir(path), legacy_replies_dir(path)] {
        let bound = if name.ends_with(".json") {
            MAX_STAGED_BYTES
        } else {
            MAX_REPLY_BYTES
        };
        let Some(raw) = read_private_text_bounded(&dir.join(name), bound)? else {
            continue;
        };
        return decode_reply_payload(name, &raw, update_id).map(Some);
    }
    Ok(None)
}

fn decode_reply_payload(name: &str, raw: &str, update_id: i64) -> Result<String> {
    if !name.ends_with(".json") {
        return Ok(raw.to_owned());
    }
    serde_json::from_str::<StagedCompletion>(raw)
        .ok()
        .filter(|staged| staged.update_id == update_id)
        .and_then(|staged| staged.text)
        .ok_or_else(|| anyhow!("a4mc_telegram_reply_lost"))
}

fn reply_file_name(update_id: i64) -> String {
    format!("reply-{update_id}.txt")
}

/// The staged-completion manifest for one update id — payload, key
/// and effect recorded before the document commits.
fn manifest_file_name(update_id: i64) -> String {
    format!("reply-{update_id}.json")
}

/// Parse `reply-<update_id>.<suffix>` names — the only file names this
/// store owns inside its replies directory.
fn staged_file_name_id(name: &str) -> Option<(i64, &str)> {
    let body = name.strip_prefix("reply-")?;
    let (id, suffix) = body.split_once('.')?;
    Some((id.parse().ok()?, suffix))
}

/// Whether a recoverable staged completion exists for the update —
/// the on-disk record stays authoritative until a document write
/// binds its pointer. A self-contained record always qualifies; a
/// pointer manifest does only while its payload file exists.
fn staged_exists(dir: &Path, update_id: i64) -> bool {
    let Ok(raw) =
        read_private_text_bounded(&dir.join(manifest_file_name(update_id)), MAX_STAGED_BYTES)
    else {
        return false;
    };
    raw.and_then(|raw| serde_json::from_str::<StagedCompletion>(&raw).ok())
        .filter(|staged| staged.update_id == update_id && staged_payload_name_ok(staged, update_id))
        .is_some_and(|staged| staged.text.is_some() || dir.join(&staged.payload).is_file())
}

/// Whether a staged record's declared payload name matches the files
/// this store owns for its update id — the self-contained record's
/// own name or a pointer manifest's `reply-<id>.txt` sidecar.
fn staged_payload_name_ok(staged: &StagedCompletion, update_id: i64) -> bool {
    staged.payload == reply_file_name(update_id) || staged.payload == manifest_file_name(update_id)
}

fn staged_update_ids(dir: &Path) -> Vec<i64> {
    let mut ids = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        if let Some((id, "json")) = entry.file_name().to_str().and_then(staged_file_name_id) {
            ids.push(id);
        }
    }
    ids
}

/// Read every staged manifest in the directory. Entries whose file
/// name, declared update id or declared payload name disagree are
/// reported as invalid; a manifest for a finished update the document
/// already answers is ignored by `apply_staged`.
fn staged_manifests(dir: &Path) -> Vec<(i64, Option<StagedCompletion>)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((id, "json")) = staged_file_name_id(name) else {
            continue;
        };
        let staged = read_private_text_bounded(&entry.path(), MAX_STAGED_BYTES)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<StagedCompletion>(&raw).ok())
            .filter(|staged: &StagedCompletion| {
                staged.update_id == id && staged_payload_name_ok(staged, id)
            });
        out.push((id, staged));
    }
    out
}

/// The document's serialized size — the bound every commit is checked
/// against. `None` means serialization failed, treated as uncommittable.
fn serialized_len(document: &BindingDocument) -> Option<usize> {
    serde_json::to_string_pretty(document)
        .ok()
        .map(|raw| raw.len())
}

/// Bind every applicable staged completion on the candidate document:
/// the declared effect re-applies exactly as the record's own commit
/// performed it, and the task gains the payload pointer and delivery
/// key. Manifests are read under the caller's lock, so a completion
/// being written by another mutation is either already durable here or
/// still staging — never half-read.
fn apply_staged(document: &mut BindingDocument, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some((id, "json")) = entry.file_name().to_str().and_then(staged_file_name_id) else {
            continue;
        };
        // A task already holding its bound reply can never re-apply
        // this record — the manifest's only remaining job is the
        // sweep, so its (potentially large) payload is not re-read and
        // re-parsed on every mutation.
        let Some(index) = document
            .pending_updates
            .iter()
            .position(|task| task.update_id == id)
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
                staged.update_id == id && staged_payload_name_ok(staged, id)
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
        apply_effect(document, &staged.effect);
        let task = &mut document.pending_updates[index];
        task.reply = None;
        task.reply_file = Some(staged.payload.clone());
        task.reply_key = Some(staged.key.clone());
        task.reply_sent = 0;
        task.reply_progress = None;
        task.reply_retry_at_ms = None;
        if serialized_len(document).is_none_or(|len| len > MAX_STATE_BYTES) {
            *document = before;
        }
    }
}

/// The staged completions a document still has not bound — each with
/// the code naming why it waits, for host surfacing. A manifest whose
/// task is gone is ignored: the sweep reclaims it.
fn stranded_staged(document: &BindingDocument, dir: &Path) -> Vec<StrandedReply> {
    let mut out = Vec::new();
    for (id, staged) in staged_manifests(dir) {
        let applied = document
            .pending_updates
            .iter()
            .find(|task| task.update_id == id)
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
            .find(|task| task.update_id == id)
        else {
            continue;
        };
        let recoverable = staged
            .as_ref()
            .is_some_and(|staged| staged.text.is_some() || dir.join(&staged.payload).is_file());
        out.push(StrandedReply {
            update_id: task.update_id,
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
fn stage_reply(
    document: &mut BindingDocument,
    dir: &Path,
    update_id: i64,
    reply: &str,
    key: &str,
    effect: StagedEffect,
) -> Result<()> {
    let Some(task) = document
        .pending_updates
        .iter_mut()
        .find(|task| task.update_id == update_id)
    else {
        return Ok(());
    };
    ensure_private_dir(dir)?;
    let record_name = manifest_file_name(update_id);
    let manifest = StagedCompletion {
        update_id,
        payload: record_name.clone(),
        key: key.to_owned(),
        effect,
        text: Some(reply.to_owned()),
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
    task.reply_key = Some(key.to_owned());
    task.reply_sent = 0;
    task.reply_progress = None;
    task.reply_retry_at_ms = None;
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
fn apply_effect(document: &mut BindingDocument, effect: &StagedEffect) -> bool {
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
            let removed = document.chats.remove(&chat_id.to_string()).is_some();
            let before = document.pairings.len();
            document.pairings.retain(|record| {
                record.chat_id != *chat_id || user_id.is_some_and(|held| record.user_id != held)
            });
            removed || document.pairings.len() != before
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
            if document
                .chats
                .get(&record.chat_id.to_string())
                .is_some_and(|binding| binding.paired && binding.user_id == record.user_id)
            {
                // The user holds a full pairing now — the staged code
                // offer is superseded, never re-published.
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
    for (id, staged) in staged_manifests(&dir) {
        let task = document
            .pending_updates
            .iter()
            .find(|task| task.update_id == id);
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
                let _ = std::fs::remove_file(dir.join(manifest_file_name(id)));
            }
            continue;
        }
        match staged {
            Some(staged) => {
                let recoverable = staged.text.is_some() || dir.join(&staged.payload).is_file();
                if task.is_none() || !recoverable {
                    // Orphaned, or a stage that died before its
                    // payload landed — nothing left to recover.
                    let _ = std::fs::remove_file(dir.join(manifest_file_name(id)));
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
                    let _ = std::fs::remove_file(dir.join(manifest_file_name(id)));
                } else {
                    live.insert(reply_file_name(id));
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        assert!(applied);
                        "Started a new conversation: s2".to_owned()
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
                        assert!(applied);
                        "Started a new conversation: s2".to_owned()
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
                        message: inbound_message(3, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: oversized,
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(5, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
            let reopened = BindingStore::open(store.path.clone()).unwrap();
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(9, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                payload: "reply-9.txt".to_owned(),
                key: "reply:9".to_owned(),
                effect: StagedEffect::Reply,
                text: None,
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
                        message: inbound_message(5, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message,
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: crowded,
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(3, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(8, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                    assert!(removed);
                    "Pairing revoked for this chat.".to_owned()
                })
                .unwrap_err();
            assert!(
                store.binding(9).is_some(),
                "the revocation committed without its reply"
            );
            assert!(!store.pending_updates()[0].has_reply());
            let reply = store
                .record_reply_and_revocation(9, 8, "reply:8", |removed| {
                    assert!(removed);
                    "Pairing revoked for this chat.".to_owned()
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(7, 9),
                        reply: Some("held reply".to_owned()),
                        reply_key: Some("reply:7".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            // The host rebinds mid-turn: the agent switch clears the
            // session, so the in-flight turn's session effect is stale.
            store.set_agent(9, Some("claude".into())).unwrap();
            store
                .record_reply_and_session(
                    9,
                    7,
                    "reply:7",
                    Some("turn-session".into()),
                    &expected,
                    |applied| {
                        assert!(!applied, "the stale effect still applied");
                        "turn reply".to_owned()
                    },
                )
                .unwrap();
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: Some("reply:7".to_owned()),
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: Some("reply-7.txt".to_owned()),
                        reply_retry_at_ms: None,
                    }],
                    &[],
                    &[],
                    8,
                )
                .unwrap();
            let legacy = store.path.with_extension("replies");
            std::fs::create_dir_all(&legacy).unwrap();
            std::fs::write(legacy.join("reply-7.txt"), "legacy payload").unwrap();

            let reopened = BindingStore::open(store.path.clone()).unwrap();
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
                        message: inbound_message(7, 9),
                        reply: None,
                        reply_key: None,
                        reply_sent: 0,
                        reply_progress: None,
                        reply_file: None,
                        reply_retry_at_ms: None,
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
                            message: big,
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
                        },
                        PendingUpdate {
                            update_id: 8,
                            message: inbound_message(8, 9),
                            reply: None,
                            reply_key: None,
                            reply_sent: 0,
                            reply_progress: None,
                            reply_file: None,
                            reply_retry_at_ms: None,
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
}
