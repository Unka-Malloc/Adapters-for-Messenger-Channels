//! Adapter self-description: what a channel dialect lowers, and how well.
//!
//! Incomplete support is declared, never claimed. Every vocabulary slot
//! the contract defines carries an explicit [`Support`] level so a host
//! can reason about coverage instead of guessing from failures.

use crate::identity::ChannelId;
use crate::mechanism::LaneMechanism;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The update kinds the normalized contract distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Message,
    MessageEdited,
    MessageDeleted,
    MemberJoined,
    MemberLeft,
    Reaction,
}

/// Optional send-side features beyond a plain text send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendFeature {
    /// Idempotent sends via `OutboundMessage::idempotency_key`.
    Idempotency,
    /// Threaded reply targeting an earlier platform message.
    ReplyTo,
    /// Editing a previously sent message.
    Edit,
    /// Deleting a previously sent message.
    Delete,
}

/// One capability's declared level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// Offered by the platform and implemented directly.
    Native,
    /// Not offered by the platform; the adapter approximates it locally
    /// (e.g. dedupe cache for idempotency keys) with documented limits.
    Adapted,
    /// Not available — absent from the platform or not yet wired.
    /// Declared, never claimed.
    Unsupported,
}

/// What one channel adapter receives and sends, and at what level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDescriptor {
    /// The dialect's channel identifier (e.g. `"telegram"`).
    pub channel: ChannelId,
    /// Every receive mechanism the platform natively offers, mapped to
    /// this adapter's support level for it.
    pub receive: BTreeMap<LaneMechanism, Support>,
    /// Support level per normalized update kind.
    pub updates: BTreeMap<UpdateKind, Support>,
    /// Support level per optional send feature.
    pub sends: BTreeMap<SendFeature, Support>,
}

impl ChannelDescriptor {
    pub fn receive_support(&self, mechanism: LaneMechanism) -> Support {
        self.receive
            .get(&mechanism)
            .copied()
            .unwrap_or(Support::Unsupported)
    }

    pub fn update_support(&self, kind: UpdateKind) -> Support {
        self.updates
            .get(&kind)
            .copied()
            .unwrap_or(Support::Unsupported)
    }

    pub fn send_support(&self, feature: SendFeature) -> Support {
        self.sends
            .get(&feature)
            .copied()
            .unwrap_or(Support::Unsupported)
    }
}

/// The normalized surface every channel adapter exposes. The host
/// collects descriptors to learn coverage before composing channels;
/// sends themselves flow through each dialect's own typed entry points.
pub trait ChannelAdapter: Send + Sync {
    /// The adapter's declared capability report — complete over the
    /// contract vocabulary, honest about gaps.
    fn descriptor(&self) -> ChannelDescriptor;
}
