//! Normalized inbound updates.
//!
//! One `InboundUpdate` is the lowered form of whatever the platform's
//! receive mechanism delivered. Variants a platform cannot report, or a
//! dialect has not wired, are declared `unsupported` in the adapter's
//! [`crate::descriptor::ChannelDescriptor`] — never silently dropped
//! from the vocabulary.

use crate::identity::{ChannelChat, ChannelId, ChannelUser, ExternalChatId, ExternalMessageId};
use serde::{Deserialize, Serialize};

/// One inbound event lowered onto the channel contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum InboundUpdate {
    /// A new message reached the channel.
    Message(InboundMessage),
    /// An existing message was edited.
    MessageEdited(InboundMessage),
    /// A message was deleted. Some platforms never report deletion;
    /// their adapters declare that honestly.
    MessageDeleted(DeletedMessage),
    /// A member joined the chat.
    MemberJoined(MemberEvent),
    /// A member left or was removed.
    MemberLeft(MemberEvent),
    /// Reactions on a message changed.
    Reaction(ReactionEvent),
    /// An update the dialect received but could not lower; carried so
    /// the host can observe the gap instead of losing it silently.
    Unsupported { raw_kind: String },
}

/// A lowered update stamped with the channel it arrived on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelEvent {
    pub channel: ChannelId,
    pub update: InboundUpdate,
}

/// The normalized content classification of one inbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Text,
    Photo,
    Document,
    Video,
    Animation,
    Voice,
    Audio,
    Sticker,
    VideoNote,
    Location,
    Venue,
    Contact,
    Poll,
    /// A platform content kind outside the normalized vocabulary.
    Other(String),
    /// Content the dialect could not classify at all.
    Unsupported,
}

impl ContentKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text => "text",
            Self::Photo => "photo",
            Self::Document => "document",
            Self::Video => "video",
            Self::Animation => "animation",
            Self::Voice => "voice",
            Self::Audio => "audio",
            Self::Sticker => "sticker",
            Self::VideoNote => "video_note",
            Self::Location => "location",
            Self::Venue => "venue",
            Self::Contact => "contact",
            Self::Poll => "poll",
            Self::Other(kind) => kind.as_str(),
            Self::Unsupported => "unsupported",
        }
    }
}

/// A media/file reference in the platform's own storage — a remote file
/// id, never a local path. Fetching the bytes is a separate platform
/// call owned by the adapter or the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRef {
    pub kind: String,
    pub remote_id: String,
    pub remote_unique_id: Option<String>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub byte_size: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_secs: Option<u32>,
    pub emoji: Option<String>,
}

/// The message a reply points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplyRef {
    pub message_id: ExternalMessageId,
    pub author_username: Option<String>,
    /// Bounded preview of the replied body, when the platform supplies one.
    pub preview: Option<String>,
    pub content_kind: Option<ContentKind>,
}

/// A platform-reported geographic point.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
}

/// One lowered inbound message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundMessage {
    /// The platform's ordering cursor for this update (e.g. Telegram's
    /// `update_id`), carried as opaque text.
    pub update_cursor: Option<String>,
    pub chat: ChannelChat,
    pub author: ChannelUser,
    pub message_id: ExternalMessageId,
    pub thread_id: Option<ExternalMessageId>,
    /// Platform-reported send time (unix seconds) — the platform's claim.
    pub sent_at: Option<u64>,
    /// Platform-reported edit time (unix seconds), when edited.
    pub edited_at: Option<u64>,
    pub content: ContentKind,
    /// The message's own text field, when present.
    pub text: Option<String>,
    /// Media caption, when present.
    pub caption: Option<String>,
    pub attachments: Vec<AttachmentRef>,
    pub reply_to: Option<ReplyRef>,
    /// Human-readable forward provenance (e.g. "forwarded from @alice").
    pub forward_label: Option<String>,
    pub location: Option<GeoPoint>,
    /// "Title — address" for venue payloads.
    pub venue_label: Option<String>,
    /// "Name phone" for contact payloads.
    pub contact_label: Option<String>,
    /// Question text for poll payloads.
    pub poll_question: Option<String>,
}

/// A deletion notice: platforms report only ids, never the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedMessage {
    pub update_cursor: Option<String>,
    pub chat_id: ExternalChatId,
    pub message_id: ExternalMessageId,
}

/// A member join/leave observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberEvent {
    pub update_cursor: Option<String>,
    pub chat_id: ExternalChatId,
    pub user: ChannelUser,
    /// Platform-reported event time (unix seconds).
    pub at: Option<u64>,
}

/// A reaction change on a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionEvent {
    pub update_cursor: Option<String>,
    pub chat_id: ExternalChatId,
    pub message_id: ExternalMessageId,
    /// The reacting user, when the platform discloses them.
    pub user: Option<ChannelUser>,
    /// Reaction emojis the event added.
    pub added: Vec<String>,
    /// Reaction emojis the event removed.
    pub removed: Vec<String>,
}
