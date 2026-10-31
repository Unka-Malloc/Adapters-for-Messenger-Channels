//! Lower Telegram-native inbound shapes onto the `a4mc` channel contract.
//!
//! Lowering is a pure projection: the telegram-shaped [`Update`] /
//! [`InboundMessage`] the parser produced becomes the normalized
//! [`a4mc::InboundUpdate`] a host consumes. Updates the platform never
//! reports (deletion) or this dialect does not yet wire (member,
//! reaction) are declared `unsupported` in [`crate::channel::descriptor`]
//! — never silently claimed.

use crate::inbound::{InboundKind, InboundMessage, MediaRef};
use crate::transport::Update;
use a4mc::{
    AttachmentRef, ChannelChat, ChannelEvent, ChannelUser, ChatKind, ContentKind, ExternalChatId,
    ExternalMessageId, ExternalUserId, GeoPoint, InboundUpdate, ReplyRef,
};

/// Lower one transport update into the normalized contract event.
/// Updates carrying no message (unsupported update types) lower to
/// `InboundUpdate::Unsupported` so the host observes the gap.
pub fn lower_event(update: &Update) -> ChannelEvent {
    ChannelEvent {
        channel: crate::channel_id(),
        update: lower_update(update),
    }
}

/// Lower one transport update into the normalized inbound update.
pub fn lower_update(update: &Update) -> InboundUpdate {
    match &update.message {
        Some(message) => lower_message(message),
        None => InboundUpdate::Unsupported {
            raw_kind: "unmapped_update".to_owned(),
        },
    }
}

/// Lower one parsed message; `edited` selects the contract variant.
pub fn lower_message(message: &InboundMessage) -> InboundUpdate {
    let normalized = normalize_message(message);
    if message.edited {
        InboundUpdate::MessageEdited(normalized)
    } else {
        InboundUpdate::Message(normalized)
    }
}

fn normalize_message(message: &InboundMessage) -> a4mc::InboundMessage {
    a4mc::InboundMessage {
        update_cursor: Some(message.update_id.to_string()),
        chat: ChannelChat {
            id: ExternalChatId::from(message.chat_id),
            kind: match message.chat_type.as_str() {
                "private" => ChatKind::Direct,
                "group" | "supergroup" => ChatKind::Group,
                "channel" => ChatKind::Channel,
                _ => ChatKind::Unknown,
            },
            title: None,
        },
        author: ChannelUser {
            id: ExternalUserId::from(message.user_id),
            username: message.username.clone(),
            display_name: message.from_name.clone(),
        },
        message_id: ExternalMessageId::from(message.message_id),
        thread_id: message.message_thread_id.map(ExternalMessageId::from),
        sent_at: message.date.and_then(|value| u64::try_from(value).ok()),
        edited_at: message
            .edit_date
            .and_then(|value| u64::try_from(value).ok()),
        content: lower_kind(&message.kind),
        text: message.text.clone(),
        caption: message.caption.clone(),
        attachments: message.media.iter().map(lower_media).collect(),
        reply_to: message.reply_to.as_ref().map(|reply| ReplyRef {
            message_id: ExternalMessageId::from(reply.message_id),
            author_username: reply.from_username.clone(),
            preview: reply.preview.clone(),
            content_kind: reply.kind.as_deref().map(content_kind_named),
        }),
        forward_label: message.forward_label.clone(),
        location: message.location.map(|(latitude, longitude)| GeoPoint {
            latitude,
            longitude,
        }),
        venue_label: message.venue_label.clone(),
        contact_label: message.contact_label.clone(),
        poll_question: message.poll_question.clone(),
    }
}

fn lower_kind(kind: &InboundKind) -> ContentKind {
    match kind {
        InboundKind::Text => ContentKind::Text,
        InboundKind::Photo => ContentKind::Photo,
        InboundKind::Document => ContentKind::Document,
        InboundKind::Video => ContentKind::Video,
        InboundKind::Animation => ContentKind::Animation,
        InboundKind::Voice => ContentKind::Voice,
        InboundKind::Audio => ContentKind::Audio,
        InboundKind::Sticker => ContentKind::Sticker,
        InboundKind::VideoNote => ContentKind::VideoNote,
        InboundKind::Location => ContentKind::Location,
        InboundKind::Venue => ContentKind::Venue,
        InboundKind::Contact => ContentKind::Contact,
        InboundKind::Poll => ContentKind::Poll,
        InboundKind::Unsupported => ContentKind::Unsupported,
    }
}

/// A reply preview records the replied message's *named* kind (the
/// parser already reduced it to text); map back into the vocabulary.
fn content_kind_named(name: &str) -> ContentKind {
    match name {
        "text" => ContentKind::Text,
        "photo" => ContentKind::Photo,
        "document" => ContentKind::Document,
        "video" => ContentKind::Video,
        "animation" => ContentKind::Animation,
        "voice" => ContentKind::Voice,
        "audio" => ContentKind::Audio,
        "sticker" => ContentKind::Sticker,
        "video_note" => ContentKind::VideoNote,
        "location" => ContentKind::Location,
        "venue" => ContentKind::Venue,
        "contact" => ContentKind::Contact,
        "poll" => ContentKind::Poll,
        "unsupported" => ContentKind::Unsupported,
        other => ContentKind::Other(other.to_owned()),
    }
}

fn lower_media(media: &MediaRef) -> AttachmentRef {
    AttachmentRef {
        kind: media.kind.clone(),
        remote_id: media.file_id.clone(),
        remote_unique_id: media.file_unique_id.clone(),
        file_name: media.file_name.clone(),
        mime_type: media.mime_type.clone(),
        byte_size: media.file_size.and_then(|value| u64::try_from(value).ok()),
        width: media.width.and_then(|value| u32::try_from(value).ok()),
        height: media.height.and_then(|value| u32::try_from(value).ok()),
        duration_secs: media.duration.and_then(|value| u32::try_from(value).ok()),
        emoji: media.emoji.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parsed(update_id: i64, body: serde_json::Value, edited: bool) -> InboundMessage {
        crate::inbound::parse_message_update(update_id, &body, edited).unwrap()
    }

    #[test]
    fn message_lowers_to_normalized_variant() {
        let message = parsed(
            41,
            json!({
                "message_id": 9,
                "text": "hi",
                "date": 1_700_000_000,
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 7, "username": "alice", "first_name": "Alice", "last_name": "A" }
            }),
            false,
        );
        let event = lower_event(&Update {
            update_id: 41,
            message: Some(message),
        });
        assert_eq!(event.channel.as_str(), "telegram");
        let InboundUpdate::Message(lowered) = event.update else {
            panic!("expected message variant");
        };
        assert_eq!(lowered.update_cursor.as_deref(), Some("41"));
        assert_eq!(lowered.chat.kind, ChatKind::Direct);
        assert_eq!(lowered.author.username.as_deref(), Some("alice"));
        assert_eq!(lowered.author.display_name.as_deref(), Some("Alice A"));
        assert_eq!(lowered.sent_at, Some(1_700_000_000));
        assert_eq!(lowered.content, ContentKind::Text);
        assert_eq!(lowered.text.as_deref(), Some("hi"));
    }

    #[test]
    fn edited_and_group_chat_lower_to_their_variants() {
        let message = parsed(
            1,
            json!({
                "message_id": 5,
                "text": "again",
                "edit_date": 1_700_000_010,
                "chat": { "id": -100, "type": "supergroup" },
                "from": { "id": 3 }
            }),
            true,
        );
        let InboundUpdate::MessageEdited(lowered) = lower_message(&message) else {
            panic!("expected edited variant");
        };
        assert_eq!(lowered.chat.kind, ChatKind::Group);
        assert_eq!(lowered.edited_at, Some(1_700_000_010));
    }

    #[test]
    fn media_and_reply_project_to_attachments_and_reply_ref() {
        let message = parsed(
            1,
            json!({
                "message_id": 9,
                "caption": "see",
                "photo": [{ "file_id": "big", "file_unique_id": "u1", "width": 10, "height": 20, "file_size": 30 }],
                "reply_to_message": {
                    "message_id": 8,
                    "text": "earlier",
                    "from": { "id": 1, "username": "bob" }
                },
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 7 }
            }),
            false,
        );
        let InboundUpdate::Message(lowered) = lower_message(&message) else {
            panic!("expected message variant");
        };
        assert_eq!(lowered.attachments.len(), 1);
        let photo = &lowered.attachments[0];
        assert_eq!(photo.remote_id, "big");
        assert_eq!(photo.byte_size, Some(30));
        assert_eq!(photo.height, Some(20));
        let reply = lowered.reply_to.unwrap();
        assert_eq!(reply.message_id.as_str(), "8");
        assert_eq!(reply.author_username.as_deref(), Some("bob"));
        assert_eq!(reply.content_kind, Some(ContentKind::Text));
    }

    #[test]
    fn updates_without_messages_lower_as_unsupported() {
        let event = lower_event(&Update {
            update_id: 9,
            message: None,
        });
        assert_eq!(
            event.update,
            InboundUpdate::Unsupported {
                raw_kind: "unmapped_update".into()
            }
        );
    }
}
