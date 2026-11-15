//! Lower a verified webhook body onto the normalized contract.
//!
//! The wire payload is the contract's own JSON, so a sender that already
//! speaks `a4mc` loses no field in translation. Three shapes are
//! accepted, in order:
//!
//! 1. [`a4mc::ChannelEvent`] — `{ "channel": ..., "update": ... }`;
//! 2. [`a4mc::InboundUpdate`] — `{ "kind": "message", ... }`;
//! 3. a bare [`a4mc::InboundMessage`] — the message object without a
//!    `kind` tag, carried as a message update.
//!
//! The returned event is always stamped with [`crate::CHANNEL`]: a
//! webhook cannot claim to be another dialect's channel. Parsing happens
//! only after signature verification, and malformed payloads become one
//! bounded error that never echoes the body.

use crate::error::WebhookError;
use a4mc::{ChannelEvent, ChannelId, InboundMessage, InboundUpdate};

/// Parse one verified body into a channel event stamped `webhook`.
pub fn parse(body: &[u8]) -> Result<ChannelEvent, WebhookError> {
    if let Ok(event) = serde_json::from_slice::<ChannelEvent>(body) {
        return Ok(stamp(event.update));
    }
    if let Ok(update) = serde_json::from_slice::<InboundUpdate>(body) {
        return Ok(stamp(update));
    }
    if let Ok(message) = serde_json::from_slice::<InboundMessage>(body) {
        return Ok(stamp(InboundUpdate::Message(message)));
    }
    Err(WebhookError::new(
        "a4mc_webhook_payload_invalid",
        "webhook body is not a normalized a4mc update",
    ))
}

fn stamp(update: InboundUpdate) -> ChannelEvent {
    ChannelEvent {
        channel: ChannelId::from(crate::CHANNEL),
        update,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a4mc::{
        AttachmentRef, ChannelChat, ChannelUser, ChatKind, ContentKind, DeletedMessage,
        ExternalChatId, ExternalMessageId, ExternalUserId, GeoPoint, MemberEvent, ReactionEvent,
        ReplyRef,
    };
    use serde_json::json;

    fn full_message() -> InboundMessage {
        InboundMessage {
            update_cursor: Some("cursor-1".into()),
            chat: ChannelChat {
                id: ExternalChatId::from("chat-1"),
                kind: ChatKind::Group,
                title: Some("Fixture Chat".into()),
            },
            author: ChannelUser {
                id: ExternalUserId::from("user-1"),
                username: Some("alice".into()),
                display_name: Some("Alice".into()),
            },
            message_id: ExternalMessageId::from("message-1"),
            thread_id: Some(ExternalMessageId::from("thread-1")),
            sent_at: Some(1_700_000_000),
            edited_at: Some(1_700_000_010),
            content: ContentKind::Photo,
            text: Some("body".into()),
            caption: Some("caption".into()),
            attachments: vec![AttachmentRef {
                kind: "photo".into(),
                remote_id: "file-1".into(),
                remote_unique_id: Some("unique-1".into()),
                file_name: Some("chart.png".into()),
                mime_type: Some("image/png".into()),
                byte_size: Some(10),
                width: Some(20),
                height: Some(30),
                duration_secs: Some(2),
                emoji: Some("🙂".into()),
            }],
            reply_to: Some(ReplyRef {
                message_id: ExternalMessageId::from("message-0"),
                author_username: Some("bob".into()),
                preview: Some("parent".into()),
                content_kind: Some(ContentKind::Text),
            }),
            forward_label: Some("forwarded from carol".into()),
            location: Some(GeoPoint {
                latitude: 1.5,
                longitude: 2.5,
            }),
            venue_label: Some("Venue — Address".into()),
            contact_label: Some("Name phone".into()),
            poll_question: Some("Which?".into()),
        }
    }

    #[test]
    fn a_full_normalized_message_roundtrips_without_field_loss() {
        let update = InboundUpdate::Message(full_message());
        let body = serde_json::to_vec(&update).unwrap();
        let event = parse(&body).unwrap();
        assert_eq!(event.channel.as_str(), crate::CHANNEL);
        assert_eq!(event.update, update);
    }

    #[test]
    fn every_update_variant_roundtrips_and_is_stamped() {
        let message = full_message();
        let variants = vec![
            InboundUpdate::Message(message.clone()),
            InboundUpdate::MessageEdited(message),
            InboundUpdate::MessageDeleted(DeletedMessage {
                update_cursor: Some("d1".into()),
                chat_id: ExternalChatId::from("chat-1"),
                message_id: ExternalMessageId::from("message-1"),
            }),
            InboundUpdate::MemberJoined(MemberEvent {
                update_cursor: Some("m1".into()),
                chat_id: ExternalChatId::from("chat-1"),
                user: ChannelUser {
                    id: ExternalUserId::from("user-2"),
                    username: Some("bob".into()),
                    display_name: None,
                },
                at: Some(1_700_000_000),
            }),
            InboundUpdate::MemberLeft(MemberEvent {
                update_cursor: None,
                chat_id: ExternalChatId::from("chat-1"),
                user: ChannelUser {
                    id: ExternalUserId::from("user-2"),
                    username: None,
                    display_name: None,
                },
                at: None,
            }),
            InboundUpdate::Reaction(ReactionEvent {
                update_cursor: Some("r1".into()),
                chat_id: ExternalChatId::from("chat-1"),
                message_id: ExternalMessageId::from("message-1"),
                user: Some(ChannelUser {
                    id: ExternalUserId::from("user-2"),
                    username: None,
                    display_name: None,
                }),
                added: vec!["eyes".into()],
                removed: vec!["fire".into()],
            }),
            InboundUpdate::Unsupported {
                raw_kind: "custom_event".into(),
            },
        ];
        for update in variants {
            let body = serde_json::to_vec(&update).unwrap();
            let event = parse(&body).unwrap();
            assert_eq!(event.channel.as_str(), crate::CHANNEL);
            assert_eq!(event.update, update);
        }
    }

    #[test]
    fn a_channel_event_is_re_stamped_and_its_update_is_preserved() {
        let body = serde_json::to_vec(&json!({
            "channel": "some-other-dialect",
            "update": {
                "kind": "messageDeleted",
                "updateCursor": "1",
                "chatId": "chat-1",
                "messageId": "message-1"
            }
        }))
        .unwrap();
        let event = parse(&body).unwrap();
        assert_eq!(event.channel.as_str(), crate::CHANNEL);
        assert_eq!(
            event.update,
            InboundUpdate::MessageDeleted(DeletedMessage {
                update_cursor: Some("1".into()),
                chat_id: ExternalChatId::from("chat-1"),
                message_id: ExternalMessageId::from("message-1"),
            })
        );
    }

    #[test]
    fn a_bare_message_object_lowers_as_a_message() {
        let body = serde_json::to_vec(&full_message()).unwrap();
        let event = parse(&body).unwrap();
        assert_eq!(event.update, InboundUpdate::Message(full_message()));
    }

    #[test]
    fn malformed_or_non_contract_bodies_fail_closed() {
        for body in [
            b"".as_slice(),
            b"not json".as_slice(),
            b"null".as_slice(),
            b"{\"kind\":\"message\"}".as_slice(),
            b"{\"unexpected\":true}".as_slice(),
        ] {
            let error = parse(body).unwrap_err();
            assert_eq!(error.code, "a4mc_webhook_payload_invalid");
            assert!(!error.message.contains("unexpected"));
        }
    }
}
