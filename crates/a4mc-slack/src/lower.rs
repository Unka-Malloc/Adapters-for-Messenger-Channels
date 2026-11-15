//! Lower Slack event callbacks onto the normalized `a4mc` contract.
//!
//! One `events_api` payload is an `event_callback` object carrying an
//! `event`. This module projects Slack's native message, edit, delete,
//! member and reaction shapes onto [`a4mc::InboundUpdate`]. Event kinds
//! the dialect has not wired lower to [`a4mc::InboundUpdate::Unsupported`]
//! so the host observes the gap instead of losing it; the descriptor
//! declares the same coverage.

use a4mc::{
    AttachmentRef, ChannelChat, ChannelEvent, ChannelUser, ChatKind, ContentKind, DeletedMessage,
    ExternalChatId, ExternalMessageId, ExternalUserId, InboundMessage, InboundUpdate, MemberEvent,
    ReactionEvent, ReplyRef,
};
use serde_json::Value;

/// Lower the `payload` of one `events_api` envelope into a normalized
/// channel event.
pub fn lower_event(payload: &Value) -> ChannelEvent {
    ChannelEvent {
        channel: crate::channel_id(),
        update: lower_update(payload),
    }
}

/// Lower the `payload` of one `events_api` envelope into an inbound
/// update.
pub fn lower_update(payload: &Value) -> InboundUpdate {
    if payload.get("type").and_then(Value::as_str) != Some("event_callback") {
        return InboundUpdate::Unsupported {
            raw_kind: payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("not_event_callback")
                .to_owned(),
        };
    }
    let Some(event) = payload.get("event").filter(|value| value.is_object()) else {
        return InboundUpdate::Unsupported {
            raw_kind: "missing_event".to_owned(),
        };
    };
    let cursor = payload
        .get("event_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let event_time = payload.get("event_time").and_then(Value::as_u64);
    let kicker = || LowerContext {
        cursor: cursor.clone(),
        event_time,
    };
    match event.get("type").and_then(Value::as_str).unwrap_or("") {
        "message" => lower_message_event(event, &kicker()),
        "app_mention" => lower_message_object(event, event, &kicker(), false),
        "member_joined_channel" => lower_member_event(event, &kicker(), true),
        "member_left_channel" => lower_member_event(event, &kicker(), false),
        "reaction_added" => lower_reaction_event(event, &kicker(), true),
        "reaction_removed" => lower_reaction_event(event, &kicker(), false),
        other => InboundUpdate::Unsupported {
            raw_kind: if other.is_empty() {
                "missing_event_type".to_owned()
            } else {
                other.to_owned()
            },
        },
    }
}

struct LowerContext {
    cursor: Option<String>,
    event_time: Option<u64>,
}

fn lower_message_event(event: &Value, context: &LowerContext) -> InboundUpdate {
    match event.get("subtype").and_then(Value::as_str) {
        Some("message_changed") => {
            let Some(message) = event.get("message").filter(|value| value.is_object()) else {
                return InboundUpdate::Unsupported {
                    raw_kind: "message_changed_without_message".to_owned(),
                };
            };
            lower_message_object(message, event, context, true)
        }
        Some("message_deleted") => {
            let message_id = event
                .get("deleted_ts")
                .or_else(|| event.pointer("/previous_message/ts"))
                .and_then(Value::as_str);
            let chat_id = event
                .get("channel")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            match (message_id, chat_id) {
                (Some(message_id), Some(chat_id)) => {
                    InboundUpdate::MessageDeleted(DeletedMessage {
                        update_cursor: context.cursor.clone(),
                        chat_id: ExternalChatId::from(chat_id),
                        message_id: ExternalMessageId::from(message_id),
                    })
                }
                _ => InboundUpdate::Unsupported {
                    raw_kind: "message_deleted_without_target".to_owned(),
                },
            }
        }
        Some("channel_join") => lower_member_event(event, context, true),
        Some("channel_leave") => lower_member_event(event, context, false),
        // `message_replied` carries the reply in a nested `message`.
        Some("message_replied") => match event.get("message").filter(|value| value.is_object()) {
            Some(message) => lower_message_object(message, event, context, false),
            None => InboundUpdate::Unsupported {
                raw_kind: "message_replied_without_message".to_owned(),
            },
        },
        // `file_share`, `bot_message`, `thread_broadcast`, `reply_broadcast`
        // and ordinary messages all carry a message body. Other subtypes
        // (`channel_topic`, `pinned_item`, ...) are channel-state events,
        // not message receipts.
        Some("file_share")
        | Some("bot_message")
        | Some("thread_broadcast")
        | Some("reply_broadcast")
        | None => lower_message_object(event, event, context, false),
        Some(other) => InboundUpdate::Unsupported {
            raw_kind: format!("message_subtype_{other}"),
        },
    }
}

/// Lower a message object. `outer` supplies the channel and any author
/// fields Slack keeps at the event level (notably for edited messages).
fn lower_message_object(
    message: &Value,
    outer: &Value,
    context: &LowerContext,
    edited: bool,
) -> InboundUpdate {
    let message_id = message
        .get("ts")
        .or_else(|| outer.get("ts"))
        .and_then(Value::as_str);
    let chat_id = outer
        .get("channel")
        .or_else(|| message.get("channel"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let (Some(message_id), Some(chat_id)) = (message_id, chat_id) else {
        return InboundUpdate::Unsupported {
            raw_kind: "message_without_identity".to_owned(),
        };
    };
    let previous = outer.get("previous_message");

    let author_id = message
        .get("user")
        .or_else(|| outer.get("user"))
        .or_else(|| previous.and_then(|value| value.get("user")))
        .or_else(|| message.get("bot_id"))
        .or_else(|| outer.get("bot_id"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let username = message
        .get("username")
        .or_else(|| outer.get("username"))
        .or_else(|| previous.and_then(|value| value.get("username")))
        .and_then(Value::as_str);
    let display_name = message
        .pointer("/bot_profile/name")
        .or_else(|| outer.pointer("/bot_profile/name"))
        .or_else(|| message.pointer("/user_profile/display_name"))
        .or_else(|| message.get("username"))
        .or_else(|| outer.get("username"))
        .or_else(|| previous.and_then(|value| value.get("username")))
        .and_then(Value::as_str);
    let files = message
        .get("files")
        .and_then(Value::as_array)
        .map(|files| files.iter().filter_map(lower_file).collect::<Vec<_>>())
        .unwrap_or_default();
    let text = message
        .get("text")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let thread_ts = message
        .get("thread_ts")
        .and_then(Value::as_str)
        .filter(|value| *value != message_id);
    let edited_at = message
        .pointer("/edited/ts")
        .and_then(parse_ts)
        .or_else(|| edited.then_some(context.event_time).flatten());
    let content = classify_content(message, &files, text.as_deref());

    let normalized = InboundMessage {
        update_cursor: context.cursor.clone(),
        chat: ChannelChat {
            id: ExternalChatId::from(chat_id),
            kind: chat_kind(chat_id),
            title: None,
        },
        author: ChannelUser {
            id: ExternalUserId::from(author_id),
            username: username.map(str::to_owned),
            display_name: display_name.map(str::to_owned),
        },
        message_id: ExternalMessageId::from(message_id),
        thread_id: thread_ts.map(ExternalMessageId::from),
        sent_at: parse_ts(&Value::String(message_id.to_owned())),
        edited_at,
        content,
        text,
        caption: None,
        attachments: files,
        reply_to: thread_ts.map(|parent| ReplyRef {
            message_id: ExternalMessageId::from(parent),
            author_username: None,
            preview: None,
            content_kind: None,
        }),
        forward_label: None,
        location: None,
        venue_label: None,
        contact_label: None,
        poll_question: None,
    };
    if edited {
        InboundUpdate::MessageEdited(normalized)
    } else {
        InboundUpdate::Message(normalized)
    }
}

fn lower_member_event(event: &Value, context: &LowerContext, joined: bool) -> InboundUpdate {
    let Some(user) = event.get("user").and_then(Value::as_str) else {
        return InboundUpdate::Unsupported {
            raw_kind: "member_event_without_user".to_owned(),
        };
    };
    let Some(chat_id) = event
        .get("channel")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return InboundUpdate::Unsupported {
            raw_kind: "member_event_without_channel".to_owned(),
        };
    };
    let member = MemberEvent {
        update_cursor: context.cursor.clone(),
        chat_id: ExternalChatId::from(chat_id),
        user: ChannelUser {
            id: ExternalUserId::from(user),
            username: None,
            display_name: None,
        },
        at: context.event_time,
    };
    if joined {
        InboundUpdate::MemberJoined(member)
    } else {
        InboundUpdate::MemberLeft(member)
    }
}

fn lower_reaction_event(event: &Value, context: &LowerContext, added: bool) -> InboundUpdate {
    let Some(item) = event.get("item").filter(|value| value.is_object()) else {
        return InboundUpdate::Unsupported {
            raw_kind: "reaction_without_item".to_owned(),
        };
    };
    if item.get("type").and_then(Value::as_str) != Some("message") {
        return InboundUpdate::Unsupported {
            raw_kind: "reaction_item_not_message".to_owned(),
        };
    }
    let Some(chat_id) = item
        .get("channel")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return InboundUpdate::Unsupported {
            raw_kind: "reaction_without_channel".to_owned(),
        };
    };
    let Some(message_id) = item
        .get("ts")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return InboundUpdate::Unsupported {
            raw_kind: "reaction_without_message".to_owned(),
        };
    };
    let reaction = event
        .get("reaction")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let user = event
        .get("user")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|user| ChannelUser {
            id: ExternalUserId::from(user),
            username: None,
            display_name: None,
        });
    InboundUpdate::Reaction(ReactionEvent {
        update_cursor: context.cursor.clone(),
        chat_id: ExternalChatId::from(chat_id),
        message_id: ExternalMessageId::from(message_id),
        user,
        added: if added {
            reaction.into_iter().map(str::to_owned).collect()
        } else {
            Vec::new()
        },
        removed: if added {
            Vec::new()
        } else {
            reaction.into_iter().map(str::to_owned).collect()
        },
    })
}

fn lower_file(file: &Value) -> Option<AttachmentRef> {
    let remote_id = file
        .get("id")
        .or_else(|| file.get("name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let filetype = file
        .get("filetype")
        .and_then(Value::as_str)
        .unwrap_or("file");
    let mime_type = file
        .get("mimetype")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let duration_secs = file
        .get("duration_ms")
        .and_then(Value::as_u64)
        .map(|millis| millis / 1000)
        .and_then(|seconds| u32::try_from(seconds).ok());
    Some(AttachmentRef {
        kind: filetype.to_owned(),
        remote_id: remote_id.to_owned(),
        remote_unique_id: None,
        file_name: file
            .get("name")
            .or_else(|| file.get("title"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        mime_type,
        byte_size: file.get("size").and_then(Value::as_u64),
        width: file
            .get("original_w")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        height: file
            .get("original_h")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        duration_secs,
        emoji: None,
    })
}

fn classify_content(message: &Value, files: &[AttachmentRef], text: Option<&str>) -> ContentKind {
    if let Some(file) = files.first() {
        let mime = file.mime_type.as_deref().unwrap_or("").to_ascii_lowercase();
        let kind = file.kind.to_ascii_lowercase();
        if mime.starts_with("image/")
            || matches!(
                kind.as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "bmp"
            )
        {
            return ContentKind::Photo;
        }
        if mime.starts_with("video/") || matches!(kind.as_str(), "mp4" | "mov" | "webm") {
            return ContentKind::Video;
        }
        if mime.starts_with("audio/") {
            return ContentKind::Audio;
        }
        return ContentKind::Document;
    }
    if text.is_some() {
        return ContentKind::Text;
    }
    if message
        .get("attachments")
        .and_then(Value::as_array)
        .is_some_and(|attachments| !attachments.is_empty())
    {
        return ContentKind::Other("attachment".to_owned());
    }
    ContentKind::Unsupported
}

fn chat_kind(channel_id: &str) -> ChatKind {
    // Slack public (`C`) and private (`G`, including multi-party DM)
    // channels are multi-user groups; only `D` is a direct conversation.
    match channel_id.chars().next() {
        Some('D') => ChatKind::Direct,
        Some('C') | Some('G') => ChatKind::Group,
        _ => ChatKind::Unknown,
    }
}

/// Slack timestamps are decimal strings: seconds with a microsecond
/// suffix (`1700000000.000100`). The contract carries whole seconds.
fn parse_ts(value: &Value) -> Option<u64> {
    match value {
        Value::String(text) => text.split('.').next()?.parse().ok(),
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().map(|value| value.max(0.0) as u64)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn callback(event_id: &str, event: Value) -> Value {
        json!({
            "type": "event_callback",
            "team_id": "T1",
            "event_id": event_id,
            "event_time": 1_700_000_000,
            "event": event,
        })
    }

    #[test]
    fn message_projects_identity_content_thread_and_file() {
        let payload = callback(
            "Ev1",
            json!({
                "type": "message",
                "channel": "C1",
                "user": "U1",
                "text": "hello",
                "ts": "1700000000.000100",
                "thread_ts": "1700000000.000001",
                "edited": { "user": "U1", "ts": "1700000005.000000" },
                "files": [{
                    "id": "F1",
                    "name": "chart.png",
                    "mimetype": "image/png",
                    "filetype": "png",
                    "size": 10,
                    "original_w": 20,
                    "original_h": 30
                }]
            }),
        );
        let InboundUpdate::Message(message) = lower_update(&payload) else {
            panic!("expected message");
        };
        assert_eq!(message.update_cursor.as_deref(), Some("Ev1"));
        assert_eq!(message.chat.id.as_str(), "C1");
        assert_eq!(message.chat.kind, ChatKind::Group);
        assert_eq!(message.author.id.as_str(), "U1");
        assert_eq!(message.message_id.as_str(), "1700000000.000100");
        assert_eq!(
            message.thread_id.as_ref().map(|id| id.as_str()),
            Some("1700000000.000001")
        );
        assert_eq!(message.sent_at, Some(1_700_000_000));
        assert_eq!(message.edited_at, Some(1_700_000_005));
        assert_eq!(message.content, ContentKind::Photo);
        assert_eq!(message.text.as_deref(), Some("hello"));
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].remote_id, "F1");
        assert_eq!(message.attachments[0].byte_size, Some(10));
        assert_eq!(message.attachments[0].height, Some(30));
        let reply = message.reply_to.unwrap();
        assert_eq!(reply.message_id.as_str(), "1700000000.000001");
    }

    #[test]
    fn message_changed_lowers_to_edited_with_outer_channel() {
        let payload = callback(
            "Ev2",
            json!({
                "type": "message",
                "subtype": "message_changed",
                "channel": "C1",
                "message": {
                    "type": "message",
                    "user": "U1",
                    "text": "hello again",
                    "ts": "1700000000.000100",
                    "edited": { "user": "U1", "ts": "1700000009.000000" }
                }
            }),
        );
        let InboundUpdate::MessageEdited(message) = lower_update(&payload) else {
            panic!("expected edited message");
        };
        assert_eq!(message.chat.id.as_str(), "C1");
        assert_eq!(message.text.as_deref(), Some("hello again"));
        assert_eq!(message.edited_at, Some(1_700_000_009));
        assert_eq!(message.update_cursor.as_deref(), Some("Ev2"));
    }

    #[test]
    fn message_deleted_carries_only_ids() {
        let payload = callback(
            "Ev3",
            json!({
                "type": "message",
                "subtype": "message_deleted",
                "channel": "C1",
                "deleted_ts": "1700000000.000100"
            }),
        );
        let InboundUpdate::MessageDeleted(deleted) = lower_update(&payload) else {
            panic!("expected deleted message");
        };
        assert_eq!(deleted.chat_id.as_str(), "C1");
        assert_eq!(deleted.message_id.as_str(), "1700000000.000100");
        assert_eq!(deleted.update_cursor.as_deref(), Some("Ev3"));
    }

    #[test]
    fn member_join_and_leave_lower_with_event_time() {
        let joined = callback(
            "Ev4",
            json!({
                "type": "member_joined_channel",
                "channel": "G1",
                "user": "U2"
            }),
        );
        let InboundUpdate::MemberJoined(member) = lower_update(&joined) else {
            panic!("expected member join");
        };
        assert_eq!(member.chat_id.as_str(), "G1");
        assert_eq!(member.user.id.as_str(), "U2");
        assert_eq!(member.at, Some(1_700_000_000));

        let left = callback(
            "Ev5",
            json!({
                "type": "member_left_channel",
                "channel": "G1",
                "user": "U2"
            }),
        );
        assert!(matches!(lower_update(&left), InboundUpdate::MemberLeft(_)));
    }

    #[test]
    fn reactions_lower_added_and_removed() {
        let added = callback(
            "Ev6",
            json!({
                "type": "reaction_added",
                "user": "U2",
                "reaction": "eyes",
                "item": { "type": "message", "channel": "C1", "ts": "1700000000.000100" }
            }),
        );
        let InboundUpdate::Reaction(reaction) = lower_update(&added) else {
            panic!("expected reaction");
        };
        assert_eq!(reaction.chat_id.as_str(), "C1");
        assert_eq!(reaction.message_id.as_str(), "1700000000.000100");
        assert_eq!(reaction.user.as_ref().unwrap().id.as_str(), "U2");
        assert_eq!(reaction.added, vec!["eyes".to_owned()]);
        assert!(reaction.removed.is_empty());

        let removed = callback(
            "Ev7",
            json!({
                "type": "reaction_removed",
                "user": "U2",
                "reaction": "eyes",
                "item": { "type": "message", "channel": "C1", "ts": "1700000000.000100" }
            }),
        );
        let InboundUpdate::Reaction(reaction) = lower_update(&removed) else {
            panic!("expected reaction");
        };
        assert!(reaction.added.is_empty());
        assert_eq!(reaction.removed, vec!["eyes".to_owned()]);
    }

    #[test]
    fn app_mention_and_bot_message_lower_as_messages() {
        let mention = callback(
            "Ev8",
            json!({
                "type": "app_mention",
                "channel": "C1",
                "user": "U1",
                "text": "<@UBOT> status",
                "ts": "1700000000.000100"
            }),
        );
        let InboundUpdate::Message(message) = lower_update(&mention) else {
            panic!("expected mentioned message");
        };
        assert_eq!(message.text.as_deref(), Some("<@UBOT> status"));

        let bot = callback(
            "Ev9",
            json!({
                "type": "message",
                "subtype": "bot_message",
                "channel": "C1",
                "bot_id": "B1",
                "username": "fixture-bot",
                "text": "automated",
                "ts": "1700000000.000101"
            }),
        );
        let InboundUpdate::Message(message) = lower_update(&bot) else {
            panic!("expected bot message");
        };
        assert_eq!(message.author.id.as_str(), "B1");
        assert_eq!(message.author.username.as_deref(), Some("fixture-bot"));
    }

    #[test]
    fn unknown_kinds_and_malformed_callbacks_are_declared_unsupported() {
        let unknown = callback(
            "Ev10",
            json!({
                "type": "channel_created",
                "channel": { "id": "C1" }
            }),
        );
        assert_eq!(
            lower_update(&unknown),
            InboundUpdate::Unsupported {
                raw_kind: "channel_created".into()
            }
        );

        let subtype = callback(
            "Ev11",
            json!({
                "type": "message",
                "subtype": "channel_topic",
                "channel": "C1",
                "ts": "1700000000.000100"
            }),
        );
        assert_eq!(
            lower_update(&subtype),
            InboundUpdate::Unsupported {
                raw_kind: "message_subtype_channel_topic".into()
            }
        );

        assert_eq!(
            lower_update(&json!({"type": "fixture"})),
            InboundUpdate::Unsupported {
                raw_kind: "fixture".into()
            }
        );
        assert_eq!(
            lower_update(&json!({"type": "event_callback"})),
            InboundUpdate::Unsupported {
                raw_kind: "missing_event".into()
            }
        );
    }

    #[test]
    fn channel_id_shapes_select_chat_kind() {
        assert_eq!(chat_kind("D1"), ChatKind::Direct);
        assert_eq!(chat_kind("C1"), ChatKind::Group);
        assert_eq!(chat_kind("G1"), ChatKind::Group);
        assert_eq!(chat_kind("X1"), ChatKind::Unknown);
    }

    #[test]
    fn lower_event_stamps_the_slack_channel() {
        let payload = callback(
            "Ev12",
            json!({
                "type": "message",
                "channel": "D1",
                "user": "U1",
                "text": "direct",
                "ts": "1700000000.000100"
            }),
        );
        let event = lower_event(&payload);
        assert_eq!(event.channel.as_str(), "slack");
        let InboundUpdate::Message(message) = event.update else {
            panic!("expected message");
        };
        assert_eq!(message.chat.kind, ChatKind::Direct);
    }

    #[test]
    fn message_replied_lowers_the_nested_reply() {
        let payload = callback(
            "Ev13",
            json!({
                "type": "message",
                "subtype": "message_replied",
                "channel": "C1",
                "ts": "1700000000.000100",
                "message": {
                    "type": "message",
                    "user": "U1",
                    "text": "thread reply",
                    "ts": "1700000000.000100",
                    "thread_ts": "1700000000.000001"
                }
            }),
        );
        let InboundUpdate::Message(message) = lower_update(&payload) else {
            panic!("expected nested reply message");
        };
        assert_eq!(message.text.as_deref(), Some("thread reply"));
        assert_eq!(
            message.thread_id.as_ref().map(|id| id.as_str()),
            Some("1700000000.000001")
        );
    }

    #[test]
    fn non_message_reaction_items_are_declared_unsupported() {
        let payload = callback(
            "Ev14",
            json!({
                "type": "reaction_added",
                "user": "U2",
                "reaction": "eyes",
                "item": { "type": "file", "file": "F1" }
            }),
        );
        assert_eq!(
            lower_update(&payload),
            InboundUpdate::Unsupported {
                raw_kind: "reaction_item_not_message".into()
            }
        );
    }
}
