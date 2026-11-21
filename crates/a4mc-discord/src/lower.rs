//! Lower Discord Gateway dispatch events onto the normalized `a4mc`
//! contract.
//!
//! One Gateway dispatch carries an event name (`MESSAGE_CREATE`,
//! `MESSAGE_UPDATE`, ...) and a JSON object. This module projects those
//! native shapes onto [`a4mc::InboundUpdate`]. Gateway event names the
//! dialect has not wired lower to [`a4mc::InboundUpdate::Unsupported`]
//! so the host observes the gap instead of losing it; the descriptor
//! declares the same coverage.
//!
//! Discord reports timestamps as ISO 8601 text. The contract carries
//! whole unix seconds, so this module parses the platform claim rather
//! than substituting local time. Missing or malformed timestamps become
//! `None`, never a fabricated value.

use a4mc::{
    AttachmentRef, ChannelChat, ChannelEvent, ChannelUser, ChatKind, ContentKind, DeletedMessage,
    ExternalChatId, ExternalMessageId, ExternalUserId, InboundMessage, InboundUpdate, MemberEvent,
    ReactionEvent, ReplyRef,
};
use serde_json::Value;

/// Lower one Gateway dispatch into a normalized channel event.
pub fn lower_event(event_name: &str, data: &Value, sequence: Option<u64>) -> ChannelEvent {
    ChannelEvent {
        channel: crate::channel_id(),
        update: lower_update(event_name, data, sequence),
    }
}

/// Lower one Gateway dispatch into one or more normalized channel events.
///
/// `MESSAGE_DELETE_BULK` carries a list of message ids and is expanded
/// into one deletion event per id, so a bulk delete is never reduced to
/// its first message or silently dropped.
pub fn lower_events(event_name: &str, data: &Value, sequence: Option<u64>) -> Vec<ChannelEvent> {
    if event_name == "MESSAGE_DELETE_BULK" {
        let Some(channel_id) = data
            .get("channel_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return vec![lower_event(event_name, data, sequence)];
        };
        let ids = data
            .get("ids")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if ids.is_empty() {
            return vec![lower_event(event_name, data, sequence)];
        }
        return ids
            .into_iter()
            .map(|message_id| ChannelEvent {
                channel: crate::channel_id(),
                update: InboundUpdate::MessageDeleted(DeletedMessage {
                    update_cursor: sequence.map(|value| value.to_string()),
                    chat_id: ExternalChatId::from(channel_id),
                    message_id: ExternalMessageId::from(message_id),
                }),
            })
            .collect();
    }
    vec![lower_event(event_name, data, sequence)]
}

/// Lower one Gateway dispatch payload into an inbound update.
pub fn lower_update(event_name: &str, data: &Value, sequence: Option<u64>) -> InboundUpdate {
    match event_name {
        "MESSAGE_CREATE" => lower_message(data, sequence, false),
        "MESSAGE_UPDATE" => lower_message(data, sequence, true),
        "MESSAGE_DELETE" => lower_delete(data, sequence),
        "GUILD_MEMBER_ADD" => lower_member(data, sequence, true),
        "GUILD_MEMBER_REMOVE" => lower_member(data, sequence, false),
        "MESSAGE_REACTION_ADD" => lower_reaction(data, sequence, true),
        "MESSAGE_REACTION_REMOVE" => lower_reaction(data, sequence, false),
        other => InboundUpdate::Unsupported {
            raw_kind: if other.is_empty() {
                "unknown_event".to_owned()
            } else {
                other.to_owned()
            },
        },
    }
}

fn lower_message(data: &Value, sequence: Option<u64>, edited: bool) -> InboundUpdate {
    let Some(message_id) = data
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return InboundUpdate::Unsupported {
            raw_kind: "message_without_identity".to_owned(),
        };
    };
    let Some(channel_id) = data
        .get("channel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return InboundUpdate::Unsupported {
            raw_kind: "message_without_channel".to_owned(),
        };
    };
    let author = data.get("author").filter(|value| value.is_object());
    let author_id = author
        .and_then(|author| author.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let username = author
        .and_then(|author| author.get("username"))
        .and_then(Value::as_str);
    let display_name = author
        .and_then(|author| author.get("global_name"))
        .and_then(Value::as_str)
        .or(username);
    let attachments: Vec<AttachmentRef> = data
        .get("attachments")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(lower_attachment).collect())
        .unwrap_or_default();
    let text = data
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let content = classify_content(data, &attachments, text.as_deref());
    let reply_to = lower_reply(data);
    let sent_at = data
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let edited_at = data
        .get("edited_timestamp")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let chat_kind = if data
        .get("guild_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        ChatKind::Group
    } else {
        // Discord omits the channel type from message dispatches. A
        // message outside a guild is a DM or group DM; both cross the
        // contract as a direct conversation shape.
        ChatKind::Direct
    };
    let poll_question = data
        .pointer("/poll/question/text")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let normalized = InboundMessage {
        update_cursor: sequence.map(|value| value.to_string()),
        chat: ChannelChat {
            id: ExternalChatId::from(channel_id),
            kind: chat_kind,
            title: None,
        },
        author: ChannelUser {
            id: ExternalUserId::from(author_id),
            username: username.map(str::to_owned),
            display_name: display_name.map(str::to_owned),
        },
        message_id: ExternalMessageId::from(message_id),
        thread_id: None,
        sent_at,
        edited_at,
        content,
        text,
        caption: None,
        attachments,
        reply_to,
        forward_label: forward_label(data),
        location: None,
        venue_label: None,
        contact_label: None,
        poll_question,
    };
    if edited {
        InboundUpdate::MessageEdited(normalized)
    } else {
        InboundUpdate::Message(normalized)
    }
}

fn lower_delete(data: &Value, sequence: Option<u64>) -> InboundUpdate {
    let (Some(message_id), Some(channel_id)) = (
        data.get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
        data.get("channel_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
    ) else {
        return InboundUpdate::Unsupported {
            raw_kind: "message_deleted_without_target".to_owned(),
        };
    };
    InboundUpdate::MessageDeleted(DeletedMessage {
        update_cursor: sequence.map(|value| value.to_string()),
        chat_id: ExternalChatId::from(channel_id),
        message_id: ExternalMessageId::from(message_id),
    })
}

fn lower_member(data: &Value, sequence: Option<u64>, joined: bool) -> InboundUpdate {
    let (Some(guild_id), Some(user_id)) = (
        data.get("guild_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
        data.pointer("/user/id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
    ) else {
        return InboundUpdate::Unsupported {
            raw_kind: "member_event_without_identity".to_owned(),
        };
    };
    let event = MemberEvent {
        update_cursor: sequence.map(|value| value.to_string()),
        chat_id: ExternalChatId::from(guild_id),
        user: ChannelUser {
            id: ExternalUserId::from(user_id),
            username: data
                .pointer("/user/username")
                .and_then(Value::as_str)
                .map(str::to_owned),
            display_name: data
                .pointer("/user/global_name")
                .and_then(Value::as_str)
                .or_else(|| data.pointer("/user/username").and_then(Value::as_str))
                .map(str::to_owned),
        },
        at: data
            .get("joined_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp),
    };
    if joined {
        InboundUpdate::MemberJoined(event)
    } else {
        InboundUpdate::MemberLeft(event)
    }
}

fn lower_reaction(data: &Value, sequence: Option<u64>, added: bool) -> InboundUpdate {
    let (Some(channel_id), Some(message_id)) = (
        data.get("channel_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
        data.get("message_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
    ) else {
        return InboundUpdate::Unsupported {
            raw_kind: "reaction_without_target".to_owned(),
        };
    };
    let emoji = data
        .pointer("/emoji/name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            data.pointer("/emoji/id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_owned);
    let user = data
        .get("user_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|user_id| ChannelUser {
            id: ExternalUserId::from(user_id),
            username: None,
            display_name: None,
        });
    let added_reactions = if added {
        emoji.iter().cloned().collect()
    } else {
        Vec::new()
    };
    let removed_reactions = if added {
        Vec::new()
    } else {
        emoji.into_iter().collect()
    };
    InboundUpdate::Reaction(ReactionEvent {
        update_cursor: sequence.map(|value| value.to_string()),
        chat_id: ExternalChatId::from(channel_id),
        message_id: ExternalMessageId::from(message_id),
        user,
        added: added_reactions,
        removed: removed_reactions,
    })
}

fn lower_attachment(item: &Value) -> Option<AttachmentRef> {
    let remote_id = item
        .get("id")
        .or_else(|| item.get("filename"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let file_name = item
        .get("filename")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mime_type = item
        .get("content_type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let kind = attachment_kind(mime_type.as_deref(), file_name.as_deref());
    Some(AttachmentRef {
        kind: kind.to_owned(),
        remote_id: remote_id.to_owned(),
        remote_unique_id: item
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|value| value != remote_id),
        file_name,
        mime_type,
        byte_size: item.get("size").and_then(Value::as_u64),
        width: item
            .get("width")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        height: item
            .get("height")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        duration_secs: item
            .get("duration_secs")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value >= 0.0)
            .map(|value| value.round() as u32),
        emoji: None,
    })
}

fn attachment_kind(mime_type: Option<&str>, file_name: Option<&str>) -> &'static str {
    let mime = mime_type.unwrap_or("").to_ascii_lowercase();
    let extension = file_name
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    if mime.starts_with("image/")
        || matches!(
            extension.as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "bmp"
        )
    {
        return "image";
    }
    if mime.starts_with("video/") || matches!(extension.as_str(), "mp4" | "mov" | "webm") {
        return "video";
    }
    if mime.starts_with("audio/") || matches!(extension.as_str(), "mp3" | "ogg" | "wav" | "m4a") {
        return "audio";
    }
    "file"
}

fn classify_content(
    data: &Value,
    attachments: &[AttachmentRef],
    text: Option<&str>,
) -> ContentKind {
    if data.get("poll").is_some_and(Value::is_object) {
        return ContentKind::Poll;
    }
    if let Some(attachment) = attachments.first() {
        return match attachment.kind.as_str() {
            "image" => ContentKind::Photo,
            "video" => ContentKind::Video,
            "audio" => ContentKind::Audio,
            _ => ContentKind::Document,
        };
    }
    if text.is_some() {
        return ContentKind::Text;
    }
    if data
        .get("embeds")
        .and_then(Value::as_array)
        .is_some_and(|embeds| !embeds.is_empty())
    {
        return ContentKind::Other("embed".to_owned());
    }
    ContentKind::Unsupported
}

fn lower_reply(data: &Value) -> Option<ReplyRef> {
    let reference = data
        .get("message_reference")
        .filter(|value| value.is_object())?;
    let message_id = reference
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let referenced = data
        .get("referenced_message")
        .filter(|value| value.is_object());
    let preview = referenced
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(bounded_preview);
    let author_username = referenced
        .and_then(|message| message.pointer("/author/username"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let content_kind = referenced.map(|message| {
        let attachments: Vec<AttachmentRef> = message
            .get("attachments")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(lower_attachment).collect())
            .unwrap_or_default();
        classify_content(
            message,
            &attachments,
            message.get("content").and_then(Value::as_str),
        )
    });
    Some(ReplyRef {
        message_id: ExternalMessageId::from(message_id),
        author_username,
        preview,
        content_kind,
    })
}

fn forward_label(data: &Value) -> Option<String> {
    let snapshot = data
        .get("message_snapshots")
        .and_then(Value::as_array)
        .and_then(|items| items.first())?
        .get("message")?;
    let author = snapshot
        .pointer("/author/username")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Some(format!("forwarded from {author}"))
}

fn bounded_preview(value: &str) -> String {
    const MAX_PREVIEW_CHARS: usize = 200;
    if value.chars().count() <= MAX_PREVIEW_CHARS {
        return value.to_owned();
    }
    let mut preview: String = value.chars().take(MAX_PREVIEW_CHARS).collect();
    preview.push('…');
    preview
}

/// Parse Discord's ISO 8601 timestamp (`2023-11-14T22:13:20.000000+00:00`
/// or the `Z` form) into whole unix seconds. Returns `None` for a value
/// that is not a valid UTC-offset timestamp; never substitutes local
/// time.
pub fn parse_timestamp(value: &str) -> Option<u64> {
    let (date, rest) = value.split_once('T').or_else(|| value.split_once(' '))?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    // Discord's `timestamp` is untrusted network text. A year outside the
    // proleptic Gregorian range Discord can actually emit is rejected
    // before any arithmetic, so a huge value cannot overflow.
    if date_parts.next().is_some() || !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return None;
    }
    let (time, offset_seconds) = if let Some(time) = rest.strip_suffix('Z') {
        (time, 0i64)
    } else if let Some(position) = rest.rfind(['+', '-']) {
        let (time, offset) = rest.split_at(position);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let offset = offset.trim_start_matches(['+', '-']);
        let (hours, minutes) = offset.split_once(':')?;
        let hours: i64 = hours.parse().ok()?;
        let minutes: i64 = minutes.parse().ok()?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        (time, sign * (hours * 3600 + minutes * 60))
    } else {
        (rest, 0)
    };
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second_text = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    let second: i64 = second_text.split('.').next()?.parse().ok()?;
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..60).contains(&second) {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)?
        .checked_sub(offset_seconds)?;
    u64::try_from(seconds).ok()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard
/// Hinnant's `days_from_civil`). Kept local so the dialect carries no
/// date-time dependency. Every step is checked: the parser accepts
/// network-controlled text, so an out-of-range value returns `None`
/// instead of panicking in debug or wrapping in release.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let year = year.checked_sub(i64::from(month <= 2))?;
    let era = if year >= 0 {
        year
    } else {
        year.checked_sub(399)?
    } / 400;
    let year_of_era = year.checked_sub(era.checked_mul(400)?)?;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * i64::from(month_prime) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_event(data: Value) -> InboundUpdate {
        lower_update("MESSAGE_CREATE", &data, Some(42))
    }

    #[test]
    fn message_create_maps_every_available_field() {
        let update = create_event(json!({
            "id": "M1",
            "channel_id": "C1",
            "guild_id": "G1",
            "author": {
                "id": "U1",
                "username": "alice",
                "global_name": "Alice"
            },
            "content": "hello",
            "timestamp": "2023-11-14T22:13:20.000000+00:00",
            "edited_timestamp": "2023-11-14T22:13:30.000000+00:00",
            "message_reference": { "message_id": "M0", "channel_id": "C1" },
            "referenced_message": {
                "id": "M0",
                "author": { "id": "U2", "username": "bob" },
                "content": "parent"
            },
            "attachments": [{
                "id": "A1",
                "filename": "chart.png",
                "content_type": "image/png",
                "size": 10,
                "width": 20,
                "height": 30,
                "duration_secs": 1.4
            }],
            "poll": { "question": { "text": "Which?" } }
        }));
        let InboundUpdate::Message(message) = update else {
            panic!("expected message");
        };
        assert_eq!(message.update_cursor.as_deref(), Some("42"));
        assert_eq!(message.chat.id.as_str(), "C1");
        assert_eq!(message.chat.kind, ChatKind::Group);
        assert_eq!(message.author.id.as_str(), "U1");
        assert_eq!(message.author.username.as_deref(), Some("alice"));
        assert_eq!(message.author.display_name.as_deref(), Some("Alice"));
        assert_eq!(message.message_id.as_str(), "M1");
        assert_eq!(message.sent_at, Some(1_700_000_000));
        assert_eq!(message.edited_at, Some(1_700_000_010));
        assert_eq!(message.content, ContentKind::Poll);
        assert_eq!(message.text.as_deref(), Some("hello"));
        assert_eq!(message.poll_question.as_deref(), Some("Which?"));
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].kind, "image");
        assert_eq!(message.attachments[0].remote_id, "A1");
        assert_eq!(
            message.attachments[0].file_name.as_deref(),
            Some("chart.png")
        );
        assert_eq!(message.attachments[0].duration_secs, Some(1));
        let reply = message.reply_to.unwrap();
        assert_eq!(reply.message_id.as_str(), "M0");
        assert_eq!(reply.author_username.as_deref(), Some("bob"));
        assert_eq!(reply.preview.as_deref(), Some("parent"));
        assert_eq!(reply.content_kind, Some(ContentKind::Text));
    }

    #[test]
    fn message_update_lowers_as_edited_with_partial_author() {
        let update = lower_update(
            "MESSAGE_UPDATE",
            &json!({
                "id": "M1",
                "channel_id": "D1",
                "content": "edited",
                "timestamp": "2023-11-14T22:13:20Z",
                "edited_timestamp": "2023-11-14T22:13:21Z"
            }),
            Some(43),
        );
        let InboundUpdate::MessageEdited(message) = update else {
            panic!("expected edited message");
        };
        assert_eq!(message.chat.kind, ChatKind::Direct);
        assert_eq!(message.author.id.as_str(), "unknown");
        assert_eq!(message.text.as_deref(), Some("edited"));
        assert_eq!(message.edited_at, Some(1_700_000_001));
    }

    #[test]
    fn delete_member_and_reaction_events_lower_with_cursor() {
        let InboundUpdate::MessageDeleted(deleted) = lower_update(
            "MESSAGE_DELETE",
            &json!({"id": "M1", "channel_id": "C1"}),
            Some(7),
        ) else {
            panic!("expected delete");
        };
        assert_eq!(deleted.message_id.as_str(), "M1");
        assert_eq!(deleted.update_cursor.as_deref(), Some("7"));

        let InboundUpdate::MemberJoined(joined) = lower_update(
            "GUILD_MEMBER_ADD",
            &json!({
                "guild_id": "G1",
                "user": { "id": "U1", "username": "alice", "global_name": "Alice" },
                "joined_at": "2023-11-14T22:13:20Z"
            }),
            Some(8),
        ) else {
            panic!("expected member join");
        };
        assert_eq!(joined.chat_id.as_str(), "G1");
        assert_eq!(joined.user.id.as_str(), "U1");
        assert_eq!(joined.user.display_name.as_deref(), Some("Alice"));
        assert_eq!(joined.at, Some(1_700_000_000));

        let InboundUpdate::Reaction(added) = lower_update(
            "MESSAGE_REACTION_ADD",
            &json!({
                "user_id": "U2",
                "channel_id": "C1",
                "message_id": "M1",
                "emoji": { "name": "eyes" }
            }),
            Some(9),
        ) else {
            panic!("expected reaction");
        };
        assert_eq!(added.user.as_ref().unwrap().id.as_str(), "U2");
        assert_eq!(added.added, vec!["eyes".to_owned()]);
        assert!(added.removed.is_empty());

        let InboundUpdate::Reaction(removed) = lower_update(
            "MESSAGE_REACTION_REMOVE",
            &json!({
                "user_id": "U2",
                "channel_id": "C1",
                "message_id": "M1",
                "emoji": { "id": "E1" }
            }),
            None,
        ) else {
            panic!("expected reaction removal");
        };
        assert!(removed.added.is_empty());
        assert_eq!(removed.removed, vec!["E1".to_owned()]);
    }

    #[test]
    fn bulk_delete_expands_every_message_id() {
        let events = lower_events(
            "MESSAGE_DELETE_BULK",
            &json!({"channel_id": "C1", "ids": ["M1", "M2", "M3"]}),
            Some(10),
        );
        assert_eq!(events.len(), 3);
        for (event, expected) in events.iter().zip(["M1", "M2", "M3"]) {
            assert_eq!(event.channel.as_str(), crate::CHANNEL);
            let InboundUpdate::MessageDeleted(deleted) = &event.update else {
                panic!("expected deletion");
            };
            assert_eq!(deleted.message_id.as_str(), expected);
            assert_eq!(deleted.chat_id.as_str(), "C1");
            assert_eq!(deleted.update_cursor.as_deref(), Some("10"));
        }
    }

    #[test]
    fn unknown_events_and_malformed_payloads_are_declared_unsupported() {
        assert_eq!(
            lower_update("TYPING_START", &json!({}), None),
            InboundUpdate::Unsupported {
                raw_kind: "TYPING_START".into()
            }
        );
        assert_eq!(
            lower_update("MESSAGE_CREATE", &json!({"id": "M1"}), None),
            InboundUpdate::Unsupported {
                raw_kind: "message_without_channel".into()
            }
        );
        assert_eq!(
            lower_update("MESSAGE_DELETE", &json!({"id": "M1"}), None),
            InboundUpdate::Unsupported {
                raw_kind: "message_deleted_without_target".into()
            }
        );
    }

    #[test]
    fn timestamps_parse_utc_offsets_and_reject_invalid_values() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_timestamp("2023-11-14T22:13:20.000000+00:00"),
            Some(1_700_000_000)
        );
        assert_eq!(
            parse_timestamp("2023-11-14T23:13:20+01:00"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_timestamp("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        assert_eq!(parse_timestamp("2023-02-29T00:00:00Z"), None);
        assert_eq!(parse_timestamp("not-a-time"), None);
        assert_eq!(parse_timestamp("2023-11-14T25:00:00Z"), None);
    }

    #[test]
    fn out_of_range_years_are_rejected_instead_of_overflowing() {
        // `999999999999999999999` does not fit i64; a four-digit but
        // far-future year must be rejected before `days_from_civil`.
        assert_eq!(
            parse_timestamp("999999999999999999999-01-01T00:00:00Z"),
            None
        );
        assert_eq!(parse_timestamp("10000-01-01T00:00:00Z"), None);
        assert_eq!(parse_timestamp("0-01-01T00:00:00Z"), None);
        // The largest accepted year still parses without overflow.
        assert_eq!(
            parse_timestamp("9999-12-31T23:59:59Z"),
            Some(253_402_300_799)
        );
    }

    #[test]
    fn forward_snapshot_is_labelled_and_previews_are_bounded() {
        let update = create_event(json!({
            "id": "M1",
            "channel_id": "C1",
            "author": { "id": "U1", "username": "alice" },
            "content": "forwarded body",
            "message_snapshots": [{
                "message": { "author": { "username": "bob" }, "content": "original" }
            }]
        }));
        let InboundUpdate::Message(message) = update else {
            panic!("expected message");
        };
        assert_eq!(message.forward_label.as_deref(), Some("forwarded from bob"));
        let long = "x".repeat(250);
        let preview = bounded_preview(&long);
        assert_eq!(preview.chars().count(), 201);
        assert!(preview.ends_with('…'));
    }
}
