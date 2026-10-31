//! Normalize Telegram Bot API inbound messages into channel content.

use serde_json::Value;

const REPLY_PREVIEW_CHARS: usize = 240;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundKind {
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
    Unsupported,
}

impl InboundKind {
    pub fn as_str(&self) -> &'static str {
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
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub kind: String,
    pub file_id: String,
    pub file_unique_id: Option<String>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: Option<i64>,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub duration: Option<i64>,
    pub emoji: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRef {
    pub message_id: i64,
    pub from_username: Option<String>,
    pub preview: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InboundMessage {
    pub update_id: i64,
    pub chat_id: i64,
    /// The platform's chat type (`private`, `group`, `supergroup`, `channel`).
    pub chat_type: String,
    pub user_id: i64,
    pub username: Option<String>,
    /// Sender's display name (first + last) as the platform reports it.
    pub from_name: Option<String>,
    pub is_private: bool,
    pub message_id: i64,
    pub message_thread_id: Option<i64>,
    pub edited: bool,
    /// Platform-reported send time (unix seconds).
    pub date: Option<i64>,
    /// Platform-reported edit time (unix seconds), when edited.
    pub edit_date: Option<i64>,
    pub kind: InboundKind,
    /// Plain `text` field when present.
    pub text: Option<String>,
    /// Media caption when present.
    pub caption: Option<String>,
    pub media: Vec<MediaRef>,
    pub reply_to: Option<ReplyRef>,
    pub forward_label: Option<String>,
    pub location: Option<(f64, f64)>,
    pub venue_label: Option<String>,
    pub contact_label: Option<String>,
    pub poll_question: Option<String>,
}

impl InboundMessage {
    /// Body used for slash-command parsing: prefer text, else caption.
    pub fn control_text(&self) -> String {
        self.text
            .as_deref()
            .or(self.caption.as_deref())
            .unwrap_or("")
            .trim()
            .to_owned()
    }

    /// Body forwarded to the local agent, including reply/media envelopes.
    pub fn agent_text(&self) -> String {
        normalize_agent_text(self)
    }

    pub fn has_agent_content(&self) -> bool {
        !self.agent_text().trim().is_empty()
    }
}

pub fn parse_message_update(
    update_id: i64,
    message: &Value,
    edited: bool,
) -> Option<InboundMessage> {
    let chat = message.get("chat")?;
    let from = message.get("from")?;
    let chat_type = chat.get("type")?.as_str()?.to_owned();
    let chat_id = chat.get("id")?.as_i64()?;
    let user_id = from.get("id")?.as_i64()?;
    let message_id = message.get("message_id")?.as_i64()?;
    let username = from
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let from_name = [
        from.get("first_name").and_then(Value::as_str),
        from.get("last_name").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    let from_name = if from_name.is_empty() {
        None
    } else {
        Some(from_name)
    };
    let text = message
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let caption = message
        .get("caption")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let message_thread_id = message.get("message_thread_id").and_then(Value::as_i64);
    let date = message.get("date").and_then(Value::as_i64);
    let edit_date = message.get("edit_date").and_then(Value::as_i64);
    let reply_to = message.get("reply_to_message").and_then(parse_reply_ref);
    let forward_label = forward_label(message);
    let classified = classify_content(message);

    // Drop empty unsupported updates with no usable body.
    if matches!(classified.kind, InboundKind::Unsupported)
        && text
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        && caption
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
    {
        return None;
    }

    Some(InboundMessage {
        update_id,
        chat_id,
        is_private: chat_type == "private",
        chat_type,
        user_id,
        username,
        from_name,
        message_id,
        message_thread_id,
        edited,
        date,
        edit_date,
        kind: classified.kind,
        text,
        caption,
        media: classified.media,
        reply_to,
        forward_label,
        location: classified.location,
        venue_label: classified.venue_label,
        contact_label: classified.contact_label,
        poll_question: classified.poll_question,
    })
}

struct ClassifiedContent {
    kind: InboundKind,
    media: Vec<MediaRef>,
    location: Option<(f64, f64)>,
    venue_label: Option<String>,
    contact_label: Option<String>,
    poll_question: Option<String>,
}

fn classify_content(message: &Value) -> ClassifiedContent {
    if let Some(photos) = message.get("photo").and_then(Value::as_array)
        && let Some(best) = photos.last()
    {
        return ClassifiedContent {
            kind: InboundKind::Photo,
            media: vec![media_from_file(best, "photo")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(document) = message.get("document") {
        return ClassifiedContent {
            kind: InboundKind::Document,
            media: vec![media_from_file(document, "document")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(video) = message.get("video") {
        return ClassifiedContent {
            kind: InboundKind::Video,
            media: vec![media_from_file(video, "video")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(animation) = message.get("animation") {
        return ClassifiedContent {
            kind: InboundKind::Animation,
            media: vec![media_from_file(animation, "animation")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(voice) = message.get("voice") {
        return ClassifiedContent {
            kind: InboundKind::Voice,
            media: vec![media_from_file(voice, "voice")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(audio) = message.get("audio") {
        return ClassifiedContent {
            kind: InboundKind::Audio,
            media: vec![media_from_file(audio, "audio")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(sticker) = message.get("sticker") {
        let mut media = media_from_file(sticker, "sticker");
        media.emoji = sticker
            .get("emoji")
            .and_then(Value::as_str)
            .map(str::to_owned);
        return ClassifiedContent {
            kind: InboundKind::Sticker,
            media: vec![media],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(video_note) = message.get("video_note") {
        return ClassifiedContent {
            kind: InboundKind::VideoNote,
            media: vec![media_from_file(video_note, "video_note")],
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(venue) = message.get("venue") {
        let title = venue
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("venue");
        let address = venue.get("address").and_then(Value::as_str).unwrap_or("");
        let location = venue
            .get("location")
            .and_then(parse_location)
            .or_else(|| message.get("location").and_then(parse_location));
        return ClassifiedContent {
            kind: InboundKind::Venue,
            media: Vec::new(),
            location,
            venue_label: Some(format!("{title} — {address}")),
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(location) = message.get("location").and_then(parse_location) {
        return ClassifiedContent {
            kind: InboundKind::Location,
            media: Vec::new(),
            location: Some(location),
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    if let Some(contact) = message.get("contact") {
        let name = [
            contact.get("first_name").and_then(Value::as_str),
            contact.get("last_name").and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        let phone = contact
            .get("phone_number")
            .and_then(Value::as_str)
            .unwrap_or("");
        return ClassifiedContent {
            kind: InboundKind::Contact,
            media: Vec::new(),
            location: None,
            venue_label: None,
            contact_label: Some(format!("{} {}", name.trim(), phone).trim().to_owned()),
            poll_question: None,
        };
    }
    if let Some(poll) = message.get("poll") {
        let question = poll
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or("poll")
            .to_owned();
        return ClassifiedContent {
            kind: InboundKind::Poll,
            media: Vec::new(),
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: Some(question),
        };
    }
    if message.get("text").and_then(Value::as_str).is_some() {
        return ClassifiedContent {
            kind: InboundKind::Text,
            media: Vec::new(),
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        };
    }
    ClassifiedContent {
        kind: InboundKind::Unsupported,
        media: Vec::new(),
        location: None,
        venue_label: None,
        contact_label: None,
        poll_question: None,
    }
}

fn media_from_file(value: &Value, kind: &str) -> MediaRef {
    MediaRef {
        kind: kind.to_owned(),
        file_id: value
            .get("file_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        file_unique_id: value
            .get("file_unique_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        file_name: value
            .get("file_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        mime_type: value
            .get("mime_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        file_size: value.get("file_size").and_then(Value::as_i64),
        width: value.get("width").and_then(Value::as_i64),
        height: value.get("height").and_then(Value::as_i64),
        duration: value.get("duration").and_then(Value::as_i64),
        emoji: None,
    }
}

fn parse_location(value: &Value) -> Option<(f64, f64)> {
    Some((
        value.get("latitude")?.as_f64()?,
        value.get("longitude")?.as_f64()?,
    ))
}

fn parse_reply_ref(value: &Value) -> Option<ReplyRef> {
    let message_id = value.get("message_id")?.as_i64()?;
    let from_username = value
        .get("from")
        .and_then(|from| from.get("username"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let preview = value
        .get("text")
        .and_then(Value::as_str)
        .or_else(|| value.get("caption").and_then(Value::as_str))
        .map(|text| truncate(text, REPLY_PREVIEW_CHARS));
    let kind = classify_content(value).kind;
    Some(ReplyRef {
        message_id,
        from_username,
        preview,
        kind: Some(kind.as_str().to_owned()),
    })
}

fn forward_label(message: &Value) -> Option<String> {
    if let Some(origin) = message.get("forward_origin") {
        match origin.get("type").and_then(Value::as_str) {
            Some("user") => {
                let user = origin.get("sender_user")?;
                let name = user
                    .get("username")
                    .and_then(Value::as_str)
                    .map(|value| format!("@{value}"))
                    .or_else(|| {
                        user.get("first_name")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })?;
                return Some(format!("forwarded from {name}"));
            }
            Some("channel") => {
                let title = origin
                    .get("chat")
                    .and_then(|chat| chat.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or("channel");
                return Some(format!("forwarded from channel {title}"));
            }
            Some("hidden_user") => {
                let name = origin
                    .get("sender_user_name")
                    .and_then(Value::as_str)
                    .unwrap_or("hidden user");
                return Some(format!("forwarded from {name}"));
            }
            _ => {}
        }
    }
    if message.get("forward_date").is_some() {
        return Some("forwarded message".to_owned());
    }
    None
}

pub fn normalize_agent_text(message: &InboundMessage) -> String {
    let mut lines = Vec::new();
    if message.edited {
        lines.push("[edited]".to_owned());
    }
    if let Some(forward) = &message.forward_label {
        lines.push(format!("[{forward}]"));
    }
    if let Some(reply) = &message.reply_to {
        let who = reply
            .from_username
            .as_deref()
            .map(|value| format!("@{value}"))
            .unwrap_or_else(|| "message".to_owned());
        let kind = reply.kind.as_deref().unwrap_or("text");
        match &reply.preview {
            Some(preview) if !preview.trim().is_empty() => {
                lines.push(format!("[reply to {who} ({kind}): {preview}]"));
            }
            _ => lines.push(format!(
                "[reply to {who} ({kind}) message_id={}]",
                reply.message_id
            )),
        }
    }
    if matches!(message.kind, InboundKind::Unsupported) {
        lines.push("[unsupported telegram content]".to_owned());
    }
    for media in &message.media {
        lines.push(format_media_placeholder(media));
    }
    if let Some((lat, lon)) = message.location {
        lines.push(format!("[location lat={lat} lon={lon}]"));
    }
    if let Some(venue) = &message.venue_label {
        lines.push(format!("[venue {venue}]"));
    }
    if let Some(contact) = &message.contact_label {
        lines.push(format!("[contact {contact}]"));
    }
    if let Some(question) = &message.poll_question {
        lines.push(format!("[poll {question}]"));
    }
    let body = message
        .text
        .as_deref()
        .or(message.caption.as_deref())
        .unwrap_or("")
        .trim();
    if !body.is_empty() {
        lines.push(body.to_owned());
    }
    lines.join("\n")
}

fn format_media_placeholder(media: &MediaRef) -> String {
    let mut parts = vec![format!("[{}", media.kind)];
    if !media.file_id.is_empty() {
        parts.push(format!("file_id={}", media.file_id));
    }
    if let Some(name) = &media.file_name {
        parts.push(format!("name={name}"));
    }
    if let Some(mime) = &media.mime_type {
        parts.push(format!("mime={mime}"));
    }
    if let Some(size) = media.file_size {
        parts.push(format!("bytes={size}"));
    }
    if let (Some(width), Some(height)) = (media.width, media.height) {
        parts.push(format!("{width}x{height}"));
    }
    if let Some(duration) = media.duration {
        parts.push(format!("duration={duration}s"));
    }
    if let Some(emoji) = &media.emoji {
        parts.push(format!("emoji={emoji}"));
    }
    format!("{}]", parts.join(" "))
}

fn truncate(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_owned();
    }
    let mut out = trimmed
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_photo_caption_and_reply() {
        let message = parse_message_update(
            11,
            &json!({
                "message_id": 9,
                "caption": "see this",
                "photo": [
                    { "file_id": "small", "width": 10, "height": 10, "file_size": 1 },
                    { "file_id": "large", "width": 100, "height": 80, "file_size": 99 }
                ],
                "reply_to_message": {
                    "message_id": 8,
                    "text": "earlier note",
                    "from": { "id": 1, "username": "bob" }
                },
                "chat": { "id": 42, "type": "private" },
                "from": { "id": 7, "username": "alice" }
            }),
            false,
        )
        .unwrap();
        assert_eq!(message.kind, InboundKind::Photo);
        assert_eq!(message.media[0].file_id, "large");
        assert_eq!(message.caption.as_deref(), Some("see this"));
        assert_eq!(message.control_text(), "see this");
        let agent = message.agent_text();
        assert!(agent.contains("[reply to @bob (text): earlier note]"));
        assert!(agent.contains("[photo file_id=large"));
        assert!(agent.contains("see this"));
    }

    #[test]
    fn parses_sticker_and_document() {
        let sticker = parse_message_update(
            1,
            &json!({
                "message_id": 2,
                "sticker": { "file_id": "st1", "emoji": "😀", "width": 1, "height": 1 },
                "chat": { "id": 1, "type": "private" },
                "from": { "id": 2 }
            }),
            false,
        )
        .unwrap();
        assert_eq!(sticker.kind, InboundKind::Sticker);
        assert!(sticker.agent_text().contains("emoji=😀"));

        let document = parse_message_update(
            1,
            &json!({
                "message_id": 3,
                "document": {
                    "file_id": "doc1",
                    "file_name": "notes.md",
                    "mime_type": "text/markdown",
                    "file_size": 12
                },
                "caption": "/status",
                "chat": { "id": 1, "type": "private" },
                "from": { "id": 2 }
            }),
            false,
        )
        .unwrap();
        assert_eq!(document.control_text(), "/status");
        assert!(document.agent_text().contains("name=notes.md"));
    }

    #[test]
    fn parses_location_contact_and_edited_text() {
        let location = parse_message_update(
            1,
            &json!({
                "message_id": 4,
                "location": { "latitude": 1.5, "longitude": 2.5 },
                "chat": { "id": 1, "type": "private" },
                "from": { "id": 2 }
            }),
            false,
        )
        .unwrap();
        assert!(location.agent_text().contains("lat=1.5"));

        let contact = parse_message_update(
            1,
            &json!({
                "message_id": 5,
                "contact": {
                    "phone_number": "+100",
                    "first_name": "Ada",
                    "last_name": "Lovelace"
                },
                "chat": { "id": 1, "type": "private" },
                "from": { "id": 2 }
            }),
            false,
        )
        .unwrap();
        assert!(contact.agent_text().contains("Ada Lovelace +100"));

        let edited = parse_message_update(
            1,
            &json!({
                "message_id": 6,
                "text": "hello",
                "date": 1_700_000_000,
                "edit_date": 1_700_000_100,
                "chat": { "id": 1, "type": "private" },
                "from": { "id": 2 }
            }),
            true,
        )
        .unwrap();
        assert!(edited.agent_text().starts_with("[edited]"));
        assert_eq!(edited.edit_date, Some(1_700_000_100));
    }
}
