//! Contract-level signed-HTTP test: a full normalized message crosses
//! the public receiver API with every field intact, and a signature
//! failure is rejected before the body is parsed.

use a4mc::{
    AttachmentRef, ChannelAdapter, ChannelChat, ChannelUser, ChatKind, ContentKind, ExternalChatId,
    ExternalMessageId, ExternalUserId, GeoPoint, InboundMessage, InboundUpdate, ReplyRef,
    SecretToken,
};
use a4mc_webhook::{
    CHANNEL, DeliveryOutcome, SIGNATURE_HEADER, TIMESTAMP_HEADER, WebhookAdapter, WebhookReceiver,
    WebhookRequest, WebhookSecret, WebhookVerifier, descriptor, sign,
};

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

fn secret() -> WebhookSecret {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let key = format!(
        "a4mc-webhook-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    );
    WebhookSecret::new(SecretToken::try_from_string(key).unwrap()).unwrap()
}

#[test]
fn signed_full_message_crosses_the_public_receiver_without_field_loss() {
    let update = InboundUpdate::Message(full_message());
    let body = serde_json::to_vec(&update).unwrap();
    let timestamp = 1_700_000_000u64;
    let key = secret();
    let request = WebhookRequest::new("POST", body.clone())
        .with_header(TIMESTAMP_HEADER, timestamp.to_string())
        .with_header(SIGNATURE_HEADER, sign(&key, timestamp, &body));

    let receiver = WebhookReceiver::new(WebhookVerifier::new(key, 300));
    let DeliveryOutcome::Event(delivery) = receiver.receive(&request, timestamp).unwrap() else {
        panic!("expected a verified event");
    };

    assert_eq!(delivery.event.channel.as_str(), CHANNEL);
    assert_eq!(delivery.event.update, update);
    assert_eq!(delivery.signed_at, timestamp);
    assert_eq!(
        receiver.receive(&request, timestamp).unwrap(),
        DeliveryOutcome::Duplicate
    );
}

#[test]
fn a_bad_signature_is_rejected_before_the_body_is_lowered() {
    let body = serde_json::to_vec(&InboundUpdate::Message(full_message())).unwrap();
    let request = WebhookRequest::new("POST", body)
        .with_header(TIMESTAMP_HEADER, "1700000000")
        .with_header(SIGNATURE_HEADER, "sha256=00");
    let receiver = WebhookReceiver::new(WebhookVerifier::new(secret(), 300));
    let error = receiver.receive(&request, 1_700_000_000).unwrap_err();
    assert_eq!(error.code, "a4mc_webhook_signature_invalid");
    assert!(!error.message.contains("sha256=00"));
}

#[test]
fn descriptor_reports_a_receive_only_channel() {
    let report = ChannelAdapter::descriptor(&WebhookAdapter);
    assert_eq!(report, descriptor());
    assert_eq!(report.channel.as_str(), CHANNEL);
}
