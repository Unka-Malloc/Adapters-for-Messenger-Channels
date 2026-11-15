//! Contract-level Discord test: the public descriptor is complete over
//! the normalized vocabulary, and a Gateway dispatch lowers through the
//! public API with its identity, content and reply fields intact.

use a4mc::{
    ChannelAdapter, ChannelChat, ChannelUser, ChatKind, ContentKind, InboundUpdate, LaneMechanism,
    OutboundMessage, SendFeature, Support, UpdateKind,
};
use a4mc_discord::{DiscordChannel, MockDiscordApi, descriptor, lower_event};
use serde_json::json;
use std::sync::Arc;

#[test]
fn descriptor_is_complete_over_the_contract_vocabulary() {
    let channel = DiscordChannel::new(Arc::new(MockDiscordApi::default()));
    let report = ChannelAdapter::descriptor(&channel);
    assert_eq!(report, descriptor());
    assert_eq!(report.channel.as_str(), "discord");
    assert_eq!(
        report.receive_support(LaneMechanism::Socket),
        Support::Native
    );
    assert_eq!(
        report.receive_support(LaneMechanism::Webhook),
        Support::Unsupported
    );
    assert_eq!(
        report.receive_support(LaneMechanism::Poll),
        Support::Unsupported
    );
    for kind in [
        UpdateKind::Message,
        UpdateKind::MessageEdited,
        UpdateKind::MessageDeleted,
        UpdateKind::MemberJoined,
        UpdateKind::MemberLeft,
        UpdateKind::Reaction,
    ] {
        assert_eq!(report.update_support(kind), Support::Native);
    }
    for feature in [
        SendFeature::Idempotency,
        SendFeature::ReplyTo,
        SendFeature::Edit,
        SendFeature::Delete,
    ] {
        assert!(report.sends.contains_key(&feature));
    }
}

#[test]
fn gateway_message_lowers_and_sends_through_the_public_surface() {
    let event = lower_event(
        "MESSAGE_CREATE",
        &json!({
            "id": "M1",
            "channel_id": "C1",
            "guild_id": "G1",
            "author": { "id": "U1", "username": "alice", "global_name": "Alice" },
            "content": "hello",
            "timestamp": "2023-11-14T22:13:20Z",
            "message_reference": { "message_id": "M0" }
        }),
        Some(1),
    );
    assert_eq!(event.channel.as_str(), "discord");
    let InboundUpdate::Message(message) = &event.update else {
        panic!("expected a message");
    };
    assert_eq!(
        message.chat,
        ChannelChat {
            id: "C1".into(),
            kind: ChatKind::Group,
            title: None
        }
    );
    assert_eq!(
        message.author,
        ChannelUser {
            id: "U1".into(),
            username: Some("alice".into()),
            display_name: Some("Alice".into()),
        }
    );
    assert_eq!(message.content, ContentKind::Text);
    assert_eq!(message.text.as_deref(), Some("hello"));
    assert_eq!(message.reply_to.as_ref().unwrap().message_id.as_str(), "M0");

    let api = Arc::new(MockDiscordApi::default());
    let channel = DiscordChannel::new(Arc::clone(&api));
    let receipt = channel
        .send(&OutboundMessage::new("C1", "reply", "contract-1"))
        .unwrap();
    assert_eq!(receipt.message_ids.len(), 1);
    assert_eq!(api.posted_requests()[0].content, "reply");
}
