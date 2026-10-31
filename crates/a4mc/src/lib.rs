//! A4MC — the normalized messenger-channel contract.
//!
//! Every `a4mc-<channel>` dialect crate lowers one messenger platform
//! onto this vocabulary:
//!
//! * [`update`] — inbound updates: message receipt, edit/delete, member
//!   and reaction events, lowered into one enum;
//! * [`send`] — outbound sends carrying an idempotency key, and their
//!   delivery receipts;
//! * [`identity`] — external channel identity: who the *platform* says
//!   a user or chat is. It never asserts a host principal — mapping
//!   channel identity to host principals is host policy;
//! * [`mechanism`] / [`descriptor`] — platform receive-mechanism
//!   classification (poll, webhook, socket) and the per-adapter support
//!   report. Incomplete support is declared, never claimed;
//! * [`lane`] — the `LanePort` the composing host installs once per
//!   process so a channel can reach local agent work;
//! * [`custody`] — the `CustodyPort` the composing host installs so a
//!   channel can resolve its bot token. The port only; this crate never
//!   stores secrets, and secret material never appears in serialized or
//!   debug forms.
//!
//! The crate is the boundary layer: serde types and ports. No network
//! code, no custody, no ledgers.

pub mod custody;
pub mod descriptor;
pub mod error;
pub mod identity;
pub mod lane;
pub mod mechanism;
pub mod send;
pub mod update;

pub use custody::{CustodyPort, MAX_SECRET_BYTES, SecretError, SecretToken};
pub use descriptor::{ChannelAdapter, ChannelDescriptor, SendFeature, Support, UpdateKind};
pub use error::ChannelError;
pub use identity::{
    ChannelChat, ChannelId, ChannelUser, ChatKind, ExternalChatId, ExternalMessageId,
    ExternalUserId,
};
pub use lane::LanePort;
pub use mechanism::LaneMechanism;
pub use send::{MAX_IDEMPOTENCY_KEY_CHARS, MAX_OUTBOUND_TEXT_CHARS, OutboundMessage, SendReceipt};
pub use update::{
    AttachmentRef, ChannelEvent, ContentKind, DeletedMessage, GeoPoint, InboundMessage,
    InboundUpdate, MemberEvent, ReactionEvent, ReplyRef,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    /// Port statics are process-wide; serialize port tests behind one lock.
    static PORT_LOCK: Mutex<()> = Mutex::new(());

    fn sample_message() -> InboundMessage {
        InboundMessage {
            update_cursor: Some("42".into()),
            chat: ChannelChat {
                id: ExternalChatId::from("7"),
                kind: ChatKind::Direct,
                title: None,
            },
            author: ChannelUser {
                id: ExternalUserId::from("9"),
                username: Some("alice".into()),
                display_name: Some("Alice".into()),
            },
            message_id: ExternalMessageId::from("11"),
            thread_id: None,
            sent_at: Some(1_700_000_000),
            edited_at: None,
            content: ContentKind::Text,
            text: Some("hello".into()),
            caption: None,
            attachments: Vec::new(),
            reply_to: None,
            forward_label: None,
            location: None,
            venue_label: None,
            contact_label: None,
            poll_question: None,
        }
    }

    #[test]
    fn inbound_update_roundtrips() {
        let update = InboundUpdate::Message(sample_message());
        let encoded = serde_json::to_string(&update).unwrap();
        let decoded: InboundUpdate = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, update);
        assert!(encoded.contains("\"kind\":\"message\""));
    }

    #[test]
    fn descriptor_reports_unsupported_honestly() {
        let descriptor = ChannelDescriptor {
            channel: ChannelId::from("fixture"),
            receive: [(LaneMechanism::Poll, Support::Native)]
                .into_iter()
                .collect(),
            updates: [(UpdateKind::Message, Support::Native)]
                .into_iter()
                .collect(),
            sends: [(SendFeature::Idempotency, Support::Adapted)]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            descriptor.receive_support(LaneMechanism::Webhook),
            Support::Unsupported
        );
        assert_eq!(
            descriptor.update_support(UpdateKind::Reaction),
            Support::Unsupported
        );
        assert_eq!(
            descriptor.send_support(SendFeature::Idempotency),
            Support::Adapted
        );
        let encoded = serde_json::to_string(&descriptor).unwrap();
        assert!(encoded.contains("\"fixture\""));
    }

    #[test]
    fn outbound_message_validate_bounds() {
        let valid = OutboundMessage::new("7", "hi", "k1");
        valid.validate().unwrap();
        assert!(OutboundMessage::new("", "hi", "k1").validate().is_err());
        assert!(OutboundMessage::new("7", "  ", "k1").validate().is_err());
        assert!(OutboundMessage::new("7", "hi", "  ").validate().is_err());
        assert!(
            OutboundMessage::new("7", "x".repeat(MAX_OUTBOUND_TEXT_CHARS + 1), "k1")
                .validate()
                .is_err()
        );
        assert!(
            OutboundMessage::new("7", "hi", "k".repeat(MAX_IDEMPOTENCY_KEY_CHARS + 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn secret_token_never_shows_bytes() {
        let token = SecretToken::try_from_string("123:fixture-secret".into()).unwrap();
        let debug = format!("{token:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("fixture-secret"));
        assert_eq!(token.expose_utf8().unwrap(), "123:fixture-secret");
        assert!(SecretToken::try_from_bytes(Vec::new()).is_err());
        assert!(SecretToken::try_from_bytes(vec![0u8; MAX_SECRET_BYTES + 1]).is_err());
        let copy = token.copy_for_persistent_read();
        assert_eq!(copy.expose_bytes(), token.expose_bytes());
    }

    #[test]
    fn lane_port_fails_closed_and_installs_once() {
        let _guard = PORT_LOCK.lock().unwrap();
        lane::clear();
        assert!(!lane::installed());
        assert_eq!(
            lane::require().err().unwrap().code,
            "a4mc_lane_port_unavailable"
        );

        fn scan() -> Result<Value, ChannelError> {
            Ok(json!({"candidates": []}))
        }
        fn empty(_: &Value) -> Result<Value, ChannelError> {
            Ok(json!({}))
        }
        let port = LanePort {
            scan_targets: scan,
            conversation_list: empty,
            open_or_resume: empty,
            dispatch: |_, _| Ok(json!({"ok": true})),
        };
        lane::install(port).unwrap();
        lane::install(port).unwrap(); // same answers: idempotent
        assert!(lane::installed());
        assert!(
            (lane::require().unwrap().dispatch)("send", &json!({})).unwrap()["ok"]
                .as_bool()
                .unwrap()
        );

        fn other(_: &Value) -> Result<Value, ChannelError> {
            Ok(json!({"other": true}))
        }
        let different = LanePort {
            conversation_list: other,
            ..port
        };
        assert!(lane::install(different).is_err());
        lane::clear();
        assert!(lane::require().is_err());
    }

    struct FixtureCustody {
        token: Option<String>,
    }
    impl CustodyPort for FixtureCustody {
        fn channel_token(&self, channel: &ChannelId) -> Result<Option<SecretToken>, ChannelError> {
            assert_eq!(channel.as_str(), "fixture");
            Ok(self
                .token
                .as_ref()
                .map(|value| SecretToken::try_from_string(value.clone()).unwrap()))
        }
    }

    #[test]
    fn custody_port_fails_closed_and_never_serializes_secret() {
        let _guard = PORT_LOCK.lock().unwrap();
        custody::clear();
        assert_eq!(
            custody::require().err().unwrap().code,
            "a4mc_custody_port_unavailable"
        );

        let port: Arc<dyn CustodyPort> = Arc::new(FixtureCustody {
            token: Some("456:fixture-token".into()),
        });
        custody::install(Arc::clone(&port)).unwrap();
        custody::install(Arc::clone(&port)).unwrap(); // same port: idempotent
        let token = custody::require()
            .unwrap()
            .channel_token(&ChannelId::from("fixture"))
            .unwrap()
            .unwrap();
        assert_eq!(token.expose_utf8().unwrap(), "456:fixture-token");

        let other: Arc<dyn CustodyPort> = Arc::new(FixtureCustody { token: None });
        assert!(custody::install(other).is_err());
        custody::clear();
        assert!(custody::require().is_err());
    }

    #[test]
    fn channel_event_carries_channel_id() {
        let event = ChannelEvent {
            channel: ChannelId::from("fixture"),
            update: InboundUpdate::MemberJoined(MemberEvent {
                update_cursor: Some("1".into()),
                chat_id: ExternalChatId::from("2"),
                user: ChannelUser {
                    id: ExternalUserId::from("3"),
                    username: None,
                    display_name: None,
                },
                at: Some(9),
            }),
        };
        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(encoded["channel"], json!("fixture"));
        assert_eq!(encoded["update"]["kind"], json!("memberJoined"));
    }
}
