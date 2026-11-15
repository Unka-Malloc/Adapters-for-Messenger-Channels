//! The signed-webhook dialect's declared capability report.
//!
//! A webhook is an inbound HTTP push mechanism: it receives updates and
//! has no platform send surface of its own. The descriptor therefore
//! declares the webhook mechanism native, socket and poll unsupported,
//! every normalized update kind native (the wire payload is the contract
//! JSON), and every send feature unsupported. A receive-only channel is
//! declared honestly rather than pretending a send exists.

use a4mc::{
    ChannelAdapter, ChannelDescriptor, ChannelId, LaneMechanism, SendFeature, Support, UpdateKind,
};
use std::collections::BTreeMap;

/// The channel identifier this dialect lowers under.
pub const CHANNEL: &str = "webhook";

/// The dialect's declared capability report.
pub fn descriptor() -> ChannelDescriptor {
    ChannelDescriptor {
        channel: ChannelId::from(CHANNEL),
        receive: BTreeMap::from([
            (LaneMechanism::Webhook, Support::Native),
            (LaneMechanism::Socket, Support::Unsupported),
            (LaneMechanism::Poll, Support::Unsupported),
        ]),
        updates: BTreeMap::from([
            (UpdateKind::Message, Support::Native),
            (UpdateKind::MessageEdited, Support::Native),
            (UpdateKind::MessageDeleted, Support::Native),
            (UpdateKind::MemberJoined, Support::Native),
            (UpdateKind::MemberLeft, Support::Native),
            (UpdateKind::Reaction, Support::Native),
        ]),
        sends: BTreeMap::from([
            (SendFeature::Idempotency, Support::Unsupported),
            (SendFeature::ReplyTo, Support::Unsupported),
            (SendFeature::Edit, Support::Unsupported),
            (SendFeature::Delete, Support::Unsupported),
        ]),
    }
}

/// The receive-only channel adapter marker.
#[derive(Debug, Default, Clone, Copy)]
pub struct WebhookAdapter;

impl ChannelAdapter for WebhookAdapter {
    fn descriptor(&self) -> ChannelDescriptor {
        descriptor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a4mc::UpdateKind;

    #[test]
    fn descriptor_declares_webhook_native_and_every_other_mechanism_unsupported() {
        let report = descriptor();
        assert_eq!(report.channel.as_str(), "webhook");
        assert_eq!(
            report.receive_support(LaneMechanism::Webhook),
            Support::Native
        );
        assert_eq!(
            report.receive_support(LaneMechanism::Socket),
            Support::Unsupported
        );
        assert_eq!(
            report.receive_support(LaneMechanism::Poll),
            Support::Unsupported
        );
    }

    #[test]
    fn descriptor_is_complete_over_updates_and_sends() {
        let report = ChannelAdapter::descriptor(&WebhookAdapter);
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
            assert_eq!(report.send_support(feature), Support::Unsupported);
        }
    }
}
