//! Downstream host fixture.
//!
//! This crate consumes `a4mc` exactly the way the composing host does:
//! through its public surface only, never through workspace internals.
//! The assertions pin the `LanePort` initialization contract — every
//! field named, `outbound_hooks` included — and the unconfigured-policy
//! path, where a lane port installed without a hook provider resolves
//! to a byte-for-byte pass-through pipeline.

#[cfg(test)]
mod tests {
    use a4mc::{
        ChannelError, LanePort, OutboundMessage, OutboundPipeline, SendContext, SendPlan, lane,
    };
    use serde_json::{Value, json};

    fn scan() -> Result<Value, ChannelError> {
        Ok(json!({"candidates": []}))
    }

    fn empty(_: &Value) -> Result<Value, ChannelError> {
        Ok(json!({}))
    }

    /// A host that mounts no outbound policy installs `LanePort` with
    /// `outbound_hooks: None`; every dialect then resolves a
    /// pass-through pipeline that plans the message as sent under the
    /// contract's own idempotency key.
    #[test]
    fn lane_port_installs_with_an_unconfigured_outbound_policy() {
        let port = LanePort {
            scan_targets: scan,
            conversation_list: empty,
            open_or_resume: empty,
            dispatch: |_, _| Ok(json!({})),
            outbound_hooks: None,
        };
        lane::install(port).unwrap();
        assert!(lane::require().unwrap().outbound_hooks.is_none());

        let pipeline = OutboundPipeline::from_lane("telegram");
        assert!(pipeline.hooks().is_none());

        let message = OutboundMessage::new("7", "hello", "key-1");
        let plan = pipeline
            .plan(&message, &SendContext::at("telegram", 0))
            .unwrap();
        let SendPlan::Send(prepared) = plan else {
            panic!("an unconfigured policy must pass the send through");
        };
        assert_eq!(prepared.dedupe_key, "key-1");
    }

    struct FixtureCustody;

    impl a4mc::CustodyPort for FixtureCustody {
        fn channel_token(
            &self,
            channel: &a4mc::ChannelId,
        ) -> Result<Option<a4mc::SecretToken>, a4mc::ChannelError> {
            let _ = channel;
            Ok(None)
        }
    }

    /// The quickstart composition compiles end to end: the host installs
    /// its ports (the lane test above owns `lane::install`; this test
    /// installs custody) and constructs every documented dialect against
    /// the published surfaces — `a4mc` 0.2 with `a4mc-telegram` 0.2 and
    /// the 0.1 Slack, Discord and webhook dialects.
    #[test]
    fn the_documented_dialects_construct_after_port_installation() {
        a4mc::custody::install(std::sync::Arc::new(FixtureCustody)).unwrap();
        assert!(a4mc::custody::installed());

        let telegram = a4mc_telegram::TelegramChannel::new(std::sync::Arc::new(
            a4mc_telegram::MockBotTransport::default(),
        ));
        let runtime = a4mc_telegram::RuntimeConfig::default();
        let slack =
            a4mc_slack::SlackChannel::new(std::sync::Arc::new(a4mc_slack::MockSlackApi::default()));
        let discord = a4mc_discord::DiscordChannel::new(std::sync::Arc::new(
            a4mc_discord::MockDiscordApi::default(),
        ));
        let secret = a4mc_webhook::WebhookSecret::new(
            a4mc::SecretToken::try_from_string(format!(
                "a4mc-fixture-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_nanos())
                    .unwrap_or(0)
            ))
            .unwrap(),
        )
        .unwrap();
        let receiver =
            a4mc_webhook::WebhookReceiver::new(a4mc_webhook::WebhookVerifier::new(secret, 300));

        let _ = (telegram, runtime, slack, discord, receiver);
    }
}
