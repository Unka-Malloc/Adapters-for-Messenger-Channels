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

    /// Pins the documented `run_gateway` call shape: the host retains
    /// the `GatewaySession`, passes it by mutable reference on every
    /// invocation, and re-enters with that same session when a handler
    /// failure is returned — but only while `can_resume()` still
    /// holds, since a retry against an expired session would open a
    /// fresh `IDENTIFY` and leave the rejected dispatch unrecoverable.
    /// Never called — a compile-time probe that fails the moment the
    /// documented example drifts from the signature a composing host
    /// links against.
    #[allow(dead_code)]
    fn the_documented_gateway_call_keeps_a_host_held_session(
        connector: &dyn a4mc_discord::GatewayConnector,
        token: &a4mc_discord::DiscordToken,
        handler: &mut dyn a4mc_discord::GatewayHandler,
        session: &mut a4mc_discord::GatewaySession,
        config: &a4mc_discord::GatewayModeConfig,
    ) -> Result<(), a4mc_discord::DiscordApiError> {
        let mut handler_retries = 0usize;
        loop {
            match a4mc_discord::run_gateway(connector, token, handler, session, config) {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.code == a4mc_discord::HANDLER_FAILED_CODE
                        && session.can_resume()
                        && handler_retries < 3 =>
                {
                    // The cursor survives the failure, so re-entering
                    // sends RESUME and the rejected dispatch replays —
                    // provided Discord accepts the resume.
                    handler_retries += 1;
                }
                // An expired session cleared the cursor with the
                // failure: surface the handler error rather than
                // IDENTIFY fresh and lose the rejected dispatch.
                Err(error) => return Err(error),
            }
        }
    }
}
