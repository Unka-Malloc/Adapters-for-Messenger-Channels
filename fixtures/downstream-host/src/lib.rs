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
}
