//! End-to-end simulated Gateway round trip: a real loopback websocket
//! delivers HELLO, READY, a MESSAGE_CREATE dispatch and RECONNECT; the
//! adapter identifies, heartbeats, lowers the message and answers through
//! the mock Discord REST API — no public callback and no live Discord
//! call.

use a4mc::{InboundUpdate, OutboundMessage, SecretToken};
use a4mc_discord::{
    DiscordApiError, DiscordChannel, GatewayConnector, GatewayHandler, GatewayPayload,
    GatewaySession, GatewayUrl, LiveGatewayConnector, MockDiscordApi, SessionOutcome,
    run_gateway_session,
};
use serde_json::{Value, json};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Test credential material is minted per run; no static token literal
/// is committed.
fn fixture_token() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "a4mc-discord-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

struct ReplyHandler {
    channel: Arc<DiscordChannel<MockDiscordApi>>,
    events: Vec<a4mc::ChannelEvent>,
    receipts: Vec<a4mc::SendReceipt>,
}

impl GatewayHandler for ReplyHandler {
    fn on_dispatch(
        &mut self,
        event: &a4mc::ChannelEvent,
        _payload: &GatewayPayload,
    ) -> Result<(), DiscordApiError> {
        self.events.push(event.clone());
        let InboundUpdate::Message(message) = &event.update else {
            return Ok(());
        };
        let text = format!("reply: {}", message.text.as_deref().unwrap_or_default());
        let outbound = OutboundMessage::new(message.chat.id.as_str(), text, "roundtrip-1");
        let receipt = self
            .channel
            .send(&outbound)
            .map_err(|error| DiscordApiError::new(error.code, error.message))?;
        self.receipts.push(receipt);
        Ok(())
    }
}

#[test]
fn gateway_dispatch_is_lowered_and_answered_over_the_rest_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let token_value = fixture_token();
    let server_token = token_value.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        socket
            .send(tungstenite::Message::text(
                json!({"op": 10, "d": {"heartbeat_interval": 1_000}}).to_string(),
            ))
            .unwrap();

        let identify = socket.read().unwrap();
        let identify: Value = serde_json::from_str(identify.to_text().unwrap()).unwrap();
        assert_eq!(identify["op"], json!(2));
        assert_eq!(identify["d"]["token"], json!(server_token));

        socket
            .send(tungstenite::Message::text(
                json!({
                    "op": 0,
                    "s": 1,
                    "t": "READY",
                    "d": {
                        "session_id": "session-1",
                        "resume_gateway_url": "ws://127.0.0.1/fixture"
                    }
                })
                .to_string(),
            ))
            .unwrap();

        let heartbeat = socket.read().unwrap();
        let heartbeat: Value = serde_json::from_str(heartbeat.to_text().unwrap()).unwrap();
        assert_eq!(heartbeat["op"], json!(1));
        socket
            .send(tungstenite::Message::text(json!({"op": 11}).to_string()))
            .unwrap();

        socket
            .send(tungstenite::Message::text(
                json!({
                    "op": 0,
                    "s": 2,
                    "t": "MESSAGE_CREATE",
                    "d": {
                        "id": "M1",
                        "channel_id": "C1",
                        "guild_id": "G1",
                        "author": { "id": "U1", "username": "alice", "global_name": "Alice" },
                        "content": "hello",
                        "timestamp": "2023-11-14T22:13:20.000000+00:00"
                    }
                })
                .to_string(),
            ))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(150));
        socket
            .send(tungstenite::Message::text(json!({"op": 7}).to_string()))
            .unwrap();
    });

    let api = Arc::new(MockDiscordApi::default());
    let channel = Arc::new(DiscordChannel::new(Arc::clone(&api)));
    let mut handler = ReplyHandler {
        channel: Arc::clone(&channel),
        events: Vec::new(),
        receipts: Vec::new(),
    };
    let token = SecretToken::try_from_string(token_value).unwrap();
    let mut connection = LiveGatewayConnector
        .connect(&GatewayUrl::new(format!("ws://127.0.0.1:{port}/?v=10")))
        .unwrap();
    let mut session = GatewaySession::default();
    let stop = AtomicBool::new(false);

    let outcome = run_gateway_session(
        &mut *connection,
        &token,
        &mut handler,
        &mut session,
        &Default::default(),
        &stop,
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(outcome, SessionOutcome::Reconnect);
    assert_eq!(session.sequence, Some(2));
    assert_eq!(session.session_id.as_deref(), Some("session-1"));
    assert_eq!(handler.events.len(), 1);
    assert_eq!(handler.receipts.len(), 1);
    assert_eq!(handler.receipts[0].idempotency_key, "roundtrip-1");
    let posted = api.posted_requests();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].channel_id, "C1");
    assert_eq!(posted[0].content, "reply: hello");
    assert!(posted[0].reply_to_message_id.is_none());
}
