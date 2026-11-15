//! End-to-end simulated Socket Mode round trip: receive a real
//! websocket event, acknowledge it, lower it onto the contract, and send
//! the reply through the mock Slack Web API — no public callback and no
//! live Slack call.

use a4mc::{InboundUpdate, OutboundMessage};
use a4mc_slack::{
    LiveSocketConnector, MockSlackApi, SeenEnvelopes, SlackApiError, SlackChannel, SocketConnector,
    SocketHandler, SocketUrl, run_socket_session,
};
use serde_json::{Value, json};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct ReplyHandler {
    channel: Arc<SlackChannel<MockSlackApi>>,
    events: Vec<a4mc::ChannelEvent>,
    receipts: Vec<a4mc::SendReceipt>,
}

impl SocketHandler for ReplyHandler {
    fn on_event(
        &mut self,
        event: &a4mc::ChannelEvent,
        _envelope: &a4mc_slack::SocketEnvelope,
    ) -> Result<(), SlackApiError> {
        self.events.push(event.clone());
        let InboundUpdate::Message(message) = &event.update else {
            return Ok(());
        };
        let text = format!("reply: {}", message.text.as_deref().unwrap_or_default());
        let outbound = OutboundMessage::new(message.chat.id.as_str(), text, "roundtrip-1");
        let receipt = self
            .channel
            .send(&outbound)
            .map_err(|error| SlackApiError::new(error.code, error.message))?;
        self.receipts.push(receipt);
        Ok(())
    }
}

#[test]
fn socket_event_is_acknowledged_lowered_and_answered_over_the_web_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        socket
            .send(tungstenite::Message::text(
                json!({"type": "hello", "num_connections": 1}).to_string(),
            ))
            .unwrap();
        socket
            .send(tungstenite::Message::text(
                json!({
                    "envelope_id": "e1",
                    "type": "events_api",
                    "payload": {
                        "type": "event_callback",
                        "team_id": "T1",
                        "event_id": "Ev1",
                        "event_time": 1_700_000_000,
                        "event": {
                            "type": "message",
                            "channel": "C1",
                            "user": "U1",
                            "text": "hello",
                            "ts": "1700000000.000100"
                        }
                    },
                    "accepts_response_payload": false
                })
                .to_string(),
            ))
            .unwrap();
        let ack = socket.read().unwrap();
        let ack: Value = serde_json::from_str(ack.to_text().unwrap()).unwrap();
        assert_eq!(ack["envelope_id"], json!("e1"));
        socket
            .send(tungstenite::Message::text(
                json!({"type": "disconnect", "reason": "test_done"}).to_string(),
            ))
            .unwrap();
    });

    let api = Arc::new(MockSlackApi::default());
    let channel = Arc::new(SlackChannel::new(Arc::clone(&api)));
    let mut handler = ReplyHandler {
        channel: Arc::clone(&channel),
        events: Vec::new(),
        receipts: Vec::new(),
    };
    let mut connection = LiveSocketConnector
        .connect(&SocketUrl::new(format!("ws://127.0.0.1:{port}")))
        .unwrap();
    let mut seen = SeenEnvelopes::new(8);
    let stop = AtomicBool::new(false);

    let outcome = run_socket_session(&mut *connection, &mut handler, &mut seen, &stop).unwrap();
    server.join().unwrap();

    assert_eq!(outcome, a4mc_slack::SessionOutcome::Reconnect);
    assert_eq!(handler.events.len(), 1);
    assert_eq!(handler.receipts.len(), 1);
    assert_eq!(handler.receipts[0].idempotency_key, "roundtrip-1");
    let posted = api.posted_requests();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].channel, "C1");
    assert_eq!(posted[0].text, "reply: hello");
    assert!(posted[0].thread_ts.is_none());
}
