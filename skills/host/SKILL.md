---
name: a4mc-host
description: Compose A4MC channel dialects in a Rust host — install the CustodyPort and LanePort once per process, then run each dialect's channel loop against the normalized contract.
---

# a4mc host mode

Embed `a4mc` and the `a4mc-<channel>` dialects the product serves;
install the two ports once per process and run the channel loops.

## When to use

- The host wants messenger channels reaching its local agent work
  through one normalized contract: inbound updates, outbound sends with
  idempotency keys, delivery receipts.
- The host owns token custody, agent admission and pairing approval —
  the adapters only render those decisions.

## Canonical calls

```rust
a4mc::custody::install(Arc::new(MyCustody))?;   // impl CustodyPort: channel_token(&ChannelId)
a4mc::lane::install(LanePort {
    scan_targets, conversation_list, open_or_resume, dispatch,
    outbound_hooks: None,                       // None = pass-through sends
})?;

let transport = a4mc_telegram::live_transport(None)?;        // resolves the token via custody
let store = a4mc_telegram::BindingStore::open_in(&dir)?;     // per-chat pairing/bindings
let identity = a4mc_telegram::run_channel_loop(transport, store, config)?;

// Slack instead runs a persistent Socket Mode websocket: no callback.
let api = Arc::new(a4mc_slack::live_api(None)?);             // app + bot tokens via custody
let channel = Arc::new(a4mc_slack::SlackChannel::new(Arc::clone(&api)));
let mut handler = MySlackHandler { channel };                // impl SocketHandler
a4mc_slack::run_socket_mode(
    &*api, &a4mc_slack::LiveSocketConnector, &mut handler,
    &a4mc_slack::SocketModeConfig::default(),
)?;

// Discord also needs no callback: run its Gateway websocket loop.
let api = Arc::new(a4mc_discord::live_api(None)?);           // bot token via custody
let channel = Arc::new(a4mc_discord::DiscordChannel::new(Arc::clone(&api)));
let mut handler = MyDiscordHandler { channel };              // impl GatewayHandler
a4mc_discord::run_gateway(
    &a4mc_discord::LiveGatewayConnector, api.token(), &mut handler,
    &a4mc_discord::GatewayModeConfig::default(),
)?;

// A webhook host owns the HTTP server; the dialect verifies and lowers.
let receiver = a4mc_webhook::WebhookReceiver::from_custody(300)?;
let request = a4mc_webhook::WebhookRequest::new(method, body)
    .with_header(a4mc_webhook::TIMESTAMP_HEADER, timestamp)
    .with_header(a4mc_webhook::SIGNATURE_HEADER, signature);
match receiver.receive(&request, now_unix)? {
    a4mc_webhook::DeliveryOutcome::Event(delivery) => {
        handle(delivery.event)?;                  // durable host acceptance
        receiver.commit(&delivery);               // only then suppress replays
    }
    a4mc_webhook::DeliveryOutcome::Duplicate => {}           // answer 2xx
}
```

`RuntimeConfig` carries `poll_timeout_secs`, `worker_count`,
`max_admitted`, `turn_deadline`, `max_poll_failures`, the shared `stop`
flag, `on_started` — the host's readiness hook invoked once after the
Bot API handshake — and `on_event`, the observer for fetched updates
this runtime cannot dispatch as a message (when it is not mounted the
update id is persisted durably before the poll cursor advances). The loop runs until `stop` and returns the bot
identity it served under. Slack's `SocketModeConfig` carries the
bounded session count, reconnect delay, envelope-dedupe capacity and
the same shared `stop` flag. Discord's `GatewayModeConfig` carries the
initial Gateway URL, intents, bounded session count, reconnect delays
and the same `stop` flag; resume state lives in the session, not in the
host.

## Rules that keep the contract

- `CustodyPort::channel_token` decides where tokens live (keyring, file,
  vault) and whether the caller may have them; `Ok(None)` means custody
  holds no token for the channel — configuration, not an error. Slack
  asks twice: `slack-app` for the app-level Socket Mode token and
  `slack` for the bot token. Discord asks for `discord`; the webhook
  verifier asks for `webhook` with its HMAC signing secret.
- Ports install once per process: reinstalling the same port is
  accepted, a different one is refused, and every port call without an
  install fails closed.
- `SecretToken` has no `Serialize` and a redacted `Debug` — tokens
  travel only from the custody port to the transport that consumes
  them. A Slack Socket Mode URL carries a one-time ticket and is also
  redacted in `Debug`; Discord Gateway and resume URLs are redacted for
  the same reason. Webhook request debug output shows header names and
  body length, never values or body content.
- Channel identity (`ChannelUser`, `ChannelChat`, `ChatKind`) is what
  the platform asserts; mapping it to a host principal is host policy,
  never the adapter's.
- Outbound policy is host-side too. Mount an `a4mc::OutboundHooks`
  implementation per channel (`with_outbound_hooks`) or answer
  `LanePort::outbound_hooks` once so every channel constructed afterwards
  shares it. Hooks supply skip, window batching, throttle budget,
  dedupe-key derivation and receipt observation; the adapters only apply
  the same ordered `OutboundPipeline`. Leave the lane provider as `None`
  for pass-through sends. Never put Quiet/Already-Told/Digest logic in a
  dialect.
