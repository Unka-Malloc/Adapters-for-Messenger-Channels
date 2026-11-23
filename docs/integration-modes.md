# Integration modes

Embed `a4mc` plus one `a4mc-<channel>` dialect per platform, install `CustodyPort` and `LanePort` once per process, and run each channel loop directly inside the host process; new platforms implement the same contract traits.

## Host — embed a channel dialect

The dialects resolve through the repository until each version lands on
crates.io — `a4mc-slack`, `a4mc-discord` and `a4mc-webhook` are not yet
published, and the registry carries only `a4mc`/`a4mc-telegram` 0.1.0.
Each `version` field asserts the checkout provides the documented API.

```toml
[dependencies]
a4mc = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", version = "0.2" }
a4mc-telegram = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", version = "0.2" }
a4mc-slack = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", version = "0.1" }
a4mc-discord = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", version = "0.1" }
a4mc-webhook = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", version = "0.1" }
```

```rust
// Installed once per process; without them lane and custody calls fail
// closed.
a4mc::custody::install(custody_port)?;   // the host's token answer
a4mc::lane::install(lane_port)?;         // verified agents, sessions, turns

let transport = a4mc_telegram::live_transport(None)?;      // token via the custody port
let store = a4mc_telegram::BindingStore::open_in(&state_dir)?;
a4mc_telegram::run_channel_loop(transport, store, a4mc_telegram::RuntimeConfig::default())?;
```

Slack runs the same composition over Socket Mode, so it needs no public
callback URL. Custody answers `slack-app` with the app-level Socket Mode
token and `slack` with the bot token; the receive loop opens a
short-lived websocket, hands each envelope to the host handler on a
worker, and acknowledges it once the handler has durably accepted the
work — so a slow lane turn never stalls reads or acknowledgements, and
an envelope whose handler fails stays unacknowledged for Slack to retry.

```rust
let api = std::sync::Arc::new(a4mc_slack::live_api(None)?);
let channel = std::sync::Arc::new(a4mc_slack::SlackChannel::new(std::sync::Arc::clone(&api)));
let mut handler = MySlackHandler { channel };              // SocketHandler
a4mc_slack::run_socket_mode(
    &*api,
    &a4mc_slack::LiveSocketConnector,
    &mut handler,
    &a4mc_slack::SocketModeConfig::default(),
)?;
```

Discord runs the same composition over its Gateway websocket: HELLO,
IDENTIFY/RESUME, heartbeats and reconnect framing are the adapter's
job, so no public callback is needed. Custody answers `discord` with the
bot token; the REST client uses the same custody-resolved token the
Gateway loop identifies with. The default intent set
(`a4mc_discord::DEFAULT_INTENTS`) contains no privileged intent: guild
messages arrive, but their text and attachment bodies are absent unless
the host enables Discord's privileged `MESSAGE_CONTENT` intent
(`a4mc_discord::INTENT_MESSAGE_CONTENT`) — in the developer portal and
in `GatewayModeConfig::intents` — and `GUILD_MEMBERS`
(`a4mc_discord::INTENT_GUILD_MEMBERS`) is likewise an explicit opt-in.

```rust
let api = std::sync::Arc::new(a4mc_discord::live_api(None)?);
let channel = std::sync::Arc::new(a4mc_discord::DiscordChannel::new(std::sync::Arc::clone(&api)));
let mut handler = MyDiscordHandler { channel };            // GatewayHandler
let mut session = a4mc_discord::GatewaySession::default(); // host-held resume state
a4mc_discord::run_gateway(
    &a4mc_discord::LiveGatewayConnector,
    api.token(),
    &mut handler,
    &mut session,
    &a4mc_discord::GatewayModeConfig::default(),
)?;
```

A webhook host owns the HTTP server and adapts its request into
`WebhookRequest`; the dialect verifies the HMAC-SHA256 signature and
timestamp window before parsing, then lowers the contract JSON. Custody
answers `webhook` with the signing secret. The receiver is built once
at server startup and shared by every request — the replay cache lives
inside it, so a receiver created per request would suppress nothing.
Replay suppression commits only after the host has accepted the event —
stored it durably or handled it successfully — so a failed handler
answers an error and the sender's retry verifies as a fresh event; once
committed, exact replays inside the window are acknowledged without
running the update again. Two bounds qualify that promise. The replay
cache is a bounded FIFO of the newest 1,024 committed signatures: a
burst of deliveries can evict a committed signature while it is still inside the timestamp window, and the evicted retry then verifies as a fresh event. Concurrent deliveries of the same payload can both classify as `Event` before either commits to the cache, so make host-side durable acceptance idempotent for overlapping retries.

```rust
// Once, at server startup — the shared receiver owns the replay cache.
let receiver = std::sync::Arc::new(a4mc_webhook::WebhookReceiver::from_custody(300)?);

// Per request, inside the HTTP handler the receiver was shared into:
let request = a4mc_webhook::WebhookRequest::new(method, body)
    .with_header(a4mc_webhook::TIMESTAMP_HEADER, timestamp)
    .with_header(a4mc_webhook::SIGNATURE_HEADER, signature);
match receiver.receive(&request, now_unix)? {
    a4mc_webhook::DeliveryOutcome::Event(delivery) => {
        handle(&delivery.event)?;                // handler takes &a4mc::ChannelEvent
        receiver.commit(&delivery);              // only then suppress replays
    }
    a4mc_webhook::DeliveryOutcome::Duplicate => {}          // answer 2xx
}
```

The adapter owns the platform's receive mechanism and send surface —
polling, Socket Mode, the Discord Gateway or signed HTTP receive, update
lowering, outbound sends with idempotency dedupe, and the channel's own
UX. The host owns where tokens live, agent admission, pairing approval
and any readiness hook.

## Outbound policy hooks

Outbound policy is the caller's. Mount one `OutboundHooks`
implementation per channel, or answer `LanePort::outbound_hooks` once and
every dialect constructed after that shares it:

```rust
use std::sync::Arc;

struct QuietHours; // caller-owned, no A4MC business logic

impl a4mc::OutboundHooks for QuietHours {
    fn skip(
        &self,
        _ctx: &a4mc::SendContext,
        _message: &a4mc::OutboundMessage,
    ) -> a4mc::SkipDecision {
        a4mc::SkipDecision::skip("quiet hours")
    }
}

let channel = a4mc_telegram::TelegramChannel::new(Arc::new(transport))
    .with_outbound_hooks(Arc::new(QuietHours));
let receipt = channel.send(&outbound)?;   // skipped: receipt.message_ids is empty
```

Every send-capable dialect (`telegram`, `slack`, `discord`) drives the
same `a4mc::OutboundPipeline` in one documented order: `skip` → `batch`
→ `throttle` → `dedupe_key` → deliver → `on_receipt`. `batch` may return
a merged replacement message or defer the send; `throttle` may defer with
a retry hint; `dedupe_key` may derive the effective idempotency key; and
`on_receipt` observes the receipt each successful non-skipped send
returns. A deferred send surfaces `a4mc_outbound_batched` or
`a4mc_outbound_throttled`; a skipped send returns an empty receipt and
makes no transport call. With no hooks mounted the pipeline is a
pass-through and the channel behaves identically.

All Quiet, Already-Told, Digest, and related send policies stay cleanly in host hooks rather than inside the adapters.

## Dialect — implement the contract

A new `a4mc-<channel>` crate lowers one platform onto `a4mc`: parse and
lower native updates into `InboundUpdate`, map `OutboundMessage` sends
onto the platform's send surface carrying the idempotency key as far as
the platform allows, and publish a `ChannelDescriptor` through
`ChannelAdapter::descriptor` that reports each `UpdateKind` and
`SendFeature` as `native`, `adapted` or `unsupported`. A dialect
depends on `a4mc` and on no sibling dialect; it resolves tokens only
through the `CustodyPort`. `a4mc-telegram` (poll), `a4mc-slack` (Socket
Mode), `a4mc-discord` (Gateway websocket) and `a4mc-webhook` (signed
HTTP) are the reference dialects.

## Skills

- `skills/host/` — composition guidance (ports, channel loop, pairing
  and binding).
- `skills/dialect/` — authoring guidance (lowering, descriptors,
  idempotency, custody hygiene).
