# A4MC — Adapters for Messenger Channels

A Rust library family that lowers messenger platforms (Telegram, Slack, Discord, and signed webhooks) onto one normalized channel contract (`a4mc`).

Each `a4mc-<channel>` dialect crate adapts a platform's native receive mechanism (long polling, Socket Mode, Gateway WebSocket, or HMAC-verified HTTP webhook) and outbound send surface into shared `a4mc` types, so the host application consumes one uniform API across every channel.

## Crates

| Crate | Responsibility |
| --- | --- |
| `a4mc` | Host-neutral channel contract: inbound updates (receipt, edit/delete, member, reaction), outbound sends with idempotency keys, delivery receipts, `ChannelDescriptor`, `LanePort` and `CustodyPort`, and optional `OutboundHooks` send policy (`OutboundPipeline`). |
| `a4mc-telegram` | Telegram Bot API adapter: `getUpdates` long polling, update lowering, durable per-chat `BindingStore`, `/pair` and slash-command surface, bounded fair scheduler, and deduplicated outbound sends. |
| `a4mc-slack` | Slack Socket Mode adapter: persistent WebSocket receive (no public callback URL), event lowering, deduplicated `chat.postMessage` sends, and custody/lane integration. |
| `a4mc-discord` | Discord Gateway adapter: WebSocket lifecycle (HELLO, IDENTIFY/RESUME, heartbeats, zombie detection, reconnect), event lowering, and REST sends with deterministic nonces and dedupe. |
| `a4mc-webhook` | Signed HTTP webhook adapter: HMAC-SHA256 verification with a bounded timestamp window, fail-closed signature checks before parsing, bounded replay suppression, and receive-only lowering. |

## Quick Usage

Embed `a4mc` alongside the channel dialect crates you need. crates.io currently carries only `a4mc`/`a4mc-telegram` 0.1.0, so until the 0.2 releases publish, depend on the repository's `nightly` branch — an unpinned git source resolves to `main`, which still carries 0.1.0. The `version` field asserts the checkout provides the documented API:

```toml
[dependencies]
a4mc = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", branch = "nightly", version = "0.2" }
a4mc-telegram = { git = "https://github.com/Unka-Malloc/Adapters-for-Messenger-Channels", branch = "nightly", version = "0.2" }
```

To pin a specific reviewed commit, replace `branch = "nightly"` with `tag = "…"` or `rev = "…"` in each entry — Cargo accepts only one of those selectors per dependency.

The Telegram example takes the host-provided custody and lane ports and a directory for durable state.

```rust
use std::{path::Path, sync::Arc};

use a4mc::{CustodyPort, lane::LanePort};
use a4mc_telegram::{BindingStore, RuntimeConfig, live_transport, run_channel_loop};

fn run_telegram(
    custody_port: Arc<dyn CustodyPort>,
    lane_port: LanePort,
    state_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    a4mc::custody::install(custody_port)?;
    a4mc::lane::install(lane_port)?;

    let transport = live_transport(None)?;
    let store = BindingStore::open_in(state_dir)?;
    run_channel_loop(transport, store, RuntimeConfig::default())?;
    Ok(())
}
```

See [docs/integration-modes.md](docs/integration-modes.md) for Slack Socket Mode, Discord Gateway, signed webhook, and `OutboundHooks` examples.

## Architecture & Guarantees

- **Host-owned custody and policy.** The host installs `CustodyPort` (for `slack-app`, `slack`, `discord`, `webhook`, and Telegram bot tokens) and `LanePort` (for verified agent discovery, sessions, and turn dispatch) once per process. Pairing approvals and agent admission stay in host logic.
- **Pluggable outbound pipeline.** Mount an optional `OutboundHooks` implementation per channel (`with_outbound_hooks`) or globally via `LanePort::outbound_hooks`. Every send-capable dialect runs the same pipeline (`skip` → `batch` → `throttle` → `dedupe_key` → deliver → `on_receipt`), passing through unchanged when unmounted.
- **Redacted secrets by construction.** `SecretToken` omits `Serialize` and redacts `Debug`; short-lived Slack Socket Mode URLs and Discord Gateway/resume URLs are redacted in debug output as well.
- **Explicit capability descriptors.** Each dialect publishes a `ChannelDescriptor` marking every update kind and send feature as `native`, `adapted`, or `unsupported`:
  - **Telegram:** native message/edit receive and reply-to; adapted idempotency dedupe; deletion, member, and reaction updates declared unsupported.
  - **Slack:** native Socket Mode receive across all six update kinds and reply-to; adapted idempotency; webhook/poll and message edit/delete declared unsupported.
  - **Discord:** native Gateway receive across all six update kinds (member events require opt-in `GUILD_MEMBERS`) and reply-to; adapted idempotency; webhook/poll and edit/delete declared unsupported.
  - **Webhook:** native webhook receive across all update kinds; receive-only (all send features declared unsupported).
- **Turn continuity.** Slack and Telegram lane turns wait for `LanePort` dispatch to complete, forwarding `timeoutMs` to the lane and rejecting overlapping duplicate dispatches for the same turn.

## Verify

```sh
scripts/verify.sh          # fmt + clippy + deterministic workspace tests
scripts/package-check.sh   # verifies packaged dialect compatibility with a4mc
```

Tests use synthetic or recorded JSON fixtures, in-memory transports (`MockBotTransport`, `MockSlackApi`, `MockDiscordApi`), loopback HTTP and WebSocket connections, and HMAC-signed payloads. They make no calls to live channel services.

## License

Apache-2.0.
