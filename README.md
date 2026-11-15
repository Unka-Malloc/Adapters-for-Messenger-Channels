# A4MC — Adapters for Messenger Channels

A4MC lowers messenger-platform channels onto one normalized channel
contract. Each `a4mc-<channel>` dialect crate adapts one platform's
native receive mechanism (poll, webhook or socket) and send surface into
the shared `a4mc` vocabulary; the composing host sees one contract for
every channel.

## Crates

| Crate | Responsibility |
| --- | --- |
| `a4mc` | Host-neutral channel contract: inbound updates (receipt, edit/delete, member and reaction events), outbound sends with idempotency keys, delivery receipts, external channel identity, receive-mechanism classification, `ChannelAdapter` descriptor, `LanePort` and `CustodyPort`. Serde types only — no network code, no custody. |
| `a4mc-telegram` | Telegram dialect: Bot API transport (long polling via `getUpdates`), update parsing and lowering onto `a4mc`, per-chat pairing/binding store, slash-command surface, bounded fair scheduler, normalized outbound send with adapter-side idempotency dedupe. |
| `a4mc-slack` | Slack dialect: Socket Mode receive over a persistent websocket — no public callback or inbound ingress — event lowering onto `a4mc`, normalized `chat.postMessage` sends with adapter-side idempotency dedupe, and custody/lane port integration. |
| `a4mc-discord` | Discord dialect: Gateway websocket receive (HELLO/IDENTIFY/RESUME, heartbeats, zombie detection, reconnect) — no public callback — event lowering onto `a4mc`, normalized REST message sends with a deterministic nonce plus adapter-side idempotency dedupe, and custody port integration. |
| `a4mc-webhook` | Signed HTTP webhook dialect: HMAC-SHA256 verification with a bounded timestamp window, fail-closed rejection before parsing, normalized update lowering without field loss, bounded replay suppression, and a receive-only descriptor. |

## Boundary

- **Adapters lower platforms onto the contract.** A dialect speaks the
  platform's API on one side and produces/consumes `a4mc` types on the
  other. It never reaches into host internals.
- **Custody, lanes and policy stay in the host.** The host installs a
  `CustodyPort` (token retrieval — the adapter never reads keychains,
  files or environment itself) and a `LanePort` (verified agent
  discovery, session list/open, turn dispatch) once per process. Without
  them every lane or custody call fails closed. Pairing approval and
  agent admission are host decisions; the adapter only renders them.
  Slack is issued two credentials: the host answers the `slack-app`
  custody key with the app-level Socket Mode token and the `slack` key
  with the bot token. Discord asks custody for `discord`; the webhook
  verifier asks for `webhook` with its HMAC signing secret.
- **Secrets never surface.** `SecretToken` has no `Serialize` and a
  redacted `Debug`; tokens travel only from the host's custody port to
  the transport that consumes them. A Socket Mode URL carries a
  short-lived ticket and is redacted in `Debug` too; Discord's Gateway
  URL and resume URL are redacted for the same reason.
- **Incomplete support is declared, never claimed.** Each adapter
  publishes a `ChannelDescriptor` reporting per-update-kind and
  per-send-feature support (`native` / `adapted` / `unsupported`).
  Telegram today: message and edited-message receive natively; deletion,
  member and reaction events declared unsupported (deletion is never
  reported by the Bot API; the rest are not yet wired); send-side
  reply-to native, idempotency adapted (bounded adapter-side dedupe —
  the platform has no native key). Slack today: Socket Mode native while
  webhook and poll are unsupported by this dialect; all six update kinds
  native; send-side reply-to native, idempotency adapted; edit and delete
  declared unsupported (not yet wired). Discord today: Gateway native
  while webhook and poll are unsupported; all six update kinds native
  (member events additionally require the privileged `GUILD_MEMBERS`
  intent); send-side reply-to native, idempotency adapted (platform nonce
  plus bounded adapter dedupe); edit and delete declared unsupported.
  Webhook today: webhook receive native while socket and poll are
  unsupported; every update kind native because the body is the contract
  JSON; every send feature unsupported — this dialect is receive-only and
  says so.
- **Turn dispatch is not abandoned at a local cutoff.** A Slack lane
  turn waits for the host's `LanePort` dispatch to return; the adapter
  forwards `timeoutMs` for the lane to bound itself and refuses to start
  a duplicate dispatch for the same turn while the original is still
  running.

## Verify

```sh
scripts/verify.sh   # fmt + clippy + tests across the workspace
```

All tests are deterministic: synthetic or recorded JSON payloads, a
loopback stub for transport error paths, the in-memory
`MockBotTransport` / `MockSlackApi` / `MockDiscordApi`, scripted or
loopback-websocket Socket Mode and Discord Gateway sessions, and
HMAC-signed webhook fixtures. No live Bot API, Slack, Discord or webhook
calls are made.

## License

Apache-2.0. The Telegram dialect was seeded from the maintainer's
earlier gateway channel and is relicensed by its owner for this
adapter family.
