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

## Boundary

- **Adapters lower platforms onto the contract.** A dialect speaks the
  platform's API on one side and produces/consumes `a4mc` types on the
  other. It never reaches into host internals.
- **Custody, lanes and policy stay in the host.** The host installs a
  `CustodyPort` (bot-token retrieval — the adapter never reads keychains,
  files or environment itself) and a `LanePort` (verified agent
  discovery, session list/open, turn dispatch) once per process. Without
  them every lane or custody call fails closed. Pairing approval and
  agent admission are host decisions; the adapter only renders them.
- **Secrets never surface.** `SecretToken` has no `Serialize` and a
  redacted `Debug`; tokens travel only from the host's custody port to
  the transport that consumes them.
- **Incomplete support is declared, never claimed.** Each adapter
  publishes a `ChannelDescriptor` reporting per-update-kind and
  per-send-feature support (`native` / `adapted` / `unsupported`).
  Telegram today: message and edited-message receive natively; deletion,
  member and reaction events declared unsupported (deletion is never
  reported by the Bot API; the rest are not yet wired); send-side
  reply-to native, idempotency adapted (bounded adapter-side dedupe —
  the platform has no native key).

## Verify

```sh
scripts/verify.sh   # fmt + clippy + tests across the workspace
```

All tests are deterministic: synthetic or recorded JSON payloads, a
loopback stub for transport error paths, and the in-memory
`MockBotTransport`. No live Bot API calls.

## License

Apache-2.0. The Telegram dialect was seeded from the maintainer's
`licoup-public-gateway` channel and is relicensed by its owner for this
adapter family.
