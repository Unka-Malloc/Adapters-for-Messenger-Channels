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
})?;

let transport = a4mc_telegram::live_transport(None)?;        // resolves the token via custody
let store = a4mc_telegram::BindingStore::open_in(&dir)?;     // per-chat pairing/bindings
let identity = a4mc_telegram::run_channel_loop(transport, store, config)?;
```

`RuntimeConfig` carries `poll_timeout_secs`, `worker_count`,
`max_admitted`, `turn_deadline`, `max_poll_failures`, the shared `stop`
flag and `on_started` — the host's readiness hook invoked once after
the Bot API handshake. The loop runs until `stop` and returns the bot
identity it served under.

## Rules that keep the contract

- `CustodyPort::channel_token` decides where tokens live (keyring, file,
  vault) and whether the caller may have them; `Ok(None)` means custody
  holds no token for the channel — configuration, not an error.
- Ports install once per process: reinstalling the same port is
  accepted, a different one is refused, and every port call without an
  install fails closed.
- `SecretToken` has no `Serialize` and a redacted `Debug` — tokens
  travel only from the custody port to the transport that consumes
  them.
- Channel identity (`ChannelUser`, `ChannelChat`, `ChatKind`) is what
  the platform asserts; mapping it to a host principal is host policy,
  never the adapter's.
