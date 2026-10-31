# Integration modes

Two ways to consume this workspace, one contract. A composing host
embeds `a4mc` plus one `a4mc-<channel>` dialect per platform, installs
the `CustodyPort` and `LanePort` once per process and runs the channel;
a new platform lands by implementing the dialect side of the same
contract. There is no sidecar — the channel loops and the custody they
draw on belong to the host process.

## Host — embed a channel dialect

```toml
[dependencies]
a4mc = "0.1"
a4mc-telegram = "0.1"
```

```rust
// Installed once per process; without them lane and custody calls fail
// closed.
a4mc::custody::install(custody_port)?;   // the host's token answer
a4mc::lane::install(lane_port)?;         // verified agents, sessions, turns

let transport = a4mc_telegram::live_transport(None)?;      // token via the custody port
let store = a4mc_telegram::BindingStore::open_in(&state_dir)?;
a4mc_telegram::run_channel_loop(transport, store, RuntimeConfig::default())?;
```

The adapter owns the platform's receive mechanism and send surface —
polling, update lowering, outbound sends with idempotency dedupe, the
slash-command surface, the bounded fair scheduler. The host owns where
the token lives, agent admission, pairing approval and the readiness
hook (`RuntimeConfig::on_started`, invoked once after the Bot API
handshake).

## Dialect — implement the contract

A new `a4mc-<channel>` crate lowers one platform onto `a4mc`: parse and
lower native updates into `InboundUpdate`, map `OutboundMessage` sends
onto the platform's send surface carrying the idempotency key as far as
the platform allows, and publish a `ChannelDescriptor` through
`ChannelAdapter::descriptor` that reports each `UpdateKind` and
`SendFeature` as `native`, `adapted` or `unsupported`. A dialect
depends on `a4mc` and on no sibling dialect; it resolves tokens only
through the `CustodyPort`. `a4mc-telegram` is the reference dialect.

## Skills

- `skills/host/` — composition guidance (ports, channel loop, pairing
  and binding).
- `skills/dialect/` — authoring guidance (lowering, descriptors,
  idempotency, custody hygiene).
