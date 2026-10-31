---
name: a4mc-dialect
description: Author an a4mc-<channel> dialect — lower one platform's receive mechanism and send surface onto the a4mc contract with an honest ChannelDescriptor.
---

# a4mc dialect mode

A dialect crate lowers one messenger platform onto `a4mc`. It speaks
the platform's API on one side and produces/consumes `a4mc` types on
the other; it never reaches into host internals.

## When to use

- A new platform needs a channel: write `a4mc-<channel>` against the
  contract — never against a sibling dialect.

## What a dialect owns

- The platform-native receive mechanism — poll, webhook or socket,
  classified as a `LaneMechanism` — and update parsing lowered onto
  `a4mc::InboundUpdate` (receipt, edit/delete, member and reaction
  events).
- `OutboundMessage` sends mapped onto the platform's send surface,
  honouring the contract's `MAX_*` bounds and carrying the idempotency
  key as far as the platform allows — adapter-side dedupe when it
  offers none.
- A `ChannelAdapter::descriptor()` report complete over the contract
  vocabulary: `native`, `adapted` or `unsupported` per `UpdateKind`
  and `SendFeature` — incomplete support declared, never claimed and
  never silently dropped.
- The channel state the platform demands (Telegram keeps per-chat
  pairing, agent and session bindings in `BindingStore`); format and
  location are the dialect's business.

## Rules that keep the contract

- Depend on `a4mc`, never on a sibling dialect. Reach custody and lane
  work only through the installed ports — no keychain, file or
  environment reads for tokens.
- Secret material never appears in serialized or debug forms.
- `a4mc-telegram` is the reference dialect: `transport` (Bot API long
  polling), `lower` (updates → contract), `channel` (descriptor +
  idempotent sends), `runtime` (the bounded fair scheduler that runs
  the channel loop).
