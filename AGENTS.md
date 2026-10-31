# Agent rules for A4MC

## Boundary

Two layers, one boundary rule each way:

- `a4mc` — the normalized channel contract: inbound updates (receipt,
  edit/delete, member and reaction events), outbound sends carrying an
  idempotency key, delivery receipts, external channel identity (it never
  asserts a host principal), platform receive-mechanism classification
  (poll / webhook / socket), and the `LanePort` and `CustodyPort`
  surfaces the composing host installs once per process. No network
  code, no custody; secrets never appear in serialized or debug forms.
- `a4mc-<channel>` — one platform dialect each: the platform-native
  receive mechanism, update lowering onto `a4mc`, and outbound send
  lowering. A dialect depends on `a4mc` and on no sibling dialect.

Custody, lane work and admission policy stay in the host. A channel
capability that is only partially implemented is declared and reported
as such — never claimed supported, and never silently dropped.

## Verify

`scripts/verify.sh`
