# 0015 — Product Positioning: Local-First and E2EE

- **Status:** Accepted
- **Date:** 2026-10-18
- **Ties together:** [ADR 0001](0001-shared-rust-core.md),
  [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0010](0010-no-bank-import.md),
  [ADR 0011](0011-capture-first-mobile.md)

## Context

The architecture decided so far — one offline-capable core, an op-log sync
protocol, opaque server payloads, manual-first entry, capture-first mobile —
is individually technical. Together it already implies a market stance, and
leaving that stance unnamed invites scope decisions that drift away from what
the architecture can actually support.

## Decision

**Local-first, end-to-end-encrypted budgeting is the deliberate
differentiator.** The pitch is ownership: it works offline, it syncs through a
rendezvous that never needs plaintext — encrypted by default, with the switch
offered only to self-hosters
([ADR 0009](0009-e2ee-opaque-payloads.md)) — and it never depends on
third-party aggregation. The open-source, self-hostable release
([ADR 0014](0014-monorepo-and-fluxvale-cloud.md)) is part of the same claim.

**Server-first plus bank-sync aggregation is a different category, not the
competition we chase.** Tools built around pulling bank feeds into a
server-side ledger solve a problem this architecture rules out by design
([ADR 0010](0010-no-bank-import.md)). We do not match them feature-for-feature,
and "no bank sync" is answered by positioning, not by a roadmap item.

## Alternatives considered

- **Compete on parity with bank-sync aggregators** — rejected: it needs
  credential handling and compliance surface, infrastructure the target
  markets do not have, and server-side plaintext
  ([ADR 0009](0009-e2ee-opaque-payloads.md) forbids the features it enables).
- **"An offline budgeting app"** — rejected: offline is table stakes in this
  category; E2EE over a rendezvous-point sync is what is defensible.
- **Server-first with an optional offline mode** — rejected: both the sync
  design ([ADR 0007](0007-oplog-sync-protocol.md)) and the shared core
  ([ADR 0001](0001-shared-rust-core.md)) assume the client owns the state.

## Consequences

- Marketing and docs lead with data ownership and offline capability, not
  integrations.
- Competitive comparisons are framed as a category difference, not as feature
  gaps to close.
- Any feature requiring server-side plaintext is out by positioning as well as
  by architecture; self-hosting remains the pressure valve for operators who
  want those features.
