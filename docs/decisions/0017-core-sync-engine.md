# 0017 — Core Sync Engine: Canonical Log, Sync Sessions, and the Op Wire Format

- **Status:** Accepted
- **Date:** 2026-10-23
- **Builds on:** [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0016](0016-core-domain-model.md)

## Context

ADR 0016 deferred three things to this slice: the serde/wire format for the
op record, the sync engine that applies remote deltas, and the multi-device
convergence proof. Transport, server, and storage remain out of scope — the
engine here is the in-memory model the future server and transports drive
(ADR 0007's rendezvous design), and it discharges the convergence claim the
whole protocol rests on.

## Decision

### Rendezvous model: `OpLog`

An append-only, per-budget, in-memory log — the server's shape without the
server:

- `append(op) -> seq`: sequences are dense, 1-based, and append order is the
  canonical order per budget (ADR 0007). The first append fixes the budget;
  foreign-budget appends are rejected, mirroring `BudgetState`.
- The log inspects **only server-visible metadata** (`op_id`, `budget_id`) —
  ADR 0009's discipline expressed in the API: payloads are data the log
  stores but never interprets.
- `op_id` is 1:1 with op content: re-appending an identical op returns its
  original sequence (safe retries on flaky links); re-appending the same
  `op_id` with different content is a loud `OpIdConflict` error —
  convergence depends on `op_id` uniquely identifying an op, so a collision
  must surface, not silently resolve per-arrival-order.
- `delta_since(seq)` serves ops with sequence greater than `seq`, in
  canonical order; `tip()` is the high-water mark a client compares its
  cursor against.

### Client model: `SyncSession`

A session is one device's `BudgetState` plus its `Hlc` clock plus a
`last_seen` cursor (0 = nothing seen). `apply_delta(ops)` processes ops in
delivered order:

- every op goes through the slice-1 idempotent LWW apply — duplicate
  `op_id`s are no-ops, stale stamps lose, arrival order does not matter;
- the session clock `merge`s every op it successfully processes — the HLC
  receive path — so after any delta the clock dominates every received
  stamp, and a subsequent local tick outranks all of them, whatever the
  device skews were (skew heals on receive, ADR 0007);
- `last_seen` is the monotonic high-water mark of processed sequences —
  overlapping or reordered re-delivery can advance it, never regress it;
- the first failing op aborts the delta with its `ApplyError`: ops
  processed before it stay applied, the cursor stops at the failure, and
  retrying the same delta reproduces the same error. Corruption is loud;
  the engine never advances past an op it could not apply.

Local capture — minting ops and applying them immediately — is not part of
the session; the capture slice composes `BudgetState::apply` with this
clock. Nothing here pre-empts that.

### Wire format

The op record serializes as two parts, matching what the server may ever
see (ADR 0009):

- `OpMeta { op_id, budget_id, device_id, user_id, hlc }` — server-visible;
- `OpPayload { entity_kind, entity_id, field, value }` — opaque to the
  server, encrypted in a later slice.

`Op::into_parts()` / `Op::from_parts()` convert. The **single serialization
choke point** is the `encode_payload` / `decode_payload` pair (serde_json
today): the E2EE layer wraps exactly this pair, and a future format change
touches exactly this pair. JSON over a binary format: self-describing,
debuggable on the wire, and matching the third-party API surface ADR 0012
wants.

Encoding rules, all round-trip exact:

- ids: hyphenated UUID strings, **validated on deserialize** — UUIDv7 stays
  enforced at the wire boundary;
- money: integer milliunits (`i64`) — never a float or a decimal string
  (ADR 0006; the workspace float guard polices everything around it);
- dates and months: strict fixed-width strings (`2026-10-23`, `2026-10`) —
  the existing `Display`/`FromStr` pair, already proven inverse;
- enums: serde's default external tagging; `Hlc` as
  `{ "physical_ms", "logical" }`.

### Convergence: statement and proof method

**Statement:** after a set of ops S has been applied, `BudgetState` is a
function of S alone. Dedupe collapses duplicates; per-field LWW by the total
order `(hlc, op_id)` picks the maximum stamp per field independent of
arrival order; equal-HLC ties break by `op_id`, identically on every replica
(ADR 0016). Therefore any devices that have each received every op hold
identical states — regardless of shuffle, duplication, batching, or clock
skew. Completeness of delivery is the (future) transport's contract.

**Tests** (deterministic xorshift loops, ADR 0016 convention — no new test
dependencies): N devices with fixed skew offsets — two sharing a clock to
force equal-HLC ties, one running a year ahead — writing ops across every
entity kind with tombstone/resurrection races and references to missing
entities; delivered (a) through the rendezvous loop — shuffled pushes,
random-sized pulls, overlapping at-least-once re-pulls — and (b) as direct
shuffled deliveries with injected duplicates; every device must equal the
canonical-order reference, across many seeds.

## Deferred (deliberately out of this slice)

Transport (WebSocket/SSE) and the server, storage persistence, push/outbox
and capture/op minting, snapshots and compaction (ADR 0007), the E2EE
encryption layer (it wraps the choke point above), delta size caps and
paging, auth and membership.

## Alternatives considered

- **Sort deltas before applying** — unneeded: application is
  order-independent, which is exactly the theorem under test; canonical
  order is what the log serves, and clients tolerate any arrival order.
- **Sequence numbers on `Op`** — rejected: sequences are server-assigned
  per budget; `Op` stays client-minted and sequence-free.
- **Deriving serde straight onto `Op`** — rejected: a flat op form dissolves
  the meta/payload boundary the E2EE discipline depends on; the split is
  the point.
- **Binary payload format (postcard/bincode)** — smaller, but JSON is the
  debuggable, third-party-friendly choice; the choke point keeps a later
  swap local to one function pair.
- **Bulk state-merge API instead of per-op application** — rejected:
  per-field LWW apply *is* the settled semantic (ADR 0016); delta
  application composes it.
- **Skipping malformed ops inside a delta** — rejected: a skipped bad op is
  a silent drop behind an advanced cursor; corruption stays loud.

## Consequences

- Deltas walk the log from the client's cursor; sequences are dense `Vec`
  indexes — the in-memory model stays naive about storage until that slice.
- Devices converge exactly when delivery is complete and ops are
  well-formed; violations of either surface as errors, never as divergence.
- The wire format is now load-bearing: it must be versioned and frozen
  before external clients depend on it (ADR 0012).
- `OpIdConflict` makes `op_id` reuse a loud rendezvous-side event — a buggy
  client minting colliding ids is caught at the log, not by silent
  divergence between devices.
