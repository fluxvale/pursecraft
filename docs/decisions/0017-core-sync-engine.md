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
- The log touches only server-visible metadata. Dedupe is by `op_id`
  alone: re-appending an op whose id is already stored returns the
  original sequence — safe retries ([ADR 0007]) — and this must hold
  under [ADR 0009] encryption, where a re-encrypted retry carries
  different payload bytes. The log therefore never compares content.
- `op_id` is 1:1 with op content, and the loud check for a violation
  lives in [`BudgetState::apply`] — where plaintext always exists, on
  every replica. The state fingerprints every applied op by `op_id`;
  replaying identical content is a no-op, while reusing an id for
  different content is an `OpIdConflict` error, because replicas fed the
  two variants would otherwise diverge silently.
- `delta_since(seq)` serves ops with sequence greater than `seq`, in
  canonical order; `tip()` is the high-water mark a client compares its
  cursor against.

### Client model: `SyncSession`

A session is one device's `BudgetState` plus its `Hlc` clock plus a
`last_seen` cursor (0 = nothing seen). `apply_delta(ops)` processes ops in
any order:

- every op goes through the slice-1 idempotent LWW apply — duplicate
  `op_id`s are no-ops, stale stamps lose, arrival order does not matter;
- the session clock `merge`s every op it successfully processes — the HLC
  receive path — so after any delta the clock dominates every received
  stamp, and a subsequent local tick outranks all of them, whatever the
  device skews were (skew heals on receive, ADR 0007);
- `last_seen` is a **contiguous resume watermark**: it advances only
  across gap-free prefixes of processed sequences. Reordered ops apply
  immediately but are held pending until the sequences below them arrive,
  so `delta_since(last_seen)` can never skip an unprocessed op — the
  wedge a max-seq cursor would have. Sequence values are advisory input:
  absurd values can stall a watermark but never move it past unapplied
  ops;
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
touches exactly this pair. `OpPayload` carries no public serde impls — the
wire shape is a private type inside the choke point — so there is no way
around it; `OpMeta` is plain serde, being exactly the part the server may
see. JSON over a binary format: self-describing, debuggable on the wire,
and matching the third-party API surface ADR 0012 wants.

Encoding rules, all round-trip exact:

- ids: hyphenated UUID strings, **validated on deserialize** — UUIDv7 stays
  enforced at the wire boundary;
- money: integer milliunits (`i64`) — never a float or a decimal string
  (ADR 0006; the workspace float guard polices everything around it);
- dates and months: strict fixed-width strings (`2026-10-23`, `2026-10`) —
  the existing `Display`/`FromStr` pair, already proven inverse, with the
  constructor domain narrowed to the 0000–9999 years the fixed width can
  round-trip;
- HLC stamps: validated on deserialize — `physical_ms` beyond `i64::MAX`
  is not a wall clock, and `logical == u32::MAX` is reserved so `merge`
  can always bump and `tick` can always borrow the next millisecond; a
  wire value can never exhaust a session's clock (loud error, never a
  panic, ADR 0016);
- enums: serde's default external tagging; `Hlc` as
  `{ "physical_ms", "logical" }`.

The decoder is deliberately lenient about shapes this core does not own:
alternative UUID string formats and unknown JSON keys are accepted. The
canonical form is what we emit; strictness and canonicalization tighten at
the versioned protocol freeze the transport slice brings (ADR 0012).

### Convergence: statement and proof method

**Statement:** after a set of ops S has been applied, `BudgetState` is a
function of S alone. Dedupe collapses duplicates; per-field LWW by the total
order `(hlc, op_id)` picks the maximum stamp per field independent of
arrival order; equal-HLC ties break by `op_id`, identically on every replica
(ADR 0016). Therefore any devices that have each received every op hold
identical states — regardless of shuffle, duplication, batching, or clock
skew. Completeness of delivery is the (future) transport's contract.

**Tests** (deterministic xorshift loops, ADR 0016 convention — no new test
dependencies): N devices with fixed skew offsets — two sharing a clock, one
running a year ahead — writing ops across every entity kind with
tombstone/resurrection races and references to missing entities; delivered
(a) through the rendezvous loop — shuffled pushes, random-sized pulls,
overlapping at-least-once re-pulls — and (b) as direct shuffled deliveries
with injected duplicates; every device must equal the canonical-order
reference, across many seeds. An equal-HLC tie is forced at the winning
stamp every seed — the year-ahead device's final op mirrored onto a twin
with the same entity, field, and HLC but its own `op_id` — and every
replica's materialized value for that field is asserted against the
independently computed `op_id`-max winner, so the tie-break's decision is
observed directly, not just carried along inside equal states.

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
- `op_id` reuse with different content is loud on every replica at apply
  time — a broken client minting colliding ids is caught wherever the
  colliding op lands, never by silent divergence between devices.
