# 0018 — Durable Local Oplog Store

- **Status:** Accepted
- **Date:** 2026-10-23
- **Builds on:** [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0016](0016-core-domain-model.md),
  [ADR 0017](0017-core-sync-engine.md)

## Context

ADR 0017's engine is in-memory by design; ADR 0016 deferred storage. This
slice puts durable local storage under it: the store a real client boots
from. Because the engine is deterministic (ADR 0017), boot-from-store equals
fresh in-memory replay is a provable property — this slice's job is to make
it true by construction and to test it byte for byte.

## Decision

### Store engine: an append-only framed log file, no database

`LocalStore` (module `store`, inside `pursecraft-core` — no new crate, no
new dependency) persists ops as an append-only sequence of checksummed
frames in one file:

- **Header** (12 bytes): magic `PCOPLOG\0`, u16 format version (1), u16
  reserved (zero today; the snapshot/compaction extension of ADR 0007
  claims it later without a second header).
- **Frame**: u32 body length, u64 FNV-1a-64 over the body, body.
- **Body**: JSON `{ "meta": OpMeta, "payload": <encode_payload string> }` —
  the ADR 0009 metadata/payload split with payload bytes taken verbatim
  from the single serialization choke point (ADR 0017). The at-rest
  encryption layer later wraps exactly that choke point, so the store body
  then carries ciphertext with no store change.

Why not a database: the data model already *is* an append-only op log
(ADR 0007) — file order is canonical order, the `op_id` dedupe index is
rebuilt on boot, and durable appends are O(1). The framing is pure std
bytes in/out, so the same format ships on every target the core compiles
for (ADR 0001): the native file adapter lands now; a browser adapter
persisting the same framed bytes (IndexedDB) is a later slice. SQLite and
friends are rejected — they either do not reach the browser target or
outweigh an append-only file (see alternatives below).

### Applied state is derived, never persisted

Boot is replay. `LocalStore::open` reads the frames, validates every op at
the wire boundary (UUIDv7 ids, HLC bounds, typed values — the validators
ADR 0017 already built), and rebuilds the in-memory `OpLog`; a client
session boots by applying `delta_since(0)` through the ordinary
`SyncSession::apply_delta` path. No materialized state touches disk — the
same reasoning as ADR 0016's rejected stored balances: persisted state
invites drift, derived state cannot. Boot-from-store == replay holds by
construction; the tests pin it. Snapshots and compaction, when they come,
are a boot-time cache over the same log and stay replay-verifiable.

### Durability, atomicity, recovery

- The commit point of an append is `write_all(frame)` + `sync_data`
  returning. Nothing before it is promised; everything after it is
  durable.
- Crash windows reduce to one case: the final frame may be absent, whole,
  or torn. Boot scans frames sequentially; the first frame that is short,
  overruns the file, or checksums bad **at the physical tail** was never
  committed — the log is truncated to the last good frame and that repair
  is synced. A frame that checksums bad **with valid frames after it**
  cannot result from the write protocol (single writer, sequential
  appends) — it is corruption and fails loudly
  (`StoreError::Corrupt`).
- A full frame whose checksum passes but whose body does not decode is
  corruption — the writer never frames such bytes — loud failure.
- A foreign file (magic mismatch) is refused loudly, never clobbered
  (`StoreError::Foreign`); a future format version likewise
  (`StoreError::UnsupportedVersion`). A file that is a strict prefix of
  the magic is a torn create (no committed data can predate the header
  fsync) and is recreated.
- A write/sync error mid-append rolls the file back to the last durable
  frame boundary (truncate + sync); if even that fails the store is
  poisoned and refuses further appends until reopened. The in-memory log
  never gains an op the disk refused.
- Honest residual: a torn *final* write whose damaged length field happens
  to decode small can masquerade as mid-log corruption. It is bounded —
  one uncommitted op, still held by the rendezvous and every peer — and
  the remedy is the future rebuild-from-rendezvous path, not silent
  truncation of a longer tail.

Single writer per path is the caller's contract this slice (the app shell
owns process singleness); locking is deferred with the browser/transport
work.

### Integration

`LocalStore` wraps the 0017 `OpLog` and mirrors its surface — `append`
(budget scoping + `op_id` dedupe + durable frame), `delta_since`, `tip`,
`budget_id` — so the engine's convergence proofs run against the backed
engine, not a parallel toy: the rendezvous loop is re-run with a
store-backed log, mid-run restarts (drop and reopen from disk) included,
and every device state is asserted equal to a fresh session booted from
the store. This slice persists the canonical (rendezvous-side) log:
per-device mirrors and cursor persistence are the transport slice's
concern — a client mirror receives reordered ops and maps its cursor to
the server's sequences, which is delivery, not storage.

### Migration story (stub)

The header carries the format version; every future change bumps it and
ships a read-old/write-new migration as one atomic replace (temp file +
rename). Version 1 is the first format, so there is nothing to migrate
yet; the reserved word keeps room for a snapshot extension.

## Deferred (deliberately out of this slice)

Snapshots and compaction (ADR 0007) — the frame format and reserved header
word do not preclude them; the browser storage adapter (IndexedDB over the
same framed bytes); at-rest E2EE (it wraps the existing choke point);
batched multi-op commits; concurrent-writer locking; server/API storage.

## Alternatives considered

- **SQLite (`rusqlite`)** — the reflex answer, but it does not reach the
  browser target (ADR 0001) without a second storage stack, and SQL buys
  nothing for an append-only log with one dedupe index.
- **`redb` / `sled`** — pure-Rust embedded stores; real dependencies with
  their own file formats and no browser story for this need. The op log's
  shape is simpler than a KV store.
- **Whole-file rewrite per commit (temp + rename)** — smaller still and
  atomic by construction, but O(log) fsync work per op, and it discards
  the property that makes crash behavior byte-testable: append framing
  lets the suite truncate the file at every offset and assert the repair,
  the same determinism culture as the convergence loops (ADRs 0016/0017).
- **Persisting materialized state alongside ops** — drift risk (ADR 0016's
  reasoning), doubles the schema, and buys boot speed that snapshots will
  buy honestly later.

## Consequences

- One file per budget log; boot cost is O(ops) — read + replay, the same
  order as any replay. Snapshots are the sanctioned answer when that
  matters (ADR 0007).
- The framing/checksum codec is the format: any target that can persist
  bytes can hold a store.
- `op_id` dedupe on boot silently collapses a duplicated record (safe
  retries, ADR 0007); `op_id` reuse with different content stays loud at
  apply time, exactly as in memory (ADR 0017).
- The io-error rollback/poison path is designed but not fault-injected in
  tests (unit tests cannot cheaply fail an fsync); the torn-tail suite
  covers the file states that path leaves behind.
