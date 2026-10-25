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

- **Header** (20 bytes): magic `PCOPLOG\0`; u16 format version (1)
  *(bumped to 2 by [ADR 0021](0021-organizations-own-budgets.md) — the
  meta shape changed (`budget_id` → `scope`); v1 files are refused
  loudly, and none shipped)*; u16
  reserved — zero today, and a future extension must set it, because
  readers refuse a set reserved word rather than misread the file; and the
  **two-phase commit marker** (see durability below).
- **Frame**: u32 body length, u64 FNV-1a-64 over the body, body.
- **Body**: JSON `{ "seq", "meta", "payload" }` — the record's canonical
  sequence (a repair can leave gaps, so sequences cannot be re-derived
  from file position), the ADR 0009 server-visible metadata, and the
  payload verbatim from the single serialization choke point (ADR 0017).
  The at-rest encryption layer later wraps exactly that choke point, so
  the store body then carries ciphertext with no store change.

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

### The store is content-blind, like the log

The store validates structure only: framing, checksums, ids, HLC bounds.
The payload stays choke-point bytes the store never interprets — under
at-rest E2EE it is ciphertext, so any payload-level validation here would
be undone by that slice. An op the engine cannot apply (a field that does
not fit the entity kind, say) therefore stores fine and wedges replay
loudly and deterministically at its sequence — exactly the engine's
designed behavior for a bad op inside any delta (ADR 0017: the first
failing op aborts the delta, the cursor stops, retrying reproduces the
error). Capture mints ops through `BudgetState::apply` *(renamed
  `ScopeState::apply`, ADR [0020](0021-organizations-own-budgets.md))* and cannot mint
them; a hostile member feeding them is the transport/auth slice's
problem — the same posture as ADR 0017's HLC poisoning. The wedge
localizes deterministically: applying `delta_since(0)` one op at a time
finds the first failing op, and its sequence comes from the delta.

### Durability, atomicity, recovery

- **Commit, in two phases.** An append writes its frame at the log's end
  plus a PENDING marker `[seq][seq]` in the header under one `sync_data`,
  then writes the COMMITTED marker `[seq][!seq]` under a second. fsync is
  a durability barrier, not an atomic multi-write — the protocol does not
  pretend otherwise — so a durable COMMITTED marker implies its frame was
  durable first, and a PENDING or torn marker grants nothing: its commit
  never acked. The sequence space never rewinds below what was
  acknowledged.
- **Torn tail vs corruption, by resync:** the first frame that is short,
  overruns the file, or checksums bad is classified by scanning for ANY
  checksum-valid frame starting after it. Checksum-valid framing cannot
  occur inside a torn write's bytes or crash garbage (a 64-bit
  collision), so one frame proves the writer produced frames beyond the
  damage — **mid-file corruption, loud** (`StoreError::Corrupt`, file
  untouched). No valid frame after it is the crash window's uncommitted
  tail: **truncate to the last good frame, sync, continue.** A stray
  trailing byte — the crash artifact delayed allocation leaves — cannot
  disguise corruption as a torn tail, and a damaged length field can
  never silently destroy the committed frames after it.
- A full frame whose checksum passes but whose body does not decode is
  loud corruption — the writer never frames such bytes.
- **Sequences are never reused.** Records carry their canonical sequence
  (strictly increasing, 1-based, within the u32 marker's reach — boot
  validates this and refuses tampering), and boot resumes the sequence
  space above the maximum of the committed marker and every sequence a
  record on disk claims. A crash-torn uncommitted tail stays dense; a
  crash between the phases stays dense (pending grants nothing; an
  unsynced-but-complete frame counts); damage to *committed* frames (bit
  rot — outside the crash model, but detected by the checksums) leaves
  the marker above the surviving records: the store resumes above it,
  leaving a gap at the lost sequences. A caught-up client still receives
  everything appended after; a client that has not crossed the gap —
  including every device booting fresh from the store — cannot cross it:
  the watermark stalls there until the compaction slice's bootstrap
  (ADR 0017's designed stall, its sanctioned repair), and sequences are
  never silently reused to fake progress. Mid-file damage does not even
  boot: the corruption rule above refuses it outright.
- **Header rules:** a file too short to hold the header, or a
  full-length header that carries nothing, is a torn create — recreated,
  since the header write is one prefix and frames only ever follow its
  fsync: no committed data can exist. "Carries nothing" means a zero
  version, zero reserved, and a marker claiming no commits — the
  crash-inside-create state, where the file's size is durable but its
  page is not. A zero version beside frames — or beside a marker that
  claims commits — is damage or foreign: refused, never recreated over,
  or one flipped bit would silently wipe every committed op. A magic
  mismatch is foreign, refused, never clobbered (`StoreError::Foreign`).
  Any other version is unsupported — refused loudly at any file length,
  the moment its bytes are readable and before any recreate decision —
  and a set reserved word alongside this core's version is refused the
  same way (`StoreError::UnsupportedVersion`).
- **Rollback:** a phase-one failure restores the previous marker,
  truncates to the committed boundary, and syncs; if even that fails the
  store is poisoned and refuses appends until reopened. A phase-two
  failure keeps the durable frame — boot resolves any marker state — and
  reports the failed ack. The in-memory log never gains an op the disk
  refused. A file that no longer ends at the committed boundary (the
  single-writer contract broken) is refused loudly at append rather than
  written into.
- **External whole-file destruction:** a file truncated into the header
  (a partial restore or copy, not a crash state — committed bytes
  survive crashes) destroys the sequence memory with it; the path starts
  a fresh 1-based space. Peers that held the old log keep their state;
  reconciling that divergence is the transport slice's epoch/freshness
  concern.
- **Honest residual:** a torn write whose damaged bytes happen to decode
  misleadingly (bounded, and requiring patterns at the u32 extremes) can
  present as corruption or a phantom gap — both visible failures, never
  silent truncation or reuse. Crafted (not crashed) bytes can make the
  resync scan quadratic — a local-file concern under the single-writer
  contract, not a protocol property.

Single writer per path is the caller's contract this slice (the app shell
owns process singleness); locking is deferred with the browser/transport
work. The directory-entry fsync after create is best effort (POSIX;
other platforms rely on the create-fsync alone).

### Integration

`LocalStore` wraps the 0017 `OpLog` and mirrors its surface — `append`
(scope scoping + `op_id` dedupe + durable commit), `delta_since`, `tip`,
`budget_id` *(→ `scope_id`, and the scoping is an org's or a budget's —
[ADR 0021](0021-organizations-own-budgets.md))* — so the engine's
convergence proofs run against the backed
engine, not a parallel toy: the rendezvous loop is re-run with a
store-backed log, mid-run restarts (drop and reopen from disk) included,
and every device state is asserted equal to a fresh session booted from
the store. The `OpLog` itself gains the storage hooks ADR 0017 deferred
when it called sequences "dense `Vec` indexes ... naive about storage
until that slice": a resumable next-sequence (`resuming_at`), an
explicit-sequence boot append (`append_sequenced`, crate-private), and
`tip` as the last op's sequence rather than its count. A fresh log is
unchanged: dense, 1-based, append order canonical. This slice persists
the canonical (rendezvous-side) log; per-device mirrors and cursor
persistence are the transport slice's concern — a client mirror receives
reordered ops and maps its cursor to the server's sequences, which is
delivery, not storage.

### Migration story (stub)

The header carries the format version; every future change bumps it and
ships a read-old/write-new migration as one atomic replace (temp file +
rename). Version 1 is the first format, so there is nothing to migrate
yet; the reserved word and the commit marker keep room for a snapshot
extension.

## Deferred (deliberately out of this slice)

Snapshots and compaction (ADR 0007) — the frame format, reserved header
word, and explicit record sequences do not preclude them; the browser
storage adapter (IndexedDB over the same framed bytes); at-rest E2EE (it
wraps the existing choke point); batched multi-op commits (one
pending/committed pair per batch would halve the syncs); concurrent-writer
locking; server/API storage.

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
- **Validating payload coherence at append** — rejected: the store is
  content-blind by E2EE discipline (ADRs 0009, 0017); the check would be
  undone by at-rest encryption, and the engine already fails loudly at
  apply time.

## Consequences

- One file per budget log; boot cost is O(ops) — read + replay, the same
  order as any replay. Snapshots are the sanctioned answer when that
  matters (ADR 0007).
- The framing/checksum codec is the format: any target that can persist
  bytes can hold a store.
- `op_id` dedupe on boot collapses a duplicated record to the first — the
  E2EE-safe rule (a re-encrypted retry carries different payload bytes
  and must dedupe). Identical duplicated bytes also collide on sequence
  and fail the boot-time increase check loudly; the crafted
  different-sequence shape collapses, and the space still resumes above
  every sequence any record claimed. Duplicated records cannot be written
  through the API — only tampering produces them.
- An append costs two fsyncs — one per phase; batching is deferred.
- Records are bounded by the u32 frame length (and the commit marker by
  u32 sequences); a 32-bit target, which reads the whole file at boot,
  cannot open stores approaching 4 GiB. Both limits are far beyond one
  budget's lifetime; snapshots answer scale.
- The io-error rollback/poison path is designed but not fault-injected in
  tests (unit tests cannot cheaply fail an fsync); the torn-tail suite
  covers the file states that path leaves behind.
