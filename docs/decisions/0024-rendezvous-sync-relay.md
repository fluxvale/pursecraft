# 0024 — Rendezvous Sync Relay: HTTP Delta Relay on apps/api

- **Status:** Accepted
- **Date:** 2026-10-25
- **Builds on:** [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0013](0013-deployment-topology.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0021](0021-organizations-own-budgets.md)
- **Amends (in part):** [ADR 0013](0013-deployment-topology.md) — the sync
  server's storage row ("Axum + Postgres") becomes Axum + embedded storage.

## Context

`apps/api` is a placeholder. ADR 0007's rendezvous needs its server: devices
push op-log deltas per scope and pull deltas since a cursor. The core already
ships the exact in-memory shape ([ADR 0017] `OpLog`, `SyncSession`) and a
durable per-scope log format ([ADR 0018] `LocalStore`). Payloads are opaque
bytes under [ADR 0009] discipline: the relay stores and forwards, never
merges (merge is client-side, [ADR 0017]), never decrypts, and never parses
payload interiors. Issue #22 fixes the scope: two-device sync first, E2EE and
capture in parallel lanes, org management beyond read-only needs out.

## Decision

### Transport: HTTP/JSON on axum, pull-based

[ADR 0013] already chose Axum; HTTP/JSON matches the wire format's JSON
choke point ([ADR 0017]: self-describing, debuggable, third-party friendly).
Sync is request/response — clients poll `GET …/ops` with their cursor; live
push (WebSocket/SSE, [ADR 0007]) stays deferred exactly as [ADR 0017]
deferred it and layers on later without protocol change. Auth rides the
`Authorization` header (no cookies, per [ADR 0013]).

### Protocol: versioned envelopes, push/pull per scope

Every request and response body carries `"v": 1`; an unknown version is a
400, never a guess. Routes are typed by scope kind (the scope is metadata
the server routes on, [ADR 0021]):

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/devices` | enrollment secret | Enroll a device → `device_id` + token |
| `POST /v1/orgs/{id}` · `POST /v1/budgets/{id}` | device token | Create a scope log; creator granted; one pairing code returned |
| `POST /v1/orgs/{id}/pairing-codes` · `…/budgets/{id}/pairing-codes` | device token, granted | Mint another pairing code |
| `POST /v1/orgs/{id}/devices` · `…/budgets/{id}/devices` | device token + code | Redeem a pairing code → grant |
| `POST /v1/orgs/{id}/ops` · `…/budgets/{id}/ops` | device token, granted | Push ops |
| `GET /v1/orgs/{id}/ops?since=N&limit=M` · budgets likewise | device token, granted | Pull delta since `N` |

- **Push** body: `{ v, ops: [{ meta: OpMeta, payload: string }] }`. The
  server validates only what it may see: `meta` deserializes as `OpMeta`
  (ids and HLC bounds checked at the boundary, [ADR 0017]), `meta.scope`
  equals the route's scope (400), and `meta.device_id` equals the
  authenticated caller (403 — a device may append only its own ops; `user_id`
  stays unverified pre-accounts, [ADR 0021] defers enforcement). The payload
  is a string stored and forwarded **verbatim**: no decode, no validation, no
  size knowledge beyond a byte cap. Response: per-op `{ op_id, seq, stored }`
  (`stored: false` = `op_id` duplicate, safe retry) plus the log `tip`.
- **Pull** returns `{ v, ops: [{ seq, meta, payload }], tip, has_more }`:
  ops with sequence greater than `since` (exclusive cursor — exactly
  [`OpLog::delta_since`], [ADR 0017]), in canonical order, paged by `limit`.
  The client's cursor is its `SyncSession::last_seen` — the **contiguous
  resume watermark**, so a pull can never strand an unprocessed op behind
  the cursor. The client decodes payloads itself; a payload that does not
  decode is a loud client-side error, never skipped.
- Sequences are dense, 1-based, per scope; the server assigns them at
  append; dedupe is by `op_id` alone (content is opaque — an encrypted
  retry with different bytes must dedupe identically, [ADR 0017]). Same-id-
  different-content is invisible to the relay by construction; the loud
  `OpIdConflict` check stays client-side where plaintext lives.

### Persistence: per-scope append-only files, full-log retention

The relay reuses [ADR 0018]'s durable log format, string-native: a new core
type, `OpaqueStore`, stores `{ seq, meta, payload-string }` frames with the
same framing, checksum, two-phase commit marker, torn-tail repair, and
never-reuse-a-sequence contract as `LocalStore` — but never decodes
payloads (the one behavioral difference, and the reason it exists: a
payload string that is not valid choke-point output — ciphertext once E2EE
lands — must round-trip verbatim). One file per scope under the data
directory; an in-memory index rebuilt on boot serves `delta_since` and the
`op_id` dedupe set. The auth database (devices, grants, pairing codes) is a
small JSON file written atomically (tmp + fsync + rename); tokens and codes
are stored SHA-256-hashed.

**This amends [ADR 0013]'s "Axum + Postgres" row.** Nothing in a
single-process, per-scope-serialized relay needs a database server, and the
self-host single-image wedge ([ADR 0013]'s own one-image-one-port principle;
[ADR 0015]) argues against requiring one. SQLite would add a bundled C
toolchain to every build and a license entry to `deny.toml` for
functionality the existing framed log already ships tested; Postgres would
make every self-hoster run a second service. If the hosted tier ever needs
horizontal scale, the HTTP contract above is the seam where a bigger store
slots in — nothing client-side moves.

**Retention: the full log, no trimming.** A late joiner boots by pulling
`since=0`; windowed retention plus a snapshot point is [ADR 0007]'s
compaction slice (snapshots at sequence N, cursors starting at N) —
inventing it here would pre-empt that slice's bootstrap protocol. Boot
replay cost and unbounded growth are accepted honestly (household-scale
logs are tiny); per-append commits mean two fsyncs per op, also accepted
(group commit is a mechanical optimization behind `append_parts` if ever
needed).

### Auth: device tokens, per-scope grants, pairing codes

Pre-accounts model, safe for two devices, shaped to grow:

- **Enrollment secret** — generated at first boot into
  `data/enrollment.secret` (0600, operator reads it once); presenting it
  enrolls a device and returns a token. Closes open enrollment on an
  exposed relay; replaced by invites/accounts later.
- **Device token** — `Bearer` header, 122-bit random, SHA-256-hashed at
  rest; identifies the device for every authenticated call.
- **Per-scope grant** — the relay's whole ACL. A grant to push/pull one
  scope's log; created by scope creation (creator) or pairing-code
  redemption.
- **Pairing code** — single-use, 1-hour TTL, hashed at rest, minted by a
  granted device; sharing it out-of-band is how a second (third, …) device
  joins a scope.

Growth into orgs/membership ([ADR 0021]): because the Budget↔Organization
tie lives in **encrypted org-log payloads**, the relay can never know which
budgets belong to which org — per-scope ACLs are not a simplification but
the only server-side grouping E2EE permits ([ADR 0009]: "no server-side
features"). The later invite flow automates what pairing codes do by hand:
invites ride the org log as encrypted data, and clients auto-redeem the
codes they find into relay grants. Role enforcement (viewer vs editor)
stays client/capture-side data per [ADR 0021] until an auth slice designs
server-side enforcement; the grant table is where it would land.

### Late join and offline devices

A late joiner enrolls, pairs, and pulls `since=0` (paging by `limit` until
`has_more` is false) — pure deltas, no snapshot path yet ([ADR 0007]
compaction deferred). An offline device mints locally, then pushes
whenever; `op_id` dedupe makes every retry safe, and the contiguous
watermark means a crash between pushes leaves nothing stranded: the next
pull re-serves from `last_seen`. Reordered or duplicated delivery is
absorbed by [`SyncSession`] by construction ([ADR 0017] theorem).

### What a hostile relay can and cannot do (honest limits)

- **Fail-stop relay** (torn writes, crash between commit phases): torn
  tails are repaired at boot; committed sequences are never reused; an
  unacked op may vanish and the client's retry re-appends — at-least-once,
  idempotent everywhere.
- **Corrupt or tamper stored bytes**: a checksum-valid rewrite is served
  onward — and is **loud on the client**: structurally broken payloads fail
  `decode_payload`; a payload swapped onto an op the client already applied
  trips `OpIdConflict` (the `op_id`↔content fingerprint, [ADR 0017]).
  Consistent tampering served to *everyone* changes the op set itself, not
  the merge — every device still converges on the same state; distinguishing
  original from consistently-rewritten bytes is the E2EE lane's
  authenticated-encryption contract, not the relay's.
- **Truncate a delta or the log**: the cursor is the contiguous watermark —
  a withheld middle op holds every client's `last_seen` below `tip` in plain
  sight (a visible stall, by design, [ADR 0017]); re-pulling re-serves the
  gap. Withholding only the newest ops is indistinguishable from an idle
  relay without signatures — again E2EE's lane.
- **Reorder, replay, or duplicate**: converges or no-ops ([ADR 0017]).
- **Fabricate ops**: possible — the relay is the rendezvous, and minting
  well-formed ops is inside its power; a fabricated log only reaches
  devices that granted it access, and cryptographic op authenticity is the
  E2EE lane's ([ADR 0009]). The relay test suite pins what this slice
  guarantees: **no server misbehavior short of fabrication produces silent
  divergence — it surfaces as an error or a visible stall, and merge
  outcomes remain a pure function of the delivered op set.**

### Envelope versioning and E2EE headroom

The `"v"` field is the relay protocol version (request routing, error
shapes, list of fields). Payload strings and future key metadata ride
inside that envelope as bytes the relay never interprets: E2EE changes what
the payload string holds (ciphertext) and adds key-transport records, with
zero relay changes — `OpaqueStore`'s no-decode contract is what makes that
claim mechanical rather than aspirational.

## Deferred (deliberately out of this slice)

Live push (WebSocket/SSE), compaction and snapshot bootstraps ([ADR 0007]),
accounts/invites/org-management endpoints, server-side role enforcement,
rate limiting beyond body/batch/payload caps, TLS termination and CORS
(deployment concerns, [ADR 0013]), group commit and multi-process operation
(one process per data directory is the contract — `OpaqueStore`'s
single-writer check fails loudly otherwise, as [ADR 0018] specified).

## Alternatives considered

- **WebSocket/SSE transport now** — rejected: store-and-forward polling is
  simpler, crash-safer (no connection state), and sufficient; live push is
  additive later without touching the delta protocol.
- **gRPC or a binary transport** — rejected against [ADR 0017]'s explicit
  JSON-choke-point reasoning (debuggable, third-party-friendly).
- **SQLite (bundled)** — rejected: a C toolchain in every build plus a
  `deny.toml` license entry for durability the framed log already provides
  and SQL the relay would never write.
- **Postgres now** — rejected (amending [ADR 0013]'s row): breaks the
  self-host single-image wedge at household scale; the HTTP contract is the
  seam for a later graduate-if-needed.
- **Reusing `LocalStore` as-is** — rejected: it decodes payloads at append
  and boot, which both violates opacity for non-JSON (future ciphertext)
  payloads and would make the relay refuse exactly the bytes E2EE produces.
- **Max-seq cursors / bulk state sync** — rejected in [ADR 0017] already;
  the relay adopts its watermark semantics unchanged.
- **Windowed retention + snapshot point now** — rejected: that is the
  compaction slice's bootstrap protocol to design ([ADR 0007]); trimming
  without it would strand late joiners.

## Consequences

- `apps/api` becomes a real Axum service: router, handlers, auth DB, and a
  `pursecraft-api` library surface the integration tests drive in-process
  (tower `oneshot` — no test HTTP client dependency). One license joins
  `deny.toml`'s allowlist, deliberately: BSD-3-Clause, via axum's route
  matcher `matchit`.
- `pursecraft-core` gains the additive `OpaqueStore` ([ADR 0018] format,
  string-native); `LocalStore` behavior is untouched.
- Two devices sync end-to-end through the relay today; the E2EE lane's
  ciphertext and the capture lane's outbox both land against interfaces
  (opaque payload strings, per-op push acks) that already exist.
- Boot replays every scope log it serves — accepted at household scale,
  revisited with compaction.
- The relay's data directory is its whole state; back it up, move it, and
  the relay follows.
