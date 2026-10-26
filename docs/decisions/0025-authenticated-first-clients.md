# 0025 — Authenticated-First Clients: Enrollment Gate and First Sync

- **Status:** Accepted
- **Date:** 2026-10-26
- **Builds on:** [ADR 0011](0011-capture-first-mobile.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0021](0021-organizations-own-budgets.md),
  [ADR 0022](0022-client-side-e2ee.md),
  [ADR 0023](0023-capture-cli.md),
  [ADR 0024](0024-rendezvous-sync-relay.md)
- **Amends (in part):** [ADR 0023](0023-capture-cli.md) — the zero-setup
  bootstrap clause: first capture now follows one-time enrollment.

## Context

The CLI is zero-setup and offline ([ADR 0023]); the relay exists but nothing
syncs to it ([ADR 0024]). Product decision (owner, Oct 26): **no client
interaction before enrollment** — a client must authenticate to the
rendezvous server before any command runs, so a client always has a home to
sync to before a user touches it. The server stays a payload-blind
store/sync home, never a source of truth; local-first ([ADR 0015]) and E2EE
([ADR 0022]) are unchanged. Once enrolled, the client is fully functional
offline — the gate is first-run, not per-launch.

Gating on a sync home the client cannot sync through would be incoherent, so
this slice also wires the first sync: `pursecraft sync`, pairing for a second
device, and the visible pending state [ADR 0011] requires.

## Decision

### The gate: session presence, once, offline-checked

Enrollment is recorded in `<home>/session.json` — the enrollment record
`{ version, server, device_id, token }`, published with the identity file's
atomic discipline ([ADR 0023]) and mode 0600 (the token is a credential).

- **Every command that touches data is gated: `add`, `list`, `sync`,
  `pair`, `join` — read-only `list` included.** The refusal is the teach:
  one `stderr` block naming `pursecraft login <relay-url>` and where the
  operator's enrollment secret lives, exit 1. A read-only escape hatch would
  blunt the decision's point: the un-enrolled client has no home, and every
  refusal says so.
- `--help`, `--version`, and usage errors answer without the gate, exactly
  as they answer without the environment today ([ADR 0023]).
- **The gate is a file-presence check, never a network round-trip.**
  Enrolled-but-offline is full function: captures queue, `list` reads, sync
  fails with a teaching error and loses nothing. A per-launch server ping
  would make the relay an availability dependency the local-first wedge
  forbids.
- The gate lives at one choke point — the command dispatch in `run()`,
  which every argv path crosses. Commands that need the token load the
  session themselves; no command body is reachable from argv without the
  dispatch check.

### Enrollment v1: `pursecraft login <relay-url>`, secret on stdin

- The relay's existing operator-secret flow ([ADR 0024]): `POST /v1/devices`
  with the enrollment secret mints a device id and a token, shown once.
- **The secret rides stdin** (one line, trimmed): scriptable
  (`pursecraft login http://host:8080 < secret.txt`), never in argv or
  shell history, no TTY prompt machinery. An empty stdin is a usage
  teaching error. Neither the secret nor the token is ever echoed to
  output.
- **v1 speaks plain `http`** to a local/LAN relay — the relay itself is
  plain HTTP ([ADR 0024]); TLS termination is the deployment slice's
  concern ([ADR 0013]). A non-`http` URL is refused at login with that
  explanation, not discovered as a transport error mid-sync.
- **Re-login re-enrolls**: a new device record replaces the session (a
  wiped relay is the realistic cause of a dead token). The local world —
  identity, stores — is untouched; see "stranded ops" below for the one
  honest cost.

### Identity reconciliation: what the server knows vs. what stays local

Enrollment precedes bootstrap, so the shapes reconcile as:

| Fact | Lives | Notes |
| --- | --- | --- |
| device id + token | relay (hashed) and `session.json` | server-minted at enrollment |
| per-scope grants | relay only | the relay's whole ACL ([ADR 0024]) |
| user id | `identity.json`, client-minted | unverified pre-accounts ([ADR 0024]); stays out of the server's knowledge |
| org/budget/membership data | the org log's payloads | opaque to the relay ([ADR 0009]) |

- Every op the CLI mints carries the **session's** device id — the relay
  enforces `meta.device_id` == caller, so a home's ops must be minted under
  the enrollment that will push them.
- `identity.json`'s `device_id` becomes the world's **founding device** (the
  session at world creation); the file's shape and version are unchanged —
  pre-gate files cannot exist behind the gate, and a world minted before a
  re-login keeps its founding id.
- Two devices of one human are two members in v1 data (each mints its own
  user id); the accounts slice reconciles identity later. Roles stay data
  ([ADR 0021]).

### Bootstrap follows enrollment (amends ADR 0023)

Capture's mechanics do not change: the first `add` still bootstraps the
world ensure-style, read-then-mint, offline. What changes is the front
door — bootstrap cannot precede enrollment because no capture can. ADR
0023's "first capture works with zero setup" clause now reads: zero setup
**after one-time enrollment**; the capture-first spirit (no setup command,
no init ritual, no prompts) is intact.

### Sync: `pursecraft sync` — manual, push-then-pull, per scope

- **Manual.** No auto-sync after `add`: every capture hitting the network
  would break the sub-second offline capture that is ADR 0023's core.
  [ADR 0011]'s background sync is a mobile lifecycle behavior; the CLI's
  contract is a visible pending state plus an explicit sync.
- The scopes are the identity's org and budget logs. Per scope, first
  `sync` **creates the relay scope** (`POST /v1/{kind}/{id}` — the creator
  is granted, [ADR 0024]) and prints the pairing bundle for the next
  device; a `409` means the scope already exists — if this device is
  granted (its own retry after a crash), sync proceeds, else the error
  teaches pairing.
- **Push**: the outbox is *derived, not stored*: local ops with
  `seq > pushed_through` whose device id is the session's. Relay-side
  `op_id` dedupe makes every retry safe — at-least-once, idempotent
  ([ADR 0024]). Acks are verified op-by-op (a short or lying ack batch is
  a loud client error, never a silent outbox drop).
- **Pull**: pages of `GET …/ops?since=N` until `has_more` is false. The
  pull cursor (`remote_seen`) is **relay-sequence space** and lives in
  `<home>/sync.json` — deliberately *not* the `SyncSession` watermark,
  which after a store boot counts local sequences ([ADR 0017]). Two
  cursors per scope in `sync.json`: `pushed_through` (local space) and
  `remote_seen` (relay space).
- Each page is **validated by the engine before anything is persisted**:
  decode, apply to the store-booted session, and only then append the
  page's ops through the **sink** ([ADR 0023]'s single append path —
  where the E2EE unwrap will land; echoes of this device's own pushes
  dedupe there). A page that fails to decode or apply aborts the scope's
  sync loudly with the cursor unmoved and the local store **untouched** —
  a hostile or damaged op can stall a sync (visible, re-served on every
  retry, [ADR 0017]) but can never poison local function. The relay
  sequences the validation carries move the session watermark into relay
  space; that watermark is deliberately unread in the sync path — the
  cursors in `sync.json` are the authority.
- `sync.json` persists per scope after that scope completes; a crash
  anywhere re-pushes and re-pulls idempotently.
- A late joiner is just a first sync: join, then pull `since=0` (paging
  until caught up — [ADR 0024] unchanged).

### Pairing: `pair` and `join` — the second device, now

The grown path ships now because two-device convergence is this slice's
headline; invites/accounts ([ADR 0024]) automate the same shape later.

- **`pursecraft pair`** (identity required — a world must exist): mints
  fresh pairing codes for the org and budget scopes and prints the exact
  join command for the other device. Codes are single-use, 1-hour TTL
  ([ADR 0024]); `pair` is how a missed first-sync code is replaced.
- **`pursecraft join <org-id> <org-code> <budget-id> <budget-code>`**:
  the joiner must already be enrolled (the gate still comes first).
  Join refuses a home that already holds an identity — the identity file
  is the root ([ADR 0023]); joining onto an existing world is a restore,
  not a join. The flow: redeem both codes → pull both scopes fully →
  write the joined world's identity (the joiner's user and membership ids
  minted locally; org/budget ids from the bundle) → mint the joiner's own
  membership ops (`user_id` + `role: Editor`, anchored per [ADR 0021]'s
  provisioning convention, read-then-mint against the pulled org state) →
  adopt the earliest live account in the joined budget as the capture
  default (minting a `Wallet` only if none exists) → full sync of both
  scopes.
- Self-minting a membership is exactly the power the pairing code grants:
  the relay's ACL admits the device to the log, and roles are data until
  an enforcement slice exists ([ADR 0021]). The org log is the single
  revocation point both log kinds key on ([ADR 0022]) — joining the org
  scope, not just the budget, is what keeps that future coherent.
- **Torn joins resume, never re-join:** after the identity lands, a crash
  anywhere later (membership ops, cursors, the closing sync) resumes as
  an ordinary `pursecraft sync` — the identity is the root and re-join is
  refused. One honest edge: a crash in the tiny window between the
  identity and the membership ops leaves the membership unminted, and the
  next capture's ensure-style bootstrap self-heals it
  ([ADR 0023]'s `provision_personal_org` probes the missing fields) —
  with the joiner's role claimed as Owner rather than Editor. Roles are
  pre-accounts client claims ([ADR 0024]); the enforcement slice is where
  that stops being cosmetic.

### Pending state (ADR 0011's badge, CLI form)

- The badge is one line — `N pending sync — run: pursecraft sync` — shown
  exactly when the derived outbox is non-empty, in both places a user
  looks: `add`'s confirmation (the capture moment, when "it's offline,
  did it stick?" is the question) and `list`'s footer. It disappears
  after a successful sync; a synced capture stays one line.
- Sync failures teach rather than alarm: unreachable relay → `error: … N
  ops remain pending — retry: pursecraft sync`; a refused token (401) →
  re-enroll with `pursecraft login`; a refused scope (403) → the relay's
  message plus the pairing hint.

### Stranded ops: the re-login edge, honest and visible

Ops minted under a previous enrollment can never be pushed — the relay
refuses another device's ops by construction ([ADR 0024]). `sync` counts
them (local ops beyond `pushed_through` whose device is the founding
device, not the session's) and reports the count once per run. They are
never silently dropped, never block new captures or pushes, and remain in
the log and in `list` forever — local-first means unsyncable, not gone.

## Alternatives considered

- **Per-launch server ping as the gate** — rejected: the relay becomes an
  availability dependency; enrolled-offline must be full function.
- **Read-only commands ungated** — rejected: halves the teach and implies
  local data is usable without a home, which is exactly what the decision
  denies.
- **Auto-sync after `add`** — rejected: network on the capture path breaks
  the sub-second offline capture ([ADR 0023]); manual sync plus the
  pending badge is the honest CLI shape.
- **Secret on argv or in an env var** — rejected: shell history and
  dotfile sprawl; stdin is scriptable and TTY-free.
- **Token in the OS keyring** — rejected for v1: a keyring dependency and
  a second trust domain; the 0600 file sits in the data home beside the
  oplog it protects.
- **A stored outbox file** — rejected: a second durable structure whose
  crash windows against the store append would strand or duplicate ops;
  the derived outbox (device filter + `pushed_through`) is rebuildable
  from the store and correct under every crash.
- **One session watermark as the pull cursor** — rejected: after a store
  boot it counts local sequences; the relay's cursor is another space
  ([ADR 0017]). Mixing them in one integer is the classic missed-op
  window; `sync.json` keeps two explicit cursors.
- **ureq / reqwest / tokio-based client** — rejected: ureq 2 drags the
  `url` crate and the ICU tree (~20 transitive crates) for a localhost
  call; a tokio client is a runtime in a sync one-shot CLI. `minreq`
  (no TLS, `json-using-serde`) adds **zero** new transitive deps — the
  repo's lean-deps discipline ([ADR 0023]) keeps its teeth.
- **Hand-rolled HTTP/1.1 on `std::net`** — rejected: chunked transfer and
  proxy semantics are correctness traps; `minreq` is small, tested, and
  ISC-licensed (deny.toml's one conscious license addition for this slice).
- **HTTPS now** — rejected: the relay is plain HTTP by decision ([ADR
  0024]); TLS arrives with the deployment/hosted slice. `login` refuses
  non-`http` URLs with that explanation.
- **Server-side changes for join** — rejected: pairing codes, grants, and
  per-scope routes already cover the flow ([ADR 0024]); the relay is
  untouched by this slice.

## Consequences

- The CLI surface becomes `login`, `sync`, `pair`, `join`, `add`, `list`
  (+ `--help`/`--version`); exit codes unchanged (`0`/`2`/`1`, [ADR 0023]).
- One new direct dependency (`minreq`, no default features); the lockfile
  grows by exactly that crate (verified by `cargo tree`, cargo-deny, and
  cargo-machete stay green).
- `pursecraft-core` and `pursecraft-api` are untouched — the CLI is a pure
  consumer of both, as [ADR 0023] established.
- Every minted op still flows through the single sink; the E2EE lane's
  wrap/unwrap lands there and in the payload choke point, with sync
  pushing and pulling whatever string the seam produces ([ADR 0022]'s
  store-cipher seam already carries the in-flight half).
- The two-device dogfood is scripted end-to-end: two CLI homes enroll
  against a live local relay, both capture offline, both sync, and
  convergence is asserted through the engine's own state equality —
  client states must equal each other and the relay's canonical replay.
- Identity's `device_id` is provenance, not authority: ops carry the
  session's device, and a re-login leaves the founding id behind as the
  stranded-ops marker.
