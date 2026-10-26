# 0028 — Wiring E2EE into the Client: Device Keys, Key Records, and Their Transport

- **Status:** Accepted
- **Date:** 2026-10-26
- **Builds on:** [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0021](0021-organizations-own-budgets.md),
  [ADR 0022](0022-client-side-e2ee.md),
  [ADR 0023](0023-capture-cli.md),
  [ADR 0024](0024-rendezvous-sync-relay.md),
  [ADR 0025](0025-authenticated-first-clients.md)

## Context

[ADR 0022](0022-client-side-e2ee.md) landed the E2EE primitives and left two
things to their lanes: the client that installs the cipher, and the channel
that carries key records. Both lanes shipped without them. `apps/cli` has no
`pursecraft-crypto` dependency, every store is opened with the default
`PlainCipher`, `sync` pushes `encode_payload` output straight onto the wire,
and [ADR 0024](0024-rendezvous-sync-relay.md) shipped no key routes at all.
The measured result: a capture synced to a live relay lands on the relay's
disk as literal `"value":{"Text":"Coffee"}`. [ADR 0015](0015-product-positioning.md)'s
whole positioning — the hosted cloud sees only ciphertext — is false of the
shipping build.

Nothing here re-decides [ADR 0022](0022-client-side-e2ee.md)'s crypto, the
store format ([ADR 0018](0018-local-oplog-store.md)), the op wire format
([ADR 0017](0017-core-sync-engine.md)), or the relay's routes and ACL
([ADR 0024](0024-rendezvous-sync-relay.md)). It settles exactly what
[ADR 0022](0022-client-side-e2ee.md) deferred to a channel and what
[ADR 0023](0023-capture-cli.md) deferred to the app shell: where the device
secret lives, who mints the first keys, what a key record looks like on the
wire, who may fetch one, which epochs an invitee receives, and how a
self-hoster turns the whole thing off without a silent mode flip.

## Decision

### Device secret: `<home>/device.key`, and the keychain as a second file

- **`<home>/device.key`** holds the 32 raw bytes of the device's X25519
  secret. Mode 0600, process-unique tmp, file fsync, rename, directory fsync —
  `session.json`'s discipline ([ADR 0025](0025-authenticated-first-clients.md)),
  not a new one. It is created once, with `create_new` semantics: a device
  key is never re-minted over an existing one, because re-minting silently
  orphans every wrap addressed to the old key.
- **`<home>/keyring.json`** holds the device's *public* key records — the
  versioned `WrappedOrgKey` / `WrappedLogKey` values it holds — as the exact
  wire strings it received or minted. Same atomic publish, same 0600.
- **Two files, not one.** The device secret is the one long-lived secret and
  is unrecoverable; the keyring is *derived* state that the relay can
  re-serve (a device that kept its `device.key` and its grants can rebuild a
  lost keyring from the org's key records). Keeping the unrecoverable file
  small, format-free, and separate means a damaged JSON file can never cost
  the device its identity, and backup advice is one sentence per file.
- **A plain file is the right answer here, stated plainly.** Platform
  keystore integration (Keychain/Keystore) remains the app shell's adapter
  ([ADR 0009](0009-e2ee-opaque-payloads.md), [ADR 0022](0022-client-side-e2ee.md))
  and is **not** in this slice. `0600` beside the oplog it protects is the
  same posture [ADR 0025](0025-authenticated-first-clients.md) took for the
  relay token, and the file is exposed exactly as much as the plaintext it
  protects: whole-disk encryption and the OS sandbox are the layer below.
- The keyring rebuilds the in-memory `KeyChain` by installing its records:
  org wraps first (they hold the epoch keys), then log wraps (which need
  them). No raw symmetric key is ever serialized — the persisted artifacts
  are the same wrapped records the wire carries, so local state and wire
  state are one format, and the crypto crate needs no new key-material
  format for at-rest use.

### Bootstrap: the founding device mints the world's keys on first write

The first device to create the world mints epoch 0 for its org
(`KeyChain::create_org`, whose wrap is addressed to itself) and one data key
per log of that org — the org log and the personal budget log
(`KeyChain::add_log`). This runs where the world is already created: the
authenticated CLI's first writing command, immediately before the store
files come into being, and on `sync` for a home that has an identity but no
keyring yet.

Ordering is the torn-state answer: **mint, persist `keyring.json`, then
write ops.** A crash between mint and persist leaves no op sealed under the
lost key, so the retry mints fresh keys and nothing is orphaned. A crash
between the org key and a log key leaves a keyring whose missing log key is
minted on the next run, because a key is minted only when the keyring lacks
it *and* that scope's store file does not exist — if the store exists, the
key is expected to exist too, and its absence is loud (below) rather than
papered over with a fresh key that no peer can read.

### Key records: one versioned, opaque record kind for the channel

`pursecraft-crypto` (which owns key-material formats,
[ADR 0022](0022-client-side-e2ee.md)) gains one type, `KeyRecord`, with three
variants — all serialized as versioned JSON strings the relay never
interprets:

| Variant | Shape | Carries |
| --- | --- | --- |
| `device` | `{"v":1,"kind":"device","device":Id,"pub":b64}` | A device's X25519 public key |
| `org` | `{"v":1,"kind":"org","to":Id,"wrap":{…}}` | A `WrappedOrgKey` addressed to device `to` |
| `log` | `{"v":1,"kind":"log","wrap":{…}}` | A `WrappedLogKey`, openable by any epoch-holding member |

- **The `device` record is how a wrap gets addressed at all**, and it is the
  one piece [ADR 0025](0025-authenticated-first-clients.md)'s pairing flow
  left unaddressed: a pairing code transfers an *ACL grant*, never a key or a
  public key, so the inviting device cannot know the joiner's key at `pair`
  time. Each device publishes its own public key on the org's key route after
  it is granted; the next sync on a key-holding device wraps to every
  registered device it has not already wrapped for. See "Two-phase handoff"
  below for what that costs.
- **`to` is coverage bookkeeping, not authentication.** It lets a
  key-holding device see which devices already have a wrap and avoid minting
  a fresh (unidentifiable) wrap every sync. Relabelling it can only make a
  device *wait* for a wrap that never arrives — a loud `MissingEpoch`, not
  a wrong key. Wrap authenticity is unchanged from
  [ADR 0022](0022-client-side-e2ee.md): the construction binds
  `(org, epoch)` in both HKDF info and AEAD AAD, but no member proves
  authorship. See Consequences.
- **Records are strict.** Unknown `kind`, unknown fields, and versions other
  than 1 are refused loudly, never skipped. Silently ignoring a record is the
  dangerous direction: a device that ignores its own rotation wrap lives on a
  dead epoch while every op it writes is unreadable to peers.

### Transport: two org-scoped routes, records blind to the relay

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/orgs/{id}/keys` | device token, granted | Publish key records |
| `GET /v1/orgs/{id}/keys` | device token, granted | Fetch the org's key records |

- **Own routes, not a payload kind on the ops channel.** The ops channel was
  the attractive option — acks, dedupe, cursors for free — and it does not
  work, for three structural reasons. (1) An op payload must decode to an
  entity/field/value and apply; a key record is none of those, so the first
  record would wedge replay at `SyncSession::apply_delta`
  ([ADR 0017](0017-core-sync-engine.md): the first failing op aborts the
  delta, cursor unmoved). (2) Ordering is inverted: key records must be
  readable *before* the ops they unseal, so they cannot ride the channel
  whose decoding depends on them. (3) The contiguous watermark would stall
  permanently on a record it cannot interpret. What we give up is real but
  small: the record set is tiny (devices × epochs), idempotent by exact
  string, and needs no cursor — every sync pulls the whole set.
- **The relay stays payload-blind.** A push body is
  `{v:1, keys:["<record json>", …]}` and a pull returns
  `{v:1, keys:[{key:"…", device:"<pushed by>"}], …}`: the relay stores each
  record as an opaque string, dedupes by exact string equality, and adds one
  thing of its own — the authenticated caller that pushed it. It never parses
  a record, exactly as it never parses a payload ([ADR 0024](0024-rendezvous-sync-relay.md)).
- **`pushed_by` is the one piece of provenance the relay can honestly give.**
  A `device` record is usable only when its claimed device id equals the
  caller the relay authenticated for that record — so a member cannot
  register a key on another device's behalf, and a passive relay cannot
  substitute one. It is relay-asserted, not cryptographic: a fully hostile
  relay is already outside this slice's threat model in the same way a relay
  that fabricates ops is ([ADR 0024](0024-rendezvous-sync-relay.md)).
- **Persistence** is one atomic JSON file per org
  (`<data>/keys/org-<uuid>.json`, tmp + fsync + rename + dir fsync, the
  `auth.json` discipline), loaded lazily and capped at
  `MAX_KEY_RECORDS` per org so a granted device cannot bloat the directory.
- **Org-scoped only.** Budget scopes get no key route: the org is the single
  revocation point ([ADR 0021](0021-organizations-own-budgets.md)); a request
  for a budget-scoped key route is a 400 that says so.

### Two-phase handoff: the joiner publishes, a key-holder delivers

A pairing code grants relay access; it carries no key material and no public
key, by [ADR 0025](0025-authenticated-first-clients.md)'s design. So the
handoff is explicit and two-phase, and it puts **no key material in the
pairing bundle** — the bundle stays an ACL credential that expires in an hour,
never a decryption credential that people paste into chat:

1. **Joiner:** redeem both codes, publish its `device` record on the org's key
   route, pull the org's key records, install what is addressed to it. On a
   first join nothing is yet — it writes the world's identity (the root, as
   [ADR 0025](0025-authenticated-first-clients.md) already has it) and says so
   in one teaching line: run `pursecraft sync` once on a device that holds
   this world, then `pursecraft sync` here.
2. **Key-holder:** its next `sync` sees the joiner's `device` record, wraps
   the org's epoch keys to it (`Grant::AllEpochs`) and publishes the `org`
   records; its log wraps are already published.
3. **Joiner again:** `sync` pulls the records, installs the org wrap then the
   log wraps, and pulls the ops it can now open.

Between (1) and (3) the joiner is a readable-identity, unreadable-data home:
`list` and `add` fail with the crypto crate's `MissingEpoch` text ("no key
material for … — fetch key wraps") wrapped by `StoreError::Cipher`, which is
exactly [ADR 0022](0022-client-side-e2ee.md)'s loud-stale-reader contract and
this slice's third acceptance check. The join's own membership ops are minted
by the next writing command, the torn-join self-heal
[ADR 0025](0025-authenticated-first-clients.md) already documents.

### Wrap policy at join: `Grant::AllEpochs`, because boot is replay

Joins grant **all** held epochs, not the current one.

History readability is usually framed as a preference; here it is forced by
the log. A late joiner pulls `since=0` ([ADR 0024](0024-rendezvous-sync-relay.md))
and a client boots by replaying the whole store ([ADR 0018](0018-local-oplog-store.md)),
so the *first* op of the log must open. A current-epoch-only joiner would
fail to boot at the first historical envelope — not "read from your join
forward", but "cannot open the store at all". Since compaction and snapshot
bootstraps are deliberately deferred ([ADR 0007](0007-oplog-sync-protocol.md),
[ADR 0024](0024-rendezvous-sync-relay.md)), `AllEpochs` is the only policy
that admits a second device to an existing world. The cost is one wrap per
held epoch per device — O(epochs), not O(logs × epochs) — and it is
consistent with [ADR 0022](0022-client-side-e2ee.md)'s honesty: history is
shared with whoever is admitted; rotation protects the future only.

### Wiring the cipher through the client's one path

- `apps/cli` gains a `keys` module holding the mode, the device key, the
  keyring, and one `World` value per command. Every store in the CLI is
  opened as `LocalStore<WorldCipher>`, where `WorldCipher` is the CLI's
  `PayloadCipher` adapter: `ScopeCipher` in E2EE mode, `PlainCipher` in the
  self-host mode. One type, one open path, so no command can accidentally
  open a store in the wrong mode.
- **At rest and in flight are the same seam.** `LocalStore::open_with`
  already seals on append and opens on boot ([ADR 0018](0018-local-oplog-store.md),
  [ADR 0022](0022-client-side-e2ee.md)); the only in-flight work is the sync
  path: `push` seals each op through the cipher before it reaches the wire
  (a fresh nonce per push, which [ADR 0022](0022-client-side-e2ee.md) and
  `op_id`-only dedupe both allow), and `pull` opens each record through the
  cipher before `decode_payload`. [ADR 0025](0025-authenticated-first-clients.md)'s
  "the E2EE wrap lands at the sink" holds: the sink is still the only append.
- `pursecraft-core` is **untouched** by this slice. The seam
  ([ADR 0022](0022-client-side-e2ee.md)) was sufficient; nothing here
  reshapes it.

### Self-host escape hatch: `PURSECRAFT_E2EE=off`, with no silent flip

- **`PURSECRAFT_E2EE=off`** (exactly that value; anything else, including
  unset, means E2EE on) selects `PlainCipher` for every store and leaves the
  key routes unused. An environment variable, not a config file: the CLI has
  none and this is a one-line operational choice, the same shape
  `PURSECRAFT_HOME` already has. Not a build feature: one artifact for cloud
  and self-host is [ADR 0009](0009-e2ee-opaque-payloads.md)'s whole point.
  The mode is injected through the CLI's `Context`, so tests never touch the
  process environment (no `set_var` under the workspace's `unsafe_code`
  forbid).
- **The choice is sticky by evidence, not by a flag file.** Two loud guards
  run at the one place a `World` is built:
  - E2EE off but `keyring.json` present → refuse: this home's logs are
    ciphered, unset `PURSECRAFT_E2EE`. (Without it, `PlainCipher` would hand
    envelope strings to `decode_payload`, which fails as *corruption* — loud
    but mislabeled.)
  - E2EE on but no `keyring.json` and a store file present → refuse: this
    home's logs were written without E2EE; set `PURSECRAFT_E2EE=off` to read
    them, or start a fresh home. (Without it, the store refuses each record
    with `StoreError::Cipher`, also loud but at the first frame rather than
    the command's front door.)
  - Behind both guards, the envelope/plaintext shape disjointness
    ([ADR 0022](0022-client-side-e2ee.md)) remains the backstop for mixed or
    tampered files: `StoreError::Cipher` one way, `StoreError::Corrupt` the
    other, never a silent reinterpretation, never a torn-tail repair over
    bytes a key would open.
- `PlainCipher` stays a first-class mode and is tested as one: the two-device
  convergence suite runs in both modes.

## Alternatives considered

- **Key records riding the ops log as a payload kind** — rejected above:
  unappliable by the engine, inverted dependency, and a permanently stalled
  watermark. The apparent freebies (acks, ordering, cursors) are exactly the
  machinery whose semantics assume domain payloads.
- **A separate key *scope* (a fourth log kind)** — rejected: every key route
  would then need its own ACL, and the org already *is* the ACL
  ([ADR 0021](0021-organizations-own-budgets.md), [ADR 0024](0024-rendezvous-sync-relay.md)).
- **One-shot handoff: the pairing bundle carries the epoch key wrapped to a
  throwaway keypair whose secret rides the bundle** — rejected. It makes
  `join` self-contained, and it turns a 1-hour, single-use *ACL* credential
  into a decryption credential for the world's history, in terminal
  scrollback and chat. [ADR 0022](0022-client-side-e2ee.md) wraps keys to
  device keys for a reason. The two-phase cost is one extra `sync` on a
  device the operator is already using.
- **The relay parses records to serve "wraps for me" only** — rejected:
  payload-blindness is the relay's one structural property
  ([ADR 0009](0009-e2ee-opaque-payloads.md), [ADR 0024](0024-rendezvous-sync-relay.md)).
  Pulling the org's whole record set and letting each device try to install
  what is addressed to it is O(records) at household scale.
- **A cursor/paging for the key route** — rejected: the set is small,
  idempotent, and needed whole on every device. A cursor would add a second
  durable client structure for nothing.
- **`Grant::CurrentEpoch` at join** — rejected: it cannot boot the store
  (see above).
- **Recording the mode in `identity.json` (or a flag file)** — rejected: the
  identity file is versioned ([ADR 0023](0023-capture-cli.md)) and a schema
  bump to carry a boolean is a migration for state that the keyring's
  presence already witnesses; a separate flag file is a third file to lose
  and a fourth thing that can disagree with the disk.
- **A build feature for the self-host mode** — rejected: two artifacts, and
  [ADR 0009](0009-e2ee-opaque-payloads.md) exists to keep one.
- **Platform keystore now** — out of scope, unchanged from
  [ADR 0022](0022-client-side-e2ee.md): the adapter belongs to the app shell.
- **Member-signed key records** (proving a wrap's author) — out of scope with
  member signing; see Consequences.

## Consequences

- The relay's disk holds ciphertext for payloads and opaque wrap records for
  keys. [ADR 0022](0022-client-side-e2ee.md)'s "we cannot read your data"
  becomes true of the shipping build, and the acceptance repro lands as the
  empty grep.
- **A second device needs two syncs and one sync on a key-holding device**
  before it can read. `join` writes the identity and teaches that in one
  line; every command in between fails loudly rather than showing an empty
  budget.
- **Losing `device.key` loses everything that device could read** — every
  wrap is bound to it. Copying the whole data home (device.key, keyring.json,
  session.json included) is the backup story, as
  [ADR 0025](0025-authenticated-first-clients.md) already says for restore.
  Losing `keyring.json` alone is recoverable while the relay still holds the
  org's records.
- **A wrap's coverage label is a claim, so coverage is read from the device's
  own keyring, not from the relay.** `to` exists to stop a key-holder minting
  a fresh wrap on every sync; if coverage were computed from served records, a
  grant-holding member could pre-empt any peer's wrap with one forged
  `to: <victim>` entry — this device's own keyring, which only it writes, is
  the only trustworthy source. The same reasoning applies to a `device`
  record: it is usable only when the relay's authenticated `pushed_by` stamp
  matches its claimed id, so no member registers a key on another's behalf.
  Both are cheap hardening against a member, and neither is a fix for the
  forgery gap below.
- **Wrap authenticity is still unproven, and the channel now makes the gap
  concrete.** Anyone holding a device's public key can wrap *some* epoch key
  to it — including a hostile relay, which learns every public key from the
  device records it serves. Servable consequences: (a) a forged wrap for an
  epoch a device does not yet hold installs, and the real ops at that epoch
  then fail authentication — a loud stall, not a silent read; (b) a forged
  wrap served to two devices makes them disagree on the epoch key, so their
  new ops are unreadable to each other — withhold-able, visible as
  `Auth`/`MissingEpoch`, and repairable only by re-fetching. The real fix is
  member-signed key records (and signed ops), which is the auth slice's, as
  [ADR 0022](0022-client-side-e2ee.md) already states. Until then the honest
  claim is "the relay cannot read the data", not "the relay cannot disrupt
  the key channel".
- **Install conflicts are loud, and loud must not mean fatal.** A wrap
  addressed to this device that lands in a slot already holding different
  material fails as `WrongKeySlot`, never a silent skip. But the relay's
  record set is append-only and readable by every granted device, so a
  *poisoned record is not allowed to stop the data path*: the records that
  open install, the ops still push and pull, and the conflicts are reported
  at the end (a non-zero exit naming them). A member can therefore plant a
  visible nuisance, not a permanent org-wide sync kill. A log wrap that fails
  authentication on a device that is not its addressee is the ordinary
  misroute/mislabel case and is skipped; the loud path is reserved for a wrap
  that actually opened for this device and conflicted.
  An **unparseable** record is treated the same way: it is collected as a
  conflict and skipped, never a parse failure that stops the data phase — the
  relay stores whatever bytes it is given, so garbage is a member's to plant
  and the client's to report, not an org-wide wedge.
  The remaining window that is *not* recoverable is a wrap sealed to a key
  this device no longer has: losing `device.key` while the keyring still holds
  records loses the world. That is a `MissingDeviceKey` naming the file to
  restore, on every command, and the key is **never** re-minted over a
  populated keyring; an *empty* keyring with no key is the crash window and is
  completed (the key binds nothing yet). Torn **keyrings** (a key present,
  some records not yet written) *are* recovered: a founder's mint re-runs on
  every capture and a joiner's on the next `sync`, because both are idempotent.
  All of this is pinned by tests.
- **Coverage is persisted, not inferred.** The wraps a device mints for a peer
  are written into its own keyring (they appear in `unpublished` until the
  relay serves them), which is what makes the `to` bookkeeping real: without
  it every sync re-wrapped every peer, and since the relay's record set is
  append-only that grew toward `MAX_KEY_RECORDS`, where `Full` is a permanent
  sync failure for the org. An idle sync now mints nothing, and a test holds
  the record count stable across repeated syncs.
- **Competing wraps for one slot adopt in relay order.** When two survivors
  mint an epoch concurrently (rotation, later slice), installs conflict
  loudly ([ADR 0022](0022-client-side-e2ee.md)) but *which* one a device
  adopts first is whichever the relay serves first — deterministic per
  device, not across devices. Ordering that race is the rotation slice's,
  with member signing as its prerequisite. Rotation itself is not wired here
  (no member-removal command exists).
- **A joiner's `device` record is a public key on the relay's disk.** It is
  the same key material every wrap already exposes to the host; no new
  secrecy claim depends on it.
- **The key route is org-only, capped, and deduped by exact string**, so a
  granted device can add records but cannot make the set unbounded; a
  device's own re-pushes are free no-ops.
- **`apps/api` gains no `pursecraft-crypto` dependency** and still cannot
  parse an envelope or a record; `apps/core` gains no code at all. The CLI
  gains `pursecraft-crypto` and nothing else (no new third-party crates;
  `deny.toml` unchanged).
- **Unverified / out of scope, stated rather than implied:** platform
  keystore integration; passphrase or recovery keys; member signing and
  attribution authenticity; member removal and rotation; mobile and web
  clients.
