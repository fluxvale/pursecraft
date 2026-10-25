# 0022 — Client-Side E2EE: Envelope Encryption over the Payload Choke Point

- **Status:** Accepted
- **Date:** 2026-10-25
- **Builds on:** [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0015](0015-product-positioning.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0021](0021-organizations-own-budgets.md)
- **Implements:** [ADR 0009](0009-e2ee-opaque-payloads.md)'s deferred
  encryption scheme, refined onto [ADR 0021](0021-organizations-own-budgets.md)'s
  per-log key hooks.

## Context

ADR 0009 made payload opacity a day-one discipline and deferred the crypto;
ADR 0017 built the single `encode_payload` / `decode_payload` choke point the
E2EE layer was promised to wrap; ADR 0018's store persists payload strings
through that same choke point and is content-blind by design; ADR 0021 left
the hooks — per-log keys, org membership as the single revocation point.
This slice lands the encryption itself: a new `pursecraft-crypto` crate
under `apps/core/crates/` plus minimal seams in `pursecraft-core`. Key
transport, the rendezvous channel, invites, and auth stay out (issue #20);
the crypto lane owns key-material formats so no other lane invents them.

## Decision

### Primitives — boring, vetted, RustCrypto

- **Payload AEAD: XChaCha20-Poly1305** (`chacha20poly1305`), exactly the
  first choice ADR 0009 named. Nonces are 24 random bytes from the OS RNG,
  one per envelope: a 192-bit random-nonce space makes collisions
  negligible (after 2³² encryptions under one key the bound is ≈ 2⁻¹²⁹),
  so no counter state exists to misuse, and a re-encrypted retry legally
  carries different bytes — which the log's `op_id`-only dedupe already
  tolerates (ADR 0017).
- **Device key wrapping: X25519 + HKDF-SHA256 + XChaCha20-Poly1305**
  (`x25519-dalek`, `hkdf`, `sha2`). One wrap = a fresh ephemeral X25519
  keypair, ECDH against the recipient device's public key, HKDF-SHA256 with
  domain-separated labels into a 32-byte wrap key, then XChaCha20-Poly1305
  over the 32-byte wrapped key. This is the `age` X25519-recipient
  construction — a fixed-parameter, non-agile KEM — not an invention.
- Symmetric keys (`DataKey`, 32 bytes) and device private keys are zeroized
  on drop (`zeroize`); `Debug` never prints key material. `argon2` is
  deliberately absent: no passphrase or recovery-key surface exists in this
  slice (device keys are generated from the OS RNG; recovery per ADR 0009
  is the identity/recovery slice's work).
- cargo-deny advisories gate CI as everywhere else (issue #12). One license
  addition was forced by `x25519-dalek`'s triple license:
  **BSD-3-Clause** joins `deny.toml`'s allow list for the dalek crates.

### Key hierarchy — device keys over org epochs over per-log keys

Three levels, matching ADR 0021's hooks:

1. **Device keypair** (X25519) — one per device. The private half never
   leaves the device; platform keystore integration (Keychain/Keystore,
   ADR 0009) is the app shell's adapter, later. A device key wraps nothing;
   it only unwraps.
2. **Org epoch key** — one random `DataKey` per (org, epoch). This is the
   root of the org's hierarchy; it encrypts no data itself.
3. **Per-log data key** — one random `DataKey` per (log scope, epoch):
   the org log and each budget log of the org get their own (ADR 0021).
   Payload envelopes are sealed under exactly these.

Wrapping: each **org epoch key is wrapped to every member's device**
(ephemeral-static X25519, above); each **log key is wrapped under its
org's same-epoch epoch key** (plain XChaCha20-Poly1305 — both sides are
symmetric keys). Why the middle layer: an invite or a new-device restore
wraps one key per epoch to one device, not one wrap per log per epoch, and
rotation re-wraps N members + M logs instead of N × M envelopes.

### Epochs and rotation — membership is the revocation point

An org's **epoch** is a u64 counter (0 at org creation), shared by every
log the org owns. Envelopes carry the epoch they were sealed under, so the
opener picks the right key without trial decryption.

- **Rotation** (ADR 0021's single revocation point): removing a member
  increments the org's epoch, mints a fresh org epoch key wrapped only to
  surviving members' devices, and mints a fresh data key for **every** log
  of the org, each wrapped under the new epoch key. Never reuse a key
  across epochs — a removed member's cached keys are old-epoch by
  construction.
- **Honesty, two ways.** A removed member keeps every key they already
  held: history stays readable to them forever (ADR 0009's stance —
  rotation protects future data only). And a stale reader is *loud*: an
  envelope with an epoch the reader lacks fails as `MissingEpoch` before
  any decryption, which is the signal to fetch new key material — the
  rendezvous lane's channel, not this slice.
- **Invites** wrap the current epoch key to the invitee's device (grant
  history by wrapping all past epoch keys too — both are one call; which
  policy applies is the capture lane's). New-device restore is the same
  operation.
- **Adoption is explicit.** A keychain installs a wrapped key by calling
  an install function with the wrap in hand; nothing auto-adopts key
  material that arrives unbidden. Key-envelope **authenticity** (a member
  proving a rotation is theirs) and **concurrent-rotation races** (two
  survivors minting competing epoch N+1s) are the distribution channel's
  contract — the rendezvous slice designs ordering/authentication there;
  this slice ships the versioned formats it will carry.

### Envelope v1 — the sealed payload format

The choke-point string under encryption is JSON, self-describing and
debuggable like the rest of the wire (ADR 0017):

```json
{"v":1,"e":<epoch u64>,"n":"<base64 24-byte nonce>","c":"<base64 ct‖tag>"}
```

- **AAD binds the envelope to its op**: associated data is the canonical
  JSON of `{"op_id", "scope", "hlc"}` under a `pursecraft.e2ee.v1` domain
  label. A server that splices one op's ciphertext onto another's
  metadata — or mints a fresh stamp onto old ciphertext — fails
  authentication. `device_id`/`user_id` ride unbound: metadata is
  plaintext and unauthenticated (ADR 0009); binding them would buy
  nothing — attribution authenticity is the auth slice's member-signing
  work.
- **Shape-disjoint from plaintext by construction**: a v1 envelope has
  none of `PayloadWire`'s required fields, and vice versa. An
  envelope-mode decoder handed plaintext fails as *not an envelope*; a
  plaintext decoder handed an envelope fails as *not a payload*. There is
  no input both accept, so strip/downgrade confusion is loud in both
  directions — the load-bearing property for "payload claiming encrypted
  when not".
- Envelope `v` is checked strictly; unknown versions fail loudly. Field
  types are strict. The format is now load-bearing alongside the wire
  format (ADR 0017) and freezes with it.

### Local wrap/unwrap only — versioned hooks, no channel

`pursecraft-crypto` ships the local operations: generate devices, create
orgs (epoch 0 keys + initial wraps), add/remove logs, wrap to devices,
install wraps, rotate, and seal/open payload envelopes through a
`PayloadCipher`. Wrapped keys serialize as **versioned opaque records**
(`WrappedOrgKey` v1: ephemeral public key, nonce, ciphertext;
`WrappedLogKey` v1: nonce, ciphertext) so any future channel — a key-log
API, records riding the org log, a side channel — relays them without
interpreting them. That channel's contract, stated once here: delivery is
at-least-once and **authenticated as to origin** (see rotation honesty
above).

### At-rest policy — the store holds ciphertext, metadata stays plain

**Both in-flight and at-rest, through the one choke point.** The seal
sits below `encode_payload`, above the store's frame encoder, so a
ciphered `LocalStore` writes ciphertext payloads with no store-format
change — exactly what ADR 0018 predicted ("the at-rest encryption layer
changes what that string holds, not this shape"). No header version bump,
no reserved word: the payload string was never specified as plaintext.

Store **metadata** (op_id, scope, device, user, HLC, sequences) stays
plaintext on disk: it is precisely the set the server sees by design
(ADR 0009), the engine's boot path (scope fixity, `op_id` dedupe, HLC
validation) is metadata-driven, and the remaining local exposure — someone
with the file already sees ids and timestamps, not amounts or memos — is
the OS sandbox/whole-disk-encryption layer's job, not the app's. Booting a
ciphered store requires its keys present: an undecryptable payload fails
as `StoreError::Cipher`, distinct from `StoreError::Corrupt`, so a missing
key never triggers the torn-tail repair path (which could otherwise
truncate good frames) and never gets mislabeled as file damage.

### Zero-knowledge posture — what the server still sees

Visible: `op_id`, `scope`, `device_id`, `user_id`, HLCs, sequences
(ADR 0009 — scope and HLCs are the routing and ordering protocol itself);
plus, per envelope, the epoch number and the ciphertext length. Length
leaks the approximate plaintext size; ids and HLCs leak activity patterns
(who wrote, when, how much). Accepted, and stated plainly: the wedge is
"we cannot read your data" (ADR 0015), not traffic-analysis resistance.
Padding and cover traffic are rejected as speculative complexity (repo
rule 1); the posture is revisitable without touching the envelope format
only by batching — noted, not designed.

### Seams in `pursecraft-core` — additive, crypto-free

Dependency direction: `pursecraft-crypto` depends on `pursecraft-core`,
never the reverse (rule 7, core-and-adapters: the seam lives in core, the
adapter in crypto — the CLI/API lanes get no new transitive deps).

- `wire::PayloadCipher` — the seam trait: `seal(&self, meta, plaintext) ->
  envelope` and `open(&self, meta, envelope) -> plaintext`, both fallible
  with a boxed error the store rewraps. `wire::PlainCipher` — the identity
  cipher, the legitimate self-host/no-E2EE mode ADR 0009 allows.
- `LocalStore<C: PayloadCipher = PlainCipher>` — the default type
  parameter keeps every existing call site source-compatible;
  `LocalStore::open_with(path, cipher)` is the ciphered constructor.
- `StoreError::Cipher` — loud and distinct, as above.
- The ciphered convergence and boot-from-store suites run in
  `pursecraft-crypto`'s tests, reusing core's deterministic generators
  through a dev-only `testkit` feature on `pursecraft-core` (never
  enabled by a real build) — no dev-dependency cycle, no duplicated
  test machinery.

## Alternatives considered

- **AES-256-GCM** — ADR 0009's other option. Rejected: 96-bit nonces make
  random per-op nonces birthday-bounded and counter nonces need
  per-device state to keep unique under concurrency; XChaCha's 192-bit
  nonce space removes the whole question and runs fast everywhere the core
  compiles (ADR 0001 targets include no-AES mobile cores).
- **HPKE (`hpke` crate, RFC 9180)** — actively maintained again (0.14,
  2026) and a fine fit; rejected for now: ADR 0009 named the RustCrypto
  primitives, HPKE drags a wider dependency tree and a freshly-overhauled
  API into a money app, its ChaCha suite uses 96-bit-nonce AEADs, and no
  HPKE capability we lack (sender auth, exporters, PQ KEMs) is on this
  slice's requirement list. Envelope versioning keeps a later HPKE (or
  PQ-hybrid) migration to v2 local.
- **`aes-kw`/RFC 3394 key wrap** — one more primitive for what
  XChaCha20-Poly1305 already does (authenticated wrap of 32 bytes), with
  no integrity advantage.
- **Flat key hierarchy (each log key wrapped to each device directly)** —
  works, but invites/restores cost O(logs) wraps per device and rotation
  O(logs × members) envelopes; the epoch-key middle layer is the standard
  envelope-encryption shape (KMS-style) and pays for itself immediately.
- **One org-wide data key (no per-log keys)** — fewer keys, but any leak
  burns every log at once and ADR 0021 already decided per-log keys;
  per-log keys also leave room for finer-grained sharing later without a
  format change.
- **Encrypting store metadata too** — buys hiding ids/timestamps from a
  local file reader, at the cost of a keyed boot before the log can even
  route by scope, and it protects nothing the hosted server doesn't
  already legitimately see. Wrong layer; see at-rest above.
- **Padding payloads to length buckets** — closes the length leak at real
  cost per op against a threat (traffic analysis by the host) the posture
  section explicitly declines to claim.
- **Argon2-derived device keys now** — a passphrase KDF with no passphrase
  UI in scope would be speculative; recovery is designed with the
  identity slice.

## Consequences

- The hosted tier's server, and any device without membership, store
  opaque bytes; server-side features stay permanently impossible (ADR
  0009) — search and reports stay client-side (FTS5 + core aggregation).
- Booting or syncing a ciphered deployment requires keys on the device;
  losing every device and every wrap is data loss by design (ADR 0009's
  recovery stance).
- The envelope format is wire-load-bearing: v1 freezes with the op wire
  format, and any AAD-binding or AEAD change is a v2 envelope with both
  readable during migration.
- The rendezvous slice inherits a stated contract: carry the versioned key
  records, at-least-once, origin-authenticated, and answer `MissingEpoch`
  with the current wraps. Concurrent rotation races are theirs to order.
- Metadata attribution (`device_id`, `user_id`) remains forgeable by the
  transport until member signing lands (auth slice); state convergence is
  unaffected because resolution reads payload values only.
