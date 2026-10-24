# 0009 — E2EE with Opaque Server Payloads

- **Status:** Accepted
- **Date:** 2026-10-15
- **Supersedes:** earlier draft stance "drop E2EE" (revised when the hosted
  cloud tier entered scope)

## Context

Pursecraft will offer a hosted cloud subscription in addition to self-hosting.
For a paid product holding financial data, "we cannot read your data" (the
Proton/Bitwarden stance) is a major trust differentiator. E2EE was initially
deprioritized because it complicates multi-user sharing; the rendezvous-point
sync design (ADR 0007) turns out to make it cheap instead.

## Decision

Two parts:

1. **Day-one discipline:** the sync protocol treats all op payloads and
   snapshots as opaque. The server only ever sees metadata: `op_id`, `device_id`,
   `user_id`, `budget_id` *(amended by [ADR 0020](0020-organizations-own-budgets.md):
   the metadata field is now the typed `scope` — an org or a budget — replacing
   `budget_id`)*, HLC timestamp, sequence numbers. All serialization
   routes through a single point in the core so encryption is a layer, not a
   rewrite. Conflict resolution already lives in the client core, so the server
   never needs plaintext.
2. **Encryption scheme (enabled at cloud launch, optional for self-host):**
   envelope encryption — a random 256-bit symmetric key per budget
   (XChaCha20-Poly1305 or AES-256-GCM), X25519 per-user keypairs, budget keys
   wrapped to each member's public key. Private keys live in Keychain/Keystore.
   Boring, audited primitives only (RustCrypto crates: `chacha20poly1305`,
   `argon2`, `x25519-dalek`).

Operational rules:

- Invite = existing member wraps the budget key for the invitee's public key.
- Revocation = rotate the budget key, re-wrap for remaining members. This
  protects future data only; removed members keep what they already decrypted —
  documented honestly.
- Recovery: a generated recovery key shown once at signup; losing all devices
  and the passphrase means data is gone permanently.
- No server-side features ever: server-side search, reports, or import services
  are impossible. Search/reports are client-side (FTS5 + core aggregation).
- Compliance surface shrinks: the cloud hosts ciphertext it cannot decrypt.

## Alternatives considered

- **Server-side encryption at rest only** — simpler, but the provider can read
  everything; unacceptable for the cloud product's trust pitch.
- **E2EE à la Actual (encrypted blobs, manual key sharing)** — validated the
  direction; improved here with per-member key wrapping and revocation.
- **Deferring E2EE until after protocol freeze** — rejected: retrofitting
  opaque payloads after shipping plaintext is expensive. The discipline costs
  nothing now.

## Consequences

- Third-party SaaS integrations cannot read data without keys (see ADR 0012 for
  the sanctioned escape hatches).
- Email summaries, server-side dashboards, and similar server-initiated
  features are permanently off the table — an accepted trade.
- Cloud and self-host can share one artifact; self-hosters may disable E2EE if
  they want future server-side features.
