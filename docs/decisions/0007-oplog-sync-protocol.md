# 0007 — YNAB-Style Op-Log Sync Protocol

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

The app must be fully functional offline — reads and writes — and reconcile
across multiple devices and users later. Internet is unreliable in the field
(capture happens in checkout lines). The sync mechanism is the hardest component
and defines the product's reliability.

## Decision

Use an append-only operation log, YNAB-style — not CRDTs:

- Every entity (account, transaction, category, ...) has a UUIDv7 id, a
  tombstone flag, and per-field last-write-wins (LWW) semantics.
- Clients append ops locally: `{op_id, device_id, user_id, entity_id, field,
  value, hlc_timestamp}`.
- The server is a rendezvous point, not an authority: it stores ops, assigns
  canonical order per budget, and serves deltas since a client's last-seen
  sequence number.
- **Hybrid logical clocks (HLC)** avoid wall-clock skew across offline devices.
- Ops are idempotent (`op_id` dedupe) — safe retries on flaky connections.
- Deletes are tombstones, never hard deletes.
- Referential conflicts (e.g., a transaction filed into a deleted category) are
  resolved deterministically in the client core (re-parent to a fallback
  category, YNAB-style) where the rule is unit-testable.
- Periodic compaction: state snapshots at sequence N; new devices bootstrap from
  snapshot + ops since N.
- Live push via WebSocket/SSE; the self-hosted single instance uses an
  in-process broadcast channel — no Redis.

## Alternatives considered

- **CRDT libraries (Automerge, cr-sqlite)** — more generality than needed, more
  complexity than justified; per-field LWW matches YNAB's actual behavior.
- **PowerSync / ElectricSQL** — legitimate shortcuts, but the project wants to
  own its sync layer; the op-log approach is a few weeks of work with zero
  dependencies and enables E2EE (ADR 0009).
- **Server-authoritative state** — incompatible with offline-first.

## Consequences

- Opaque-payload discipline is possible from day one (see ADR 0009).
- Per-field LWW means two users budgeting the same category cell resolve to
  last-writer — matching YNAB behavior users expect.
- The protocol becomes a public artifact third parties build on; it must be
  versioned and frozen once external clients exist (see ADR 0012).
