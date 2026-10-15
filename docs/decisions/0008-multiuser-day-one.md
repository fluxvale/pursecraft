# 0008 — Multi-User Budgets from Day One

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Budgets are shared by households (e.g., partners). Multi-user support was
initially deferred, but shared budgets change what must exist at launch:
authentication, authorization, and conflict behavior that assumes concurrent
editors.

## Decision

Build multi-user into the foundation:

- `budget_memberships` table (user ↔ budget) with roles: **owner / editor /
  viewer**.
- Every entity carries `budget_id`; the server enforces scoping on both op
  ingestion and delta reads.
- Invite flow: link/email token → membership → device registers → syncs.
- Every op is tagged with `user_id` and `device_id`, giving attribution/audit
  trails for free ("who changed this").
- Conflict behavior per ADR 0007 (per-field LWW + deterministic referential
  rules), which holds up under concurrent editors.

## Alternatives considered

- **Single-user first, multi-user later** — rejected: retrofitting scoping and
  auth into a shipped sync protocol and data model is far more expensive than
  including them from the start.

## Consequences

- Accounts and auth exist at v1 even though the first user is a household of one.
- Actor tagging later powers per-device/per-agent audit and revocation
  (see ADR 0012).
- Multi-user accelerates op-log growth, making compaction (ADR 0007) a
  launch requirement rather than a later optimization.
