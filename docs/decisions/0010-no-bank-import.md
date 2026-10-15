# 0010 — No Bank Import — Manual-First

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

The primary user lives in the Philippines where Plaid-class services are
unavailable. Most of the world budgets without bank API access, yet virtually
every budgeting tool (commercial and OSS) assumes US/EU banking infrastructure.
Bank sync also brings credential-handling risk and compliance burden.

## Decision

Ship without any bank import or sync — no Plaid/GoCardless/SimpleFIN adapters,
no credential storage, no background refresh jobs. Manual entry is the only
entry path.

Kept regardless of cost:

- `cleared` / `reconciled` flags on transactions — manual statement
  reconciliation (GCash/BPI exports) still happens at month-end.
- A duplicate heuristic on manual entry: same amount + nearby date + uncleared →
  "possible duplicate" prompt. Double entry is the main data-quality risk
  without bank import.

Explicitly deferred (optional, post-v1):

- **CSV/OFX statement import** — parsing a self-exported file, fully offline,
  no API dependency. A weekend feature; add only if the itch appears.

## Alternatives considered

- **GoCardless/SimpleFIN (Actual's approach)** — EU/US-centric, adds credential
  and compliance surface, and remains unavailable where the product's niche
  lives.
- **No cleared/reconciled flags** — rejected; they are nearly free and the only
  reconciliation mechanism manual-first users have.

## Consequences

- Manual entry is the product: the quick-add screen gets the most UX polish of
  anything built (see ADR 0011).
- Security surface shrinks — bank credentials are never touched or stored.
- Sharpens positioning: "built for places Plaid doesn't reach."
