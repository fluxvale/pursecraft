# 0011 — Capture-First Mobile Scope

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Mobile exists primarily because the user (and users like them) record
transactions while out shopping — not for budget planning, which happens on
desktop/web. A full-featured mobile clone would delay the daily-driver value by
months.

## Decision

Mobile v1 ships exactly three screens:

1. **Quick-add transaction** — amount → account → category → done, in 3–4 taps.
   The most polished screen in the entire product.
2. **Category balances** — the "can I buy this?" check.
3. **Account list / balances**.

Required behaviors:

- Offline capture: transactions entered offline are `cleared=false`, queue in
  the op log, and sync on reconnect. The UI shows a visible pending-sync state
  so users trust it.
- Background sync on app foreground/reconnect (mobile lifecycle handled
  properly).
- Biometric lock (table stakes for a finance app).
- Duplicate-entry heuristic surfaced during quick-add (ADR 0010).

Budget editing, reports, and payee management come later.

## Alternatives considered

- **Full-parity mobile app first** — rejected: months of extra work before any
  daily value, and the 2x native tax (ADR 0003) compounds with scope.
- **PWA as the mobile v1** — rejected: startup speed, biometrics, and reliability
  in a checkout line all favor native.

## Consequences

- Mobile moves up the build order — it ships right after sync v1, not last.
- The narrow scope keeps the two-native-UI cost small.
- Home-screen widget quick-add is a natural v2 extension on the same screens.
