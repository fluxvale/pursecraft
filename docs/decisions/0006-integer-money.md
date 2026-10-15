# 0006 — Money as Integers (Milliunits)

- **Status:** Accepted
- **Date:** 2026-10-15

## Context

Budget arithmetic is the core of the product. Binary floating-point cannot
represent most decimal currency values exactly (0.1 + 0.2 ≠ 0.3), and rounding
drift across thousands of transactions silently corrupts balances. This is the
single most common source of budgeting-app bugs.

## Decision

All monetary amounts are stored and computed as `i64` integer milliunits
(1 unit = 1000 milliunits, YNAB's convention), regardless of currency. No
floating-point types are permitted anywhere near amounts — enforced by types in
the core crate, not convention.

## Alternatives considered

- **Floating point with rounding** — rejected; drift is inevitable.
- **Decimal/fixed-point libraries** — unnecessary dependency; integer
  milliunits give three decimal places of precision, enough for all retail
  currencies and crypto-adjacent display needs at this scope.

## Consequences

- Exact arithmetic, trivially testable.
- Formatting/parsing at the UI boundary must respect locale conventions; all
  conversions live in the presentation layer.
- A core-lint/clippy rule or type alias (e.g., `Milliunits`) should make float
  leakage a compile-time or CI error.
