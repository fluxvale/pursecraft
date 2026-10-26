# 0026 — Budgeting Semantics in the CLI: Categories, Inbox, Allocation, Balances

- **Status:** Accepted
- **Date:** 2026-10-26
- **Builds on:** [ADR 0006](0006-integer-money.md),
  [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0011](0011-capture-first-mobile.md),
  [ADR 0016](0016-core-domain-model.md),
  [ADR 0021](0021-organizations-own-budgets.md),
  [ADR 0023](0023-capture-cli.md),
  [ADR 0025](0025-authenticated-first-clients.md)
- **Amends (in part):** [ADR 0023](0023-capture-cli.md) — the
  category-at-capture clause: quick-add's category step arrives as an
  optional `--category` flag, and "uncategorized is a valid, designed
  state" now has a name and a surface (the Inbox).

## Context

The CLI captures transactions ([ADR 0023]) but attaches no category — a
ledger, not yet a budget. Every entity this slice needs has existed in the
core since [ADR 0016]: `CategoryGroup`, `Category`, `MonthCategory` (the
month × category allocation cell), alongside `Transaction`. [ADR 0011]'s
own quick-add spec is `amount -> account -> category -> done`; the CLI
stopped at account. This slice makes the CLI a budgeting app: envelopes,
allocation, and the "can I buy this?" check that is the product's point.

Nothing here touches sync semantics: category, group, and month-cell ops
are entities + ops on the budget log like any other, converge through the
existing engine ([ADR 0017]), and flow through the CLI's single
[`sink`](0023-capture-cli.md) mint path.

## Decision

### Category-aware capture: `--category`, and uncategorized stays unset

```text
pursecraft add <payee> <amount> [--date YYYY-MM-DD] [--account <name>] [--category <name>]
```

- `--category` resolves an exact live category name — unknown names are
  teaching errors listing the known categories, exactly like `--account`.
  No find-or-create: a typo at capture would silently mint a category and
  fragment the budget. `--category Inbox` is legal (explicitly parking a
  capture in the review queue).
- Without the flag, capture writes **no category op** — `category_id`
  stays unset, precisely [ADR 0023]'s "ready to assign" state. The Inbox
  (below) is the *view* of that state, not a write: capture stays five
  ops, one-shot, sub-second, and there is exactly one representation of
  "needs review" instead of two.

### The Inbox: a real bootstrap category, found by name

Uncategorized transactions land in an **Inbox** — a real `Category`
entity named `Inbox`, so it rides the budget log, syncs like any entity,
and is nameable from every client.

- **Minted at bootstrap, not reserved.** A reserved-id phantom category
  (an entity with no ops) violates the oplog model — entities materialize
  from ops ([ADR 0016]) — and every projection would special-case it.
- **Found by name, not persisted in `identity.json`.** Every
  budget-writing command (`add`, `category new`, `categorize <id> <cat>`,
  `assign`) runs an ensure step: the earliest live category named
  `Inbox`, else mint one with an anchored name op (the payee/account
  read-then-mint precedent, [ADR 0023]). No identity version bump: worlds
  created before this ADR self-heal on their next writing command, and a
  user-minted "Inbox" is adopted rather than twinned. The name is
  reserved by adoption — `category new` refuses live-name duplicates.
- **The inbox bucket** (the review surface) is a projection: every
  visible transaction whose resolved category
  ([ADR 0016](0016-core-domain-model.md)'s re-parenting included) is
  either `Uncategorized` or the Inbox entity. Deleted-category
  transactions re-parent to the earliest-created survivor — the Inbox, by
  construction (bootstrap mints it first) — so nothing escapes
  classification into silence; it lands on the review surface instead.
- **Read-only commands never mint.** `list`, `budget`, `category list`,
  and bare `categorize` render the bucket from the projection alone; the
  entity exists to be named and listed, not to gate the view.

### Category surface: groups ship, as labels

```text
pursecraft category new <name> [--group <name>]
pursecraft category list
```

- `category new` refuses exact live-name duplicates (duplicates make
  name-keyed resolution — `--category`, `assign`, `categorize` —
  ambiguous). Torn creations retried are answered by that rule: "already
  exists" is the honest idempotence for an explicit mint.
- **Groups ship in v1 as labels**: `--group` find-or-creates by exact
  name (a typo'd group is cosmetic; a typo'd category is money), groups
  have no commands of their own, and `category list` renders grouped with
  ungrouped categories under a plain block. The entity existed since
  [ADR 0016]; hiding it entirely would only postpone this same decision.
- `category list` marks the Inbox (`(inbox)`), teaching where uncaptured
  classification lives.

### Deferred classification: `categorize`, one-shot, id-exact

```text
pursecraft categorize                     # the inbox review listing
pursecraft categorize <txn> <category>    # file one transaction
```

- No interactivity (the [ADR 0023] shape): the bare command lists the
  bucket — short id, date, payee, amount — newest first, with the
  filing syntax in the footer. The listing prints each transaction's
  UUIDv7 as an 8-hex short form; the filing command accepts exactly that
  short form or the full UUID. Positional row numbers were rejected: a
  list that changed between look and file would misfile money.
- `categorize <txn> <category>` files **any** visible transaction (re-filing
  between categories is free; filing into `Inbox` un-files). Unknown id,
  hidden transaction, or unknown category = teaching error. One op — the
  transaction's `CategoryId` — through the sink; the confirmation names
  the move (`filed coffee -4.500 on 2026-10-24 into Groceries`).

### Allocation: `assign` and month semantics

```text
pursecraft assign <category> <amount> [--month YYYY-MM]
```

- **Months are calendar months of the transaction date** (YNAB-style
  envelopes): a transaction's activity belongs to the month of its
  `date`, regardless of when it was captured. `--month` is the core's
  strict `YYYY-MM`; the default is the local civil today's month
  ([ADR 0023]'s injected `today`, not a UTC month). No month arithmetic
  exists in v1 — no next/previous navigation — so year rollover cannot
  misfile; the month always comes from a validated `Date` or `Month`.
- The amount is the strict [Milliunits grammar](0006-integer-money.md)
  with **no sign** — assignment is a magnitude set aside. A negative is a
  teaching error (assign a smaller amount to reduce, never a minus);
  `0` is legal (how a cell is zeroed).
- The cell is read-then-mint: the earliest live `MonthCategory` whose
  `(month, category)` matches gets the `budgeted` write (plain HLC ticks
  — this is the household race per-field LWW exists for, [ADR 0016]); a
  cell is minted only when none exists. A torn assign (cell entity
  landed, `budgeted` did not) is completed, never twinned.
- **`assign` refuses the Inbox**: it is a review surface, not an
  envelope; the error teaches `categorize` first.

### Balances: `budget [show] [YYYY-MM]` and the core equation

- `budget` (or `budget show`, optionally with a month) renders one row
  per live category — `ASSIGNED  ACTIVITY  AVAILABLE` — grouped like
  `category list`, plus the Inbox row (rendered only when the bucket is
  non-empty that month — a nag, not an envelope) and a to-be-budgeted
  line.
- **The core equation, per category, per month:**

  ```text
  available = assigned + activity
  ```

  `assigned` = the sum of visible `MonthCategory.budgeted` cells for
  (month, category) — summed, so deterministically-converging twin cells
  (two devices assigning offline) overstate rather than understate, and
  the next `assign` re-targets the earliest cell and corrects the total.
  `activity` = the sum of visible transactions dated in the month and
  resolving to the category. **Single-month window: no cross-month
  carry** (deferred with goals and move-money; a carried balance would
  break the equation this slice pins).
- **To be budgeted (TBB):** `TBB = inflow − assigned`, where **inflow is
  the sum of positive amounts in the inbox bucket** for the month. The
  Inbox doubles as YNAB's "Inflow: To be Budgeted": an uncategorized
  positive is budgetable by default; categorizing a positive into a
  category makes it a refund of that category's activity (and removes it
  from TBB), exactly YNAB's semantics. This keeps one conservation
  identity over the month, pinned by tests:

  ```text
  Σ(available over rows) + TBB = Σ(all visible transaction amounts in the month)
  ```

  A negative TBB is over-assigned and renders as a negative number —
  visible, never clamped.
- Torn data is faithful, not defaulted ([ADR 0016]'s no-silent-zero
  rule): only *landed* ops count. A transaction without its `amount` op,
  a cell without its `budgeted` op, and a transaction without its `date`
  (no month bucket) are excluded until their ops land; `list` still
  renders torn cells as `?` per [ADR 0023].

### `list` grows a category column

The recap adds the resolved category between payee and amount — `Inbox`
for the bucket, the resolved name otherwise. The unset category is not a
tear to hide behind `?`: it is the designed ready-to-assign state.

### Where the math lives: the core, purely

The roll-up is a pure projection — `budget::project(state, month,
inbox)` over [`ScopeState`] → rows + inflow + TBB — and it lives in
`pursecraft-core` as a new, self-contained module: the equation is
domain logic every client (mobile, web) must reproduce identically
([ADR 0001](0001-shared-rust-core.md)'s thesis), and the core edit is
additive — no existing behavior changes, no sync semantics, nothing for
the parallel lanes to rebase around. The CLI supplies policy (which
category is the Inbox) and rendering; ordering inside the projection is
by category id (engine-deterministic), and the CLI sorts by group/name
for display.

### Surface summary

The gated surface ([ADR 0025]'s choke point is unchanged — every new
command sits behind the enrollment gate):

```text
add <payee> <amount> [--date] [--account] [--category]
list
category new <name> [--group <name>]
category list
categorize [<txn> <category>]
assign <category> <amount> [--month YYYY-MM]
budget [show] [YYYY-MM]
login | sync | pair | join        (unchanged, ADR 0025)
```

`category new`, `categorize <txn> <cat>`, and `assign` require a world
(the identity file) and teach `pursecraft add …` when absent — bootstrap
ownership stays with capture ([ADR 0023]). Write commands mint through
the sink and carry ADR 0011's pending badge; exit codes stay `0`/`2`/`1`.

## Alternatives considered

- **Writing the Inbox id into every uncategorized capture** — rejected:
  one extra op per capture and two representations of "needs review"
  (unset *and* filed-to-Inbox) that every view must unify; the projection
  bucket needs no write.
- **A reserved Inbox id (phantom entity)** — rejected: entities
  materialize from ops ([ADR 0016]); a phantom forces projection
  special-cases and ignores deletes.
- **Persisting the Inbox id in `identity.json`** — rejected: an identity
  version bump that bricks pre-existing worlds, for precision a
  name-probe already gives (the payee precedent). The name — not an id —
  is the stable user-facing key.
- **Interactive `categorize` wizard** — rejected: the [ADR 0023] argument
  (scriptable, one-shot, sub-second) verbatim; the review pass is a
  listing plus id-exact filing commands.
- **Row numbers as `categorize` selectors** — rejected: raciness between
  listing and filing misfiles money; ids are exact.
- **Signed `assign` amounts** — rejected: assignment is a magnitude; a
  negative assignment has no meaning a smaller positive doesn't express
  better.
- **Cross-month carried available (full YNAB)** — rejected for v1: it
  breaks the single-month equation this slice pins, and the carry
  interacts with goals/move-money, both out of scope. The window widens
  in a later slice.
- **TBB = all positive transactions** — rejected: a categorized positive
  is a refund (category activity), so counting it as inflow too
  double-counts; only inbox positives are new budgetable money, and the
  conservation identity pins the choice.
- **Groups fully internal** — rejected: the entity exists, the flag is
  small, and flat-forever only postpones the same decision; labels
  without commands contain the cost.
- **Stored balances** — rejected again ([ADR 0016]): derived views only;
  storing invites drift.

## Consequences

- The CLI answers "can I buy this?" offline: `budget` renders envelopes
  with assigned/activity/available and to-be-budgeted, all derived from
  the local log.
- The capture surface grows one optional flag; bare capture is
  byte-for-byte the [ADR 0023] behavior (five ops, unset category).
- The Inbox is name-addressed: adoption means a user-created "Inbox"
  becomes the review surface (documented behavior, not a collision). If
  the Inbox entity is deleted out-of-band (no CLI path exists), the
  ensure step re-mints it; transactions resolving to a dead Inbox follow
  [ADR 0016]'s fallback to the earliest survivor.
- Core gains one pure module; the engine, store, wire, and relay are
  untouched — category ops converge exactly as transactions already do,
  which the two-device convergence test now exercises with categories,
  assignments, and re-filing in the mix.
- Month cells stay client-unique by convention ([ADR 0016]'s deferral
  stands): twins from true concurrent offline assigns sum in the roll-up
  (deterministic, over-stating) and self-correct on the next assign.
- `list`'s column layout shifts (a category column lands between payee
  and amount) — scripts parsing fixed columns must adjust once, here.
