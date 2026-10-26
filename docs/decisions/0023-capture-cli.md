# 0023 — Capture CLI: Fast Local Transaction Capture

- **Status:** Accepted
- **Date:** 2026-10-25
- **Amended (in part) by:** [ADR 0025](0025-authenticated-first-clients.md) —
  the zero-setup bootstrap clause: first capture follows one-time
  enrollment.
- **Builds on:** [ADR 0006](0006-integer-money.md),
  [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0011](0011-capture-first-mobile.md),
  [ADR 0016](0016-core-domain-model.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0021](0021-organizations-own-budgets.md)

## Context

`apps/cli` is a placeholder. [ADR 0011](0011-capture-first-mobile.md) steers the
product capture-first: the fastest path from thought to stored transaction is
the first product surface, and the CLI is where that path is shortest. The core
already ships everything capture needs — the domain and Milliunits
([ADR 0016](0016-core-domain-model.md)), the read-then-mint capture contract
with org anchoring ([ADR 0021](0021-organizations-own-budgets.md)), the sync
engine and the payload serialization choke point ([ADR 0017](0017-core-sync-engine.md)),
and the durable local store ([ADR 0018](0018-local-oplog-store.md)) — but no
consumer exists yet.

Two lanes run in parallel against the same core: the E2EE crypto crate and the
rendezvous server. This slice therefore adds **zero** `pursecraft-core` edits —
the CLI is a pure consumer — and keeps one seam so the E2EE wrap lands later
without rewiring (below).

## Decision

### Interaction: one-shot argv, sub-second, offline

The CLI takes exactly one shape: a single process invoked with argv, doing
synchronous file work, exiting. No prompts, no daemon, no network — sync is
unwired by design until the sync slice, so every capture is offline-captured
per [ADR 0011](0011-capture-first-mobile.md). "Fast" is boot-to-exit well under
a second: the work is opening two small store files, replaying them through
the ordinary `SyncSession` path, minting ops, and appending — linear in op
count and milliseconds for years of captures.
*(Amended by [ADR 0025](0025-authenticated-first-clients.md): the sync slice
has landed — `pursecraft sync` is networked, manually invoked; capture itself
stays offline, and a one-time enrollment gate now precedes every command.)*

### Command surface: `add` and `list`

```text
pursecraft add <payee> <amount> [--date YYYY-MM-DD] [--account <name>]
pursecraft list
```

- **`add`** captures one transaction: the free-text payee (quick-add's first
  field, [ADR 0011](0011-capture-first-mobile.md)), a signed amount, today's
  date by default, the bootstrapped account by default. It is quiet by
  default: one confirmation line showing exactly what was stored —
  `added coffee -4.500 on 2026-10-25 (Wallet, new payee)` — plus a bootstrap
  line the first time anything is created. Feedback first, never noise.
- **`list`** is a minimal recap, not a browser: the last 10 visible
  transactions newest-first (date, resolved payee, exact 3-decimal amount),
  with a count footer. Visibility and payee resolution come from the core's
  projections — a transaction whose account is deleted is hidden, a deleted
  payee renders blank ([ADR 0016](0016-core-domain-model.md)).
- Exit codes: `0` success, `2` usage errors, `1` everything else (store,
  identity, parse failures). Errors are one `stderr` line.
- Category is deliberately **unset** at capture — uncategorized is "ready to
  assign" ([ADR 0016](0016-core-domain-model.md)); categorization is a later,
  considered activity, not a capture-time tax. Payee, date, account, amount,
  and `cleared = uncleared` are the capture set.

Argv parsing is hand-rolled. Two commands with two flags do not buy `clap`'s
dependency tree; the parser is ~60 lines and total.

### Amounts: signed, strict, currency-agnostic

- **A sign is required.** `-4.50` records spending, `+4.50` records income —
  the ledger-CLI convention. Unsigned input is a usage error that teaches the
  convention (`amount "4.50" needs a sign: -4.50 records spending…`). No
  silent direction is ever guessed: a default-outflow convention would
  silently misfile income, a pass-through convention would silently misfile
  spending, and both are money errors, not UX friction.
- **Normalization is whitespace-trim only**, then the core's exact
  [`Milliunits::from_str`](0016-core-domain-model.md) grammar
  (`[+-]?[0-9]+(\.[0-9]{1,3})?`). Thousands separators, currency symbols, and
  >3 fraction digits are errors with a corrective message — never stripped,
  because stripping is locale-ambiguous: accepting `1,50` by comma-removal
  stores `150` (a 100× silent error), and `₱1,000` vs `1.000,50` cannot be
  told apart without a locale the product does not have yet.
- **Currency handling at capture time is: none.** Milliunits are
  currency-free integers ([ADR 0006](0006-integer-money.md)); currency is a
  presentation concern deferred with locale formatting. Capture stores exact
  milliunits of whatever currency the user means; display shows the exact
  3-decimal form.

### Anchoring, bootstrap, and the identity file

Transactions and their payees/accounts live in the **budget log**; the
`Organization`, `Membership`, and `Budget` entities live in the **org log**
([ADR 0021](0021-organizations-own-budgets.md)). The first `add` bootstraps a
complete, minimal world and every later `add` re-ensures it read-then-mint:

1. **Identity file** (`<home>/identity.json`, published durably and alone
   before any op exists): `device_id`, `user_id` (auth is later; both minted
   locally as opaque UUIDv4 per [ADR 0016](0016-core-domain-model.md)'s
   any-version rule), plus the bootstrapped `org_id`, `membership_id`,
   `budget_id`, and `account_id`. Persisting the ids is what makes bootstrap
   retries idempotent — a retry reuses entity ids, never mints twins.
   Publishing mirrors the core store's create discipline
   ([ADR 0018](0018-local-oplog-store.md)): a process-unique tmp file, file
   fsync, atomic rename, directory fsync — then a read-back, so the common
   concurrent first-run interleavings fail loudly instead of minting ops
   against a root the loser does not hold (a rename landing in the
   microsecond gap between another creator's rename and its read-back can
   still slip through — accepted for a single-user CLI; a lock file is the
   heavier closure if that ever matters). A corrupt or future-version
   identity file is refused loudly, never overwritten; deleting it orphans
   the stores (the file is the root).
2. **Org log** — personal-org provisioning via the core's
   `provision_personal_org` (the read-then-mint contract's reference
   implementation: it probes the booted org state and emits only missing
   fields), plus the budget's `name` op. Both carry **anchored stamps** — the
   entity id's own UUIDv7 millisecond ([ADR 0021](0021-organizations-own-budgets.md)'s
   guard) — so a stale retry loses every contested field on merge. Names are
   fixed constants for now: org `Personal`, budget `Personal`.
3. **Budget log** — the account's `name` (`Wallet`) and `kind` (`Cash`) ops,
   anchored and probed the same way.

Regular capture ops (payee name, and the five transaction ops: account, date,
amount, payee, cleared) are stamped by the device's HLC — `Hlc::now()` seeded
from the booted sessions' clocks (the receive-merge discipline of
[ADR 0017](0017-core-sync-engine.md)), ticked per op.

Read-then-mint at capture time means: boot the store through `SyncSession`,
probe, then mint. The payee is find-or-create by exact live name (earliest id
on duplicate names, [ADR 0016](0016-core-domain-model.md)'s deterministic
convention); `--account` matches live accounts by exact name and errors
listing the known ones rather than guessing.

### The payload sink: one mint path

Every op the CLI mints reaches its `LocalStore` through **one function**,
`sink` in `apps/cli/src/sink.rs` — the CLI's only caller of
`LocalStore::append`. This is the seam the E2EE lane's wrap slots into (with
the core's `wire::encode_payload` choke point beneath it,
[ADR 0009](0009-e2ee-opaque-payloads.md)): wrapping payloads later changes
that one function, nothing else. Tests and review hold the invariant — no
other module appends.

### Data home and store layout

```text
<PURSECRAFT_HOME>/              (override, tests included)
$XDG_DATA_HOME/pursecraft/      (default on unix)
~/.local/share/pursecraft/
├── identity.json
├── orgs/<org-id>.ops           (org log, ADR 0021)
└── budgets/<budget-id>.ops     (budget log)
```

Non-unix falls back to `~/.pursecraft`. The single-writer contract is
[ADR 0018](0018-local-oplog-store.md)'s: one CLI invocation at a time per
home; a racing append — or a racing first-run identity create — fails loudly
rather than corrupting or silently forking the world.

### Dependencies and safety rails

`uuid` (id bit handling only — v7 ids are minted in this crate from the
clock and OS entropy, so no `rng` feature and no `rand` tree),
`serde`/`serde_json` (identity file; already in the lockfile), and `jiff`
(std-only, local civil date for the `today` default — a UTC-only "today"
would misdate every capture west of midnight UTC; license `Unlicense OR MIT`,
satisfied by the deny-list's MIT; the resolved unix build pulls just
`jiff-core`, while Cargo.lock additionally pins jiff's optional and
other-target dependencies).
*(Amended by [ADR 0025](0025-authenticated-first-clients.md): `minreq`
(no default features, `json-using-serde` only — zero new transitive
dependencies, license ISC per deny.toml) joins for the relay's plain-HTTP
sync surface.)*
No floats (workspace guard), no `unsafe`
(workspace forbid) — which rules out `std::env::set_var` in tests, so the
library is fully injectable: explicit home paths, explicit `today`, argv as
a slice; the environment is read only in `data_home()` and the thin
`main.rs` (help, version, and usage errors answer without touching it).

## Alternatives considered

- **Interactive prompts** — rejected: slower than argv, unscriptable, hostile
  to shell history and aliases; the exact opposite of capture-first.
- **`clap`** — rejected: two commands and two flags do not buy a ~30-crate
  dependency tree (cargo-deny and cargo-machete gate this repo).
- **Unsigned amounts with a default direction** (YNAB's outflow default or
  pass-through) — rejected: both silently misfile one direction; a teaching
  error beats a money error.
- **Lenient amount normalization** (strip ``,``, `.`, symbols) — rejected:
  locale-ambiguous input must fail, not guess (the `1,50` → `150` trap).
- **A `setup`/`init` command before first capture** — rejected: one more step
  before first value; ensure-style bootstrap is invisible, idempotent, and
  self-heals partial states by construction.
- **Transactions in the org log** — rejected: kind-vs-scope validity forbids
  it ([ADR 0021](0021-organizations-own-budgets.md)).
- **Category prompt/flag at capture** — rejected: uncategorized is a valid,
  designed state ("ready to assign"); capture stays amount→done.

## Consequences

- First capture works with zero setup *(amended by
  [ADR 0025](0025-authenticated-first-clients.md): after one-time enrollment —
  `pursecraft login <relay-url>`; bootstrap mechanics are unchanged)*:
  `pursecraft add coffee -4.50` and the org/budget/account world exists,
  durably, offline.
- The core is untouched — the parallel lanes rebase onto an unchanged core.
- The sign convention is learned once from a helpful error; the confirmation
  line always shows the stored signed amount.
- All minted payloads flow through one sink; the E2EE wrap is a one-function
  change when that lane lands.
- Everything is pending sync (none exists yet) — the pending-sync badge of
  [ADR 0011](0011-capture-first-mobile.md) arrives with the sync slice.
  *(It has: [ADR 0025](0025-authenticated-first-clients.md) — `list` shows
  the pending footer, `pursecraft sync` drains it.)*
- Deleting `identity.json` orphans prior stores on disk (they are no longer
  discoverable); the file is the root and is never recreated around.
