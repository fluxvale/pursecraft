# 0016 — Core Domain Model: Entities, Fields, and Op Mapping

- **Status:** Accepted — entity set and value vocabulary amended by
  [ADR 0020](0020-organizations-own-budgets.md) (Budget entity moves to org
  scope; org entities and the `User`/`Role` values arrive)
- **Date:** 2026-10-20
- **Builds on:** [ADR 0006](0006-integer-money.md),
  [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0008](0008-multiuser-day-one.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md)

## Context

The first product slice needs the concrete shapes everything later consumes:
the entity set of a YNAB-style budget, how the per-field LWW op record
([ADR 0007](0007-oplog-sync-protocol.md)) maps onto those entities, the money
type ([ADR 0006](0006-integer-money.md)), and the minimal HLC timestamp that
orders writes. This ADR settles the design before implementation (repo rule 3);
the sync engine, transport, and storage are later slices.

## Decision

### Entity set

Seven entities. Every entity carries the same envelope: a **UUIDv7 id**, the
**`budget_id`** scope ([ADR 0008](0008-multiuser-day-one.md)), and a
**`deleted` tombstone flag** — modeled as an ordinary bool *field*, so deletes
ride the same per-field LWW path as any other write.

| Entity | Fields (beyond the envelope) | Value type |
| --- | --- | --- |
| `Budget` | `name` | text |
| `Account` | `name`, `kind` | text, account-kind enum |
| `CategoryGroup` | `name` | text |
| `Category` | `name`, `group_id`, `note` | text, id, text |
| `Payee` | `name` | text |
| `Transaction` | `account_id`, `date`, `amount`, `payee_id`, `category_id`, `memo`, `cleared` | id, date, milliunits, id, id, text, cleared enum |
| `MonthCategory` | `month`, `category_id`, `budgeted` | month, id, milliunits |

`MonthCategory` is the month × category "budgeted" cell — the write two
household members race on, and the reason per-field LWW exists. Accounts carry
a `kind` enum (checking, savings, credit card, cash, line of credit,
investment, mortgage, other asset, other liability, other) — reference data,
extendable. `cleared` is uncleared / cleared / reconciled
([ADR 0010](0010-no-bank-import.md) keeps it regardless of cost).

Entity fields are `Option` until an op sets them: per-field ops mean partial
entities exist transiently, and money must never default silently to zero.
Id types are distinct newtypes (`AccountId`, `CategoryId`, …) over `Uuid` so
references cannot be mixed up by accident; all entity/op ids validate as
UUIDv7 at construction. `device_id`/`user_id` are opaque UUIDs of any version
(they come from auth, not from capture).

### Op record and its mapping to entities

The core-side op is typed; the wire form is opaque
([ADR 0009](0009-e2ee-opaque-payloads.md)):

```text
Op { op_id, budget_id, device_id, user_id,
     entity_kind, entity_id, field, value, hlc }
```

`field` is a nested enum — `Field::Deleted` shared by every entity, plus one
variant per entity wrapping that entity's field enum — so `match` is
exhaustive and adding a field is compiler-guided. `value` is a closed
`Value` enum (bool, text, milliunits, id, date, month, account-kind,
cleared). The server-visible form is metadata only (`op_id`, `device_id`,
`user_id`, `budget_id`, HLC, sequence): `entity_kind`/`entity_id`/`field`/
`value` live inside the encrypted payload. Serialization itself is deferred;
`Value` is the single choke point it will route through.

### Application semantics

- **Idempotence:** ops are deduplicated by `op_id`; a replayed op is a no-op.
- **Single-budget state:** a `BudgetState` is scoped to one budget — the
  first applied op fixes it, and ops for any other budget are rejected
  loudly (the core-side mirror of [ADR 0008]'s server scoping, making
  cross-budget resolution leaks structurally impossible).
- **Per-field LWW:** each entity keeps a write stamp `(hlc, op_id)` per field.
  An op with a strictly greater stamp wins; otherwise it is stale and ignored.
  Ties on identical HLC are impossible to see twice (same `op_id` → dedupe),
  so equal-HLC different-`op_id` writes are broken by `op_id` — deterministic
  on every device, since all replicas compare the same pairs.
- **Materialization:** an op targeting an unknown id creates a shell entity
  of the op's kind (all fields `None`, not deleted); the field write then
  applies. A later op whose kind disagrees with the existing entity is
  rejected loudly (corruption, not merged).
- **Type mismatches** (field vs value kind, field vs entity kind) are errors,
  never silent drops.

### HLC timestamp

`Hlc { physical_ms: u64, logical: u32 }`, totally ordered by
`(physical_ms, logical)`. `now()`, `tick()` (local event: advance logical
within the same millisecond, else reset), and `merge(remote)` (receive:
dominate both clocks) — the clock itself, not a sync engine. Apply logic only
ever *compares* Hlcs carried on ops.

### Referential resolution (projection time, never mutating stored state)

- A transaction whose `category_id` is unset is *uncategorized* (ready to
  assign).
- A transaction filed into a deleted or missing category **re-parents to the
  earliest-created surviving category** — minimum UUIDv7, which is
  chronological within clock skew; if none survives, uncategorized.
- A transaction whose account is deleted or missing is **hidden** (cascade
  tombstone; the data stays, projections skip it).
- A deleted/missing payee resolves to "no payee".
- A category whose group is deleted or missing renders **ungrouped** — no
  data-losing re-parent.
- `MonthCategory` cells of deleted/missing categories are hidden; re-parenting
  budgeted money is a user action (new ops), not an automatic rule.

### Milliunits

Newtype over `i64` milliunits (1 unit = 1000): `from_major` / `from_milli`
constructors, exact `FromStr` (≤ 3 fractional digits; more digits is an
error — input rounding must be explicit, never silent), `Display` with
exactly 3 fractional digits (round-trips; locale formatting is presentation
per [ADR 0006](0006-integer-money.md)), checked add/sub (panics on the
practically unreachable overflow rather than wrapping), ordering, and
`allocate(weights)` distributing a total across non-negative weights with
**largest-remainder** apportionment: `sum(parts) == total` exactly, leftover
milliunits to the largest fractional remainders, ties to the lowest index.

### Float guard

No constructor accepts a float, and a workspace-root `clippy.toml` denies
`f32`/`f64` as disallowed types — `scripts/ci/core.sh` runs clippy with
`-D warnings`, so any float makes CI fail.

## Deferred (deliberately out of this slice)

UUIDv7/op minting and capture commands (client capture builds ops; tests use
deterministic ids), serde/wire format and the E2EE layer, sync engine
(transport, sequences, compaction, snapshots), balances and reports,
transfers and split subtransactions, goals, currency and locale formatting,
month-cell uniqueness enforcement (client-enforced for now), auth/roles,
storage.

## Alternatives considered

- **String field names / single flat field enum** — rejected: no
  exhaustiveness checking, cross-entity nonsense compiles.
- **Generic multi-version register per field (CRDT-lite)** — rejected:
  [ADR 0007](0007-oplog-sync-protocol.md) already chose LWW; stamps are enough.
- **Stored balances** — rejected: derived from transactions; storing them
  invites drift.
- **`chrono`/`time` for `Date`** — rejected for this slice: a validated
  civil date derives chronological `Ord` from `(year, month, day)` directly;
  no calendar arithmetic is needed yet.
- **`proptest` for property tests** — rejected as a dependency: deterministic
  xorshift loops cover the same properties reproducibly with zero lockfile
  growth.

## Consequences

- Adding a field is a variant + match arm; the compiler finds every site.
- `Value` is the future serialization choke point ([ADR 0009]) — one place to
  encrypt.
- Stored state stays faithful to the op log; resolution is a pure projection,
  so it can change without migrating data.
- Single-budget state means resolution can never re-parent into another
  budget, whatever a buggy client feeds the core.
- Equal-HLC ties resolve by `op_id` randomness — deterministic everywhere,
  not "fair"; accepted and documented.
