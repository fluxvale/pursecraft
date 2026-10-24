# 0020 — Organizations Own Budgets

- **Status:** Accepted
- **Date:** 2026-10-24
- **Builds on:** [ADR 0007](0007-oplog-sync-protocol.md),
  [ADR 0008](0008-multiuser-day-one.md),
  [ADR 0009](0009-e2ee-opaque-payloads.md),
  [ADR 0016](0016-core-domain-model.md),
  [ADR 0017](0017-core-sync-engine.md),
  [ADR 0018](0018-local-oplog-store.md)
- **Supersedes (in part):** [ADR 0008](0008-multiuser-day-one.md) — the
  membership shape (user ↔ budget roles) moves to the organization level.
  Also amends [ADR 0016](0016-core-domain-model.md) (entity set, value
  vocabulary) and [ADR 0017](0017-core-sync-engine.md) (scope model, state
  type rename).

## Context

Budgets are shared by households and groups, not just pairs of users, and at
the product owner's direction ownership moves to a GitHub-style organization
model: every user gets a default personal organization at creation (no user
without one, creator is owner), users may create and join several orgs, and
budgets belong to orgs — a user reaches budgets across orgs with different
roles. The portfolio's platform (FluxVale) provisions a personal org plus
owner membership transactionally and idempotently at user creation; that
invariant and shape transfer, the mechanics do not — this repo is local-first
with an oplog core, and the deep question is where org-level state lives
when every existing log is a per-budget log (ADR 0017).

## Decision

### Scope model: one more log kind, the same engine

The op's log scope generalizes from a budget to a typed
`ScopeId { Org(OrgId) | Budget(BudgetId) }`. One canonical log per scope, as
today: an **org log** (scope = the org) carries org-level entities; a
**budget log** (scope = the budget) carries budget content. Everything
downstream is reused unchanged in shape: the same `Op` record, the same
per-field LWW application, the same canonical-log / sync-session / local-
store machinery. `BudgetState` is renamed `ScopeState` — it materializes
exactly one scope of either kind.

The scope is **metadata** (`OpMeta.scope`), the one thing a server always
sees: the rendezvous of later slices routes per-log authorization on it.
The core enforces two structural rules at apply time, both loud:

- **Scope fixity** (as today): the first applied op fixes the state's/log's
  scope; any other scope id is `ScopeMismatch` — an op from one org can
  never influence another's resolution, exactly as budgets already could
  not.
- **Kind-vs-scope validity**: `Organization`, `Membership`, and `Budget`
  entities exist only in org scope; the six budget-content entities only in
  budget scope. A mismatch is loud corruption, never merged. Additionally,
  the org's entity slot is reserved: an op touching the scope org's uuid
  must be the `Organization` entity, and an `Organization` op's entity id
  must be that org id — exactly one organization entity per org log, and
  nothing else can squat its slot (a squatter would blind the org
  permanently).

### Entity set (org scope)

| Entity | Fields (beyond the envelope: id, `scope`, `deleted`) | Value type |
| --- | --- | --- |
| `Organization` | `name`, `personal_for` | text, user id |
| `Membership` | `user_id`, `role` | user id, membership-role enum |
| `Budget` (moved here from budget scope, ADR 0016) | `name` | text |

`MembershipRole` is **Owner / Editor / Viewer** — ADR 0008's role set,
transferred to the org level intact (viewer is a real finance-app role;
owner matches both ADR 0008 and the GitHub model). The `Value` vocabulary
gains `User(UserId)` — user ids are auth-issued opaque UUIDs of any version
(ADR 0016's id rules) — and `Role(MembershipRole)`.

### The Budget ↔ Organization tie

The `Budget` entity lives in the owning org's log; **the scope is the
tie**. A budget log (scope = the budget's id) holds only the six content
entities — it no longer self-describes. Consequences, all deliberate:

- **Offline discovery:** an org member enumerates the org's budgets by
  scanning the org log — no server round-trip, per the local-first wedge
  (ADR 0015).
- **Org deletion cascades within one state:** a tombstone on the
  `Organization` entity hides every budget in that org — resolvable purely
  inside the org state, the same cascade-hide philosophy as account
  deletion hiding transactions (ADR 0016: data stays, projections skip).
- Budget deletion is a tombstone on the `Budget` entity in the org log;
  the budget log's content stays faithful for surviving members.

### Membership and role resolution (pure projections)

- `membership_role(org_state, user)`: the **earliest-created surviving
  role-bearing** membership naming the user — minimum UUIDv7, ADR 0016's
  fallback-category convention; a torn, role-less write shadows nothing. A
  user appears at most once per org in well-formed data (capture reuses the
  existing membership entity); a racing twin resolves deterministically
  everywhere. Tombstoned memberships confer nothing.
- `budget_access(org_state, user, budget)`: the user's role iff the budget
  is visible (entity alive, org alive, and the budget's stored scope IS
  this org — cross-org composition cannot smuggle a foreign org's budget
  past the projection) and a surviving membership exists. Roles are
  **data** this slice — enforcing them (who may append what) is the auth
  slice's job, server- and capture-side.
- **Per-budget role overrides are rejected.** The requirement is different
  roles across budgets of *different orgs*, which different memberships
  already deliver; overrides would recreate the superseded ADR 0008 shape
  one level down.
- **Membership removal** (tombstone) drops the user's access to every
  budget in that org; other members' data is untouched. **Org deletion**
  hides the org's budgets and moots its memberships. Both are ordinary LWW
  writes; resolution stays a pure function of applied ops, so it converges
  with them.

### Personal organizations: provisioning as data

Every user gets a personal org at creation; the creator is its owner. The
FluxVale pattern — one transaction, idempotent — translates to oplog data:

- **Provisioning op-set** (`provision_personal_org`): the ops that write
  the `Organization` entity (`name`, `personal_for = user`) and the owner
  `Membership` — **probe-first**: an op is emitted only where the current
  state holds no value for its field. That is the FluxVale probe
  transferred to oplog data, and it is what makes retrying safe: a
  crash-retry mints fresh op ids AND a fresh stamp, and under plain LWW
  that retry would revert a user's rename or re-escalate a self-demotion —
  the probe instead emits nothing for fields already written, so user
  edits survive every retry and a partially-applied first attempt is
  completed, never redone. The caller owns id minting (ADR 0016 keeps
  capture deferred).
- **Invariant as data:** `live_personal_orgs(org_states, user)` returns the
  live orgs claiming `personal_for = user` (deduplicated — repeated input
  states are legal); a user's state satisfies the clause iff exactly one
  exists. The second clause is `owner_membership_intact(org_state, user)`,
  false when the creator's membership in their own org was removed. The
  checkers are pure and multi-state — a user's orgs live in several org
  logs, which never mix.
- **Policy:** a personal org is **not deletable**, and its owner membership
  is **not removable** — a user always has a home. Enforcement lives at
  capture (the later capture slice refuses to mint such ops) and at the
  invariant checker (flags violations loudly); the log itself stays
  faithful — a hostile or buggy tombstone is data the checker reports,
  never something resolution silently merges away. Personal orgs may hold
  further members: that is day-one household sharing.

### Sync, storage, wire

Org logs run through the unchanged engine and store: `OpLog` fixes its
`ScopeId`, `SyncSession` applies deltas to a `ScopeState` of either kind,
`LocalStore` is content-blind and persists whatever `OpMeta` says. The
convergence and boot-from-store proofs extend by parameterizing the
deterministic op generators (ADR 0016's xorshift convention) over both
scopes: the rendezvous and shuffled-delivery loops run over org logs with
org-entity pools — membership races, org tombstone/resurrection, dangling
user references — and the store suite boots org logs from disk mid-run.

`OpMeta` becomes `{ op_id, scope, device_id, user_id, hlc }`; the payload
choke point is untouched (ADRs 0009, 0017). The store's record body carries
meta verbatim, so the local store format version bumps 1 → 2. **No
read-old migration ships:** version 1 was never released and exists in no
store outside test fixtures; a v1 file is refused loudly per ADR 0018's
contract, never misread.

### E2EE hooks (crypto deferred, ADR 0009)

ADR 0009's per-budget key generalizes to a **per-log key**: each org log
and each budget log gets its own symmetric key, wrapped to the members of
the owning org. Membership changes in the org log are then the single
revocation point for both log kinds (rotate, re-wrap for survivors), and
invites wrap keys through org membership. Nothing here forces the crypto
design; the hooks are the scope-isolated logs themselves.

## Deferred (deliberately out of this slice)

Invites and the invite-token flow, auth/identity enforcement (roles are
data; capture- and server-side enforcement is later), the rendezvous
server, transports, the E2EE key hierarchy itself, per-budget role
overrides (rejected above), org slugs (server routing concerns, not
local-first data), capture commands and op minting, UI.

## Alternatives considered

- **Org entities inside each budget's log** — rejected: org state must
  converge among org members who hold no budget log, and org-level writes
  would race across every budget log of the org.
- **A per-user log for org state** — rejected: one org's member list would
  be smeared across per-user logs; resolving an org's state means joining
  them, and org admins would write into other principals' logs.
- **Untyped scope ids (orgs reuse the budget-id field)** — rejected: the
  server cannot distinguish an org log from a budget log for routing —
  payloads are encrypted (ADR 0009) — and the core could not enforce
  kind-vs-scope structurally. Baked-in ambiguity.
- **Carrying `(org_id, budget_id)` pairs in every op's metadata** —
  rejected: speculative server-routing generality (rule 1); the auth slice
  designs ACL routing when it exists, and the wire is not frozen yet
  (ADR 0017).
- **Budget entity stays in budget scope with an `org_id` field** —
  rejected: budget discovery becomes server-dependent (against the
  local-first wedge) and org deletion needs cross-scope projection to
  hide anything.
- **GitHub's two-role set (owner/member)** — rejected: viewer is a real
  finance-app role; ADR 0008's three transfer intact to the org level.

## Consequences

- Budget logs no longer self-describe; a budget's org is known from the
  org log (and, later, server routing data).
- Two orgs claiming the same budget id (hostile input, not possible from
  well-formed capture) are two isolated states — each org resolves its
  own; detection is the auth slice's, as with HLC poisoning (ADR 0017).
- One more entity-level invariant — organization-id == scope org — keeps
  org logs single-org by construction.
- Store format version 2: v1 files are refused loudly; nothing shipped
  reads them.
- The convergence theorem extends by case analysis on scope: per-scope
  states converge (same proof, org-entity pools), and every org-level
  resolution is a pure function of one org's state — so cross-org views
  (a user's budget list across orgs) compose convergent parts without a
  cross-scope log ever existing.
