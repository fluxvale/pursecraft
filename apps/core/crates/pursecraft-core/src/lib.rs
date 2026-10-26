//! Pursecraft core: budget engine, sync protocol, and persistence (ADR 0001).
//!
//! This slice covers the domain model and op semantics of ADR 0016 — integer
//! money, ids, HLC timestamps, entities, per-field LWW op application, and
//! deterministic referential resolution — the sync engine and op wire
//! format of ADR 0017: the canonical op log, delta-applying sync sessions,
//! and the metadata/payload split whose single choke point the E2EE layer
//! will wrap — the durable local store of ADR 0018: the append-only
//! framed file a real client boots the engine from — and the organization
//! scope of ADR 0021: orgs own budgets, personal-org provisioning, and
//! org-level roles and resolution.

pub mod budget;
pub mod date;
pub mod domain;
pub mod hlc;
pub mod ids;
pub mod money;
pub mod ops;
pub mod org;
pub mod resolve;
pub mod store;
pub mod sync;
pub mod wire;

/// Deterministic helpers for the crate's own tests and the E2EE
/// integration suites (enabled as a hidden feature by
/// `pursecraft-crypto`'s dev-dependency — never part of any real build).
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit {
    use std::path::{Path, PathBuf};

    use uuid::Uuid;

    /// Deterministic UUIDv7: `ms` timestamp plus an arbitrary disambiguator.
    pub fn v7(ms: u64, rand: u64) -> Uuid {
        let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
        Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
    }

    /// xorshift64* — deterministic, reproducible pseudo-randomness for
    /// property-test loops (ADR 0016: no proptest dependency).
    pub struct Rng(u64);

    impl Rng {
        pub fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        pub fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        pub fn next_i64(&mut self) -> i64 {
            self.next_u64() as i64
        }

        /// Value in `0..n` (modulo bias is irrelevant for test properties).
        pub fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    /// A per-test scratch directory under the system temp dir, removed on
    /// drop (best effort — a panicking test leaks its scratch dir, which
    /// is harmless). No tempfile dependency (ADR 0016: zero test
    /// dependencies).
    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "pursecraft-core-{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The shared convergence-test machinery of ADR 0017 — deterministic op
    /// generators and state assertions — reused by the store suite
    /// (ADR 0018) and parameterized over the log scope (ADR 0021: the same
    /// theorem, proved for org logs and budget logs). All loops are
    /// xorshift-deterministic per the ADR 0016 convention.
    pub mod conv {
        use crate::domain::{
            AccountField, BudgetField, CategoryField, CategoryGroupField, EntityKind, Field,
            MembershipField, MembershipRole, MonthCategoryField, OrgField, PayeeField,
            TransactionField, Value,
        };
        use crate::hlc::Hlc;
        use crate::ids::{BudgetId, DeviceId, EntityId, OpId, OrgId, ScopeId, UserId};
        use crate::money::Milliunits;
        use crate::ops::{Op, ScopeState};
        use crate::sync::SequencedOp;
        use crate::testkit::{Rng, v7};
        use uuid::Uuid;

        /// Synthetic stamps far above any real wall clock keep sessions'
        /// clock behavior deterministic (same trick as the hlc tests).
        pub const HLC_BASE: u64 = 1 << 60;
        /// v7-friendly ms for deterministic ids.
        pub const ID_MS: u64 = 1 << 40;
        const BUDGET_RAND: u64 = 1;
        const ORG_RAND: u64 = 2;

        pub fn budget() -> BudgetId {
            BudgetId::new(v7(1, BUDGET_RAND)).unwrap()
        }

        /// The scope org of org-scope generations, on the same `ID_MS` base
        /// as pool entity ids — the org entity's id must equal the scope
        /// org id exactly (ADR 0021).
        pub fn org() -> OrgId {
            OrgId::new(v7(ID_MS, ORG_RAND)).unwrap()
        }

        /// The two scopes the convergence loops prove (ADR 0021).
        pub fn scopes() -> [ScopeId; 2] {
            [ScopeId::Budget(budget()), ScopeId::Org(org())]
        }

        /// One deterministic op. `op_rand` disambiguates the op id; `(ms,
        /// logical)` is the stamp.
        pub fn op(op_rand: u64, ms: u64, logical: u32, field: Field, value: Value) -> Op {
            Op {
                op_id: OpId::new(v7(ID_MS, op_rand)).unwrap(),
                scope: ScopeId::Budget(budget()),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: UserId::new(Uuid::nil()).unwrap(),
                entity_kind: EntityKind::Transaction,
                entity_id: EntityId::new(v7(ID_MS, 50)).unwrap(),
                field,
                value,
                hlc: Hlc {
                    physical_ms: ms,
                    logical,
                },
            }
        }

        pub fn sequenced(seq: u64, op: Op) -> SequencedOp {
            SequencedOp { seq, op }
        }

        pub fn amount(milli: i64) -> (Field, Value) {
            (
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(Milliunits::from_milli(milli)),
            )
        }

        pub const DEVICES: u64 = 5;
        pub const OPS_PER_DEVICE: usize = 80;
        /// Fixed per-device offsets in ms: two devices share a clock (forcing
        /// equal-HLC ties broken by op_id), one runs a year ahead, one a day
        /// behind the base.
        const SKEW: [u64; DEVICES as usize] = [0, 0, 3_600_000, 31_536_000_000, 86_399_999];

        /// Entity pool for budget scope (ADR 0016's content entities; the
        /// Budget entity itself lives in org scope, ADR 0021): (kind, id
        /// rand) — multiple entities per kind so ops race across both
        /// fields and entities.
        const BUDGET_POOL: [(EntityKind, u64); 10] = [
            (EntityKind::Account, 2),
            (EntityKind::Account, 30),
            (EntityKind::CategoryGroup, 3),
            (EntityKind::Category, 4),
            (EntityKind::Category, 21),
            (EntityKind::Category, 22),
            (EntityKind::Payee, 5),
            (EntityKind::Transaction, 6),
            (EntityKind::Transaction, 50),
            (EntityKind::MonthCategory, 60),
        ];

        /// Entity pool for org scope (ADR 0021): the organization entry
        /// uses the scope's own org rand (an org log holds exactly its own
        /// org entity), plus racing memberships and budgets.
        const ORG_POOL: [(EntityKind, u64); 7] = [
            (EntityKind::Organization, ORG_RAND),
            (EntityKind::Membership, 7),
            (EntityKind::Membership, 61),
            (EntityKind::Membership, 62),
            (EntityKind::Budget, 8),
            (EntityKind::Budget, 63),
            (EntityKind::Budget, 64),
        ];

        /// Users the generator writes into membership/personal-for fields:
        /// two auth-issued ids plus a dangling third (a user with no
        /// membership — resolution's missing-reference path).
        fn users() -> [UserId; 3] {
            [
                UserId::new(Uuid::nil()).unwrap(),
                UserId::new(Uuid::max()).unwrap(),
                UserId::new(v7(ID_MS, 300)).unwrap(),
            ]
        }

        const TEXTS: [&str; 5] = ["", "GCash", "groceries ₱", "Meralco", "uña"];

        /// The pool a scope generates from.
        fn pool_for(scope: ScopeId) -> &'static [(EntityKind, u64)] {
            match scope {
                ScopeId::Budget(_) => &BUDGET_POOL,
                ScopeId::Org(_) => &ORG_POOL,
            }
        }

        fn fields_for(kind: EntityKind) -> &'static [Field] {
            match kind {
                EntityKind::Organization => &[
                    Field::Deleted,
                    Field::Organization(OrgField::Name),
                    Field::Organization(OrgField::PersonalFor),
                ],
                EntityKind::Membership => &[
                    Field::Deleted,
                    Field::Membership(MembershipField::UserId),
                    Field::Membership(MembershipField::Role),
                ],
                EntityKind::Budget => &[Field::Deleted, Field::Budget(BudgetField::Name)],
                EntityKind::Account => &[
                    Field::Deleted,
                    Field::Account(AccountField::Name),
                    Field::Account(AccountField::Kind),
                ],
                EntityKind::CategoryGroup => &[
                    Field::Deleted,
                    Field::CategoryGroup(CategoryGroupField::Name),
                ],
                EntityKind::Category => &[
                    Field::Deleted,
                    Field::Category(CategoryField::Name),
                    Field::Category(CategoryField::GroupId),
                    Field::Category(CategoryField::Note),
                ],
                EntityKind::Payee => &[Field::Deleted, Field::Payee(PayeeField::Name)],
                EntityKind::Transaction => &[
                    Field::Deleted,
                    Field::Transaction(TransactionField::AccountId),
                    Field::Transaction(TransactionField::Date),
                    Field::Transaction(TransactionField::Amount),
                    Field::Transaction(TransactionField::PayeeId),
                    Field::Transaction(TransactionField::CategoryId),
                    Field::Transaction(TransactionField::Memo),
                    Field::Transaction(TransactionField::Cleared),
                ],
                EntityKind::MonthCategory => &[
                    Field::Deleted,
                    Field::MonthCategory(MonthCategoryField::Month),
                    Field::MonthCategory(MonthCategoryField::CategoryId),
                    Field::MonthCategory(MonthCategoryField::Budgeted),
                ],
            }
        }

        /// An id value: a pool entity of the referenced kind, or a dangling id
        /// (resolution's missing-reference path, ADR 0016).
        fn reference_value(rng: &mut Rng, kind: EntityKind) -> Value {
            let candidates: Vec<u64> = BUDGET_POOL
                .iter()
                .filter(|(k, _)| *k == kind)
                .map(|(_, r)| *r)
                .chain([9999])
                .collect();
            Value::Id(
                EntityId::new(v7(
                    ID_MS,
                    candidates[rng.below(candidates.len() as u64) as usize],
                ))
                .unwrap(),
            )
        }

        /// A user value: one of the fixed users, or a dangling id (ADR 0021).
        fn user_value(rng: &mut Rng) -> Value {
            let users = users();
            let i = rng.below(users.len() as u64 + 1) as usize;
            if i == users.len() {
                Value::User(UserId::new(v7(ID_MS, 8888)).unwrap())
            } else {
                Value::User(users[i])
            }
        }

        fn random_value(rng: &mut Rng, field: Field) -> Value {
            use crate::date::{Date, Month};
            match field {
                Field::Deleted => Value::Bool(rng.below(2) == 0),
                Field::Organization(OrgField::Name)
                | Field::Budget(BudgetField::Name)
                | Field::Account(AccountField::Name)
                | Field::CategoryGroup(CategoryGroupField::Name)
                | Field::Category(CategoryField::Name)
                | Field::Category(CategoryField::Note)
                | Field::Payee(PayeeField::Name)
                | Field::Transaction(TransactionField::Memo) => {
                    Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].into())
                }
                Field::Organization(OrgField::PersonalFor)
                | Field::Membership(MembershipField::UserId) => user_value(rng),
                Field::Membership(MembershipField::Role) => Value::Role(match rng.below(3) {
                    0 => MembershipRole::Owner,
                    1 => MembershipRole::Editor,
                    _ => MembershipRole::Viewer,
                }),
                Field::Account(AccountField::Kind) => Value::AccountKind(match rng.below(11) {
                    0 => crate::domain::AccountKind::Checking,
                    1 => crate::domain::AccountKind::Savings,
                    2 => crate::domain::AccountKind::CreditCard,
                    3 => crate::domain::AccountKind::Cash,
                    4 => crate::domain::AccountKind::LineOfCredit,
                    5 => crate::domain::AccountKind::Investment,
                    6 => crate::domain::AccountKind::Mortgage,
                    7 => crate::domain::AccountKind::OtherAsset,
                    8 => crate::domain::AccountKind::OtherLiability,
                    9 => crate::domain::AccountKind::Other,
                    _ => crate::domain::AccountKind::Checking,
                }),
                Field::Category(CategoryField::GroupId) => {
                    reference_value(rng, EntityKind::CategoryGroup)
                }
                Field::Transaction(TransactionField::AccountId) => {
                    reference_value(rng, EntityKind::Account)
                }
                Field::Transaction(TransactionField::PayeeId) => {
                    reference_value(rng, EntityKind::Payee)
                }
                Field::Transaction(TransactionField::CategoryId) => {
                    reference_value(rng, EntityKind::Category)
                }
                Field::Transaction(TransactionField::Date) => Value::Date(
                    Date::new(
                        2020 + rng.below(11) as u16,
                        1 + rng.below(12) as u8,
                        1 + rng.below(28) as u8,
                    )
                    .unwrap(),
                ),
                Field::Transaction(TransactionField::Amount)
                | Field::MonthCategory(MonthCategoryField::Budgeted) => {
                    Value::Milliunits(Milliunits::from_milli(rng.next_i64() / 8))
                }
                Field::Transaction(TransactionField::Cleared) => {
                    Value::Cleared(match rng.below(3) {
                        0 => crate::domain::Cleared::Uncleared,
                        1 => crate::domain::Cleared::Cleared,
                        _ => crate::domain::Cleared::Reconciled,
                    })
                }
                Field::MonthCategory(MonthCategoryField::Month) => Value::Month(
                    Month::new(2024 + rng.below(4) as u16, 1 + rng.below(12) as u8).unwrap(),
                ),
                Field::MonthCategory(MonthCategoryField::CategoryId) => {
                    reference_value(rng, EntityKind::Category)
                }
            }
        }

        /// Deterministic op stream for one scope: `DEVICES × OPS_PER_DEVICE`
        /// ops, per-device clock offsets, occasional same-ms logical bumps.
        /// Org-scope streams draw from the org pool — the organization
        /// entity pinned to the scope's own org id (ADR 0021).
        pub fn generate_ops(seed: u64, scope: ScopeId) -> Vec<Op> {
            let mut rng = Rng::new(seed | 1);
            let pool = pool_for(scope);
            let mut ops = Vec::new();
            let mut global: u64 = 0;
            for device in 0..DEVICES {
                for event in 0..OPS_PER_DEVICE as u64 {
                    global += 1;
                    let (kind, entity_rand) = pool[rng.below(pool.len() as u64) as usize];
                    let fields = fields_for(kind);
                    let field = fields[rng.below(fields.len() as u64) as usize];
                    let value = random_value(&mut rng, field);
                    let ms = HLC_BASE + SKEW[device as usize] + event;
                    let logical = if rng.below(8) == 0 {
                        rng.below(3) as u32
                    } else {
                        0
                    };
                    ops.push(Op {
                        op_id: OpId::new(v7(ID_MS, global)).unwrap(),
                        scope,
                        device_id: DeviceId::new(v7(ID_MS + device, 100 + device)).unwrap(),
                        user_id: UserId::new(v7(ID_MS + device % 2, 200 + device % 2)).unwrap(),
                        entity_kind: kind,
                        entity_id: EntityId::new(v7(ID_MS, entity_rand)).unwrap(),
                        field,
                        value,
                        hlc: Hlc {
                            physical_ms: ms,
                            logical,
                        },
                    });
                }
            }
            // Force an equal-HLC tie AT THE WINNING STAMP: the year-ahead
            // device's final event carries the highest HLC of any op, so the
            // preceding op is overwritten to mirror it — same entity, field,
            // and stamp, its own op_id and a fresh value. No later write can
            // mask the decision, and the convergence tests assert the tie's
            // winner directly against the op_id order.
            let (kind, entity_id, field, hlc) = {
                let winner = &ops[TIE_WINNER];
                (
                    winner.entity_kind,
                    winner.entity_id,
                    winner.field,
                    winner.hlc,
                )
            };
            let mirror = &mut ops[TIE_MIRROR];
            mirror.entity_kind = kind;
            mirror.entity_id = entity_id;
            mirror.field = field;
            mirror.value = random_value(&mut rng, field);
            mirror.hlc = hlc;
            ops
        }

        /// The op holding the global-maximum HLC (the year-ahead device's last
        /// event) and the op mirroring it into an equal-HLC tie.
        const TIE_WINNER: usize = 4 * OPS_PER_DEVICE - 1;
        const TIE_MIRROR: usize = 4 * OPS_PER_DEVICE - 2;

        /// The materialized value of one field — the test-side inverse of
        /// `set_field`, so convergence assertions can read state back.
        pub fn materialized(state: &ScopeState, id: EntityId, field: Field) -> Option<Value> {
            use crate::domain::Entity;
            match (state.entity(&id)?, field) {
                (Entity::Organization(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Organization(e), Field::Organization(OrgField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Organization(e), Field::Organization(OrgField::PersonalFor)) => {
                    e.personal_for.map(Value::User)
                }
                (Entity::Membership(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Membership(e), Field::Membership(MembershipField::UserId)) => {
                    e.user_id.map(Value::User)
                }
                (Entity::Membership(e), Field::Membership(MembershipField::Role)) => {
                    e.role.map(Value::Role)
                }
                (Entity::Budget(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Budget(e), Field::Budget(BudgetField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Account(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Account(e), Field::Account(AccountField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Account(e), Field::Account(AccountField::Kind)) => {
                    e.kind.map(Value::AccountKind)
                }
                (Entity::CategoryGroup(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::CategoryGroup(e), Field::CategoryGroup(CategoryGroupField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Category(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Category(e), Field::Category(CategoryField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Category(e), Field::Category(CategoryField::GroupId)) => e
                    .group_id
                    .map(|g| Value::Id(EntityId::from_raw(g.as_uuid()))),
                (Entity::Category(e), Field::Category(CategoryField::Note)) => {
                    e.note.clone().map(Value::Text)
                }
                (Entity::Payee(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Payee(e), Field::Payee(PayeeField::Name)) => {
                    e.name.clone().map(Value::Text)
                }
                (Entity::Transaction(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::Transaction(e), Field::Transaction(TransactionField::AccountId)) => e
                    .account_id
                    .map(|v| Value::Id(EntityId::from_raw(v.as_uuid()))),
                (Entity::Transaction(e), Field::Transaction(TransactionField::Date)) => {
                    e.date.map(Value::Date)
                }
                (Entity::Transaction(e), Field::Transaction(TransactionField::Amount)) => {
                    e.amount.map(Value::Milliunits)
                }
                (Entity::Transaction(e), Field::Transaction(TransactionField::PayeeId)) => e
                    .payee_id
                    .map(|v| Value::Id(EntityId::from_raw(v.as_uuid()))),
                (Entity::Transaction(e), Field::Transaction(TransactionField::CategoryId)) => e
                    .category_id
                    .map(|v| Value::Id(EntityId::from_raw(v.as_uuid()))),
                (Entity::Transaction(e), Field::Transaction(TransactionField::Memo)) => {
                    e.memo.clone().map(Value::Text)
                }
                (Entity::Transaction(e), Field::Transaction(TransactionField::Cleared)) => {
                    e.cleared.map(Value::Cleared)
                }
                (Entity::MonthCategory(e), Field::Deleted) => Some(Value::Bool(e.deleted)),
                (Entity::MonthCategory(e), Field::MonthCategory(MonthCategoryField::Month)) => {
                    e.month.map(Value::Month)
                }
                (
                    Entity::MonthCategory(e),
                    Field::MonthCategory(MonthCategoryField::CategoryId),
                ) => e
                    .category_id
                    .map(|v| Value::Id(EntityId::from_raw(v.as_uuid()))),
                (Entity::MonthCategory(e), Field::MonthCategory(MonthCategoryField::Budgeted)) => {
                    e.budgeted.map(Value::Milliunits)
                }
                _ => None,
            }
        }

        /// The forced tie's independently computed expectation: the value of
        /// whichever tied op carries the greater `op_id` (ADR 0016's
        /// equal-HLC rule).
        pub fn expected_tie_value(ops: &[Op]) -> (EntityId, Field, Value) {
            let winner = if ops[TIE_WINNER].op_id > ops[TIE_MIRROR].op_id {
                &ops[TIE_WINNER]
            } else {
                &ops[TIE_MIRROR]
            };
            (winner.entity_id, winner.field, winner.value.clone())
        }

        pub fn shuffle<T>(rng: &mut Rng, slice: &mut [T]) {
            for i in (1..slice.len()).rev() {
                let j = rng.below((i + 1) as u64) as usize;
                slice.swap(i, j);
            }
        }

        /// One op per (entity kind × field), covering every `Value`
        /// variant — including calendar edges, empty and non-ASCII text,
        /// and extreme milliunits; org-scope entities (ADR 0021) ride org
        /// ops. The wire suite round-trips this set through the choke
        /// point; the E2EE suite round-trips it through the real cipher
        /// (ADR 0022).
        pub fn every_variant() -> Vec<Op> {
            use crate::date::{Date, Month};
            use crate::domain::{
                AccountField, AccountKind, BudgetField, CategoryField, CategoryGroupField, Cleared,
                Field, MembershipField, MembershipRole, MonthCategoryField, OrgField, PayeeField,
                TransactionField, Value,
            };
            use crate::ids::{BudgetId, DeviceId, EntityId, OpId, OrgId, ScopeId, UserId};
            use crate::money::Milliunits;
            use uuid::Uuid;

            const MS: u64 = 1 << 40;

            fn op(
                scope: ScopeId,
                kind: crate::domain::EntityKind,
                entity_rand: u64,
                field: Field,
                value: Value,
            ) -> Op {
                Op {
                    op_id: OpId::new(super::v7(MS, entity_rand)).unwrap(),
                    scope,
                    device_id: DeviceId::new(Uuid::nil()).unwrap(),
                    user_id: UserId::new(Uuid::max()).unwrap(),
                    entity_kind: kind,
                    entity_id: EntityId::new(super::v7(MS, entity_rand)).unwrap(),
                    field,
                    value,
                    hlc: crate::hlc::Hlc {
                        physical_ms: MS + entity_rand,
                        logical: 0,
                    },
                }
            }

            fn budget_op(
                kind: crate::domain::EntityKind,
                entity_rand: u64,
                field: Field,
                value: Value,
            ) -> Op {
                op(
                    ScopeId::Budget(BudgetId::new(super::v7(1, 1)).unwrap()),
                    kind,
                    entity_rand,
                    field,
                    value,
                )
            }

            fn org_op(
                kind: crate::domain::EntityKind,
                entity_rand: u64,
                field: Field,
                value: Value,
            ) -> Op {
                op(
                    ScopeId::Org(OrgId::new(super::v7(MS, 1)).unwrap()),
                    kind,
                    entity_rand,
                    field,
                    value,
                )
            }

            let id = |rand: u64| Value::Id(EntityId::new(super::v7(MS, rand)).unwrap());

            vec![
                org_op(
                    crate::domain::EntityKind::Organization,
                    1,
                    Field::Organization(OrgField::Name),
                    Value::Text("Home ₱".into()),
                ),
                org_op(
                    crate::domain::EntityKind::Organization,
                    1,
                    Field::Organization(OrgField::PersonalFor),
                    Value::User(UserId::new(Uuid::max()).unwrap()),
                ),
                org_op(
                    crate::domain::EntityKind::Membership,
                    8,
                    Field::Membership(MembershipField::UserId),
                    Value::User(UserId::new(Uuid::nil()).unwrap()),
                ),
                org_op(
                    crate::domain::EntityKind::Membership,
                    8,
                    Field::Membership(MembershipField::Role),
                    Value::Role(MembershipRole::Viewer),
                ),
                org_op(
                    crate::domain::EntityKind::Budget,
                    9,
                    Field::Budget(BudgetField::Name),
                    Value::Text("Household".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Account,
                    2,
                    Field::Account(AccountField::Name),
                    Value::Text(String::new()),
                ),
                budget_op(
                    crate::domain::EntityKind::Account,
                    2,
                    Field::Account(AccountField::Kind),
                    Value::AccountKind(AccountKind::OtherLiability),
                ),
                budget_op(
                    crate::domain::EntityKind::CategoryGroup,
                    3,
                    Field::CategoryGroup(CategoryGroupField::Name),
                    Value::Text("Bills".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Category,
                    4,
                    Field::Category(CategoryField::Name),
                    Value::Text("Power".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Category,
                    4,
                    Field::Category(CategoryField::GroupId),
                    id(3),
                ),
                budget_op(
                    crate::domain::EntityKind::Category,
                    4,
                    Field::Category(CategoryField::Note),
                    Value::Text("note — em dash".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Payee,
                    5,
                    Field::Payee(PayeeField::Name),
                    Value::Text("Meralco".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::AccountId),
                    id(2),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::Date),
                    Value::Date(Date::new(2024, 2, 29).unwrap()),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::Amount),
                    Value::Milliunits(Milliunits::MIN),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::Amount),
                    Value::Milliunits(Milliunits::MAX),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::PayeeId),
                    id(5),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::CategoryId),
                    id(4),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::Memo),
                    Value::Text("groceries".into()),
                ),
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Transaction(TransactionField::Cleared),
                    Value::Cleared(Cleared::Reconciled),
                ),
                budget_op(
                    crate::domain::EntityKind::MonthCategory,
                    7,
                    Field::MonthCategory(MonthCategoryField::Month),
                    Value::Month(Month::new(2026, 1).unwrap()),
                ),
                budget_op(
                    crate::domain::EntityKind::MonthCategory,
                    7,
                    Field::MonthCategory(MonthCategoryField::CategoryId),
                    id(4),
                ),
                budget_op(
                    crate::domain::EntityKind::MonthCategory,
                    7,
                    Field::MonthCategory(MonthCategoryField::Budgeted),
                    Value::Milliunits(Milliunits::from_major(-45)),
                ),
                // The tombstone field rides the same wire.
                budget_op(
                    crate::domain::EntityKind::Transaction,
                    6,
                    Field::Deleted,
                    Value::Bool(true),
                ),
            ]
        }
    }
}
