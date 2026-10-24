//! The op record and its application semantics (ADRs 0007, 0016, 0020).
//!
//! Core-side ops are typed; the wire form is opaque (ADR 0009) —
//! `entity_kind`/`entity_id`/`field`/`value` live inside the encrypted
//! payload, and only `op_id`, the `scope` (an org or a budget, ADR 0020),
//! `device_id`, `user_id`, and the HLC timestamp are server-visible
//! metadata.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::domain::{
    AccountField, BudgetField, CategoryField, CategoryGroupField, Entity, EntityKind, Field,
    MembershipField, MonthCategoryField, OrgField, PayeeField, TransactionField, Value,
};
use crate::hlc::Hlc;
use crate::ids::{
    AccountId, CategoryGroupId, CategoryId, DeviceId, EntityId, OpId, OrgId, PayeeId, ScopeId,
    UserId,
};

/// One client write (ADR 0007).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Op {
    pub op_id: OpId,
    pub scope: ScopeId,
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub entity_kind: EntityKind,
    pub entity_id: EntityId,
    pub field: Field,
    pub value: Value,
    pub hlc: Hlc,
}

/// Per-field write stamp: `(hlc, op_id)` totally ordered. Equal HLCs from
/// different ops break by `op_id` — deterministic on every device, since all
/// replicas compare the same pairs (ADR 0016).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct WriteStamp {
    pub hlc: Hlc,
    pub op_id: OpId,
}

/// An entity plus its per-field write stamps.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntityRecord {
    pub entity: Entity,
    pub stamps: BTreeMap<Field, WriteStamp>,
}

/// State materialized from applied ops, scoped to exactly one log — an
/// organization's or a budget's (ADR 0020): the first applied op fixes the
/// scope, and ops of any other scope are rejected — cross-scope resolution
/// is structurally impossible, for orgs exactly as for budgets before them
/// (ADR 0016).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ScopeState {
    scope: Option<ScopeId>,
    entities: HashMap<EntityId, EntityRecord>,
    /// Every applied op's id with a content fingerprint: `op_id` must be
    /// 1:1 with op content (ADR 0017) — an id reused for different
    /// content is loud corruption here, where plaintext always lives,
    /// not silent per-device divergence.
    seen_ops: HashMap<OpId, u64>,
}

/// How [`ScopeState::apply`] disposed of an op.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Applied {
    /// Written (or the entity's field set for the first time).
    Applied,
    /// `op_id` was already applied — idempotent replay (ADR 0007).
    Duplicate,
    /// An equal or newer stamp already won this field — ignored.
    Stale,
}

/// A malformed or inconsistent op — corruption is loud, never merged or
/// silently dropped (ADR 0016).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ApplyError {
    /// The field does not belong to the op's (or the entity's) kind.
    KindMismatch { kind: EntityKind, field: Field },
    /// The value type does not match the field.
    ValueMismatch { field: Field, value: Value },
    /// Scope mismatch against this state's single fixed scope (ADRs 0008,
    /// 0020).
    ScopeMismatch {
        op_scope: ScopeId,
        state_scope: ScopeId,
    },
    /// The entity kind cannot exist in the op's scope kind (ADR 0020):
    /// org entities (Organization, Membership, Budget) only in org scope,
    /// budget-content entities only in budget scope.
    ScopeKindMismatch { scope: ScopeId, kind: EntityKind },
    /// An `Organization` op whose entity id is not its scope's org id —
    /// one org log holds exactly one organization entity (ADR 0020).
    OrganizationIdMismatch { entity_id: EntityId, scope: ScopeId },
    /// The `op_id` was already applied with different content — `op_id`
    /// must uniquely identify an op or replicas diverge silently, so the
    /// collision is loud (ADR 0017).
    OpIdConflict { op_id: OpId },
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindMismatch { kind, field } => {
                write!(f, "field {field:?} does not apply to {kind:?} entities")
            }
            Self::ValueMismatch { field, value } => {
                write!(f, "value {value:?} does not fit field {field:?}")
            }
            Self::ScopeMismatch {
                op_scope,
                state_scope,
            } => write!(
                f,
                "op scope {op_scope:?} does not belong to state scoped to {state_scope:?}"
            ),
            Self::ScopeKindMismatch { scope, kind } => {
                write!(f, "{kind:?} entities cannot exist in scope {scope:?}")
            }
            Self::OrganizationIdMismatch { entity_id, scope } => {
                write!(
                    f,
                    "organization entity {entity_id} does not match its scope {scope:?}"
                )
            }
            Self::OpIdConflict { op_id } => {
                write!(f, "op id {op_id} re-applied with different content")
            }
        }
    }
}

impl std::error::Error for ApplyError {}

impl ScopeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one op: idempotent by `op_id` (identical content replays as a
    /// no-op; a reused id with different content is an [`ApplyError::
    /// OpIdConflict`]), per-field LWW by `(hlc, op_id)` (ADR 0016, ADR
    /// 0017). Errors leave the state untouched.
    pub fn apply(&mut self, op: Op) -> Result<Applied, ApplyError> {
        let fingerprint = op_fingerprint(&op);
        if let Some(&seen) = self.seen_ops.get(&op.op_id) {
            if seen == fingerprint {
                return Ok(Applied::Duplicate);
            }
            return Err(ApplyError::OpIdConflict { op_id: op.op_id });
        }
        if !field_valid_for(op.entity_kind, op.field) {
            return Err(ApplyError::KindMismatch {
                kind: op.entity_kind,
                field: op.field,
            });
        }
        if !value_matches_field(&op.field, &op.value) {
            return Err(ApplyError::ValueMismatch {
                field: op.field,
                value: op.value,
            });
        }
        // Single-scope state (ADRs 0008, 0020): the first applied op fixes
        // it.
        if let Some(state_scope) = self.scope
            && state_scope != op.scope
        {
            return Err(ApplyError::ScopeMismatch {
                op_scope: op.scope,
                state_scope,
            });
        }
        // Kind-vs-scope validity (ADR 0020): an org entity in a budget log,
        // or budget content in an org log, is loud corruption — never
        // merged, never silently materialized.
        if !kind_valid_in_scope(op.entity_kind, op.scope) {
            return Err(ApplyError::ScopeKindMismatch {
                scope: op.scope,
                kind: op.entity_kind,
            });
        }
        // One org log, one organization entity, its own id (ADR 0020): a
        // stray org entity cannot masquerade as another personal org.
        if op.entity_kind == EntityKind::Organization
            && ScopeId::Org(OrgId::from_raw(op.entity_id.as_uuid())) != op.scope
        {
            return Err(ApplyError::OrganizationIdMismatch {
                entity_id: op.entity_id,
                scope: op.scope,
            });
        }

        let record = self
            .entities
            .entry(op.entity_id)
            .or_insert_with(|| EntityRecord {
                entity: Entity::shell(op.entity_kind, op.entity_id, op.scope),
                stamps: BTreeMap::new(),
            });
        if record.entity.kind() != op.entity_kind {
            return Err(ApplyError::KindMismatch {
                kind: op.entity_kind,
                field: op.field,
            });
        }

        let incoming = WriteStamp {
            hlc: op.hlc,
            op_id: op.op_id,
        };
        let outcome = if matches!(
            record.stamps.get(&op.field),
            Some(prev) if *prev >= incoming
        ) {
            Applied::Stale
        } else {
            set_field(&mut record.entity, op.field, op.value);
            record.stamps.insert(op.field, incoming);
            Applied::Applied
        };
        if self.scope.is_none() {
            self.scope = Some(op.scope);
        }
        self.seen_ops.insert(op.op_id, fingerprint);
        Ok(outcome)
    }

    pub fn entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.get(id).map(|r| &r.entity)
    }

    pub fn entities(&self) -> impl Iterator<Item = &Entity> {
        self.entities.values().map(|r| &r.entity)
    }

    /// The scope this state is fixed to, once the first applied op fixes
    /// it (ADR 0020).
    pub fn scope_id(&self) -> Option<ScopeId> {
        self.scope
    }
}

/// A content fingerprint for one op (everything but the `op_id`, which is
/// the key it is stored under). Deterministic within a process — it is
/// never serialized, only compared against the stored entry for the same
/// `op_id` (ADR 0017).
fn op_fingerprint(op: &Op) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    op.scope.hash(&mut hasher);
    op.device_id.hash(&mut hasher);
    op.user_id.hash(&mut hasher);
    op.entity_kind.hash(&mut hasher);
    op.entity_id.hash(&mut hasher);
    op.field.hash(&mut hasher);
    op.value.hash(&mut hasher);
    op.hlc.hash(&mut hasher);
    hasher.finish()
}

/// Whether `field` can be written on `kind` — checked before any mutation.
fn field_valid_for(kind: EntityKind, field: Field) -> bool {
    match field {
        Field::Deleted => true,
        Field::Organization(_) => kind == EntityKind::Organization,
        Field::Membership(_) => kind == EntityKind::Membership,
        Field::Budget(_) => kind == EntityKind::Budget,
        Field::Account(_) => kind == EntityKind::Account,
        Field::CategoryGroup(_) => kind == EntityKind::CategoryGroup,
        Field::Category(_) => kind == EntityKind::Category,
        Field::Payee(_) => kind == EntityKind::Payee,
        Field::Transaction(_) => kind == EntityKind::Transaction,
        Field::MonthCategory(_) => kind == EntityKind::MonthCategory,
    }
}

/// Whether `kind` exists in the scope kind (ADR 0020): org entities in
/// org scope, budget-content entities in budget scope.
pub(crate) fn kind_valid_in_scope(kind: EntityKind, scope: ScopeId) -> bool {
    matches!(
        (kind, scope),
        (
            EntityKind::Organization | EntityKind::Membership | EntityKind::Budget,
            ScopeId::Org(_),
        ) | (
            EntityKind::Account
                | EntityKind::CategoryGroup
                | EntityKind::Category
                | EntityKind::Payee
                | EntityKind::Transaction
                | EntityKind::MonthCategory,
            ScopeId::Budget(_),
        )
    )
}

/// Whether `value`'s type fits `field` — checked before any mutation.
fn value_matches_field(field: &Field, value: &Value) -> bool {
    matches!(
        (field, value),
        (Field::Deleted, Value::Bool(_))
            | (Field::Organization(OrgField::Name), Value::Text(_))
            | (Field::Organization(OrgField::PersonalFor), Value::User(_))
            | (Field::Membership(MembershipField::UserId), Value::User(_))
            | (Field::Membership(MembershipField::Role), Value::Role(_))
            | (Field::Budget(BudgetField::Name), Value::Text(_))
            | (Field::Account(AccountField::Name), Value::Text(_))
            | (Field::Account(AccountField::Kind), Value::AccountKind(_))
            | (
                Field::CategoryGroup(CategoryGroupField::Name),
                Value::Text(_)
            )
            | (Field::Category(CategoryField::Name), Value::Text(_))
            | (Field::Category(CategoryField::GroupId), Value::Id(_))
            | (Field::Category(CategoryField::Note), Value::Text(_))
            | (Field::Payee(PayeeField::Name), Value::Text(_))
            | (
                Field::Transaction(TransactionField::AccountId),
                Value::Id(_)
            )
            | (Field::Transaction(TransactionField::Date), Value::Date(_))
            | (
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(_)
            )
            | (Field::Transaction(TransactionField::PayeeId), Value::Id(_))
            | (
                Field::Transaction(TransactionField::CategoryId),
                Value::Id(_)
            )
            | (Field::Transaction(TransactionField::Memo), Value::Text(_))
            | (
                Field::Transaction(TransactionField::Cleared),
                Value::Cleared(_)
            )
            | (
                Field::MonthCategory(MonthCategoryField::Month),
                Value::Month(_)
            )
            | (
                Field::MonthCategory(MonthCategoryField::CategoryId),
                Value::Id(_)
            )
            | (
                Field::MonthCategory(MonthCategoryField::Budgeted),
                Value::Milliunits(_)
            )
    )
}

/// Write `value` into `field`. Kind and value type are pre-validated by
/// [`ScopeState::apply`]; the `expect`s below cannot fire through it.
fn set_field(entity: &mut Entity, field: Field, value: Value) {
    let ok = "field/value agreement pre-validated in apply";
    match (entity, field) {
        (Entity::Organization(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Organization(e), Field::Organization(OrgField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Organization(e), Field::Organization(OrgField::PersonalFor)) => {
            e.personal_for = Some(value.into_user().expect(ok));
        }
        (Entity::Membership(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Membership(e), Field::Membership(MembershipField::UserId)) => {
            e.user_id = Some(value.into_user().expect(ok));
        }
        (Entity::Membership(e), Field::Membership(MembershipField::Role)) => {
            e.role = Some(value.into_role().expect(ok));
        }
        (Entity::Budget(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Budget(e), Field::Budget(BudgetField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Account(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Account(e), Field::Account(AccountField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Account(e), Field::Account(AccountField::Kind)) => {
            e.kind = Some(value.into_account_kind().expect(ok));
        }
        (Entity::CategoryGroup(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::CategoryGroup(e), Field::CategoryGroup(CategoryGroupField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Category(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Category(e), Field::Category(CategoryField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Category(e), Field::Category(CategoryField::GroupId)) => {
            e.group_id = Some(CategoryGroupId::from_raw(
                value.into_id().expect(ok).as_uuid(),
            ));
        }
        (Entity::Category(e), Field::Category(CategoryField::Note)) => {
            e.note = Some(value.into_text().expect(ok));
        }
        (Entity::Payee(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Payee(e), Field::Payee(PayeeField::Name)) => {
            e.name = Some(value.into_text().expect(ok));
        }
        (Entity::Transaction(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::Transaction(e), Field::Transaction(TransactionField::AccountId)) => {
            e.account_id = Some(AccountId::from_raw(value.into_id().expect(ok).as_uuid()));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::Date)) => {
            e.date = Some(value.into_date().expect(ok));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::Amount)) => {
            e.amount = Some(value.into_milliunits().expect(ok));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::PayeeId)) => {
            e.payee_id = Some(PayeeId::from_raw(value.into_id().expect(ok).as_uuid()));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::CategoryId)) => {
            e.category_id = Some(CategoryId::from_raw(value.into_id().expect(ok).as_uuid()));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::Memo)) => {
            e.memo = Some(value.into_text().expect(ok));
        }
        (Entity::Transaction(e), Field::Transaction(TransactionField::Cleared)) => {
            e.cleared = Some(value.into_cleared().expect(ok));
        }
        (Entity::MonthCategory(e), Field::Deleted) => e.deleted = value.into_bool().expect(ok),
        (Entity::MonthCategory(e), Field::MonthCategory(MonthCategoryField::Month)) => {
            e.month = Some(value.into_month().expect(ok));
        }
        (Entity::MonthCategory(e), Field::MonthCategory(MonthCategoryField::CategoryId)) => {
            e.category_id = Some(CategoryId::from_raw(value.into_id().expect(ok).as_uuid()));
        }
        (Entity::MonthCategory(e), Field::MonthCategory(MonthCategoryField::Budgeted)) => {
            e.budgeted = Some(value.into_milliunits().expect(ok));
        }
        _ => unreachable!("{ok}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::{Date, Month};
    use crate::domain::{
        AccountKind, Budget, CategoryGroup, Cleared, Membership, MembershipField,
        MembershipRole as Role, OrgField, Organization, Payee, Transaction,
    };
    use crate::money::Milliunits;
    use crate::testkit::v7;
    use uuid::Uuid;

    use crate::ids::BudgetId;

    const TXN_RAND: u64 = 77;
    const MS_BASE: u64 = 1 << 40;

    /// Deterministic transaction-op builder for tests: `rand` disambiguates
    /// the op id, `(ms, logical)` is the HLC stamp.
    fn txn_op(rand: u64, ms: u64, logical: u32, field: Field, value: Value) -> Op {
        Op {
            op_id: OpId::new(v7(ms, rand)).unwrap(),
            scope: ScopeId::Budget(BudgetId::new(v7(1, 1)).unwrap()),
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::nil()).unwrap(),
            entity_kind: EntityKind::Transaction,
            entity_id: EntityId::new(v7(MS_BASE, TXN_RAND)).unwrap(),
            field,
            value,
            hlc: Hlc {
                physical_ms: ms,
                logical,
            },
        }
    }

    fn amount_field(value: i64) -> (Field, Value) {
        (
            Field::Transaction(TransactionField::Amount),
            Value::Milliunits(Milliunits::from_milli(value)),
        )
    }

    fn txn_entity(state: &ScopeState) -> Transaction {
        match state.entity(&EntityId::new(v7(MS_BASE, TXN_RAND)).unwrap()) {
            Some(Entity::Transaction(t)) => t.clone(),
            other => panic!("expected transaction, got {other:?}"),
        }
    }

    #[test]
    fn first_op_materializes_a_shell_entity() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(-4_500);
        assert_eq!(
            state.apply(txn_op(1, 10, 0, field, value)),
            Ok(Applied::Applied)
        );
        let t = txn_entity(&state);
        assert_eq!(t.amount, Some(Milliunits::from_milli(-4_500)));
        assert_eq!(t.memo, None, "untouched fields stay unset — no silent zero");
        assert!(!t.deleted);
    }

    #[test]
    fn replayed_op_id_is_a_duplicate_no_op() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(1_000);
        let first = txn_op(5, 10, 0, field, value);
        state.apply(first.clone()).unwrap();
        let before = state.clone();
        assert_eq!(state.apply(first.clone()), Ok(Applied::Duplicate));
        assert_eq!(state, before, "duplicate replays must not touch state");
    }

    #[test]
    fn reused_op_id_with_different_content_is_loud() {
        let mut state = ScopeState::new();
        let (field, _) = amount_field(1_000);
        let first = txn_op(5, 10, 0, field, amount_field(1_000).1);
        state.apply(first.clone()).unwrap();
        let before = state.clone();
        // Same op_id, any changed field — hlc here, value there — is
        // corruption: two replicas fed the two variants would otherwise
        // diverge silently (ADR 0017).
        let restamped = txn_op(5, 99, 9, field, amount_field(1_000).1);
        let revalued = txn_op(5, 10, 0, Field::Deleted, Value::Bool(true));
        for mut mutated in [restamped, revalued] {
            mutated.op_id = first.op_id;
            assert_eq!(
                state.apply(mutated),
                Err(ApplyError::OpIdConflict { op_id: first.op_id })
            );
        }
        assert_eq!(state, before, "a rejected op must not touch state");
        // Identical replay is still a silent no-op.
        assert_eq!(state.apply(first), Ok(Applied::Duplicate));
    }

    #[test]
    fn lww_is_order_independent() {
        let (field, _) = amount_field(0);
        let older = txn_op(
            1,
            10,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(111)),
        );
        let newer = txn_op(
            2,
            20,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(222)),
        );
        for order in [
            vec![older.clone(), newer.clone()],
            vec![newer.clone(), older.clone()],
        ] {
            let mut state = ScopeState::new();
            for op in order {
                state.apply(op).unwrap();
            }
            assert_eq!(
                txn_entity(&state).amount,
                Some(Milliunits::from_milli(222)),
                "newer stamp must win in any arrival order"
            );
        }
    }

    #[test]
    fn equal_hlc_breaks_by_op_id() {
        let (field, _) = amount_field(0);
        let small = txn_op(
            1,
            10,
            5,
            field,
            Value::Milliunits(Milliunits::from_milli(1)),
        );
        let big = txn_op(
            9,
            10,
            5,
            field,
            Value::Milliunits(Milliunits::from_milli(9)),
        );
        assert_eq!(small.hlc, big.hlc, "same (ms, logical)");
        assert_ne!(small.op_id, big.op_id);
        for order in [
            vec![small.clone(), big.clone()],
            vec![big.clone(), small.clone()],
        ] {
            let mut state = ScopeState::new();
            for op in order {
                state.apply(op).unwrap();
            }
            assert_eq!(
                txn_entity(&state).amount,
                Some(Milliunits::from_milli(9)),
                "higher op_id must win an equal-HLC tie, in any order"
            );
        }
    }

    #[test]
    fn older_stamp_after_newer_is_stale() {
        let mut state = ScopeState::new();
        let (field, _) = amount_field(0);
        let newer = txn_op(
            2,
            20,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(222)),
        );
        let older = txn_op(
            1,
            10,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(111)),
        );
        assert_eq!(state.apply(newer), Ok(Applied::Applied));
        assert_eq!(state.apply(older.clone()), Ok(Applied::Stale));
        // A stale op leaves entities and stamps untouched (only the dedupe
        // set grows, so a retried stale op is a Duplicate).
        assert_eq!(state.apply(older), Ok(Applied::Duplicate));
        assert_eq!(txn_entity(&state).amount, Some(Milliunits::from_milli(222)));
        // Equal stamp, lower op_id: the previous winner keeps the field.
        let tie_loser = txn_op(
            1,
            20,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(333)),
        );
        assert_eq!(state.apply(tie_loser), Ok(Applied::Stale));
        assert_eq!(txn_entity(&state).amount, Some(Milliunits::from_milli(222)));
    }

    #[test]
    fn fields_are_independent_lww_registers() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(5_000);
        state.apply(txn_op(1, 50, 0, field, value)).unwrap();
        // A lower-stamped write to a *different* field still applies...
        state
            .apply(txn_op(
                2,
                30,
                0,
                Field::Transaction(TransactionField::Memo),
                Value::Text("market".into()),
            ))
            .unwrap();
        assert_eq!(txn_entity(&state).memo.as_deref(), Some("market"));
        // ...and does not disturb the amount's stamp: an amount write older
        // than the amount's own stamp is stale regardless of the memo write.
        let (field, value) = amount_field(9_999);
        assert_eq!(
            state.apply(txn_op(3, 40, 0, field, value)),
            Ok(Applied::Stale)
        );
        assert_eq!(
            txn_entity(&state).amount,
            Some(Milliunits::from_milli(5_000))
        );
    }

    #[test]
    fn tombstone_is_just_a_field() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(1);
        state.apply(txn_op(1, 10, 0, field, value)).unwrap();
        state
            .apply(txn_op(2, 20, 0, Field::Deleted, Value::Bool(true)))
            .unwrap();
        assert!(txn_entity(&state).deleted);
        // A later write resurrects — LWW applies to deletes like anything else.
        state
            .apply(txn_op(3, 30, 0, Field::Deleted, Value::Bool(false)))
            .unwrap();
        assert!(!txn_entity(&state).deleted);
    }

    #[test]
    fn every_entity_kind_round_trips_field_writes() {
        let mut state = ScopeState::new();
        let account = EntityId::new(v7(MS_BASE, 12)).unwrap();
        let group = EntityId::new(v7(MS_BASE, 13)).unwrap();
        let category = EntityId::new(v7(MS_BASE, 14)).unwrap();
        let payee = EntityId::new(v7(MS_BASE, 15)).unwrap();
        let txn = EntityId::new(v7(MS_BASE, 16)).unwrap();
        let cell = EntityId::new(v7(MS_BASE, 17)).unwrap();

        // Budget scope holds the six content entities; the Budget entity
        // itself lives in org scope (ADR 0020).
        let cases: Vec<(EntityKind, EntityId, Field, Value)> = vec![
            (
                EntityKind::Account,
                account,
                Field::Account(AccountField::Name),
                Value::Text("GCash".into()),
            ),
            (
                EntityKind::Account,
                account,
                Field::Account(AccountField::Kind),
                Value::AccountKind(AccountKind::Cash),
            ),
            (
                EntityKind::CategoryGroup,
                group,
                Field::CategoryGroup(CategoryGroupField::Name),
                Value::Text("Bills".into()),
            ),
            (
                EntityKind::Category,
                category,
                Field::Category(CategoryField::Name),
                Value::Text("Power".into()),
            ),
            (
                EntityKind::Payee,
                payee,
                Field::Payee(PayeeField::Name),
                Value::Text("Meralco".into()),
            ),
            (
                EntityKind::Transaction,
                txn,
                Field::Transaction(TransactionField::Cleared),
                Value::Cleared(Cleared::Reconciled),
            ),
            (
                EntityKind::MonthCategory,
                cell,
                Field::MonthCategory(MonthCategoryField::Month),
                Value::Month(Month::new(2026, 10).unwrap()),
            ),
        ];
        for (i, (kind, entity_id, field, value)) in cases.into_iter().enumerate() {
            let op = Op {
                op_id: OpId::new(v7(10 + i as u64, 30 + i as u64)).unwrap(),
                scope: ScopeId::Budget(BudgetId::new(v7(1, 1)).unwrap()),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: UserId::new(Uuid::nil()).unwrap(),
                entity_kind: kind,
                entity_id,
                field,
                value,
                hlc: Hlc {
                    physical_ms: 10 + i as u64,
                    logical: 0,
                },
            };
            assert_eq!(state.apply(op), Ok(Applied::Applied));
        }

        assert_eq!(
            state.entities().count(),
            6,
            "account writes share one entity"
        );
        match state.entity(&account) {
            Some(Entity::Account(a)) => {
                assert_eq!(a.name.as_deref(), Some("GCash"));
                assert_eq!(a.kind, Some(AccountKind::Cash));
            }
            other => panic!("expected account, got {other:?}"),
        }
        match state.entity(&group) {
            Some(Entity::CategoryGroup(CategoryGroup { name, .. })) => {
                assert_eq!(name.as_deref(), Some("Bills"))
            }
            other => panic!("expected category group, got {other:?}"),
        }
        match state.entity(&payee) {
            Some(Entity::Payee(Payee { name, .. })) => assert_eq!(name.as_deref(), Some("Meralco")),
            other => panic!("expected payee, got {other:?}"),
        }
    }

    /// One op per org-scope entity field (ADR 0020), into one org log.
    #[test]
    fn org_scope_entities_round_trip_field_writes() {
        let org = OrgId::new(v7(MS_BASE, 1)).unwrap();
        let scope = ScopeId::Org(org);
        let membership = EntityId::new(v7(MS_BASE, 2)).unwrap();
        let budget = EntityId::new(v7(MS_BASE, 3)).unwrap();
        let terence = UserId::new(Uuid::nil()).unwrap();
        let cases: Vec<(EntityKind, EntityId, Field, Value)> = vec![
            (
                EntityKind::Organization,
                EntityId::from_raw(org.as_uuid()),
                Field::Organization(OrgField::Name),
                Value::Text("Terence's org".into()),
            ),
            (
                EntityKind::Organization,
                EntityId::from_raw(org.as_uuid()),
                Field::Organization(OrgField::PersonalFor),
                Value::User(terence),
            ),
            (
                EntityKind::Membership,
                membership,
                Field::Membership(MembershipField::UserId),
                Value::User(terence),
            ),
            (
                EntityKind::Membership,
                membership,
                Field::Membership(MembershipField::Role),
                Value::Role(Role::Owner),
            ),
            (
                EntityKind::Budget,
                budget,
                Field::Budget(BudgetField::Name),
                Value::Text("Home".into()),
            ),
        ];
        let mut state = ScopeState::new();
        for (i, (kind, entity_id, field, value)) in cases.into_iter().enumerate() {
            let op = Op {
                op_id: OpId::new(v7(20 + i as u64, 40 + i as u64)).unwrap(),
                scope,
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: terence,
                entity_kind: kind,
                entity_id,
                field,
                value,
                hlc: Hlc {
                    physical_ms: 20 + i as u64,
                    logical: 0,
                },
            };
            assert_eq!(state.apply(op), Ok(Applied::Applied));
        }
        assert_eq!(state.entities().count(), 3, "org + membership + budget");
        assert_eq!(state.scope_id(), Some(scope));
        match state.entity(&EntityId::from_raw(org.as_uuid())) {
            Some(Entity::Organization(Organization {
                name, personal_for, ..
            })) => {
                assert_eq!(name.as_deref(), Some("Terence's org"));
                assert_eq!(*personal_for, Some(terence));
            }
            other => panic!("expected organization, got {other:?}"),
        }
        match state.entity(&membership) {
            Some(Entity::Membership(Membership { user_id, role, .. })) => {
                assert_eq!(*user_id, Some(terence));
                assert_eq!(*role, Some(Role::Owner));
            }
            other => panic!("expected membership, got {other:?}"),
        }
        match state.entity(&budget) {
            Some(Entity::Budget(Budget { name, .. })) => assert_eq!(name.as_deref(), Some("Home")),
            other => panic!("expected budget, got {other:?}"),
        }
    }

    #[test]
    fn field_for_wrong_kind_is_rejected_without_materializing() {
        let mut state = ScopeState::new();
        let bad = txn_op(
            1,
            10,
            0,
            Field::Account(AccountField::Name),
            Value::Text("nope".into()),
        );
        assert_eq!(
            state.apply(bad),
            Err(ApplyError::KindMismatch {
                kind: EntityKind::Transaction,
                field: Field::Account(AccountField::Name),
            })
        );
        assert_eq!(
            state.entities().count(),
            0,
            "a rejected op must not materialize anything"
        );
    }

    #[test]
    fn kind_lie_against_existing_entity_is_rejected() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(1);
        state.apply(txn_op(1, 10, 0, field, value)).unwrap();
        let lie = Op {
            op_id: OpId::new(v7(20, 2)).unwrap(),
            scope: ScopeId::Budget(BudgetId::new(v7(1, 1)).unwrap()),
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::nil()).unwrap(),
            entity_kind: EntityKind::Payee,
            entity_id: EntityId::new(v7(MS_BASE, TXN_RAND)).unwrap(), // the transaction's id
            field: Field::Payee(PayeeField::Name),
            value: Value::Text("x".into()),
            hlc: Hlc {
                physical_ms: 20,
                logical: 0,
            },
        };
        assert!(matches!(
            state.apply(lie),
            Err(ApplyError::KindMismatch { .. })
        ));
    }

    #[test]
    fn value_type_mismatch_is_rejected_without_state_change() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(7);
        state.apply(txn_op(1, 10, 0, field, value)).unwrap();
        let before = state.clone();
        let (field, _) = amount_field(0);
        let bad = txn_op(2, 20, 0, field, Value::Text("seven".into()));
        assert!(matches!(
            state.apply(bad),
            Err(ApplyError::ValueMismatch { .. })
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn foreign_scope_is_rejected() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(1);
        state.apply(txn_op(1, 10, 0, field, value.clone())).unwrap();
        let mut foreign = txn_op(2, 20, 0, field, value);
        foreign.scope = ScopeId::Budget(BudgetId::new(v7(9, 9)).unwrap());
        assert!(matches!(
            state.apply(foreign),
            Err(ApplyError::ScopeMismatch { .. })
        ));
        // An org-scoped op is equally foreign to a budget-scoped state —
        // orgs cannot leak into budget logs (ADR 0020).
        let mut org_op = txn_op(3, 30, 0, amount_field(0).0, amount_field(0).1);
        org_op.scope = ScopeId::Org(OrgId::new(v7(9, 9)).unwrap());
        assert!(matches!(
            state.apply(org_op),
            Err(ApplyError::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn state_is_single_scope() {
        let mut state = ScopeState::new();
        let (field, value) = amount_field(1);
        assert_eq!(
            state.apply(txn_op(1, 10, 0, field, value)),
            Ok(Applied::Applied)
        );
        // A fresh-id op for another budget is rejected too — a ScopeState
        // is one scope (ADRs 0008, 0020), so resolution can never leak
        // across scopes via fallback categories or accounts.
        let mut foreign = txn_op(
            2,
            20,
            0,
            Field::Transaction(TransactionField::Memo),
            Value::Text("x".into()),
        );
        foreign.entity_id = EntityId::new(v7(MS_BASE, 999)).unwrap();
        foreign.scope = ScopeId::Budget(BudgetId::new(v7(9, 9)).unwrap());
        assert!(matches!(
            state.apply(foreign),
            Err(ApplyError::ScopeMismatch { .. })
        ));
        assert_eq!(
            state.entities().count(),
            1,
            "a foreign-scope op must not materialize anything"
        );
    }

    /// Kind-vs-scope validity (ADR 0020): org entities cannot be written
    /// into a budget log, budget-content entities cannot be written into
    /// an org log, and an org log holds exactly one organization entity —
    /// its own.
    #[test]
    fn entity_kinds_outside_their_scope_are_rejected_loudly() {
        let mut budget_state = ScopeState::new();
        let (field, value) = amount_field(1);
        budget_state.apply(txn_op(1, 10, 0, field, value)).unwrap();
        let mut org_entity = txn_op(2, 20, 0, Field::Deleted, Value::Bool(true));
        org_entity.entity_kind = EntityKind::Membership;
        org_entity.entity_id = EntityId::new(v7(MS_BASE, 88)).unwrap();
        org_entity.field = Field::Membership(MembershipField::Role);
        org_entity.value = Value::Role(Role::Viewer);
        assert!(matches!(
            budget_state.apply(org_entity),
            Err(ApplyError::ScopeKindMismatch { .. })
        ));

        let org = OrgId::new(v7(MS_BASE, 5)).unwrap();
        let scope = ScopeId::Org(org);
        let mut org_state = ScopeState::new();
        let mut content = Op {
            op_id: OpId::new(v7(30, 3)).unwrap(),
            scope,
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::nil()).unwrap(),
            entity_kind: EntityKind::Transaction,
            entity_id: EntityId::new(v7(MS_BASE, 99)).unwrap(),
            field: Field::Transaction(TransactionField::Memo),
            value: Value::Text("x".into()),
            hlc: Hlc {
                physical_ms: 30,
                logical: 0,
            },
        };
        assert!(matches!(
            org_state.apply(content.clone()),
            Err(ApplyError::ScopeKindMismatch { .. })
        ));
        assert_eq!(
            org_state.entities().count(),
            0,
            "a rejected op must not materialize anything"
        );

        // The organization entity's id must equal the scope's org id.
        content.entity_kind = EntityKind::Organization;
        content.entity_id = EntityId::new(v7(MS_BASE, 77)).unwrap(); // not the org id
        content.field = Field::Organization(OrgField::Name);
        content.value = Value::Text("imposter".into());
        assert!(matches!(
            org_state.apply(content),
            Err(ApplyError::OrganizationIdMismatch { .. })
        ));
        assert_eq!(org_state.entities().count(), 0);

        // A second org's op is foreign to this org's state, exactly as a
        // second budget is to a budget state.
        let foreign_org = Op {
            op_id: OpId::new(v7(40, 4)).unwrap(),
            scope: ScopeId::Org(OrgId::new(v7(MS_BASE, 6)).unwrap()),
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::nil()).unwrap(),
            entity_kind: EntityKind::Organization,
            entity_id: EntityId::from_raw(OrgId::new(v7(MS_BASE, 6)).unwrap().as_uuid()),
            field: Field::Organization(OrgField::Name),
            value: Value::Text("other".into()),
            hlc: Hlc {
                physical_ms: 40,
                logical: 0,
            },
        };
        let mut own_org = foreign_org.clone();
        own_org.scope = scope;
        own_org.entity_id = EntityId::from_raw(org.as_uuid());
        own_org.op_id = OpId::new(v7(41, 5)).unwrap();
        assert_eq!(
            org_state.apply(own_org),
            Ok(Applied::Applied),
            "the org's own entity applies"
        );
        assert!(matches!(
            org_state.apply(foreign_org),
            Err(ApplyError::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn stamp_order_is_hlc_first_then_op_id() {
        // Decorrelate op_id from HLC: the older-HLC write carries the
        // HIGHER op_id and must still lose — op_id only breaks equal-HLC
        // ties (ADR 0016).
        let (field, _) = amount_field(0);
        let mut old_hlc_big_id = txn_op(
            9,
            10,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(1)),
        );
        old_hlc_big_id.op_id = OpId::new(v7(9_999, 9)).unwrap();
        let mut new_hlc_small_id = txn_op(
            1,
            20,
            0,
            field,
            Value::Milliunits(Milliunits::from_milli(2)),
        );
        new_hlc_small_id.op_id = OpId::new(v7(1, 1)).unwrap();
        assert!(old_hlc_big_id.op_id > new_hlc_small_id.op_id);
        assert!(old_hlc_big_id.hlc < new_hlc_small_id.hlc);
        for order in [
            vec![old_hlc_big_id.clone(), new_hlc_small_id.clone()],
            vec![new_hlc_small_id.clone(), old_hlc_big_id.clone()],
        ] {
            let mut state = ScopeState::new();
            for op in order {
                state.apply(op).unwrap();
            }
            assert_eq!(
                txn_entity(&state).amount,
                Some(Milliunits::from_milli(2)),
                "HLC must dominate the op_id tiebreak"
            );
        }
    }

    #[test]
    fn full_transaction_and_month_cell_lifecycle() {
        let mut state = ScopeState::new();
        let account_id = AccountId::new(v7(MS_BASE, 51)).unwrap();
        let category_id = CategoryId::new(v7(MS_BASE, 52)).unwrap();
        let fields = [
            (
                Field::Transaction(TransactionField::AccountId),
                Value::Id(EntityId::new(account_id.as_uuid()).unwrap()),
            ),
            (
                Field::Transaction(TransactionField::Date),
                Value::Date(Date::new(2026, 10, 20).unwrap()),
            ),
            (
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(Milliunits::from_major(-45)),
            ),
            (
                Field::Transaction(TransactionField::CategoryId),
                Value::Id(EntityId::new(category_id.as_uuid()).unwrap()),
            ),
            (
                Field::Transaction(TransactionField::Memo),
                Value::Text("groceries".into()),
            ),
            (
                Field::Transaction(TransactionField::Cleared),
                Value::Cleared(Cleared::Cleared),
            ),
        ];
        for (i, (field, value)) in fields.into_iter().enumerate() {
            state
                .apply(txn_op(i as u64 + 1, 10 + i as u64, 0, field, value))
                .unwrap();
        }
        let t = txn_entity(&state);
        assert_eq!(t.account_id, Some(account_id));
        assert_eq!(t.date, Some(Date::new(2026, 10, 20).unwrap()));
        assert_eq!(t.amount, Some(Milliunits::from_major(-45)));
        assert_eq!(t.category_id, Some(category_id));
        assert_eq!(t.memo.as_deref(), Some("groceries"));
        assert_eq!(t.cleared, Some(Cleared::Cleared));
    }
}
