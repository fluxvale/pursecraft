//! Deterministic referential resolution at projection time (ADRs 0007, 0016).
//!
//! Resolution is a pure projection over [`BudgetState`] — it never mutates
//! stored state, so the op log stays faithful and the rules can change
//! without migrating data.

use crate::domain::{Category, Entity, MonthCategory, Transaction};
use crate::ids::{AccountId, CategoryGroupId, CategoryId, EntityId, PayeeId};
use crate::ops::BudgetState;

/// Where a transaction's category assignment lands after resolution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CategoryResolution {
    /// No category assignment — ready to assign.
    Uncategorized,
    /// The surviving category the transaction resolves to.
    Category(CategoryId),
}

/// YNAB-style re-parent (ADR 0007): a deleted or missing category falls
/// back to the earliest-created surviving category — minimum UUIDv7, which
/// is chronological within clock skew — else uncategorized (ADR 0016).
pub fn transaction_category(state: &BudgetState, txn: &Transaction) -> CategoryResolution {
    let Some(&requested) = txn.category_id.as_ref() else {
        return CategoryResolution::Uncategorized;
    };
    if category_alive(state, requested) {
        return CategoryResolution::Category(requested);
    }
    match fallback_category(state) {
        Some(fallback) => CategoryResolution::Category(fallback),
        None => CategoryResolution::Uncategorized,
    }
}

/// The earliest-created surviving category in the budget, if any.
pub fn fallback_category(state: &BudgetState) -> Option<CategoryId> {
    state
        .entities()
        .filter_map(|e| match e {
            Entity::Category(c) if !c.deleted => Some(c.id),
            _ => None,
        })
        .min()
}

/// A transaction is visible only if it and its account survive; deleting an
/// account hides its transactions (cascade tombstone, ADR 0016).
pub fn transaction_visible(state: &BudgetState, txn: &Transaction) -> bool {
    !txn.deleted
        && txn
            .account_id
            .is_some_and(|account| account_alive(state, account))
}

/// A deleted or missing payee resolves to "no payee" (ADR 0016).
pub fn transaction_payee(state: &BudgetState, txn: &Transaction) -> Option<PayeeId> {
    txn.payee_id.filter(|&payee| payee_alive(state, payee))
}

/// A category whose group is deleted or missing renders ungrouped — no
/// data-losing re-parent (ADR 0016).
pub fn category_group(state: &BudgetState, category: &Category) -> Option<CategoryGroupId> {
    category.group_id.filter(|&group| {
        matches!(
            state.entity(&EntityId::from_raw(group.as_uuid())),
            Some(Entity::CategoryGroup(g)) if !g.deleted
        )
    })
}

/// A month × category cell is visible only if its category survives
/// (ADR 0016).
pub fn month_category_visible(state: &BudgetState, cell: &MonthCategory) -> bool {
    !cell.deleted && cell.category_id.is_some_and(|c| category_alive(state, c))
}

fn category_alive(state: &BudgetState, id: CategoryId) -> bool {
    matches!(
        state.entity(&EntityId::from_raw(id.as_uuid())),
        Some(Entity::Category(c)) if !c.deleted
    )
}

fn account_alive(state: &BudgetState, id: AccountId) -> bool {
    matches!(
        state.entity(&EntityId::from_raw(id.as_uuid())),
        Some(Entity::Account(a)) if !a.deleted
    )
}

fn payee_alive(state: &BudgetState, id: PayeeId) -> bool {
    matches!(
        state.entity(&EntityId::from_raw(id.as_uuid())),
        Some(Entity::Payee(p)) if !p.deleted
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AccountField, CategoryField, CategoryGroupField, EntityKind, Field, MonthCategoryField,
        TransactionField, Value,
    };
    use crate::hlc::Hlc;
    use crate::ids::{BudgetId, DeviceId, MonthCategoryId, PayeeId, TransactionId, UserId};
    use crate::money::Milliunits;
    use crate::ops::{Applied, Op};
    use crate::testkit::v7;
    use uuid::Uuid;

    /// Test harness: applies `(kind, entity_rand, field, value)` writes at
    /// increasing HLCs into one budget.
    #[derive(Default)]
    struct Fixture {
        state: BudgetState,
        ms: u64,
    }

    impl Fixture {
        fn write(
            &mut self,
            kind: EntityKind,
            entity_rand: u64,
            field: Field,
            value: Value,
        ) -> &mut Self {
            self.ms += 1;
            let op = Op {
                op_id: crate::ids::OpId::new(v7(self.ms, entity_rand)).unwrap(),
                budget_id: budget(),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: UserId::new(Uuid::nil()).unwrap(),
                entity_kind: kind,
                entity_id: EntityId::new(v7(100, entity_rand)).unwrap(),
                field,
                value,
                hlc: Hlc {
                    physical_ms: self.ms,
                    logical: 0,
                },
            };
            assert_eq!(self.state.apply(op), Ok(Applied::Applied));
            self
        }

        fn txn(&self) -> Transaction {
            match self.state.entity(&EntityId::new(v7(100, TXN)).unwrap()) {
                Some(Entity::Transaction(t)) => t.clone(),
                other => panic!("expected transaction, got {other:?}"),
            }
        }

        /// A transaction that exists only as a value under test — resolution
        /// is a pure projection, so it needs no applied ops at all.
        fn synthetic_txn(category: Option<CategoryId>) -> Transaction {
            Transaction {
                id: TransactionId::new(v7(100, TXN)).unwrap(),
                budget_id: budget(),
                deleted: false,
                account_id: None,
                date: None,
                amount: None,
                payee_id: None,
                category_id: category,
                memo: None,
                cleared: None,
            }
        }
    }

    const BUDGET_RAND: u64 = 1;
    const GROUP_RAND: u64 = 10;
    const CAT_EARLY: u64 = 20;
    const CAT_MID: u64 = 21;
    const CAT_LATE: u64 = 22;
    const ACCOUNT_RAND: u64 = 30;
    const PAYEE_RAND: u64 = 40;
    const TXN: u64 = 50;
    const CELL_RAND: u64 = 60;

    fn budget() -> BudgetId {
        BudgetId::new(v7(0, BUDGET_RAND)).unwrap()
    }

    fn category_id(rand: u64) -> CategoryId {
        CategoryId::new(v7(100, rand)).unwrap()
    }

    /// Three categories, earliest-created first by UUIDv7 order.
    fn fx_with_categories() -> Fixture {
        let mut fx = Fixture::default();
        fx.write(
            EntityKind::CategoryGroup,
            GROUP_RAND,
            Field::CategoryGroup(CategoryGroupField::Name),
            Value::Text("Bills".into()),
        )
        .write(
            EntityKind::Category,
            CAT_EARLY,
            Field::Category(CategoryField::Name),
            Value::Text("Power".into()),
        )
        .write(
            EntityKind::Category,
            CAT_MID,
            Field::Category(CategoryField::Name),
            Value::Text("Water".into()),
        )
        .write(
            EntityKind::Category,
            CAT_LATE,
            Field::Category(CategoryField::Name),
            Value::Text("Internet".into()),
        );
        fx
    }

    #[test]
    fn healthy_references_resolve_directly() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::Transaction,
            TXN,
            Field::Transaction(TransactionField::CategoryId),
            Value::Id(EntityId::new(category_id(CAT_MID).as_uuid()).unwrap()),
        );
        assert_eq!(
            transaction_category(&fx.state, &fx.txn()),
            CategoryResolution::Category(category_id(CAT_MID))
        );
        assert_eq!(fallback_category(&fx.state), Some(category_id(CAT_EARLY)));
    }

    #[test]
    fn unset_category_is_uncategorized() {
        let fx = fx_with_categories();
        assert_eq!(
            transaction_category(&fx.state, &Fixture::synthetic_txn(None)),
            CategoryResolution::Uncategorized
        );
    }

    #[test]
    fn deleted_category_reparents_to_earliest_survivor() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::Transaction,
            TXN,
            Field::Transaction(TransactionField::CategoryId),
            Value::Id(EntityId::new(category_id(CAT_MID).as_uuid()).unwrap()),
        );
        fx.write(
            EntityKind::Category,
            CAT_MID,
            Field::Deleted,
            Value::Bool(true),
        );
        assert_eq!(
            transaction_category(&fx.state, &fx.txn()),
            CategoryResolution::Category(category_id(CAT_EARLY)),
            "must fall back to the earliest-created survivor"
        );
    }

    #[test]
    fn missing_category_reparents_to_earliest_survivor() {
        let fx = fx_with_categories();
        let txn = Fixture::synthetic_txn(Some(category_id(999))); // never materialized
        assert_eq!(
            transaction_category(&fx.state, &txn),
            CategoryResolution::Category(category_id(CAT_EARLY))
        );
    }

    #[test]
    fn id_of_the_wrong_kind_counts_as_missing() {
        let fx = fx_with_categories();
        let txn = Fixture::synthetic_txn(Some(CategoryId::new(v7(100, ACCOUNT_RAND)).unwrap())); // an account id
        assert_eq!(
            transaction_category(&fx.state, &txn),
            CategoryResolution::Category(category_id(CAT_EARLY))
        );
    }

    #[test]
    fn no_surviving_categories_means_uncategorized() {
        let mut fx = fx_with_categories();
        for cat in [CAT_EARLY, CAT_MID, CAT_LATE] {
            fx.write(EntityKind::Category, cat, Field::Deleted, Value::Bool(true));
        }
        fx.write(
            EntityKind::Transaction,
            TXN,
            Field::Transaction(TransactionField::CategoryId),
            Value::Id(EntityId::new(category_id(CAT_MID).as_uuid()).unwrap()),
        );
        assert_eq!(
            transaction_category(&fx.state, &fx.txn()),
            CategoryResolution::Uncategorized
        );
    }

    #[test]
    fn deleted_account_hides_the_transaction() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::Account,
            ACCOUNT_RAND,
            Field::Account(AccountField::Name),
            Value::Text("GCash".into()),
        )
        .write(
            EntityKind::Transaction,
            TXN,
            Field::Transaction(TransactionField::AccountId),
            Value::Id(
                EntityId::new(AccountId::new(v7(100, ACCOUNT_RAND)).unwrap().as_uuid()).unwrap(),
            ),
        );
        assert!(transaction_visible(&fx.state, &fx.txn()));

        fx.write(
            EntityKind::Transaction,
            TXN,
            Field::Deleted,
            Value::Bool(true),
        );
        assert!(!transaction_visible(&fx.state, &fx.txn()));
        fx.write(
            EntityKind::Transaction,
            TXN,
            Field::Deleted,
            Value::Bool(false),
        ); // resurrect

        fx.write(
            EntityKind::Account,
            ACCOUNT_RAND,
            Field::Deleted,
            Value::Bool(true),
        );
        assert!(!transaction_visible(&fx.state, &fx.txn()), "cascade hide");

        let mut missing = fx.txn();
        missing.account_id = Some(AccountId::new(v7(100, 999)).unwrap());
        assert!(!transaction_visible(&fx.state, &missing));
    }

    #[test]
    fn deleted_payee_resolves_to_none() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::Payee,
            PAYEE_RAND,
            Field::Payee(crate::domain::PayeeField::Name),
            Value::Text("Meralco".into()),
        )
        .write(
            EntityKind::Transaction,
            TXN,
            Field::Transaction(TransactionField::PayeeId),
            Value::Id(EntityId::new(PayeeId::new(v7(100, PAYEE_RAND)).unwrap().as_uuid()).unwrap()),
        );
        assert_eq!(
            transaction_payee(&fx.state, &fx.txn()),
            Some(PayeeId::new(v7(100, PAYEE_RAND)).unwrap())
        );
        fx.write(
            EntityKind::Payee,
            PAYEE_RAND,
            Field::Deleted,
            Value::Bool(true),
        );
        assert_eq!(transaction_payee(&fx.state, &fx.txn()), None);
        let mut missing = fx.txn();
        missing.payee_id = Some(PayeeId::new(v7(100, 987)).unwrap());
        assert_eq!(transaction_payee(&fx.state, &missing), None);
    }

    #[test]
    fn category_in_deleted_group_renders_ungrouped() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::Category,
            CAT_MID,
            Field::Category(CategoryField::GroupId),
            Value::Id(EntityId::from_raw(v7(100, GROUP_RAND))),
        );
        let mid = match fx.state.entity(&EntityId::new(v7(100, CAT_MID)).unwrap()) {
            Some(Entity::Category(c)) => c.clone(),
            other => panic!("expected category, got {other:?}"),
        };
        assert_eq!(
            category_group(&fx.state, &mid),
            Some(CategoryGroupId::new(v7(100, GROUP_RAND)).unwrap())
        );
        fx.write(
            EntityKind::CategoryGroup,
            GROUP_RAND,
            Field::Deleted,
            Value::Bool(true),
        );
        assert_eq!(category_group(&fx.state, &mid), None);
        let mut orphan = mid.clone();
        orphan.group_id = Some(CategoryGroupId::new(v7(100, 654)).unwrap());
        assert_eq!(category_group(&fx.state, &orphan), None);
    }

    #[test]
    fn month_cell_visibility_follows_its_category() {
        let mut fx = fx_with_categories();
        fx.write(
            EntityKind::MonthCategory,
            CELL_RAND,
            Field::MonthCategory(MonthCategoryField::CategoryId),
            Value::Id(EntityId::new(category_id(CAT_LATE).as_uuid()).unwrap()),
        )
        .write(
            EntityKind::MonthCategory,
            CELL_RAND,
            Field::MonthCategory(MonthCategoryField::Budgeted),
            Value::Milliunits(Milliunits::from_major(250)),
        );
        let cell = match fx.state.entity(&EntityId::new(v7(100, CELL_RAND)).unwrap()) {
            Some(Entity::MonthCategory(m)) => m.clone(),
            other => panic!("expected month category, got {other:?}"),
        };
        assert_eq!(cell.id, MonthCategoryId::new(v7(100, CELL_RAND)).unwrap());
        assert!(month_category_visible(&fx.state, &cell));
        fx.write(
            EntityKind::Category,
            CAT_LATE,
            Field::Deleted,
            Value::Bool(true),
        );
        assert!(!month_category_visible(&fx.state, &cell));
    }
}
