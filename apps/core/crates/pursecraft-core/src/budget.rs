//! The month budget projection (ADR 0027): a pure derivation of
//! per-category envelopes and to-be-budgeted from a budget's state —
//! never stored (stored balances invite drift, ADR 0016), never mutating.
//!
//! The core equation, pinned here for every client to share:
//! `available = assigned + activity` per category per month, and the
//! conservation identity `Σ(available) + to_be_budgeted = Σ(all visible
//! transaction amounts in the month)`. Months are calendar months of the
//! transaction date; the window is single-month (no carry, ADR 0027).
//!
//! The caller supplies the one policy input `inbox` — which category is
//! the review queue (ADR 0027: the earliest live category named
//! "Inbox") — so the projection itself stays policy-free. Ordering is by
//! category id (earliest-created first, ADR 0016's deterministic
//! convention); presentation sorting is the client's concern.

use std::collections::BTreeMap;

use crate::date::Month;
use crate::domain::Entity;
use crate::ids::CategoryId;
use crate::money::Milliunits;
use crate::ops::ScopeState;
use crate::resolve::{
    CategoryResolution, month_category_visible, transaction_category, transaction_visible,
};

/// One category's envelope for one month. The equation holds by
/// construction: `available == assigned + activity` (ADR 0027).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CategoryRow {
    pub category: CategoryId,
    pub assigned: Milliunits,
    pub activity: Milliunits,
    pub available: Milliunits,
}

/// The inbox bucket's row (ADR 0027): activity counts only the bucket's
/// non-positive transactions — positives are inflow (to-be-budgeted),
/// and a positive filed into a category is a refund of that category's
/// activity instead. `count` is the bucket's in-month membership
/// (positives included): the review surface's visibility signal, so a
/// nag row renders even when the bucket holds only income (whose
/// amounts live in `inflow`, not `activity`). `category` is `None` when
/// no Inbox entity exists; the bucket of uncategorized transactions
/// still renders (the review surface never depends on an entity being
/// minted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InboxRow {
    pub category: Option<CategoryId>,
    pub assigned: Milliunits,
    pub activity: Milliunits,
    pub available: Milliunits,
    /// How many in-month visible transactions resolve to the bucket.
    pub count: usize,
}

/// One month's budget, derived (ADR 0027).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BudgetMonth {
    pub month: Month,
    /// One row per live non-inbox category, sorted by category id.
    pub rows: Vec<CategoryRow>,
    pub inbox: InboxRow,
    /// The month's positive inbox-bucket amounts — new budgetable money.
    pub inflow: Milliunits,
    /// `inflow − Σ(assigned)` over the rows and the inbox. Negative is
    /// over-assigned: visible, never clamped.
    pub to_be_budgeted: Milliunits,
}

impl BudgetMonth {
    /// All available summed — the conservation identity's left side
    /// (test-pinned, ADR 0027).
    #[cfg(test)]
    fn total_available(&self) -> Milliunits {
        self.rows
            .iter()
            .fold(self.inbox.available, |acc, row| add(acc, row.available))
    }
}

/// Checked fold — panics on the practically unreachable overflow rather
/// than wrapping (ADR 0016's convention).
fn add(lhs: Milliunits, rhs: Milliunits) -> Milliunits {
    lhs.checked_add(rhs).expect("month sums fit in milliunits")
}

/// Project one month's budget (ADR 0027).
///
/// Only landed ops count (ADR 0016's no-silent-zero rule): a transaction
/// without its `date` (no month bucket) or `amount`, and a month cell
/// without its `budgeted`, are excluded until their ops land — faithful
/// to the log, never defaulted to zero.
pub fn project(state: &ScopeState, month: Month, inbox: Option<CategoryId>) -> BudgetMonth {
    // Live categories in id order; each carries (assigned, activity).
    // A BTreeMap keeps every iteration deterministic (ADR 0016).
    let mut envelopes: BTreeMap<CategoryId, (Milliunits, Milliunits)> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Category(c) if !c.deleted => Some((c.id, (Milliunits::ZERO, Milliunits::ZERO))),
            _ => None,
        })
        .collect();
    let mut inbox_assigned = Milliunits::ZERO;

    for entity in state.entities() {
        if let Entity::MonthCategory(cell) = entity
            && month_category_visible(state, cell)
            && cell.month == Some(month)
            && let Some(budgeted) = cell.budgeted
        {
            // month_category_visible guarantees a live category, so the
            // envelope exists; twin cells (ADR 0027) sum by accumulation.
            let category = cell.category_id.expect("visible cell has a category");
            if Some(category) == inbox {
                inbox_assigned = add(inbox_assigned, budgeted);
            } else if let Some(entry) = envelopes.get_mut(&category) {
                entry.0 = add(entry.0, budgeted);
            }
        }
    }

    let mut inbox_activity = Milliunits::ZERO;
    let mut inbox_count: usize = 0;
    let mut inflow = Milliunits::ZERO;
    for entity in state.entities() {
        let Entity::Transaction(txn) = entity else {
            continue;
        };
        if !transaction_visible(state, txn) {
            continue;
        }
        let (Some(date), Some(amount)) = (txn.date, txn.amount) else {
            continue; // torn: no month bucket, or no amount op yet
        };
        if (date.year(), date.month()) != (month.year(), month.month()) {
            continue;
        }
        let bucket = match transaction_category(state, txn) {
            CategoryResolution::Uncategorized => true,
            CategoryResolution::Category(category) => {
                // Resolution only ever resolves to a live category, and
                // `envelopes` holds exactly the live categories — a miss
                // is unreachable corruption, loud rather than a silent
                // drop that would break the conservation identity.
                let entry = envelopes
                    .get_mut(&category)
                    .expect("resolution resolves to a live category");
                if Some(category) == inbox {
                    true
                } else {
                    entry.1 = add(entry.1, amount);
                    false
                }
            }
        };
        if bucket {
            inbox_count += 1;
            if amount > Milliunits::ZERO {
                inflow = add(inflow, amount);
            } else {
                inbox_activity = add(inbox_activity, amount);
            }
        }
    }

    let mut rows = Vec::new();
    let mut total_assigned = inbox_assigned;
    for (category, (assigned, activity)) in envelopes {
        if Some(category) == inbox {
            continue; // the bucket renders as InboxRow, not an envelope
        }
        total_assigned = add(total_assigned, assigned);
        rows.push(CategoryRow {
            category,
            assigned,
            activity,
            available: add(assigned, activity),
        });
    }

    BudgetMonth {
        month,
        rows,
        inbox: InboxRow {
            category: inbox,
            assigned: inbox_assigned,
            activity: inbox_activity,
            available: add(inbox_assigned, inbox_activity),
            count: inbox_count,
        },
        inflow,
        to_be_budgeted: inflow
            .checked_sub(total_assigned)
            .expect("fits in milliunits"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::{Date, Month};
    use crate::domain::{
        AccountField, CategoryField, EntityKind, Field, MonthCategoryField, TransactionField, Value,
    };
    use crate::hlc::Hlc;
    use crate::ids::{BudgetId, DeviceId, EntityId, OpId, ScopeId, UserId};
    use crate::ops::{Applied, Op};
    use crate::testkit::v7;
    use uuid::Uuid;

    /// Test harness (the resolve.rs fixture pattern): applies writes at
    /// increasing HLCs into one budget.
    #[derive(Default)]
    struct Fx {
        state: ScopeState,
        ms: u64,
    }

    impl Fx {
        fn write(&mut self, kind: EntityKind, rand: u64, field: Field, value: Value) -> &mut Self {
            self.ms += 1;
            let op = Op {
                op_id: OpId::new(v7(self.ms, rand)).unwrap(),
                scope: ScopeId::Budget(BUDGET),
                device_id: DeviceId::new(Uuid::nil()).unwrap(),
                user_id: UserId::new(Uuid::nil()).unwrap(),
                entity_kind: kind,
                entity_id: EntityId::new(v7(100, rand)).unwrap(),
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

        fn category(&mut self, rand: u64, name: &str) -> &mut Self {
            self.write(
                EntityKind::Category,
                rand,
                Field::Category(CategoryField::Name),
                Value::Text(name.into()),
            )
        }

        fn cell(&mut self, rand: u64, month: Month, category: u64, budgeted: i64) -> &mut Self {
            self.write(
                EntityKind::MonthCategory,
                rand,
                Field::MonthCategory(MonthCategoryField::Month),
                Value::Month(month),
            )
            .write(
                EntityKind::MonthCategory,
                rand,
                Field::MonthCategory(MonthCategoryField::CategoryId),
                Value::Id(cat_entity(category)),
            )
            .write(
                EntityKind::MonthCategory,
                rand,
                Field::MonthCategory(MonthCategoryField::Budgeted),
                Value::Milliunits(Milliunits::from_milli(budgeted)),
            )
        }

        fn txn(
            &mut self,
            rand: u64,
            date: (u16, u8, u8),
            amount: i64,
            category: Option<u64>,
        ) -> &mut Self {
            self.write(
                EntityKind::Transaction,
                rand,
                Field::Transaction(TransactionField::AccountId),
                Value::Id(EntityId::new(v7(100, ACCOUNT)).unwrap()),
            )
            .write(
                EntityKind::Transaction,
                rand,
                Field::Transaction(TransactionField::Date),
                Value::Date(Date::new(date.0, date.1, date.2).unwrap()),
            )
            .write(
                EntityKind::Transaction,
                rand,
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(Milliunits::from_milli(amount)),
            );
            if let Some(category) = category {
                self.write(
                    EntityKind::Transaction,
                    rand,
                    Field::Transaction(TransactionField::CategoryId),
                    Value::Id(cat_entity(category)),
                );
            }
            self
        }
    }

    const BUDGET: BudgetId = BudgetId::from_raw(Uuid::nil());
    const INBOX: u64 = 20; // earliest category id — the fallback (ADR 0016)
    const FOOD: u64 = 21;
    const FUN: u64 = 22;
    const DEAD: u64 = 23;
    const ACCOUNT: u64 = 30;
    const ACCOUNT2: u64 = 31;
    const OCT: (u16, u8) = (2026, 10);
    const NOV: (u16, u8) = (2026, 11);

    fn cat_entity(rand: u64) -> EntityId {
        EntityId::new(v7(100, rand)).unwrap()
    }

    fn month(of: (u16, u8)) -> Month {
        Month::new(of.0, of.1).unwrap()
    }

    fn inbox_id() -> Option<CategoryId> {
        Some(CategoryId::new(v7(100, INBOX)).unwrap())
    }

    /// A world with categories, cells, and transactions in two months.
    fn world() -> Fx {
        let mut fx = Fx::default();
        fx.write(
            EntityKind::Account,
            ACCOUNT,
            Field::Account(AccountField::Name),
            Value::Text("Wallet".into()),
        )
        .category(INBOX, "Inbox")
        .category(FOOD, "Food")
        .category(FUN, "Fun")
        .category(DEAD, "Doomed");
        fx
    }

    fn row(budget: &BudgetMonth, category: u64) -> &CategoryRow {
        budget
            .rows
            .iter()
            .find(|r| r.category == CategoryId::new(v7(100, category)).unwrap())
            .unwrap_or_else(|| panic!("no row for {category} in {:?}", budget.rows))
    }

    fn milli(units: Milliunits) -> i64 {
        units.milli()
    }

    /// THE core equation (issue #29), pinned: every row satisfies
    /// available = assigned + activity, and the month conserves —
    /// Σ(available) + to-be-budgeted equals every visible in-month
    /// transaction amount summed, so no money is created or lost between
    /// envelopes and the unallocated pool.
    #[test]
    fn available_is_assigned_plus_activity_and_the_month_conserves() {
        let mut fx = world();
        fx.cell(60, month(OCT), FOOD, 500_000)
            .cell(61, month(OCT), FUN, 100_000)
            // November cells must not leak into October.
            .cell(62, month(NOV), FOOD, 999_000)
            .txn(50, (2026, 10, 2), -4_500, Some(FOOD))
            .txn(51, (2026, 10, 5), -12_000, Some(FOOD))
            .txn(52, (2026, 10, 8), 800_000, None) // income → inbox → inflow
            .txn(53, (2026, 10, 9), -1_500, Some(FUN))
            .txn(54, (2026, 10, 10), 2_000, Some(FOOD)) // a refund, not inflow
            .txn(55, (2026, 10, 31), -900, None); // uncategorized spend

        let budget = project(&fx.state, month(OCT), inbox_id());
        let food = row(&budget, FOOD);
        assert_eq!(milli(food.assigned), 500_000);
        assert_eq!(milli(food.activity), -4_500 - 12_000 + 2_000);
        assert_eq!(
            milli(food.available),
            milli(food.assigned.checked_add(food.activity).unwrap()),
            "the equation, not a coincidence"
        );
        let fun = row(&budget, FUN);
        assert_eq!(
            (
                milli(fun.assigned),
                milli(fun.activity),
                milli(fun.available)
            ),
            (100_000, -1_500, 98_500)
        );

        // The inbox: income diverted to inflow, spend nagging as activity.
        // Both count toward the bucket — the nag row's visibility signal.
        assert_eq!(budget.inbox.count, 2);
        assert_eq!(milli(budget.inflow), 800_000);
        assert_eq!(milli(budget.inbox.activity), -900);
        assert_eq!(
            milli(budget.inbox.available),
            -900,
            "unbudgeted uncategorized spend is exactly the nag"
        );
        assert_eq!(milli(budget.to_be_budgeted), 800_000 - 600_000);

        for r in &budget.rows {
            assert_eq!(r.available, r.assigned.checked_add(r.activity).unwrap());
        }
        let visible_total: i64 = [-4_500, -12_000, 800_000, -1_500, 2_000, -900].iter().sum();
        assert_eq!(
            milli(
                budget
                    .total_available()
                    .checked_add(budget.to_be_budgeted)
                    .unwrap()
            ),
            visible_total,
            "conservation: envelopes + unallocated == the month's money"
        );

        // November: only its cell and nothing else.
        let nov = project(&fx.state, month(NOV), inbox_id());
        assert_eq!(milli(row(&nov, FOOD).assigned), 999_000);
        assert_eq!(milli(nov.inflow), 0);
        assert_eq!(
            milli(nov.to_be_budgeted),
            -999_000,
            "over-assigned is negative"
        );
    }

    /// Activity rolls up by resolution (ADR 0016), and only landed,
    /// visible transactions count: a deleted category's spending
    /// re-parents to the earliest survivor (the inbox — it stays on the
    /// review surface), a deleted account hides its transactions, torn
    /// transactions are excluded, not defaulted.
    #[test]
    fn activity_rolls_up_by_month_category_and_resolution() {
        let mut fx = world();
        fx.write(
            EntityKind::Account,
            ACCOUNT2,
            Field::Account(AccountField::Name),
            Value::Text("Ghost".into()),
        );
        fx.txn(50, (2026, 10, 2), -4_500, Some(DEAD))
            .txn(51, (2026, 10, 4), -7_000, Some(FOOD));
        // Hidden below: its account dies (cascade, ADR 0016).
        fx.txn(52, (2026, 10, 5), -99_999, Some(FOOD));
        // Point txn 52 at the second account instead of the default.
        fx.write(
            EntityKind::Transaction,
            52,
            Field::Transaction(TransactionField::AccountId),
            Value::Id(EntityId::new(v7(100, ACCOUNT2)).unwrap()),
        );
        // Torn: amount op never landed.
        fx.write(
            EntityKind::Transaction,
            53,
            Field::Transaction(TransactionField::AccountId),
            Value::Id(EntityId::new(v7(100, ACCOUNT)).unwrap()),
        )
        .write(
            EntityKind::Transaction,
            53,
            Field::Transaction(TransactionField::Date),
            Value::Date(Date::new(2026, 10, 6).unwrap()),
        );
        fx.write(
            EntityKind::Category,
            DEAD,
            Field::Deleted,
            Value::Bool(true),
        )
        .write(
            EntityKind::Account,
            ACCOUNT2,
            Field::Deleted,
            Value::Bool(true),
        );

        let budget = project(&fx.state, month(OCT), inbox_id());
        // DEAD's transaction re-parented to the earliest survivor (INBOX),
        // landing on the review surface — never silently on Food.
        assert_eq!(milli(budget.inbox.activity), -4_500);
        assert_eq!(milli(row(&budget, FOOD).activity), -7_000);
        assert!(
            !budget
                .rows
                .iter()
                .any(|r| { r.category == CategoryId::new(v7(100, DEAD)).unwrap() })
        );
    }

    /// Twin cells (two devices assigning offline, ADR 0027) sum —
    /// deterministic on every replica, overstating rather than losing,
    /// and the next assign re-targets the earliest cell.
    #[test]
    fn twin_cells_sum_deterministically() {
        let mut fx = world();
        fx.cell(60, month(OCT), FOOD, 300_000)
            .cell(61, month(OCT), FOOD, 250_000);
        let budget = project(&fx.state, month(OCT), inbox_id());
        assert_eq!(milli(row(&budget, FOOD).assigned), 550_000);
    }

    /// The bucket does not need the entity: with no Inbox minted,
    /// uncategorized money still inflows and nags (ADR 0027).
    #[test]
    fn the_bucket_renders_without_the_inbox_entity() {
        let mut fx = Fx::default();
        fx.write(
            EntityKind::Account,
            ACCOUNT,
            Field::Account(AccountField::Name),
            Value::Text("Wallet".into()),
        )
        .category(FOOD, "Food")
        .txn(50, (2026, 10, 2), 500_000, None)
        .txn(51, (2026, 10, 3), -100, None);

        let budget = project(&fx.state, month(OCT), None);
        assert_eq!(budget.inbox.category, None);
        assert_eq!(budget.inbox.count, 2, "membership does not need the entity");
        assert_eq!(milli(budget.inflow), 500_000);
        assert_eq!(milli(budget.inbox.activity), -100);
        assert_eq!(milli(budget.to_be_budgeted), 500_000);
        assert_eq!(budget.rows.len(), 1, "the envelope rows are unaffected");
    }

    /// An empty budget month is all zeros — rows for the live categories
    /// (the envelopes exist even when unfilled), nothing to budget.
    #[test]
    fn an_empty_month_shows_every_envelope_at_zero() {
        let fx = world();
        let budget = project(&fx.state, month(OCT), inbox_id());
        assert_eq!(
            budget.rows.len(),
            3,
            "inbox excluded, food/fun/dead included"
        );
        assert!(
            budget
                .rows
                .windows(2)
                .all(|w| w[0].category < w[1].category)
        );
        assert!(budget.rows.iter().all(|r| r.available == Milliunits::ZERO));
        assert_eq!(milli(budget.to_be_budgeted), 0);
    }
}
