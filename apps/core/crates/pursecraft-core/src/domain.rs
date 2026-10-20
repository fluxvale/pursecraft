//! Domain entities and the typed field/value vocabulary ops write
//! (ADRs 0007, 0008, 0016).
//!
//! Every entity carries the same envelope: a UUIDv7 id, the `budget_id`
//! scope, and a `deleted` tombstone flag modeled as an ordinary field so
//! deletes ride the same per-field LWW path as any other write. Entity
//! fields are `Option` until an op sets them — money must never default
//! silently to zero (ADR 0016).

use crate::date::{Date, Month};
use crate::ids::{
    AccountId, BudgetId, CategoryGroupId, CategoryId, EntityId, MonthCategoryId, PayeeId,
    TransactionId,
};
use crate::money::Milliunits;

/// Account kind — reference data, extend freely (ADR 0016).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum AccountKind {
    Checking,
    Savings,
    CreditCard,
    Cash,
    LineOfCredit,
    Investment,
    Mortgage,
    OtherAsset,
    OtherLiability,
    Other,
}

/// Manual statement-reconciliation state (ADR 0010).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Cleared {
    Uncleared,
    Cleared,
    Reconciled,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Budget {
    pub id: BudgetId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    pub id: AccountId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub name: Option<String>,
    pub kind: Option<AccountKind>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CategoryGroup {
    pub id: CategoryGroupId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Category {
    pub id: CategoryId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub name: Option<String>,
    pub group_id: Option<CategoryGroupId>,
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payee {
    pub id: PayeeId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub id: TransactionId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub account_id: Option<AccountId>,
    pub date: Option<Date>,
    pub amount: Option<Milliunits>,
    pub payee_id: Option<PayeeId>,
    pub category_id: Option<CategoryId>,
    pub memo: Option<String>,
    pub cleared: Option<Cleared>,
}

/// The month × category "budgeted" cell — the write household members race
/// on, and the reason per-field LWW exists (ADR 0016).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MonthCategory {
    pub id: MonthCategoryId,
    pub budget_id: BudgetId,
    pub deleted: bool,
    pub month: Option<Month>,
    pub category_id: Option<CategoryId>,
    pub budgeted: Option<Milliunits>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum EntityKind {
    Budget,
    Account,
    CategoryGroup,
    Category,
    Payee,
    Transaction,
    MonthCategory,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Entity {
    Budget(Budget),
    Account(Account),
    CategoryGroup(CategoryGroup),
    Category(Category),
    Payee(Payee),
    Transaction(Transaction),
    MonthCategory(MonthCategory),
}

impl Entity {
    pub const fn kind(&self) -> EntityKind {
        match self {
            Self::Budget(_) => EntityKind::Budget,
            Self::Account(_) => EntityKind::Account,
            Self::CategoryGroup(_) => EntityKind::CategoryGroup,
            Self::Category(_) => EntityKind::Category,
            Self::Payee(_) => EntityKind::Payee,
            Self::Transaction(_) => EntityKind::Transaction,
            Self::MonthCategory(_) => EntityKind::MonthCategory,
        }
    }

    pub fn entity_id(&self) -> EntityId {
        let uuid = match self {
            Self::Budget(e) => e.id.as_uuid(),
            Self::Account(e) => e.id.as_uuid(),
            Self::CategoryGroup(e) => e.id.as_uuid(),
            Self::Category(e) => e.id.as_uuid(),
            Self::Payee(e) => e.id.as_uuid(),
            Self::Transaction(e) => e.id.as_uuid(),
            Self::MonthCategory(e) => e.id.as_uuid(),
        };
        EntityId::from_raw(uuid)
    }

    pub const fn budget_id(&self) -> BudgetId {
        match self {
            Self::Budget(e) => e.budget_id,
            Self::Account(e) => e.budget_id,
            Self::CategoryGroup(e) => e.budget_id,
            Self::Category(e) => e.budget_id,
            Self::Payee(e) => e.budget_id,
            Self::Transaction(e) => e.budget_id,
            Self::MonthCategory(e) => e.budget_id,
        }
    }

    pub const fn deleted(&self) -> bool {
        match self {
            Self::Budget(e) => e.deleted,
            Self::Account(e) => e.deleted,
            Self::CategoryGroup(e) => e.deleted,
            Self::Category(e) => e.deleted,
            Self::Payee(e) => e.deleted,
            Self::Transaction(e) => e.deleted,
            Self::MonthCategory(e) => e.deleted,
        }
    }

    /// An all-`None`, not-deleted entity of `kind` — materialized by the
    /// first op that targets `id` (ADR 0016).
    pub(crate) fn shell(kind: EntityKind, id: EntityId, budget_id: BudgetId) -> Self {
        let uuid = id.as_uuid();
        match kind {
            EntityKind::Budget => Self::Budget(Budget {
                id: BudgetId::from_raw(uuid),
                budget_id,
                deleted: false,
                name: None,
            }),
            EntityKind::Account => Self::Account(Account {
                id: AccountId::from_raw(uuid),
                budget_id,
                deleted: false,
                name: None,
                kind: None,
            }),
            EntityKind::CategoryGroup => Self::CategoryGroup(CategoryGroup {
                id: CategoryGroupId::from_raw(uuid),
                budget_id,
                deleted: false,
                name: None,
            }),
            EntityKind::Category => Self::Category(Category {
                id: CategoryId::from_raw(uuid),
                budget_id,
                deleted: false,
                name: None,
                group_id: None,
                note: None,
            }),
            EntityKind::Payee => Self::Payee(Payee {
                id: PayeeId::from_raw(uuid),
                budget_id,
                deleted: false,
                name: None,
            }),
            EntityKind::Transaction => Self::Transaction(Transaction {
                id: TransactionId::from_raw(uuid),
                budget_id,
                deleted: false,
                account_id: None,
                date: None,
                amount: None,
                payee_id: None,
                category_id: None,
                memo: None,
                cleared: None,
            }),
            EntityKind::MonthCategory => Self::MonthCategory(MonthCategory {
                id: MonthCategoryId::from_raw(uuid),
                budget_id,
                deleted: false,
                month: None,
                category_id: None,
                budgeted: None,
            }),
        }
    }
}

/// Which field of which entity an op writes. Nested enums keep `match`
/// exhaustive: adding a field is a variant plus compiler-guided arms
/// (ADR 0016). `Deleted` applies to every entity kind.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Field {
    Deleted,
    Budget(BudgetField),
    Account(AccountField),
    CategoryGroup(CategoryGroupField),
    Category(CategoryField),
    Payee(PayeeField),
    Transaction(TransactionField),
    MonthCategory(MonthCategoryField),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum BudgetField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum AccountField {
    Name,
    Kind,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CategoryGroupField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CategoryField {
    Name,
    GroupId,
    Note,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum PayeeField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TransactionField {
    AccountId,
    Date,
    Amount,
    PayeeId,
    CategoryId,
    Memo,
    Cleared,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum MonthCategoryField {
    Month,
    CategoryId,
    Budgeted,
}

/// A field value — the closed vocabulary the op log writes, and the future
/// single serialization choke point (ADR 0009, ADR 0016).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    Bool(bool),
    Text(String),
    Milliunits(Milliunits),
    Id(EntityId),
    Date(Date),
    Month(Month),
    AccountKind(AccountKind),
    Cleared(Cleared),
}

impl Value {
    pub(crate) fn into_text(self) -> Option<String> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn into_bool(self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(b),
            _ => None,
        }
    }

    pub(crate) fn into_milliunits(self) -> Option<Milliunits> {
        match self {
            Self::Milliunits(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn into_id(self) -> Option<EntityId> {
        match self {
            Self::Id(i) => Some(i),
            _ => None,
        }
    }

    pub(crate) fn into_date(self) -> Option<Date> {
        match self {
            Self::Date(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn into_month(self) -> Option<Month> {
        match self {
            Self::Month(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn into_account_kind(self) -> Option<AccountKind> {
        match self {
            Self::AccountKind(k) => Some(k),
            _ => None,
        }
    }

    pub(crate) fn into_cleared(self) -> Option<Cleared> {
        match self {
            Self::Cleared(c) => Some(c),
            _ => None,
        }
    }
}
