//! Domain entities and the typed field/value vocabulary ops write
//! (ADRs 0007, 0016, 0020).
//!
//! Every entity carries the same envelope: a UUIDv7 id, the `scope` of its
//! log (an org or a budget, ADR 0020), and a `deleted` tombstone flag
//! modeled as an ordinary field so deletes ride the same per-field LWW path
//! as any other write. Entity fields are `Option` until an op sets them —
//! money must never default silently to zero (ADR 0016).

use serde::{Deserialize, Serialize};

use crate::date::{Date, Month};
use crate::ids::{
    AccountId, BudgetId, CategoryGroupId, CategoryId, EntityId, MonthCategoryId, OrgId, PayeeId,
    ScopeId, TransactionId, UserId,
};
use crate::money::Milliunits;

/// Account kind — reference data, extend freely (ADR 0016).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Cleared {
    Uncleared,
    Cleared,
    Reconciled,
}

/// A user's role in an organization (ADR 0020): ADR 0008's owner/editor/
/// viewer set, transferred to the org level. Roles are data — enforcing
/// them is the auth slice's job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum MembershipRole {
    Owner,
    Editor,
    Viewer,
}

/// An organization — the ownership scope for budgets (ADR 0020). Exactly
/// one per org log, its id equal to the log's scope; `personal_for` marks
/// the default org every user is provisioned with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Organization {
    pub id: OrgId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
    pub personal_for: Option<UserId>,
}

/// A user's membership in an organization, with a role (ADR 0020). Lives
/// in the org's log; well-formed data has one per (org, user), and racing
/// twins resolve deterministically to the earliest-created (ADR 0020).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Membership {
    pub id: EntityId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub user_id: Option<UserId>,
    pub role: Option<MembershipRole>,
}

/// A budget, owned by the organization whose log this entity lives in —
/// the scope is the tie (ADR 0020). Budget *content* entities live in the
/// budget's own log; this entity is the org-visible registry entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Budget {
    pub id: BudgetId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    pub id: AccountId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
    pub kind: Option<AccountKind>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CategoryGroup {
    pub id: CategoryGroupId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Category {
    pub id: CategoryId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
    pub group_id: Option<CategoryGroupId>,
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payee {
    pub id: PayeeId,
    pub scope: ScopeId,
    pub deleted: bool,
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub id: TransactionId,
    pub scope: ScopeId,
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
    pub scope: ScopeId,
    pub deleted: bool,
    pub month: Option<Month>,
    pub category_id: Option<CategoryId>,
    pub budgeted: Option<Milliunits>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum EntityKind {
    Organization,
    Membership,
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
    Organization(Organization),
    Membership(Membership),
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
            Self::Organization(_) => EntityKind::Organization,
            Self::Membership(_) => EntityKind::Membership,
            Self::Budget(_) => EntityKind::Budget,
            Self::Account(_) => EntityKind::Account,
            Self::CategoryGroup(_) => EntityKind::CategoryGroup,
            Self::Category(_) => EntityKind::Category,
            Self::Payee(_) => EntityKind::Payee,
            Self::Transaction(_) => EntityKind::Transaction,
            Self::MonthCategory(_) => EntityKind::MonthCategory,
        }
    }

    /// An all-`None`, not-deleted entity of `kind` — materialized by the
    /// first op that targets `id` (ADR 0016).
    pub(crate) fn shell(kind: EntityKind, id: EntityId, scope: ScopeId) -> Self {
        let uuid = id.as_uuid();
        match kind {
            EntityKind::Organization => Self::Organization(Organization {
                id: OrgId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
                personal_for: None,
            }),
            EntityKind::Membership => Self::Membership(Membership {
                id,
                scope,
                deleted: false,
                user_id: None,
                role: None,
            }),
            EntityKind::Budget => Self::Budget(Budget {
                id: BudgetId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
            }),
            EntityKind::Account => Self::Account(Account {
                id: AccountId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
                kind: None,
            }),
            EntityKind::CategoryGroup => Self::CategoryGroup(CategoryGroup {
                id: CategoryGroupId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
            }),
            EntityKind::Category => Self::Category(Category {
                id: CategoryId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
                group_id: None,
                note: None,
            }),
            EntityKind::Payee => Self::Payee(Payee {
                id: PayeeId::from_raw(uuid),
                scope,
                deleted: false,
                name: None,
            }),
            EntityKind::Transaction => Self::Transaction(Transaction {
                id: TransactionId::from_raw(uuid),
                scope,
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
                scope,
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum Field {
    Deleted,
    Organization(OrgField),
    Membership(MembershipField),
    Budget(BudgetField),
    Account(AccountField),
    CategoryGroup(CategoryGroupField),
    Category(CategoryField),
    Payee(PayeeField),
    Transaction(TransactionField),
    MonthCategory(MonthCategoryField),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum OrgField {
    Name,
    PersonalFor,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum MembershipField {
    UserId,
    Role,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum BudgetField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum AccountField {
    Name,
    Kind,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum CategoryGroupField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum CategoryField {
    Name,
    GroupId,
    Note,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum PayeeField {
    Name,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum TransactionField {
    AccountId,
    Date,
    Amount,
    PayeeId,
    CategoryId,
    Memo,
    Cleared,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum MonthCategoryField {
    Month,
    CategoryId,
    Budgeted,
}

/// A field value — the closed vocabulary the op log writes, and the future
/// single serialization choke point (ADR 0009, ADR 0016, ADR 0020).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Text(String),
    Milliunits(Milliunits),
    Id(EntityId),
    User(UserId),
    Role(MembershipRole),
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

    pub(crate) fn into_user(self) -> Option<UserId> {
        match self {
            Self::User(u) => Some(u),
            _ => None,
        }
    }

    pub(crate) fn into_role(self) -> Option<MembershipRole> {
        match self {
            Self::Role(r) => Some(r),
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
