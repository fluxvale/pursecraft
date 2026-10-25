//! The minimal recap (ADR 2023): a read-only projection of recent
//! transactions — newest first, resolved payees, exact amounts. Not a
//! browser; visibility and payee resolution come from the core's
//! projections ([ADR 0016](../../../docs/decisions/0016-core-domain-model.md)).

use std::fmt;
use std::path::Path;

use pursecraft_core::date::Date;
use pursecraft_core::domain::{Entity, Transaction};
use pursecraft_core::ids::{EntityId, TransactionId};
use pursecraft_core::money::Milliunits;
use pursecraft_core::ops::ApplyError;
use pursecraft_core::resolve::{transaction_payee, transaction_visible};
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::SyncSession;

use crate::home::{IdentityError, budget_log, load_identity};

/// How many transactions `list` shows (ADR 2023's minimal recap).
pub const RECENT: usize = 10;

/// A failed recap.
#[derive(Debug)]
pub enum ListError {
    Identity(IdentityError),
    Store(StoreError),
    /// A stored op was rejected during replay — loud, never merged.
    Apply(ApplyError),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
        }
    }
}

impl std::error::Error for ListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
        }
    }
}

impl From<IdentityError> for ListError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<StoreError> for ListError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for ListError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

const EMPTY: &str = "no transactions yet\n\ntry: pursecraft add coffee -4.50\n";

/// Render the recap for the data home at `home` (ADR 2023): the last
/// [`RECENT`] visible transactions, newest first, with a count footer.
/// Read-only — an absent world shows the getting-started hint.
pub fn list(home: &Path) -> Result<String, ListError> {
    let Some(identity) = load_identity(home)? else {
        return Ok(EMPTY.to_owned());
    };
    let path = budget_log(home, identity.budget_id);
    if !path.exists() {
        return Ok(EMPTY.to_owned());
    }
    let store = LocalStore::open(&path)?;
    let mut session = SyncSession::new();
    session.apply_delta(store.delta_since(0))?;
    let state = session.state();

    let mut rows: Vec<(Option<Date>, String, Milliunits, TransactionId)> = Vec::new();
    for entity in state.entities() {
        let Entity::Transaction(txn) = entity else {
            continue;
        };
        if !transaction_visible(state, txn) {
            continue;
        }
        rows.push(row(state, txn));
    }
    if rows.is_empty() {
        return Ok(EMPTY.to_owned());
    }
    // Newest first: date descending, then id descending (UUIDv7 is
    // chronological within clock skew — ADR 0016). Undated transactions
    // sort last.
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.3.cmp(&a.3)));

    let total = rows.len();
    let mut out = format!("{:<10}   {:<24} {:>12}\n", "DATE", "PAYEE", "AMOUNT");
    for (date, payee, amount, _) in rows.iter().take(RECENT) {
        let date = date
            .map(|d| d.to_string())
            .unwrap_or_else(|| "?".to_owned());
        let amount = amount.to_string();
        out.push_str(&format!("{date:<10}   {payee:<24} {amount:>12}\n"));
    }
    if total > RECENT {
        out.push_str(&format!("\nshowing {RECENT} of {total} transactions\n"));
    } else if total == 1 {
        out.push_str("\n1 transaction\n");
    } else {
        out.push_str(&format!("\n{total} transactions\n"));
    }
    Ok(out)
}

/// One recap row: date, resolved live payee name, exact amount.
fn row(
    state: &pursecraft_core::ops::ScopeState,
    txn: &Transaction,
) -> (Option<Date>, String, Milliunits, TransactionId) {
    let payee = transaction_payee(state, txn)
        .and_then(|payee| state.entity(&EntityId::new(payee.as_uuid()).expect("stored v7")))
        .and_then(|entity| match entity {
            Entity::Payee(p) => p.name.clone(),
            _ => None,
        })
        .unwrap_or_default();
    (
        txn.date,
        payee,
        txn.amount.unwrap_or(Milliunits::ZERO),
        txn.id,
    )
}
