//! The minimal recap (ADR 0023): a read-only projection of recent
//! transactions — newest first, resolved payees, exact amounts. Not a
//! browser; visibility and payee resolution come from the core's
//! projections ([ADR 0016](../../../docs/decisions/0016-core-domain-model.md)).

use std::fmt;
use std::path::Path;

use pursecraft_core::date::Date;
use pursecraft_core::domain::{Entity, Transaction};
use pursecraft_core::ids::{EntityId, TransactionId};
use pursecraft_core::ops::ApplyError;
use pursecraft_core::resolve::{
    CategoryResolution, transaction_category, transaction_payee, transaction_visible,
};
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::SyncSession;

use crate::home::{IdentityError, budget_log, load_identity};
use crate::session::Session;
use crate::sync;

/// How many transactions `list` shows (ADR 0023's minimal recap).
pub const RECENT: usize = 10;
/// A failed recap.
#[derive(Debug)]
pub enum ListError {
    Identity(IdentityError),
    Store(StoreError),
    /// A stored op was rejected during replay — loud, never merged.
    Apply(ApplyError),
    /// The pending-sync count failed (ADR 0011's badge must not lie).
    Sync(sync::SyncError),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
            Self::Sync(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
            Self::Sync(e) => Some(e),
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

impl From<sync::SyncError> for ListError {
    fn from(e: sync::SyncError) -> Self {
        Self::Sync(e)
    }
}

const EMPTY: &str = "no transactions yet\n\ntry: pursecraft add coffee -4.50\n";

/// Render the recap for the data home at `home` (ADR 0023): the last
/// [`RECENT`] visible transactions, newest first, with a count footer —
/// and, when captures wait for the relay, the visible pending-sync badge
/// (ADR 0011, ADR 0025). Read-only — an absent world shows the
/// getting-started hint.
pub fn list(home: &Path, session: &Session) -> Result<String, ListError> {
    let Some(identity) = load_identity(home)? else {
        return Ok(EMPTY.to_owned());
    };
    // The badge (ADR 0025): derived, never stored; zero after a sync.
    let pending = sync::pending_count(home, session, &identity)?;
    let path = budget_log(home, identity.budget_id);
    if !path.exists() {
        return Ok(with_pending_sync(EMPTY.to_owned(), pending));
    }
    let store = LocalStore::open(&path)?;
    let mut replay = SyncSession::new();
    replay.apply_delta(store.delta_since(0))?;
    let state = replay.state();

    let mut rows: Vec<(Option<Date>, String, String, String, String, TransactionId)> = Vec::new();
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
        return Ok(with_pending_sync(EMPTY.to_owned(), pending));
    }
    // Newest first: date descending, then id descending (UUIDv7 is
    // chronological within clock skew — ADR 0016). Undated transactions
    // sort last.
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.5.cmp(&a.5)));

    let total = rows.len();
    let mut out = format!(
        "{:<10}   {:<24} {:<16} {:>12}\n",
        "DATE", "PAYEE", "CATEGORY", "AMOUNT"
    );
    for (_, date, payee, category, amount, _) in rows.iter().take(RECENT) {
        out.push_str(&format!(
            "{date:<10}   {payee:<24} {category:<16} {amount:>12}\n"
        ));
    }
    if total > RECENT {
        out.push_str(&format!("\nshowing {RECENT} of {total} transactions\n"));
    } else if total == 1 {
        out.push_str("\n1 transaction\n");
    } else {
        out.push_str(&format!("\n{total} transactions\n"));
    }
    Ok(with_pending_sync(out, pending))
}

/// Append the pending-sync badge (ADR 0011) when captures wait for the
/// relay; a synced home shows nothing extra (feedback first, never
/// noise). Shared by every read surface that renders state (`list`,
/// `categorize`'s review, `budget`).
pub(crate) fn with_pending_sync(mut out: String, pending: u64) -> String {
    if pending > 0 {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("{pending} pending sync — run: pursecraft sync\n"));
    }
    out
}

/// The transaction's resolved live payee name (blank when it resolves
/// to none), shared by every row renderer (ADR 0016's "no payee").
pub(crate) fn resolved_payee_name(
    state: &pursecraft_core::ops::ScopeState,
    txn: &Transaction,
) -> String {
    transaction_payee(state, txn)
        .and_then(|payee| state.entity(&EntityId::new(payee.as_uuid()).expect("stored v7")))
        .and_then(|entity| match entity {
            Entity::Payee(p) => p.name.clone(),
            _ => None,
        })
        .unwrap_or_default()
}

/// One recap row: (date key for ordering, date cell, resolved live payee
/// name, resolved category cell, amount cell, id for the tiebreak).
/// Torn cells render `?` — a missing amount must never fake a real zero
/// capture as `0.000`. An unset category is NOT a tear: it is the
/// designed ready-to-assign state and renders as the Inbox (ADR 0026).
#[allow(clippy::type_complexity)]
fn row(
    state: &pursecraft_core::ops::ScopeState,
    txn: &Transaction,
) -> (Option<Date>, String, String, String, String, TransactionId) {
    let payee = resolved_payee_name(state, txn);
    let date = txn
        .date
        .map(|d| d.to_string())
        .unwrap_or_else(|| "?".to_owned());
    let category = match transaction_category(state, txn) {
        CategoryResolution::Uncategorized => "Inbox".to_owned(),
        CategoryResolution::Category(resolved) => {
            let inbox = crate::category::inbox_of(state);
            if Some(resolved) == inbox {
                "Inbox".to_owned()
            } else {
                state
                    .entity(&EntityId::new(resolved.as_uuid()).expect("stored v7"))
                    .and_then(|entity| match entity {
                        Entity::Category(c) => c.name.clone(),
                        _ => None,
                    })
                    .unwrap_or_else(|| "?".to_owned())
            }
        }
    };
    let amount = txn
        .amount
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".to_owned());
    (txn.date, date, payee, category, amount, txn.id)
}
