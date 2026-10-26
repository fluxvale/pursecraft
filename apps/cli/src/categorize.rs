//! The inbox review pass (ADR 0027): `pursecraft categorize` lists the
//! bucket — visible transactions resolving to no category or to the
//! Inbox — and `pursecraft categorize <txn> <category>` files one by
//! its id. One-shot, id-exact, no prompts: a list that changed between
//! look and file must never misfile money, so positional row numbers are
//! not a selector.

use std::fmt;

use pursecraft_core::domain::{Entity, Field, TransactionField, Value};
use pursecraft_core::ids::{EntityId, ScopeId};
use pursecraft_core::ops::{ApplyError, ScopeState};
use pursecraft_core::resolve::{CategoryResolution, transaction_category, transaction_visible};
use pursecraft_core::store::StoreError;

use crate::capture::{Minter, boot};
use crate::category::{CategoryError, ensure_inbox, find_category, inbox_line, inbox_of};
use crate::home::{IdentityError, budget_log, load_identity};
use crate::keys::{KeysError, World};
use crate::session::Session;
use crate::sink;

/// The short id length the listing prints and the filing command
/// accepts (the full UUID also works; anything between is refused with
/// the teaching error — unambiguous exactness over convenience).
const SHORT_ID: usize = 8;

/// A failed categorize.
#[derive(Debug)]
pub enum CategorizeError {
    Identity(IdentityError),
    Keys(KeysError),
    Store(StoreError),
    Apply(ApplyError),
    Category(CategoryError),
    /// The pending-sync count failed (ADR 0011's badge must not lie).
    Sync(crate::sync::SyncError),
    /// The selector matches no visible transaction.
    UnknownTransaction {
        selector: String,
    },
    /// The short id prefixes more than one visible transaction.
    Ambiguous {
        selector: String,
        ids: Vec<String>,
    },
}

impl fmt::Display for CategorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(e) => write!(f, "{e}"),
            Self::Keys(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
            Self::Category(e) => write!(f, "{e}"),
            Self::Sync(e) => write!(f, "{e}"),
            Self::UnknownTransaction { selector } => write!(
                f,
                "no visible transaction matches {selector:?} (the id is the {SHORT_ID}-character \
                 short form pursecraft categorize prints)"
            ),
            Self::Ambiguous { selector, ids } => write!(
                f,
                "{selector:?} matches several transactions ({ids:?}) — use a full id"
            ),
        }
    }
}

impl std::error::Error for CategorizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
            Self::Category(e) => Some(e),
            Self::Sync(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for CategorizeError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<KeysError> for CategorizeError {
    fn from(e: KeysError) -> Self {
        Self::Keys(e)
    }
}

impl From<StoreError> for CategorizeError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for CategorizeError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

impl From<CategoryError> for CategorizeError {
    fn from(e: CategoryError) -> Self {
        Self::Category(e)
    }
}

impl From<crate::sync::SyncError> for CategorizeError {
    fn from(e: crate::sync::SyncError) -> Self {
        Self::Sync(e)
    }
}

impl From<crate::category::EnsureError> for CategorizeError {
    fn from(e: crate::category::EnsureError) -> Self {
        match e {
            crate::category::EnsureError::Store(e) => Self::Store(e),
            crate::category::EnsureError::Apply(e) => Self::Apply(e),
        }
    }
}

impl From<std::io::Error> for CategorizeError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e.into())
    }
}

/// The bucket's members (ADR 0027): visible transactions resolving to
/// `Uncategorized` or the Inbox entity — newest first (date descending,
/// then id descending, `list`'s convention).
fn bucket(state: &ScopeState) -> Vec<&pursecraft_core::domain::Transaction> {
    let inbox = inbox_of(state);
    let mut txns: Vec<_> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Transaction(txn) => Some(txn),
            _ => None,
        })
        .filter(|txn| transaction_visible(state, txn))
        .filter(|txn| match transaction_category(state, txn) {
            CategoryResolution::Uncategorized => true,
            CategoryResolution::Category(resolved) => Some(resolved) == inbox,
        })
        .collect();
    txns.sort_by(|a, b| b.date.cmp(&a.date).then(b.id.cmp(&a.id)));
    txns
}

/// The transaction's short id: the LAST [`SHORT_ID`] hex of its UUIDv7 —
/// the random `rand_b` bits, not the leading timestamp (two captures in
/// one millisecond share a timestamp prefix; the random end does not).
fn short_id(txn: &pursecraft_core::domain::Transaction) -> String {
    let simple = txn.id.as_uuid().simple().to_string();
    simple[simple.len() - SHORT_ID..].to_owned()
}

/// `pursecraft categorize` — the review listing (ADR 0027). Read-only;
/// an absent world shows the getting-started hint.
pub fn review(world: &World, session: &Session) -> Result<String, CategorizeError> {
    let home = world.home.as_path();
    let Some(identity) = load_identity(home)? else {
        return Ok("nothing captured yet\n\ntry: pursecraft add coffee -4.50\n".to_owned());
    };
    if !budget_log(home, identity.budget_id).exists() {
        return Ok("the inbox is empty\n".to_owned());
    }
    let store = world.open_log(ScopeId::Budget(identity.budget_id))?;
    let replay = boot(&store)?;
    let state = replay.state();
    let txns = bucket(state);
    if txns.is_empty() {
        return Ok("the inbox is empty\n".to_owned());
    }
    let mut out = format!(
        "{:<8}   {:<10}   {:<24} {:>12}\n",
        "ID", "DATE", "PAYEE", "AMOUNT"
    );
    for txn in &txns {
        let payee = crate::list::resolved_payee_name(state, txn);
        let date = txn
            .date
            .map(|d| d.to_string())
            .unwrap_or_else(|| "?".to_owned());
        let amount = txn
            .amount
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_owned());
        out.push_str(&format!(
            "{:<8}   {date:<10}   {payee:<24} {amount:>12}\n",
            short_id(txn)
        ));
    }
    out.push_str(&format!(
        "\n{} in the inbox — file with: pursecraft categorize <id> <category>\n",
        txns.len()
    ));
    Ok(crate::list::with_pending_sync(
        out,
        crate::sync::pending_count(world, session, &identity)?,
    ))
}

/// `pursecraft categorize <txn> <category>` — file one visible
/// transaction (ADR 0027). Re-filing between categories is free; filing
/// into the Inbox un-files. Id-exact: the printed short form or the
/// full UUID, nothing looser.
pub fn file(
    world: &World,
    session: &Session,
    selector: &str,
    category: &str,
) -> Result<String, CategorizeError> {
    let home = world.home.as_path();
    let Some(identity) = load_identity(home)? else {
        return Err(CategoryError::NotBootstrapped.into());
    };
    let mut minter = Minter::new(session, &identity);

    let mut store = world.open_log(ScopeId::Budget(identity.budget_id))?;
    let mut out = String::new();
    if ensure_inbox(&mut minter, &mut store, &identity)? {
        out.push_str(&inbox_line());
    }
    let boot_session = boot(&store)?;
    minter.absorb(boot_session.clock());
    let state = boot_session.state();

    // Unknown category is the teaching error listing the known ones.
    let target = match find_category(state, category.trim()) {
        Some(id) => id,
        None => {
            return Err(CategoryError::Unknown {
                wanted: category.trim().to_owned(),
                known: crate::category::known_names(state),
            }
            .into());
        }
    };

    let selector = selector.trim().to_lowercase().replace('-', "");
    if selector.len() != SHORT_ID && selector.len() != 32 {
        return Err(CategorizeError::UnknownTransaction {
            selector: selector.clone(),
        });
    }
    let mut matches: Vec<&pursecraft_core::domain::Transaction> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Transaction(txn) => Some(txn),
            _ => None,
        })
        .filter(|txn| transaction_visible(state, txn))
        .filter(|txn| txn.id.as_uuid().simple().to_string().ends_with(&selector))
        .collect();
    matches.sort_by_key(|txn| txn.id);
    let txn = match matches.len() {
        0 => {
            return Err(CategorizeError::UnknownTransaction { selector });
        }
        1 => matches[0].clone(),
        _ => {
            return Err(CategorizeError::Ambiguous {
                selector,
                ids: matches
                    .iter()
                    .map(|txn| txn.id.as_uuid().hyphenated().to_string())
                    .collect(),
            });
        }
    };

    // Resolve once more for the "was" half of the confirmation.
    let before = match transaction_category(state, &txn) {
        CategoryResolution::Uncategorized => "the inbox".to_owned(),
        CategoryResolution::Category(resolved) => state
            .entity(&EntityId::new(resolved.as_uuid()).expect("stored v7"))
            .and_then(|entity| match entity {
                Entity::Category(c) => c.name.clone(),
                _ => None,
            })
            .unwrap_or_else(|| "?".to_owned()),
    };
    let target_id = target;
    let into = state
        .entity(&target_id)
        .and_then(|entity| match entity {
            Entity::Category(c) => c.name.clone(),
            _ => None,
        })
        .unwrap_or_else(|| "?".to_owned());

    let payee = crate::list::resolved_payee_name(state, &txn);
    let date = txn
        .date
        .map(|d| d.to_string())
        .unwrap_or_else(|| "?".to_owned());
    let amount = txn
        .amount
        .map(|a| a.to_string())
        .unwrap_or_else(|| "?".to_owned());
    if transaction_category(state, &txn)
        == CategoryResolution::Category(
            pursecraft_core::ids::CategoryId::new(target_id.as_uuid()).expect("stored v7"),
        )
    {
        return Ok(format!(
            "{out}{payee} {amount} on {date} is already in {into}\n"
        ));
    }

    sink::sink(
        &mut store,
        minter.op_now(
            ScopeId::Budget(identity.budget_id),
            pursecraft_core::domain::EntityKind::Transaction,
            EntityId::new(txn.id.as_uuid()).expect("stored v7"),
            Field::Transaction(TransactionField::CategoryId),
            Value::Id(target_id),
        ),
    )?;
    Ok(format!(
        "{out}filed {payee} {amount} on {date} into {into} (was {before})\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::home::Identity;
    use crate::home::budget_log;
    use crate::idmint::mint_uuid;
    use crate::testsupport::TempDir;
    use pursecraft_core::date::Date;
    use pursecraft_core::ids::{DeviceId, TransactionId};
    use pursecraft_core::money::Milliunits;
    use pursecraft_core::ops::{Op, ScopeState};
    use pursecraft_core::store::LocalStore;
    use pursecraft_core::sync::SyncSession;
    use std::path::Path;

    fn session() -> crate::session::Session {
        crate::session::Session {
            version: 1,
            server: "http://127.0.0.1:9".into(),
            device_id: DeviceId::new(mint_uuid()).unwrap(),
            token: "test-only".into(),
        }
    }

    fn add(world: &World, payee: &str, amount: &str, category: Option<&str>) {
        crate::capture::add(
            &mut world.clone(),
            &session(),
            &crate::capture::RawAdd {
                payee,
                amount,
                date: None,
                account: None,
                category,
            },
            Date::new(2026, 10, 25).unwrap(),
        )
        .unwrap();
    }

    fn state_of(home: &Path) -> (Identity, LocalStore, ScopeState) {
        let identity = load_identity(home).unwrap().expect("world");
        let store = LocalStore::open(&budget_log(home, identity.budget_id)).unwrap();
        let mut replay = SyncSession::new();
        replay.apply_delta(store.delta_since(0)).unwrap();
        (identity, store, replay.state().clone())
    }

    /// THE inbox flow (issue #29): capture uncategorized → the review
    /// listing shows it → file it → the listing empties, the category
    /// moved, and the op is a single CategoryId write.
    #[test]
    fn the_inbox_flow_lists_files_and_empties() {
        let tmp = TempDir::new("inbox-flow");
        let home = tmp.path();
        add(&World::plain(home), "coffee", "-4.50", None);
        let (_, store, _) = state_of(home);
        let tip = store.tip();
        drop(store);

        let listing = review(&World::plain(home), &session()).unwrap();
        assert!(listing.contains("coffee"), "{listing}");
        let short = listing
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(short.len(), SHORT_ID);
        assert!(listing.contains("1 in the inbox"), "{listing}");

        // File it into a category minted for the purpose.
        crate::category::new_category(&World::plain(home), &session(), "Food", None).unwrap();
        let filed = file(&World::plain(home), &session(), &short, "Food").unwrap();
        assert!(
            filed.contains("filed coffee -4.500 on 2026-10-25 into Food (was the inbox)"),
            "{filed}"
        );

        let (_, store, state) = state_of(home);
        // Exactly one transaction op landed (plus the ensure/creation
        // ops above the tip): the CategoryId write.
        let fresh: Vec<Op> = store.delta_since(tip).map(|s| s.op.clone()).collect();
        let category_writes = fresh
            .iter()
            .filter(|op| matches!(op.field, Field::Transaction(TransactionField::CategoryId)))
            .count();
        assert_eq!(category_writes, 1, "{fresh:?}");
        let txn = state
            .entities()
            .find_map(|e| match e {
                Entity::Transaction(t) => Some(t.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            transaction_category(&state, &txn),
            CategoryResolution::Category(
                find_category(&state, "Food")
                    .map(|id| pursecraft_core::ids::CategoryId::new(id.as_uuid()).unwrap())
                    .unwrap()
            )
        );
        assert_eq!(txn.amount, Some(Milliunits::from_milli(-4_500)));

        let again = review(&World::plain(home), &session()).unwrap();
        assert!(again.contains("the inbox is empty"), "{again}");
    }

    /// Id-exactness: a too-short or non-matching selector teaches; a
    /// full UUID works; re-filing an already-filed transaction is a
    /// no-op message, not an op.
    #[test]
    fn selectors_are_exact_and_refiling_is_free() {
        let tmp = TempDir::new("selectors");
        let home = tmp.path();
        add(&World::plain(home), "coffee", "-4.50", None);
        crate::category::new_category(&World::plain(home), &session(), "Food", None).unwrap();
        let (_, store, state) = state_of(home);
        let txn_id = state
            .entities()
            .find_map(|e| match e {
                Entity::Transaction(t) => Some(TransactionId::new(t.id.as_uuid()).unwrap()),
                _ => None,
            })
            .unwrap();
        drop(store);

        let err = file(&World::plain(home), &session(), "0192", "Food").unwrap_err();
        assert!(
            err.to_string().contains("no visible transaction matches"),
            "{err}"
        );
        let err = file(&World::plain(home), &session(), "ffffffff", "Food").unwrap_err();
        assert!(err.to_string().contains("no visible transaction"), "{err}");
        let err = file(
            &World::plain(home),
            &session(),
            &txn_id.as_uuid().simple().to_string(),
            "Nope",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown category"), "{err}");

        // The full hyphenated id files; then the same file is a no-op.
        let full = txn_id.as_uuid().hyphenated().to_string();
        assert!(
            file(&World::plain(home), &session(), &full, "Food")
                .unwrap()
                .contains("into Food")
        );
        let (_, store, _) = state_of(home);
        let tip = store.tip();
        drop(store);
        let again = file(&World::plain(home), &session(), &full, "Food").unwrap();
        assert!(again.contains("is already in Food"), "{again}");
        let (_, store, _) = state_of(home);
        assert_eq!(store.tip(), tip, "no op for a no-op re-file");
    }
}
