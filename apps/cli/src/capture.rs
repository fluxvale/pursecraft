//! Read-then-mint capture (ADRs 0021, 0023): boot the stores through the
//! ordinary [`SyncSession`] replay, probe the state, mint only what is
//! missing, and commit every op through the single payload [`sink`].
//!
//! The first `add` bootstraps the minimal world — personal org (via the
//! core's `provision_personal_org`, the read-then-mint reference), a named
//! budget in the org log, a cash account in the budget log — and every
//! later `add` re-ensures it: probes emit nothing once satisfied, so
//! crash-retries complete partial states instead of duplicating them.

use std::fmt;
use std::path::Path;

use pursecraft_core::date::Date;
use pursecraft_core::domain::{
    AccountField, AccountKind, BudgetField, Cleared, Entity, EntityKind, Field, PayeeField,
    TransactionField, Value,
};
use pursecraft_core::hlc::Hlc;
use pursecraft_core::ids::{DeviceId, EntityId, OpId, ScopeId, UserId};
use pursecraft_core::money::Milliunits;
use pursecraft_core::ops::{ApplyError, Op, ScopeState};
use pursecraft_core::org::{PersonalOrgIds, provision_personal_org};
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::SyncSession;

use crate::amount;
use crate::home::{Identity, IdentityError, budget_log, load_or_create_identity, org_log};
use crate::idmint::mint_uuid;
use crate::session::Session;
use crate::sink;

/// The bootstrapped organization's name (ADR 0023: fixed constants until a
/// setup UX exists).
pub const ORG_NAME: &str = "Personal";
/// The bootstrapped budget's name.
pub const BUDGET_NAME: &str = "Personal";
/// The bootstrapped account's name.
pub const ACCOUNT_NAME: &str = "Wallet";

/// One capture request, as raw argv strings; parsing lives here so amount
/// and date error messages are consistent for every caller.
pub struct RawAdd<'a> {
    pub payee: &'a str,
    pub amount: &'a str,
    pub date: Option<&'a str>,
    pub account: Option<&'a str>,
}

/// What one capture stored — the confirmation line's data (ADR 0023's
/// quiet-by-default feedback).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Receipt {
    /// The bootstrap ran this call (identity freshly created).
    pub bootstrapped: bool,
    /// No live payee of this name existed, so one was minted.
    pub new_payee: bool,
    pub payee: String,
    pub amount: Milliunits,
    pub date: Date,
    pub account_name: String,
}

impl Receipt {
    /// The human feedback: one line per event, exact amounts.
    pub fn confirmation(&self) -> String {
        let mut out = String::new();
        if self.bootstrapped {
            out.push_str(&format!(
                "initialized org {ORG_NAME:?}, budget {BUDGET_NAME:?}, account {ACCOUNT_NAME:?}\n"
            ));
        }
        let new_payee = if self.new_payee { ", new payee" } else { "" };
        out.push_str(&format!(
            "added {} {} on {} ({}{new_payee})\n",
            self.payee, self.amount, self.date, self.account_name
        ));
        out
    }
}

/// A failed capture.
#[derive(Debug)]
pub enum CaptureError {
    Amount(amount::AmountError),
    Date {
        input: String,
    },
    Identity(IdentityError),
    Store(StoreError),
    /// A stored op was rejected during replay — the log is inconsistent
    /// with the engine; loud, never merged (ADR 0016).
    Apply(ApplyError),
    /// `--account` named no live account; `known` lists what exists.
    UnknownAccount {
        wanted: String,
        known: Vec<String>,
    },
    /// The bootstrapped account is dead or missing — a loud dead-default
    /// error, never a silent fabrication that `list` would then hide the
    /// transaction behind.
    NoDefaultAccount {
        known: Vec<String>,
    },
    /// The payee positional was empty (argv rejects this; the public API
    /// defends it too).
    EmptyPayee,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amount(e) => write!(f, "{e}"),
            Self::Date { input } => {
                write!(f, "invalid date {input:?} (expected YYYY-MM-DD)")
            }
            Self::Identity(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "stored op rejected by the engine: {e}"),
            Self::UnknownAccount { wanted, known } => {
                if known.is_empty() {
                    write!(f, "unknown account {wanted:?} (no accounts exist)")
                } else {
                    write!(
                        f,
                        "unknown account {wanted:?} (known: {})",
                        known.join(", ")
                    )
                }
            }
            Self::NoDefaultAccount { known } => {
                if known.is_empty() {
                    write!(
                        f,
                        "the bootstrapped account no longer exists and no account does; pass --account after creating one"
                    )
                } else {
                    write!(
                        f,
                        "the bootstrapped account no longer exists (known: {}; pass --account <name>)",
                        known.join(", ")
                    )
                }
            }
            Self::EmptyPayee => write!(f, "payee must not be empty"),
        }
    }
}

impl std::error::Error for CaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Amount(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Apply(e) => Some(e),
            _ => None,
        }
    }
}

impl From<amount::AmountError> for CaptureError {
    fn from(e: amount::AmountError) -> Self {
        Self::Amount(e)
    }
}

impl From<IdentityError> for CaptureError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<StoreError> for CaptureError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<ApplyError> for CaptureError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

impl From<std::io::Error> for CaptureError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e.into())
    }
}

/// Capture one transaction (ADR 0023): parse, ensure the bootstrapped
/// world, resolve account and payee read-then-mint, append the ops through
/// the [`sink`], return the receipt. Input parsing comes first so a bad
/// amount or date never creates files. The enrollment's device mints the
/// ops (ADR 0025) — the relay refuses another device's.
pub fn add(
    home: &Path,
    session: &Session,
    raw: &RawAdd<'_>,
    today: Date,
) -> Result<Receipt, CaptureError> {
    let payee = raw.payee.trim();
    if payee.is_empty() {
        return Err(CaptureError::EmptyPayee);
    }
    let amount = amount::parse(raw.amount)?;
    let date = match raw.date {
        Some(input) => input.trim().parse().map_err(|_| CaptureError::Date {
            input: input.trim().to_owned(),
        })?,
        None => today,
    };

    let (identity, bootstrapped) = load_or_create_identity(home, session.device_id)?;
    let mut minter = Minter::new(session, &identity);

    // Org side (ADR 0021): provisioning + the budget registry entry.
    let org_path = org_log(home, identity.org_id);
    std::fs::create_dir_all(org_path.parent().expect("store parent"))?;
    let mut org_store = LocalStore::open(&org_path)?;
    ensure_org(&mut minter, &mut org_store, &identity)?;
    drop(org_store);

    // Budget side: ensure the account, then boot fresh for the capture.
    let budget_path = budget_log(home, identity.budget_id);
    std::fs::create_dir_all(budget_path.parent().expect("store parent"))?;
    let mut budget_store = LocalStore::open(&budget_path)?;
    if ensure_account(&mut minter, &mut budget_store, &identity)? {
        budget_store = LocalStore::open(&budget_path)?; // re-read post-writes
    }
    let session = boot(&budget_store)?;
    minter.absorb(session.clock());

    let state = session.state();
    let (account_id, account_name) = resolve_account(state, raw.account, identity.account_id)?;
    let (payee_id, new_payee, ops) = match find_payee(state, payee) {
        Some(existing) => (existing, false, Vec::new()),
        None => {
            let id = EntityId::new(mint_uuid()).expect("minted v7");
            let op = minter.op_now(
                ScopeId::Budget(identity.budget_id),
                EntityKind::Payee,
                id,
                Field::Payee(PayeeField::Name),
                Value::Text(payee.to_owned()),
            );
            (id, true, vec![op])
        }
    };

    let scope = ScopeId::Budget(identity.budget_id);
    let txn = EntityId::new(mint_uuid()).expect("minted v7");
    let fields = [
        (
            Field::Transaction(TransactionField::AccountId),
            Value::Id(account_id),
        ),
        (
            Field::Transaction(TransactionField::Date),
            Value::Date(date),
        ),
        (
            Field::Transaction(TransactionField::Amount),
            Value::Milliunits(amount),
        ),
        (
            Field::Transaction(TransactionField::PayeeId),
            Value::Id(payee_id),
        ),
        (
            Field::Transaction(TransactionField::Cleared),
            Value::Cleared(Cleared::Uncleared),
        ),
    ];
    let mut ops = ops;
    for (field, value) in fields {
        ops.push(minter.op_now(scope, EntityKind::Transaction, txn, field, value));
    }
    for op in ops {
        sink::sink(&mut budget_store, op)?;
    }

    Ok(Receipt {
        bootstrapped,
        new_payee,
        payee: payee.to_owned(),
        amount,
        date,
        account_name,
    })
}

/// The device's op mint (ADR 0023): owns the HLC — seeded from the booted
/// sessions (receive-merge discipline, ADR 0017) so post-boot ticks outrank
/// every stored op — and mints ids. Ops carry the SESSION's device (ADR
/// 0025: the relay enforces caller == `meta.device_id`) and the world's
/// user (ADR 0023).
pub(crate) struct Minter {
    device_id: DeviceId,
    user_id: UserId,
    clock: Hlc,
}

impl Minter {
    pub(crate) fn new(session: &Session, identity: &Identity) -> Self {
        Self {
            device_id: session.device_id,
            user_id: identity.user_id,
            clock: Hlc::now(),
        }
    }

    /// Receive a booted session's clock (ADR 0017).
    pub(crate) fn absorb(&mut self, remote: Hlc) {
        self.clock.merge(remote);
    }

    /// Mint one op at the next local tick.
    pub(crate) fn op_now(
        &mut self,
        scope: ScopeId,
        kind: EntityKind,
        entity: EntityId,
        field: Field,
        value: Value,
    ) -> Op {
        self.clock.tick();
        let hlc = self.clock;
        self.op_at(hlc, scope, kind, entity, field, value)
    }

    /// Mint one op at an explicit stamp — the anchored-stamp path for
    /// bootstrap writes (ADR 0021's stale-retry guard).
    pub(crate) fn op_at(
        &mut self,
        hlc: Hlc,
        scope: ScopeId,
        kind: EntityKind,
        entity: EntityId,
        field: Field,
        value: Value,
    ) -> Op {
        Op {
            op_id: OpId::new(mint_uuid()).expect("minted v7"),
            scope,
            device_id: self.device_id,
            user_id: self.user_id,
            entity_kind: kind,
            entity_id: entity,
            field,
            value,
            hlc,
        }
    }
}

/// The entity id's own UUIDv7 millisecond, logical zero (ADR 0021's
/// anchoring convention): bootstrap writes stamped here lose every
/// contested field on merge to any device that has seen the entity.
pub(crate) fn anchored_at(id: EntityId) -> Hlc {
    Hlc {
        physical_ms: (id.as_uuid().as_u128() >> 80) as u64,
        logical: 0,
    }
}

/// Boot a session from a store — read-then-mint's read half, the ordinary
/// replay path (ADR 0018).
pub(crate) fn boot(store: &LocalStore) -> Result<SyncSession, ApplyError> {
    let mut session = SyncSession::new();
    session.apply_delta(store.delta_since(0))?;
    Ok(session)
}

/// Ensure the org-side bootstrap (ADR 0023): personal-org provisioning via
/// the core's read-then-mint reference, plus the budget's `name` op in the
/// org log — both probed against the booted state, stamped at their
/// entity's own mint ms. Returns whether anything was emitted.
fn ensure_org(
    minter: &mut Minter,
    store: &mut LocalStore,
    identity: &Identity,
) -> Result<bool, CaptureError> {
    let session = boot(store)?;
    let ids = PersonalOrgIds {
        user: identity.user_id,
        org: identity.org_id,
        membership: identity.membership_id,
    };
    let mut ops =
        provision_personal_org(session.state(), ids, ORG_NAME, identity.device_id, || {
            OpId::new(mint_uuid()).expect("minted v7")
        });
    let scope = ScopeId::Org(identity.org_id);
    let budget_entity = EntityId::new(identity.budget_id.as_uuid()).expect("stored v7");
    let budget_named = matches!(
        session.state().entity(&budget_entity),
        Some(Entity::Budget(b)) if b.name.is_some()
    );
    if !budget_named {
        ops.push(minter.op_at(
            anchored_at(budget_entity),
            scope,
            EntityKind::Budget,
            budget_entity,
            Field::Budget(BudgetField::Name),
            Value::Text(BUDGET_NAME.to_owned()),
        ));
    }
    if ops.is_empty() {
        return Ok(false);
    }
    for op in ops {
        sink::sink(store, op)?;
    }
    Ok(true)
}

/// Ensure the bootstrapped account exists in the budget log (ADR 0023):
/// `name` + `kind`, each probed per-field so a partial write is completed,
/// never redone. Stamped at the account's own mint ms. Returns whether
/// anything was emitted.
fn ensure_account(
    minter: &mut Minter,
    store: &mut LocalStore,
    identity: &Identity,
) -> Result<bool, CaptureError> {
    let session = boot(store)?;
    let (name_set, kind_set) = match session.state().entity(&identity.account_id) {
        Some(Entity::Account(a)) => (a.name.is_some(), a.kind.is_some()),
        _ => (false, false),
    };
    if name_set && kind_set {
        return Ok(false);
    }
    let scope = ScopeId::Budget(identity.budget_id);
    let anchor = anchored_at(identity.account_id);
    let account = identity.account_id;
    let mut emitted = false;
    if !name_set {
        sink::sink(
            store,
            minter.op_at(
                anchor,
                scope,
                EntityKind::Account,
                account,
                Field::Account(AccountField::Name),
                Value::Text(ACCOUNT_NAME.to_owned()),
            ),
        )?;
        emitted = true;
    }
    if !kind_set {
        sink::sink(
            store,
            minter.op_at(
                anchor,
                scope,
                EntityKind::Account,
                account,
                Field::Account(AccountField::Kind),
                Value::AccountKind(AccountKind::Cash),
            ),
        )?;
        emitted = true;
    }
    Ok(emitted)
}

/// The state's live, named accounts as `(id, name)` pairs, earliest id
/// first (ADR 0016's deterministic convention) — the one enumeration both
/// capture's account resolution and sync's joiner adoption read.
pub(crate) fn live_accounts(state: &ScopeState) -> Vec<(EntityId, String)> {
    let mut accounts: Vec<(EntityId, String)> = state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Account(a) if !a.deleted && a.name.is_some() => Some((
                EntityId::new(a.id.as_uuid()).expect("stored v7"),
                a.name.clone().unwrap_or_default(),
            )),
            _ => None,
        })
        .collect();
    accounts.sort();
    accounts
}

/// Resolve the capture account (ADR 0023): `wanted` by exact live name
/// (earliest id on duplicates — ADR 0016's deterministic convention), or
/// the bootstrapped account — which must itself be live: a dead or missing
/// default is a loud error, never a silent fabrication that `list` would
/// then hide the transaction behind.
fn resolve_account(
    state: &ScopeState,
    wanted: Option<&str>,
    default: EntityId,
) -> Result<(EntityId, String), CaptureError> {
    let accounts = live_accounts(state);
    let find_by_name = |name: &str| accounts.iter().find(|(_, known)| known == name).cloned();
    let known = || accounts.iter().map(|(_, name)| name.clone()).collect();
    match wanted {
        Some(wanted) => find_by_name(wanted).ok_or_else(|| CaptureError::UnknownAccount {
            wanted: wanted.to_owned(),
            known: known(),
        }),
        None => accounts
            .iter()
            .find(|(id, _)| *id == default)
            .cloned()
            .ok_or_else(|| CaptureError::NoDefaultAccount { known: known() }),
    }
}

/// Find the earliest-created live payee named exactly `name` (ADR 0023:
/// read-then-mint's read half for payees).
fn find_payee(state: &ScopeState, name: &str) -> Option<EntityId> {
    state
        .entities()
        .filter_map(|entity| match entity {
            Entity::Payee(p) if !p.deleted && p.name.as_deref() == Some(name) => {
                Some(EntityId::new(p.id.as_uuid()).expect("stored v7"))
            }
            _ => None,
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::home::load_identity;
    use crate::testsupport::TempDir;
    use pursecraft_core::domain::{MembershipRole, Payee, Transaction};
    use pursecraft_core::ids::{AccountId, BudgetId, PayeeId};
    use pursecraft_core::org::{membership_role, organization};

    /// A stamp far beyond any real wall clock (same trick as the core's
    /// convergence tests).
    const MS_FUTURE: u64 = (1u64 << 60) + 10_000_000_000;

    fn today() -> Date {
        Date::new(2026, 10, 25).unwrap()
    }

    /// A synthetic enrollment (ADR 0025): the session struct only — no
    /// relay, no session file; capture is offline.
    fn session() -> crate::session::Session {
        crate::session::Session {
            version: 1,
            server: "http://127.0.0.1:9".into(),
            device_id: DeviceId::new(mint_uuid()).unwrap(),
            token: "test-only".into(),
        }
    }

    fn add_cmd(home: &Path, raw: &RawAdd<'_>) -> Result<Receipt, CaptureError> {
        add(home, &session(), raw, today())
    }

    fn raw<'a>(payee: &'a str, amount: &'a str) -> RawAdd<'a> {
        RawAdd {
            payee,
            amount,
            date: None,
            account: None,
        }
    }

    /// Read the identity back and reopen the budget store from disk.
    fn reopened(home: &Path) -> (Identity, LocalStore) {
        let identity = load_identity(home).unwrap().expect("identity exists");
        let store = LocalStore::open(&budget_log(home, identity.budget_id)).unwrap();
        (identity, store)
    }

    fn org_tip(home: &Path, identity: &Identity) -> u64 {
        LocalStore::open(&org_log(home, identity.org_id))
            .unwrap()
            .tip()
    }

    /// THE round trip (issue #21): command → ops → store → replayed state.
    #[test]
    fn capture_round_trips_command_to_replayed_state() {
        let tmp = TempDir::new("roundtrip");
        let home = tmp.path();
        let receipt = add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        assert!(receipt.bootstrapped);
        assert!(receipt.new_payee);
        assert_eq!(receipt.amount, Milliunits::from_milli(-4_500));
        assert_eq!(receipt.account_name, ACCOUNT_NAME);
        assert_eq!(
            receipt.confirmation(),
            format!(
                "initialized org {ORG_NAME:?}, budget {BUDGET_NAME:?}, account {ACCOUNT_NAME:?}\n\
                 added coffee -4.500 on 2026-10-25 (Wallet, new payee)\n"
            )
        );

        // Org log: 4 provisioning ops + the budget name op (ADR 0021),
        // replayed from disk through the ordinary engine path.
        let (identity, _) = reopened(home);
        assert_eq!(org_tip(home, &identity), 5);
        let mut org_session = SyncSession::new();
        let org_store = LocalStore::open(&org_log(home, identity.org_id)).unwrap();
        org_session.apply_delta(org_store.delta_since(0)).unwrap();
        let org = organization(org_session.state()).expect("org entity");
        assert_eq!(org.name.as_deref(), Some(ORG_NAME));
        assert_eq!(org.personal_for, Some(identity.user_id));
        assert_eq!(
            membership_role(org_session.state(), identity.user_id),
            Some(MembershipRole::Owner)
        );

        // Budget log: account (2 ops) + payee (1) + transaction (5),
        // replayed into exactly the captured transaction.
        let (_, store) = reopened(home);
        assert_eq!(store.tip(), 8);
        let mut session = SyncSession::new();
        session.apply_delta(store.delta_since(0)).unwrap();
        let state = session.state();
        let account = state
            .entities()
            .find_map(|e| match e {
                Entity::Account(a) if a.id.as_uuid() == identity.account_id.as_uuid() => {
                    Some(a.clone())
                }
                _ => None,
            })
            .expect("bootstrapped account");
        assert_eq!(account.name.as_deref(), Some(ACCOUNT_NAME));
        assert_eq!(account.kind, Some(AccountKind::Cash));
        let payees: Vec<&Payee> = state
            .entities()
            .filter_map(|e| match e {
                Entity::Payee(p) if p.name.as_deref() == Some("coffee") => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(payees.len(), 1, "exactly one coffee payee");
        let txns: Vec<&Transaction> = state
            .entities()
            .filter_map(|e| match e {
                Entity::Transaction(t) => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(txns.len(), 1);
        let txn = txns[0];
        assert_eq!(txn.amount, Some(Milliunits::from_milli(-4_500)));
        assert_eq!(txn.date, Some(today()));
        assert_eq!(
            txn.account_id,
            Some(AccountId::new(identity.account_id.as_uuid()).unwrap())
        );
        assert_eq!(
            txn.payee_id,
            Some(PayeeId::new(payees[0].id.as_uuid()).unwrap())
        );
        assert_eq!(txn.cleared, Some(Cleared::Uncleared));
        assert_eq!(txn.memo, None, "capture sets no memo");
        assert_eq!(
            txn.category_id, None,
            "capture leaves the txn ready to assign"
        );
    }

    #[test]
    fn second_capture_reuses_the_payee_and_mints_only_transaction_ops() {
        let tmp = TempDir::new("reuse");
        let home = tmp.path();
        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        let (identity, store) = reopened(home);
        let tip = store.tip();
        let org_tip_before = org_tip(home, &identity);
        drop(store);

        let receipt = add_cmd(home, &raw("coffee", "-8")).unwrap();
        assert!(!receipt.bootstrapped, "bootstrap happened once");
        assert!(!receipt.new_payee, "the payee is reused");

        let (_, store) = reopened(home);
        assert_eq!(store.tip(), tip + 5, "only the five transaction ops");
        assert_eq!(
            org_tip(home, &identity),
            org_tip_before,
            "org log untouched"
        );
        let mut session = SyncSession::new();
        session.apply_delta(store.delta_since(0)).unwrap();
        let state = session.state();
        assert_eq!(
            state
                .entities()
                .filter(|e| matches!(e, Entity::Payee(_)))
                .count(),
            1
        );
        assert_eq!(
            state
                .entities()
                .filter(|e| matches!(e, Entity::Transaction(_)))
                .count(),
            2
        );
    }

    /// Idempotent re-runs (issue #21): the bootstrap probe emits nothing
    /// once satisfied, and re-appending the identical op set is a dedupe
    /// no-op that writes no bytes (ADR 0018).
    #[test]
    fn idempotent_re_runs() {
        let tmp = TempDir::new("idempotent");
        let home = tmp.path();
        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        let (identity, store) = reopened(home);
        let tip = store.tip();
        let org_tip_before = org_tip(home, &identity);
        drop(store);

        // A later add re-ensures the world: no bootstrap ops re-landed —
        // `bread` is a new payee, so six ops land (payee + transaction).
        add_cmd(home, &raw("bread", "-2")).unwrap();
        let (_, store) = reopened(home);
        assert_eq!(
            org_tip(home, &identity),
            org_tip_before,
            "org log is stable"
        );
        assert_eq!(
            store.tip(),
            tip + 6,
            "only the new payee and transaction ops"
        );

        // At-least-once append safety: replaying every stored op is a
        // dedupe no-op that writes no bytes (ADR 0018).
        let path = budget_log(home, identity.budget_id);
        let mut store = LocalStore::open(&path).unwrap();
        let ops: Vec<Op> = store.delta_since(0).map(|s| s.op.clone()).collect();
        let len = std::fs::metadata(&path).unwrap().len();
        for op in ops {
            sink::sink(&mut store, op).unwrap();
        }
        assert_eq!(store.tip(), tip + 6);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "dedupe writes no bytes"
        );
    }

    /// HLC hygiene (ADR 0017): the minter absorbs the booted session's
    /// clock, so ops minted after an ahead-stamped stored op outrank it.
    #[test]
    fn minter_absorbs_the_log_clock() {
        let tmp = TempDir::new("absorb");
        let home = tmp.path();
        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        let (identity, mut store) = reopened(home);
        let mut session = SyncSession::new();
        session.apply_delta(store.delta_since(0)).unwrap();
        let txn = session
            .state()
            .entities()
            .find_map(|e| match e {
                Entity::Transaction(t) => Some(t.clone()),
                _ => None,
            })
            .unwrap();
        // An op stamped far in the future lands in the store…
        sink::sink(
            &mut store,
            Op {
                op_id: OpId::new(mint_uuid()).unwrap(),
                scope: ScopeId::Budget(identity.budget_id),
                device_id: identity.device_id,
                user_id: identity.user_id,
                entity_kind: EntityKind::Transaction,
                entity_id: EntityId::new(txn.id.as_uuid()).unwrap(),
                field: Field::Transaction(TransactionField::Memo),
                value: Value::Text("from the future".into()),
                hlc: Hlc {
                    physical_ms: MS_FUTURE,
                    logical: 0,
                },
            },
        )
        .unwrap();
        let tip = store.tip();
        drop(store);

        // …and the next capture (payee reused, five ops) still mints above it.
        add_cmd(home, &raw("coffee", "-2")).unwrap();
        let (_, store) = reopened(home);
        let fresh: Vec<Op> = store.delta_since(tip).map(|s| s.op.clone()).collect();
        assert_eq!(fresh.len(), 5);
        assert!(
            fresh.iter().all(|op| op.hlc.physical_ms >= MS_FUTURE),
            "every newly minted op outranks the future stamp"
        );
    }

    /// Seed one op into a fresh budget log (the torn attempt's landed
    /// write), creating the directory `add` would have made.
    fn seed_budget_op(home: &Path, identity: &Identity, op: Op) {
        let path = budget_log(home, identity.budget_id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut store = LocalStore::open(&path).unwrap();
        sink::sink(&mut store, op).unwrap();
    }

    fn payee_name_op(identity: &Identity, payee: EntityId, name: &str) -> Op {
        Op {
            op_id: OpId::new(mint_uuid()).unwrap(),
            scope: ScopeId::Budget(identity.budget_id),
            device_id: identity.device_id,
            user_id: identity.user_id,
            entity_kind: EntityKind::Payee,
            entity_id: payee,
            field: Field::Payee(PayeeField::Name),
            value: Value::Text(name.into()),
            hlc: Hlc {
                physical_ms: 1_000,
                logical: 0,
            },
        }
    }

    /// Torn-bootstrap resume (issue #21 / ADR 0023): a partial first
    /// attempt is completed by the next add, never redone. Crash window A:
    /// the payee op landed, the transaction ops did not.
    #[test]
    fn a_payee_only_torn_capture_is_resumed_not_duplicated() {
        let tmp = TempDir::new("torn-payee");
        let home = tmp.path();
        let (identity, _) = load_or_create_identity(home, session().device_id).unwrap();
        seed_budget_op(
            home,
            &identity,
            payee_name_op(&identity, EntityId::new(mint_uuid()).unwrap(), "coffee"),
        );

        let receipt = add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        assert!(!receipt.new_payee, "the torn attempt's payee is reused");
        let (_, store) = reopened(home);
        assert_eq!(store.tip(), 8, "payee(1) + account(2) + transaction(5)");
        let mut session = SyncSession::new();
        session.apply_delta(store.delta_since(0)).unwrap();
        assert_eq!(
            session
                .state()
                .entities()
                .filter(|e| matches!(e, Entity::Payee(_)))
                .count(),
            1,
            "no twin payee"
        );
    }

    /// Crash window B: the account landed its `name` but not its `kind` —
    /// the ensure step completes only the missing field.
    #[test]
    fn a_half_written_account_is_completed_not_redone() {
        let tmp = TempDir::new("torn-account");
        let home = tmp.path();
        let (identity, _) = load_or_create_identity(home, session().device_id).unwrap();
        seed_budget_op(
            home,
            &identity,
            Op {
                op_id: OpId::new(mint_uuid()).unwrap(),
                scope: ScopeId::Budget(identity.budget_id),
                device_id: identity.device_id,
                user_id: identity.user_id,
                entity_kind: EntityKind::Account,
                entity_id: identity.account_id,
                field: Field::Account(AccountField::Name),
                value: Value::Text(ACCOUNT_NAME.into()),
                hlc: anchored_at(identity.account_id),
            },
        );

        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        let (_, store) = reopened(home);
        // Seeded name + emitted kind + payee + 5 transaction ops.
        assert_eq!(store.tip(), 8);
        let fresh: Vec<Op> = store.delta_since(1).map(|s| s.op.clone()).collect();
        assert_eq!(fresh.len(), 7, "only the missing kind op re-lands");
        assert!(
            !fresh.iter().any(|op| op.entity_kind == EntityKind::Account
                && matches!(op.field, Field::Account(AccountField::Name))),
            "the satisfied name write is never redone"
        );
    }

    /// Crash window C: the org log holds only part of the provisioning
    /// op-set — the next add completes it with the missing fields.
    #[test]
    fn a_partial_org_provisioning_is_completed() {
        let tmp = TempDir::new("torn-org");
        let home = tmp.path();
        let (identity, _) = load_or_create_identity(home, session().device_id).unwrap();
        let org_path = org_log(home, identity.org_id);
        std::fs::create_dir_all(org_path.parent().unwrap()).unwrap();
        let mut org_store = LocalStore::open(&org_path).unwrap();
        let session = boot(&org_store).unwrap();
        let ops = provision_personal_org(
            session.state(),
            PersonalOrgIds {
                user: identity.user_id,
                org: identity.org_id,
                membership: identity.membership_id,
            },
            ORG_NAME,
            identity.device_id,
            || OpId::new(mint_uuid()).expect("minted v7"),
        );
        assert_eq!(ops.len(), 4);
        for op in &ops[..2] {
            sink::sink(&mut org_store, op.clone()).unwrap();
        }
        drop(org_store);

        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        assert_eq!(
            org_tip(home, &identity),
            5,
            "2 seeded + 2 completed + budget name"
        );
        let mut org_session = SyncSession::new();
        let org_store = LocalStore::open(&org_log(home, identity.org_id)).unwrap();
        org_session.apply_delta(org_store.delta_since(0)).unwrap();
        assert_eq!(
            membership_role(org_session.state(), identity.user_id),
            Some(MembershipRole::Owner),
            "the completed provisioning yields a whole world"
        );
        assert_eq!(
            organization(org_session.state()).unwrap().name.as_deref(),
            Some(ORG_NAME)
        );
    }

    /// Crash window D: a capture tore after only its account op landed —
    /// `list` shows the transaction with `?` cells, never a faked
    /// `0.000`/blank (ADR 0023).
    #[test]
    fn a_torn_transaction_renders_unknown_cells() {
        let tmp = TempDir::new("torn-txn");
        let home = tmp.path();
        add_cmd(home, &raw("coffee", "-4.50")).unwrap();
        let identity = load_identity(home).unwrap().unwrap();
        let torn = EntityId::new(mint_uuid()).unwrap();
        seed_budget_op(
            home,
            &identity,
            Op {
                op_id: OpId::new(mint_uuid()).unwrap(),
                scope: ScopeId::Budget(identity.budget_id),
                device_id: identity.device_id,
                user_id: identity.user_id,
                entity_kind: EntityKind::Transaction,
                entity_id: torn,
                field: Field::Transaction(TransactionField::AccountId),
                value: Value::Id(identity.account_id),
                hlc: Hlc {
                    physical_ms: 1_000,
                    logical: 0,
                },
            },
        );

        let list = crate::list::list(home, &session()).unwrap();
        let torn_row = list
            .lines()
            .find(|l| l.contains('?'))
            .unwrap_or_else(|| panic!("no torn row rendered\n{list}"));
        // The amount column starts at 38 (10 date + 3 + 24 payee + 1).
        assert_eq!(
            torn_row[38..].trim(),
            "?",
            "a faked amount would hide the tear\n{list}"
        );
        assert!(!torn_row.contains("0.000"));
        assert_eq!(
            torn_row[..10].trim(),
            "?",
            "the torn date cell renders ? too"
        );
        assert!(list.contains("2 transactions"), "{list}");
    }

    #[test]
    fn flags_select_date_and_account() {
        let tmp = TempDir::new("flags");
        let home = tmp.path();
        let receipt = add_cmd(
            home,
            &RawAdd {
                payee: "Meralco",
                amount: "-890",
                date: Some("2026-10-24"),
                account: Some(ACCOUNT_NAME),
            },
        )
        .unwrap();
        assert_eq!(receipt.date, Date::new(2026, 10, 24).unwrap());
        assert_eq!(receipt.account_name, ACCOUNT_NAME);
        // An invalid calendar date is a loud error, not a normalized one.
        let err = add_cmd(
            home,
            &RawAdd {
                payee: "x",
                amount: "-1",
                date: Some("2026-02-30"),
                account: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, CaptureError::Date { .. }), "{err}");
    }

    #[test]
    fn unknown_account_lists_the_known_ones() {
        let tmp = TempDir::new("account");
        let home = tmp.path();
        let err = add_cmd(
            home,
            &RawAdd {
                payee: "coffee",
                amount: "-4.50",
                date: None,
                account: Some("Nope"),
            },
        )
        .unwrap_err();
        match err {
            CaptureError::UnknownAccount { wanted, known } => {
                assert_eq!(wanted, "Nope");
                assert_eq!(known, [ACCOUNT_NAME.to_owned()]);
            }
            other => panic!("expected UnknownAccount, got {other}"),
        }
        assert!(
            add_cmd(home, &raw("coffee", "4.50")).is_err(),
            "unsigned amounts are rejected"
        );
    }

    /// The sink dedupes at-least-once retries (ADR 0023's seam; the
    /// only-append-through-sink invariant itself is enforced by review and
    /// the round-trip tests above).
    #[test]
    fn sink_dedupes_retries() {
        let tmp = TempDir::new("sink-only");
        let path = tmp.path().join("probe.ops");
        let mut store = LocalStore::open(&path).unwrap();
        let scope = ScopeId::Budget(BudgetId::new(mint_uuid()).unwrap());
        let entity = EntityId::new(mint_uuid()).unwrap();
        let op = Op {
            op_id: OpId::new(mint_uuid()).unwrap(),
            scope,
            device_id: DeviceId::new(mint_uuid()).unwrap(),
            user_id: UserId::new(mint_uuid()).unwrap(),
            entity_kind: EntityKind::Payee,
            entity_id: entity,
            field: Field::Payee(PayeeField::Name),
            value: Value::Text("probe".into()),
            hlc: Hlc {
                physical_ms: 1,
                logical: 0,
            },
        };
        assert_eq!(sink::sink(&mut store, op.clone()).unwrap(), 1);
        assert_eq!(sink::sink(&mut store, op).unwrap(), 1, "the retry dedupes");
    }
}
