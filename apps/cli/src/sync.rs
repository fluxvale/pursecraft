//! First sync through the rendezvous relay (ADR 0025): manual
//! push-then-pull per scope, pairing for the second device, and the
//! derived pending state.
//!
//! Two cursors per scope live in `<home>/sync.json` ([ADR 0025]):
//! `pushed_through` (local-store space — the outbox is everything of this
//! session's device beyond it) and `remote_seen` (relay space — the pull
//! cursor; deliberately NOT the `SyncSession` watermark, which after a
//! store boot counts local sequences, [ADR 0017]). Pulled ops flow through
//! the single [`sink`] and are applied under their local sequences, so the
//! session stays in one sequence space; a failing page aborts loudly with
//! cursors unmoved, and every retry is an idempotent re-delivery.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use pursecraft_core::domain::{AccountField, AccountKind, Field, MembershipField, MembershipRole};
use pursecraft_core::ids::{BudgetId, EntityId, OrgId, ScopeId, UserId};
use pursecraft_core::ops::{ApplyError, Op};
use pursecraft_core::org::org_alive;
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::{SequencedOp, SyncSession};
use pursecraft_core::wire::decode_payload;

use crate::capture::{ACCOUNT_NAME, Minter, anchored_at, boot};
use crate::home::{Identity, IdentityError, budget_log, create_identity, load_identity, org_log};
use crate::idmint::mint_uuid;
use crate::relay::{Relay, RelayError};
use crate::session::{Session, SessionError};
use crate::sink;
use serde::{Deserialize, Serialize};

/// Ops per push request — under the relay's batch cap (ADR 0024), one
/// round trip per capture session at household scale.
const PUSH_CHUNK: usize = 500;
/// Pull page size (ADR 0024 paged deltas; the loop pages until caught up).
const PULL_PAGE: usize = 200;
/// The sync-state file name under the data home.
const SYNC_FILE: &str = "sync.json";
/// The sync-state file version this CLI writes and reads.
const SYNC_VERSION: u16 = 1;

/// A failed sync, pair, or join — every failure mode is loud and teaching
/// (ADR 0025).
#[derive(Debug)]
pub enum SyncError {
    Relay(RelayError),
    Store(StoreError),
    Identity(IdentityError),
    Session(SessionError),
    /// A pulled op was rejected by the engine — the cursor stays put and
    /// the same page re-serves (ADR 0017).
    Apply(ApplyError),
    /// A pulled payload does not decode — possibly damaged relay bytes;
    /// nothing is applied past it (ADR 0024).
    Decode {
        scope: String,
        seq: u64,
        source: serde_json::Error,
    },
    Io(std::io::Error),
    /// `sync.json` does not decode or speaks an unknown version — loud,
    /// never reset (the identity discipline, ADR 0023).
    BadState {
        path: PathBuf,
        detail: String,
    },
    /// `pair` before the relay knows this home's scopes.
    NotSyncedYet,
    /// `sync` or `pair` before the first capture — bootstrap is capture's
    /// (ADR 0023), so an enrolled-but-empty home has nothing to sync.
    NotBootstrapped,
    /// `join` onto a home that already holds a world.
    AlreadyHasWorld,
    /// A join bundle that does not hold together (bad ids, dead org).
    BadBundle(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relay(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Session(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "a pulled op was rejected by the engine: {e}"),
            Self::Decode { scope, seq, source } => write!(
                f,
                "a pulled op ({scope} seq {seq}) does not decode: {source} — nothing was applied past it"
            ),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::BadState { path, detail } => {
                write!(f, "{} is not a usable sync state: {detail}", path.display())
            }
            Self::NotSyncedYet => {
                write!(
                    f,
                    "the relay does not know this home's scopes yet — run: pursecraft sync"
                )
            }
            Self::NotBootstrapped => write!(
                f,
                "nothing to sync yet — capture a transaction first: pursecraft add coffee -4.50"
            ),
            Self::AlreadyHasWorld => write!(
                f,
                "this home already holds a budget; join is for a fresh device (identity.json exists)"
            ),
            Self::BadBundle(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<RelayError> for SyncError {
    fn from(e: RelayError) -> Self {
        Self::Relay(e)
    }
}

impl From<StoreError> for SyncError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<IdentityError> for SyncError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<SessionError> for SyncError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<ApplyError> for SyncError {
    fn from(e: ApplyError) -> Self {
        Self::Apply(e)
    }
}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// What one `pursecraft sync` did — the rendered output plus the pairing
/// bundle a first sync mints (ADR 0025).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SyncReceipt {
    pub server: String,
    /// One line per scope: `org: pushed N, pulled M`.
    pub scopes: Vec<String>,
    /// Stranded-ops notes (re-login edge, ADR 0025).
    pub notes: Vec<String>,
    /// Set when this run created relay scopes (first sync).
    pub created: Option<PairingBundle>,
}

impl SyncReceipt {
    fn new(server: &str) -> Self {
        Self {
            server: server.to_owned(),
            scopes: Vec::new(),
            notes: Vec::new(),
            created: None,
        }
    }

    /// The command's stdout (ADR 0025's quiet-by-default shape).
    pub fn render(&self) -> String {
        let mut out = format!("synced with {}\n", self.server);
        for scope in &self.scopes {
            out.push_str(scope);
            out.push('\n');
        }
        if let Some(bundle) = &self.created {
            out.push_str("created the org and budget scopes on the relay\n");
            out.push_str(&bundle.render());
        }
        for note in &self.notes {
            out.push_str(note);
            out.push('\n');
        }
        out
    }
}

/// The single-use pairing codes a first sync (or `pair`) mints, rendered
/// as the exact join command for the other device (ADR 0025).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PairingBundle {
    pub server: String,
    pub org_id: OrgId,
    pub org_code: String,
    pub budget_id: BudgetId,
    pub budget_code: String,
}

impl PairingBundle {
    pub fn render(&self) -> String {
        format!(
            "on another device:\n  \
             pursecraft login {server}\n  \
             pursecraft join {org} {org_code} {budget} {budget_code}\n\
             (pairing codes work once and expire in 1 hour; fresh ones anytime: pursecraft pair)\n",
            server = self.server,
            org = self.org_id.as_uuid(),
            org_code = self.org_code,
            budget = self.budget_id.as_uuid(),
            budget_code = self.budget_code,
        )
    }
}

/// One sync: per scope, ensure the relay scope exists, push the derived
/// outbox, pull paged deltas through the sink (ADR 0025).
pub fn sync(home: &Path, session: &Session, identity: &Identity) -> Result<SyncReceipt, SyncError> {
    let relay = Relay::new(&session.server, &session.token);
    let mut file = load_sync_file(home)?;
    let mut receipt = SyncReceipt::new(&session.server);
    let mut stranded_total: u64 = 0;
    for (scope, label) in scopes_of(identity) {
        let key = scope_key(scope);
        let mut cursors = file.scopes.get(&key).copied().unwrap_or_default();

        // First sync creates the relay scope (ADR 0025); a 409 means it
        // already exists — fine exactly when this device is granted.
        if !file.scopes.contains_key(&key) {
            match relay.create_scope(scope) {
                Ok(code) => {
                    if receipt.created.is_none() {
                        receipt.created = Some(PairingBundle {
                            server: session.server.to_owned(),
                            org_id: identity.org_id,
                            org_code: String::new(),
                            budget_id: identity.budget_id,
                            budget_code: String::new(),
                        });
                    }
                    let bundle = receipt.created.as_mut().expect("just set");
                    match scope {
                        ScopeId::Org(_) => bundle.org_code = code,
                        ScopeId::Budget(_) => bundle.budget_code = code,
                    }
                }
                Err(RelayError::Status { code: 409, .. }) => {
                    // Exists: probe the grant — a refusal teaches pairing.
                    relay.pull(scope, 0, 1)?;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let path = scope_log_path(home, identity, scope);
        let mut store = open_store(&path)?;

        // The derived outbox (ADR 0025): this session's ops beyond the
        // pushed watermark. Ops of the founding device (a previous
        // enrollment) can never be pushed — they are counted, not hidden.
        let mut outbox: Vec<(u64, Op)> = Vec::new();
        let mut stranded: u64 = 0;
        for sequenced in store.delta_since(cursors.pushed_through) {
            if sequenced.op.device_id == session.device_id {
                outbox.push((sequenced.seq, sequenced.op.clone()));
            } else if sequenced.op.device_id == identity.device_id {
                stranded += 1;
            }
        }
        let mut pushed: u64 = 0;
        for chunk in outbox.chunks(PUSH_CHUNK) {
            let ops: Vec<Op> = chunk.iter().map(|(_, op)| op.clone()).collect();
            relay.push(scope, &ops)?;
            pushed += chunk.len() as u64;
        }
        let pushed_through = outbox
            .last()
            .map(|(seq, _)| *seq)
            .unwrap_or(cursors.pushed_through);
        drop(outbox);

        // Pull: through the sink, applied under local sequences, cursors
        // moving only over applied pages (ADR 0025).
        let mut sync_session = boot(&store)?;
        let (remote_seen, pulled) = drain_pull(
            &relay,
            scope,
            &mut store,
            &mut sync_session,
            cursors.remote_seen,
        )?;

        cursors.pushed_through = pushed_through;
        cursors.remote_seen = remote_seen;
        file.scopes.insert(key, cursors);
        save_sync_file(home, &file)?;
        receipt
            .scopes
            .push(format!("{label}: pushed {pushed}, pulled {pulled}"));
        stranded_total += stranded;
    }
    if stranded_total > 0 {
        receipt.notes.push(format!(
            "note: {stranded_total} ops were minted by a previous enrollment and can never be pushed \
             (the relay refuses another device's ops); they stay in the local log"
        ));
    }
    Ok(receipt)
}

/// Mint fresh pairing codes for both scopes and render the join command
/// (ADR 0025's `pair`). Requires a first sync (the relay must know the
/// scopes and hold this device's grants).
pub fn pair(home: &Path, session: &Session, identity: &Identity) -> Result<String, SyncError> {
    let file = load_sync_file(home)?;
    for (scope, _) in scopes_of(identity) {
        if !file.scopes.contains_key(&scope_key(scope)) {
            return Err(SyncError::NotSyncedYet);
        }
    }
    let relay = Relay::new(&session.server, &session.token);
    let org_code = relay.mint_pairing_code(ScopeId::Org(identity.org_id))?;
    let budget_code = relay.mint_pairing_code(ScopeId::Budget(identity.budget_id))?;
    Ok(PairingBundle {
        server: session.server.to_owned(),
        org_id: identity.org_id,
        org_code,
        budget_id: identity.budget_id,
        budget_code,
    }
    .render())
}

/// A join request as raw argv strings; parsing and its teaching messages
/// live here (ADR 0025).
pub struct JoinArgs<'a> {
    pub org_id: &'a str,
    pub org_code: &'a str,
    pub budget_id: &'a str,
    pub budget_code: &'a str,
}

/// Join another device's world (ADR 0025): redeem both pairing codes,
/// pull both logs fully, write the joined world's identity, mint the
/// joiner's membership (and, if needed, an account), then sync. The
/// identity file lands alone before any op — a torn join resumes as an
/// ordinary sync, never a second world.
pub fn join(home: &Path, session: &Session, args: &JoinArgs<'_>) -> Result<String, SyncError> {
    if load_identity(home)?.is_some() {
        return Err(SyncError::AlreadyHasWorld);
    }
    let org_id = parse_v7_id(args.org_id, "org id", OrgId::new)?;
    let budget_id = parse_v7_id(args.budget_id, "budget id", BudgetId::new)?;
    let org_scope = ScopeId::Org(org_id);
    let budget_scope = ScopeId::Budget(budget_id);
    let relay = Relay::new(&session.server, &session.token);
    relay.redeem(org_scope, args.org_code)?;
    relay.redeem(budget_scope, args.budget_code)?;

    // Read-then-mint's read half: pull both logs completely first.
    let mut org_store = open_store(&org_log(home, org_id))?;
    let mut org_session = boot(&org_store)?;
    let (org_seen, org_pulled) =
        drain_pull(&relay, org_scope, &mut org_store, &mut org_session, 0)?;
    if !org_alive(org_session.state()) {
        return Err(SyncError::BadBundle(
            "the joined org log does not show a live organization — check the join arguments"
                .into(),
        ));
    }
    let mut budget_store = open_store(&budget_log(home, budget_id))?;
    let mut budget_session = boot(&budget_store)?;
    let (budget_seen, budget_pulled) = drain_pull(
        &relay,
        budget_scope,
        &mut budget_store,
        &mut budget_session,
        0,
    )?;

    // The joiner's slice, minted locally (ADR 0025): a fresh user and
    // membership (Editor — the pairing code is the authorization; roles
    // are data until an enforcement slice, ADR 0021), and the joined
    // budget's earliest live account ADOPTED as the capture default —
    // a Wallet is minted only when none exists.
    let adopted = earliest_live_account(budget_session.state());
    let account_id = match adopted {
        Some((id, _)) => id,
        None => EntityId::new(mint_uuid()).expect("minted v7"),
    };
    let identity = Identity {
        version: 1,
        device_id: session.device_id,
        user_id: UserId::new(mint_uuid()).expect("any version accepted"),
        org_id,
        membership_id: EntityId::new(mint_uuid()).expect("minted v7"),
        budget_id,
        account_id,
    };
    let mut minter = Minter::new(session, &identity);
    minter.absorb(org_session.clock());
    minter.absorb(budget_session.clock());

    let mut account_ops = Vec::new();
    let account_name = match adopted {
        Some((_, name)) => name,
        None => {
            let anchor = anchored_at(identity.account_id);
            account_ops.push(minter.op_at(
                anchor,
                budget_scope,
                pursecraft_core::domain::EntityKind::Account,
                identity.account_id,
                Field::Account(AccountField::Name),
                pursecraft_core::domain::Value::Text(ACCOUNT_NAME.to_owned()),
            ));
            account_ops.push(minter.op_at(
                anchor,
                budget_scope,
                pursecraft_core::domain::EntityKind::Account,
                identity.account_id,
                Field::Account(AccountField::Kind),
                pursecraft_core::domain::Value::AccountKind(AccountKind::Cash),
            ));
            ACCOUNT_NAME.to_owned()
        }
    };

    // Root first (ADR 0023): the identity publishes alone, before any op.
    create_identity(home, &identity)?;

    let member_anchor = anchored_at(identity.membership_id);
    let membership_ops = [
        (
            Field::Membership(MembershipField::UserId),
            pursecraft_core::domain::Value::User(identity.user_id),
        ),
        (
            Field::Membership(MembershipField::Role),
            pursecraft_core::domain::Value::Role(MembershipRole::Editor),
        ),
    ];
    for (field, value) in membership_ops {
        sink::sink(
            &mut org_store,
            minter.op_at(
                member_anchor,
                org_scope,
                pursecraft_core::domain::EntityKind::Membership,
                identity.membership_id,
                field,
                value,
            ),
        )?;
    }
    for op in account_ops {
        sink::sink(&mut budget_store, op)?;
    }

    // Record the pulls' cursors, then sync — the ordinary path pushes the
    // joiner's ops (the identity is already the root, so a torn join
    // resumes as a plain sync, never a re-join).
    let mut file = SyncFile {
        version: SYNC_VERSION,
        scopes: BTreeMap::new(),
    };
    file.scopes.insert(
        scope_key(org_scope),
        ScopeCursors {
            pushed_through: 0,
            remote_seen: org_seen,
        },
    );
    file.scopes.insert(
        scope_key(budget_scope),
        ScopeCursors {
            pushed_through: 0,
            remote_seen: budget_seen,
        },
    );
    save_sync_file(home, &file)?;

    let receipt = sync(home, session, &identity)?;
    Ok(format!(
        "joined org {} budget {} (pulled {} + {} ops, default account {account_name})\n{}",
        org_id.as_uuid(),
        budget_id.as_uuid(),
        org_pulled,
        budget_pulled,
        receipt.render()
    ))
}

/// The pending-sync count (ADR 0011's visible badge): this session's
/// unpushed ops across both scopes. Derived, never stored (ADR 0025).
pub fn pending_count(
    home: &Path,
    session: &Session,
    identity: &Identity,
) -> Result<u64, SyncError> {
    let file = load_sync_file(home)?;
    let mut count: u64 = 0;
    for (scope, _) in scopes_of(identity) {
        let path = scope_log_path(home, identity, scope);
        if !path.exists() {
            continue;
        }
        let store = LocalStore::open(&path)?;
        let pushed_through = file
            .scopes
            .get(&scope_key(scope))
            .map(|c| c.pushed_through)
            .unwrap_or(0);
        count += store
            .delta_since(pushed_through)
            .filter(|s| s.op.device_id == session.device_id)
            .count() as u64;
    }
    Ok(count)
}

/// Pull pages until caught up (ADR 0025). Each page is **validated
/// against the engine before anything is persisted** — a hostile or
/// damaged op aborts the scope's sync loudly with the cursor unmoved and
/// the local store untouched (local function survives hostile bytes;
/// re-pull re-serves the same page and the same refusal, ADR 0017).
/// Ops that pass are sunk (the single append path, deduping echoes of
/// this device's own pushes). Sequences here are the RELAY's — the
/// session watermark they move is deliberately unread (the store-booted
/// watermark counts local sequences; `sync.json` owns both cursors).
fn drain_pull(
    relay: &Relay<'_>,
    scope: ScopeId,
    store: &mut LocalStore,
    sync_session: &mut SyncSession,
    since: u64,
) -> Result<(u64, u64), SyncError> {
    let mut remote_seen = since;
    let mut pulled: u64 = 0;
    loop {
        let page = relay.pull(scope, remote_seen, PULL_PAGE)?;
        if page.ops.is_empty() {
            if page.has_more {
                return Err(RelayError::BadAnswer(
                    "an empty page claimed has_more (the relay never emits that shape)".into(),
                )
                .into());
            }
            return Ok((remote_seen, pulled));
        }
        let batch: Vec<SequencedOp> = page
            .ops
            .iter()
            .map(|wire| {
                let payload =
                    decode_payload(&wire.payload).map_err(|source| SyncError::Decode {
                        scope: scope_key(scope),
                        seq: wire.seq,
                        source,
                    })?;
                Ok(SequencedOp {
                    seq: wire.seq,
                    op: Op::from_parts(wire.meta.clone(), payload),
                })
            })
            .collect::<Result<Vec<_>, SyncError>>()?;
        let summary = sync_session.apply_delta(&batch)?;
        for sequenced in &batch {
            sink::sink(store, sequenced.op.clone())?;
        }
        remote_seen = page.ops.last().expect("nonempty page").seq;
        // New-to-here ops only (applied + stale): echoes of this device's
        // own pushes are duplicates and must not pad the count.
        pulled += summary.applied + summary.stale;
        if !page.has_more {
            return Ok((remote_seen, pulled));
        }
    }
}

/// The identity's two scopes: the org log and the budget log (ADR 0021).
fn scopes_of(identity: &Identity) -> [(ScopeId, &'static str); 2] {
    [
        (ScopeId::Org(identity.org_id), "org"),
        (ScopeId::Budget(identity.budget_id), "budget"),
    ]
}

/// The compact, readable scope key used in `sync.json` (client-local
/// shape; the ids' hyphenated form).
fn scope_key(scope: ScopeId) -> String {
    match scope {
        ScopeId::Org(id) => format!("org:{}", id.as_uuid()),
        ScopeId::Budget(id) => format!("budget:{}", id.as_uuid()),
    }
}

fn scope_log_path(home: &Path, identity: &Identity, scope: ScopeId) -> std::path::PathBuf {
    match scope {
        ScopeId::Org(_) => org_log(home, identity.org_id),
        ScopeId::Budget(_) => budget_log(home, identity.budget_id),
    }
}

/// Open (creating dirs and file as needed) a scope's local store.
fn open_store(path: &std::path::Path) -> Result<LocalStore, SyncError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(LocalStore::open(path)?)
}

/// The earliest live account in a budget state (ADR 0016's deterministic
/// earliest-created convention) — the joiner's default.
fn earliest_live_account(state: &pursecraft_core::ops::ScopeState) -> Option<(EntityId, String)> {
    crate::capture::live_accounts(state).into_iter().min()
}

/// Parse one join-bundle scope id with a teaching failure — the ids come
/// from `pursecraft pair`'s printed bundle and are UUIDv7.
fn parse_v7_id<T>(
    raw: &str,
    what: &str,
    mk: impl Fn(uuid::Uuid) -> Result<T, pursecraft_core::ids::IdVersionError>,
) -> Result<T, SyncError> {
    let uuid = uuid::Uuid::parse_str(raw.trim())
        .map_err(|e| SyncError::BadBundle(format!("the {what} {raw:?} is not a uuid: {e}")))?;
    mk(uuid).map_err(|_| {
        SyncError::BadBundle(format!(
            "the {what} {raw:?} is not a v7 id from pursecraft pair"
        ))
    })
}

// ---------------------------------------------------------------------
// sync.json (ADR 0025): per-scope cursors, client state — not log data.
// ---------------------------------------------------------------------

/// One scope's sync cursors (ADR 0025).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ScopeCursors {
    /// Local-store space: every op of the session's device at or below it
    /// is pushed (the outbox is everything of the device beyond it).
    pub pushed_through: u64,
    /// Relay space: the pull cursor — every relay sequence at or below it
    /// is applied locally.
    pub remote_seen: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncFile {
    version: u16,
    scopes: BTreeMap<String, ScopeCursors>,
}

impl Default for SyncFile {
    fn default() -> Self {
        Self {
            version: SYNC_VERSION,
            scopes: BTreeMap::new(),
        }
    }
}

/// Load the sync state (absent file = never synced; corrupt or
/// future-version files are loud, never reset).
fn load_sync_file(home: &Path) -> Result<SyncFile, SyncError> {
    let path = home.join(SYNC_FILE);
    if !path.try_exists()? {
        return Ok(SyncFile::default());
    }
    let bytes = std::fs::read(&path)?;
    let file: SyncFile = serde_json::from_slice(&bytes).map_err(|source| SyncError::BadState {
        path: path.clone(),
        detail: format!("does not decode: {source}"),
    })?;
    if file.version != SYNC_VERSION {
        return Err(SyncError::BadState {
            path,
            detail: format!(
                "version {} is not this pursecraft's {SYNC_VERSION}",
                file.version
            ),
        });
    }
    Ok(file)
}

/// Persist the sync state atomically (the identity discipline, ADR 0023).
fn save_sync_file(home: &Path, file: &SyncFile) -> Result<(), SyncError> {
    let path = home.join(SYNC_FILE);
    let tmp = home.join(format!("{SYNC_FILE}.{}.tmp", std::process::id()));
    {
        use std::io::Write;
        let mut out = std::fs::File::create(&tmp)?;
        out.write_all(
            &serde_json::to_vec_pretty(file)
                .map_err(|e| SyncError::Io(std::io::Error::other(e)))?,
        )?;
        out.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(home) {
        let _ = dir.sync_all();
    }
    Ok(())
}
