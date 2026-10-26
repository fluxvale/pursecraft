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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use pursecraft_core::domain::{AccountField, AccountKind, Field, MembershipField, MembershipRole};
use pursecraft_core::ids::{BudgetId, DeviceId, EntityId, OrgId, ScopeId, UserId};
use pursecraft_core::ops::{ApplyError, Op};
use pursecraft_core::org::org_alive;
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::{SequencedOp, SyncSession};
use pursecraft_core::wire::{PayloadCipher, decode_payload};

use crate::capture::{ACCOUNT_NAME, Minter, anchored_at, boot};
use crate::home::{Identity, IdentityError, create_identity, load_identity};
use crate::idmint::mint_uuid;
use crate::keys::{KeysError, World};
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
    Keys(KeysError),
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
    /// A pulled payload could not be opened — missing or stale key material,
    /// or bytes the cipher refused (ADR 0028). Distinct from [`Self::Decode`]:
    /// a key problem is not damage, and the two teach different fixes.
    Cipher {
        scope: String,
        seq: u64,
        detail: String,
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
    /// Key records that would not install — the rotation race or poison
    /// (ADR 0028). The data sync still ran; this is the loud report.
    KeyConflict {
        detail: String,
    },
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relay(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Keys(e) => write!(f, "{e}"),
            Self::Session(e) => write!(f, "{e}"),
            Self::Apply(e) => write!(f, "a pulled op was rejected by the engine: {e}"),
            Self::Decode { scope, seq, source } => write!(
                f,
                "a pulled op ({scope} seq {seq}) does not decode: {source} — nothing was applied past it"
            ),
            Self::Cipher { scope, seq, detail } => write!(
                f,
                "a pulled op ({scope} seq {seq}) does not open: {detail} — nothing was applied past it"
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
            Self::KeyConflict { detail } => write!(
                f,
                "key records did not install: {detail} — this device's keys disagree with the \
                 relay's; a rotation may have raced, and the data sync still ran"
            ),
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

impl From<KeysError> for SyncError {
    fn from(e: KeysError) -> Self {
        Self::Keys(e)
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
    /// This run finished an interrupted join (ADR 0028).
    resumed_join: bool,
}

impl SyncReceipt {
    fn new(server: &str) -> Self {
        Self {
            server: server.to_owned(),
            scopes: Vec::new(),
            notes: Vec::new(),
            created: None,
            resumed_join: false,
        }
    }

    /// A join still waiting for its keys (ADR 0028): one teaching line, and
    /// the marker keeps the home resumable.
    fn waiting_for_keys(server: &str, org: OrgId) -> Self {
        let mut receipt = Self::new(server);
        receipt.notes.push(format!(
            "this device is registered with org {} — the world's keys are not here yet\n\
             \nnext:\n  \
             pursecraft sync        # on a device that already holds this world\n  \
             pursecraft sync        # here, to install the keys and finish joining\n",
            org.as_uuid()
        ));
        receipt.resumed_join = true;
        receipt
    }

    /// A resumed join's outcome, rendered verbatim (ADR 0028).
    fn joined(text: String) -> Self {
        let mut receipt = Self::new("");
        receipt.scopes.clear();
        receipt.notes.push(text);
        receipt.resumed_join = true;
        receipt
    }

    /// The command's stdout (ADR 0025's quiet-by-default shape).
    pub fn render(&self) -> String {
        if self.resumed_join {
            return self.notes.join("");
        }
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
pub fn sync(
    world: &mut World,
    session: &Session,
    identity: &Identity,
) -> Result<SyncReceipt, SyncError> {
    let home = world.home.clone();
    let home = home.as_path();
    let relay = Relay::new(&session.server, &session.token);
    let mut file = load_sync_file(home)?;
    let mut receipt = SyncReceipt::new(&session.server);
    let mut stranded_total: u64 = 0;
    let mut key_conflict: Option<String> = None;
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

        // The key channel runs once the org's grant exists and before its log
        // is opened (ADR 0028): a device that arrives with no keys yet must
        // install them before its store can be read at all. Its conflicts are
        // held until the data sync finishes — a planted record must never
        // stop captures from reaching the relay.
        if matches!(scope, ScopeId::Org(_))
            && world.is_sealed()
            && let Some(conflict) = sync_keys(world, &relay, session, identity, &mut receipt)?
        {
            key_conflict = Some(conflict);
        }

        let mut store = world.open_log(scope)?;

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
            // Seal for the wire (ADR 0028): a fresh envelope, so the relay
            // never sees the plaintext and `op_id`-only dedupe still holds
            // (ADR 0017). In the self-host mode this is the identity.
            relay.push(scope, &ops, &world.cipher()?)?;
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
            &world.cipher()?,
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
    if let Some(detail) = key_conflict {
        return Err(SyncError::KeyConflict { detail });
    }
    Ok(receipt)
}

/// Whether a join is unfinished (ADR 0028) — the one case `sync` may run
/// without an identity.
pub fn has_pending_join(home: &Path) -> Result<bool, SyncError> {
    Ok(load_join(home)?.is_some())
}

/// Finish an interrupted join (ADR 0028): the keys have landed, so the world
/// can be read, the identity written, and the joiner's slice minted. The
/// key channel runs first — it is what brings the keys.
pub fn resume_join(world: &mut World, session: &Session) -> Result<SyncReceipt, SyncError> {
    let Some(mark) = load_join(&world.home)? else {
        return Err(SyncError::NotBootstrapped);
    };
    if world.is_sealed() {
        // A crash between the marker and the device key leaves a keyring with
        // no key: complete it here. `join` is idempotent (ADR 0028), and this
        // is the only command the gate lets a keyless joiner run.
        world.join()?;
        let relay = Relay::new(&session.server, &session.token);
        let outcome = publish_and_install(world, &relay, session, mark.org_id)?;
        let mut receipt = if world.holds_log_key(ScopeId::Org(mark.org_id)) {
            let joined = complete_join(world, session, mark.org_id, mark.budget_id)?;
            SyncReceipt::joined(joined)
        } else {
            // Still keyless: nothing to finish with, and the marker keeps the
            // home resumable.
            SyncReceipt::waiting_for_keys(&session.server, mark.org_id)
        };
        return match outcome.finish(&mut receipt) {
            Some(detail) => Err(SyncError::KeyConflict { detail }),
            None => Ok(receipt),
        };
    }
    let joined = complete_join(world, session, mark.org_id, mark.budget_id)?;
    Ok(SyncReceipt::joined(joined))
}

/// Publish this device's public key and install every record addressed to it
/// (ADR 0028). The key channel's pull half, shared by `join`, `sync`, and a
/// resumed join.
///
/// A failing **install** is collected, not fatal: the relay's record set is
/// append-only and readable by every granted device, so one member's poisoned
/// record must not become a permanent org-wide sync kill. The records that
/// open are installed, the data sync runs, and the failures surface loudly at
/// the end (a non-zero exit naming them) — visible, but never a wedge a
/// hostile member can plant.
fn publish_and_install(
    world: &World,
    relay: &Relay<'_>,
    session: &Session,
    org: OrgId,
) -> Result<InstallOutcome, SyncError> {
    if let Some(record) = world.device_record(session.device_id) {
        relay.publish_keys(org, &[record])?;
    }
    let pulled = relay.pull_keys(org)?;
    // Org wraps first, then log wraps: a log key is wrapped under its org's
    // same-epoch epoch key (ADR 0022), so the relay's record order — which is
    // push order, not dependency order — cannot be trusted for installs.
    let mut installed = 0usize;
    let mut conflicts = Vec::new();
    for org_pass in [true, false] {
        for wire in &pulled {
            let is_org_wrap = matches!(
                pursecraft_crypto::KeyRecord::parse(&wire.record).ok(),
                Some(pursecraft_crypto::KeyRecord::Org { .. })
            );
            if is_org_wrap != org_pass {
                continue;
            }
            match world.install(&wire.record, org) {
                Ok(true) => installed += 1,
                Ok(false) => {}
                Err(e) => conflicts.push(format!("{e} (record from {})", wire.pushed_by)),
            }
        }
    }
    Ok(InstallOutcome {
        installed,
        pulled,
        conflicts,
    })
}

/// What one key-channel pull produced (ADR 0028).
struct InstallOutcome {
    installed: usize,
    pulled: Vec<crate::relay::KeyRecordWire>,
    /// Records that would not install — a slot conflict above all, which is
    /// the rotation race ADR 0022 refuses to resolve silently. Reported, never
    /// swallowed, and never fatal to the data sync.
    conflicts: Vec<String>,
}

impl InstallOutcome {
    /// Note what landed on the receipt and hand back the conflicts, if any.
    /// The caller reports them after the data sync — loud, never a silent
    /// swallow, and never a wedge a hostile member can plant.
    fn finish(self, receipt: &mut SyncReceipt) -> Option<String> {
        if self.installed > 0 {
            receipt
                .notes
                .push(format!("installed {} key records\n", self.installed));
        }
        (!self.conflicts.is_empty()).then(|| self.conflicts.join("; "))
    }
}

/// One pass over the org's key records (ADR 0028): publish this device's own
/// record and any wrap it holds that the relay lacks; install every record
/// addressed to this device; and wrap the org's epoch keys to any device
/// registered in the org's records that this device has not wrapped for yet.
/// Runs before any log is opened — a keyless device's store cannot be read
/// until its wraps land.
fn sync_keys(
    world: &World,
    relay: &Relay<'_>,
    session: &Session,
    identity: &Identity,
    receipt: &mut SyncReceipt,
) -> Result<Option<String>, SyncError> {
    let org = identity.org_id;
    // A device that holds no keys yet (a fresh joiner) still registers its
    // public key and takes whatever it is addressed; a key-holding device
    // does everything.
    let outcome = publish_and_install(world, relay, session, org)?;
    let published: BTreeSet<String> = outcome
        .pulled
        .iter()
        .map(|wire| wire.record.clone())
        .collect();

    // Each registered device's public key. A `device` record is only trusted
    // when the relay's authenticated stamp matches its claimed id (ADR 0028):
    // a member cannot register a key for someone else.
    let mut known: Vec<(DeviceId, pursecraft_crypto::DevicePublicKey)> = Vec::new();
    for wire in &outcome.pulled {
        // An unparseable record is a granted member's planted bytes, not a
        // reason to stop syncing: skip it here (the install pass already
        // collected it as a conflict) rather than wedge the data path.
        let Ok(record) = pursecraft_crypto::KeyRecord::parse(&wire.record) else {
            continue;
        };
        if let pursecraft_crypto::KeyRecord::Device { device, public } = record
            && device == wire.pushed_by
        {
            known.push((device, public));
        }
    }
    let mut owed = Vec::new();
    for (device, public) in known {
        if device == session.device_id {
            continue;
        }
        // Coverage is this device's own keyring (ADR 0028), so a peer is
        // wrapped once per epoch, however many syncs follow.
        owed.extend(world.wraps_for(org, device, public)?);
    }
    // Our own held records the relay does not serve yet (the founder's org
    // wrap and log wraps, or a rotation's output).
    owed.extend(world.unpublished(&published));
    if !owed.is_empty() {
        relay.publish_keys(org, &owed)?;
    }
    Ok(outcome.finish(receipt))
}

/// Mint fresh pairing codes for both scopes and render the join command
/// (ADR 0025's `pair`). Requires a first sync (the relay must know the
/// scopes and hold this device's grants).
pub fn pair(world: &World, session: &Session, identity: &Identity) -> Result<String, SyncError> {
    let home = world.home.as_path();
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
pub fn join(
    world: &mut World,
    session: &Session,
    args: &JoinArgs<'_>,
) -> Result<String, SyncError> {
    let home = world.home.clone();
    let home = home.as_path();
    if load_identity(home)?.is_some() {
        return Err(SyncError::AlreadyHasWorld);
    }
    let org_id = parse_v7_id(args.org_id, "org id", OrgId::new)?;
    let budget_id = parse_v7_id(args.budget_id, "budget id", BudgetId::new)?;
    let relay = Relay::new(&session.server, &session.token);
    let pending = load_join(home)?;

    // A resumed join does not redeem again: the codes are single-use and were
    // burned by the attempt that left the marker (ADR 0025's single-use
    // contract; the relay already granted this device).
    if pending.is_none() {
        relay.redeem(ScopeId::Org(org_id), args.org_code)?;
        relay.redeem(ScopeId::Budget(budget_id), args.budget_code)?;
        save_join(home, JoinMark { org_id, budget_id })?;
    } else if pending != Some(JoinMark { org_id, budget_id }) {
        return Err(SyncError::BadBundle(
            "this home has an unfinished join for a different world — finish it first".into(),
        ));
    }

    // The joiner's own key material (ADR 0028): a device key and an empty
    // joining keyring. It mints nothing; it publishes its public key so a
    // key-holding device can wrap the world's keys to it.
    world.join()?;
    let mut conflicts = Vec::new();
    if world.is_sealed() {
        if let Some(record) = world.device_record(session.device_id) {
            relay.publish_keys(org_id, &[record])?;
        }
        // Org wraps first, then log wraps (ADR 0022's hierarchy); a record
        // that will not install is reported after the join, never a wedge.
        let pulled = relay.pull_keys(org_id)?;
        for org_pass in [true, false] {
            for wire in &pulled {
                let is_org_wrap = matches!(
                    pursecraft_crypto::KeyRecord::parse(&wire.record).ok(),
                    Some(pursecraft_crypto::KeyRecord::Org { .. })
                );
                if is_org_wrap != org_pass {
                    continue;
                }
                match world.install(&wire.record, org_id) {
                    Ok(_) => {}
                    Err(e) => conflicts.push(e.to_string()),
                }
            }
        }
    }
    if world.is_sealed() && !world.holds_log_key(ScopeId::Org(org_id)) {
        // Keyless: the join is granted and registered, and the marker makes it
        // resumable. Nothing is written into the world yet — an identity whose
        // account could not be adopted from the log would be a dead root
        // (ADR 0025). The remaining steps run on the next `sync`.
        return Ok(format!(
            "registered this device with org {} — the world's keys are not here yet\n\
             \nnext:\n  \
             pursecraft sync        # on a device that already holds this world\n  \
             pursecraft sync        # here, to install the keys and finish joining\n",
            org_id.as_uuid()
        ));
    }
    if world.is_sealed() && !world.holds_log_key(ScopeId::Org(org_id)) {
        // Keyless: the join is granted and registered, and the marker makes it
        // resumable (ADR 0028). Conflicts still report.
        return match conflicts.is_empty() {
            true => Ok(format!(
                "registered this device with org {} — the world's keys are not here yet\n\
                 \nnext:\n  \
                 pursecraft sync        # on a device that already holds this world\n  \
                 pursecraft sync        # here, to install the keys and finish joining\n",
                org_id.as_uuid()
            )),
            false => Err(SyncError::KeyConflict {
                detail: conflicts.join("; "),
            }),
        };
    }
    let joined = complete_join(world, session, org_id, budget_id)?;
    if conflicts.is_empty() {
        return Ok(joined);
    }
    Err(SyncError::KeyConflict {
        detail: conflicts.join("; "),
    })
}

/// The resumable half of a join (ADR 0025's torn-join rule, extended by ADR
/// 0028 to a keyless joiner): pull both logs, write the identity root, mint
/// the joiner's membership and account, then sync. Safe to re-run — the
/// identity is written once and the ops are read-then-mint.
fn complete_join(
    world: &mut World,
    session: &Session,
    org_id: OrgId,
    budget_id: BudgetId,
) -> Result<String, SyncError> {
    let home = world.home.clone();
    let home = home.as_path();
    let relay = Relay::new(&session.server, &session.token);
    let org_scope = ScopeId::Org(org_id);
    let budget_scope = ScopeId::Budget(budget_id);
    let cipher = world.cipher()?;

    // Read-then-mint's read half: pull both logs.
    let mut org_store = world.open_log(org_scope)?;
    let mut org_session = boot(&org_store)?;
    let (org_seen, org_pulled) = drain_pull(
        &relay,
        org_scope,
        &mut org_store,
        &mut org_session,
        0,
        &cipher,
    )?;
    if !org_alive(org_session.state()) {
        return Err(SyncError::BadBundle(
            "the joined org log does not show a live organization — check the join arguments"
                .into(),
        ));
    }
    let mut budget_store = world.open_log(budget_scope)?;
    let mut budget_session = boot(&budget_store)?;
    let (budget_seen, budget_pulled) = drain_pull(
        &relay,
        budget_scope,
        &mut budget_store,
        &mut budget_session,
        0,
        &cipher,
    )?;

    // The joiner's slice, minted locally (ADR 0025): a fresh user and
    // membership (Editor — the pairing code is the authorization; roles are
    // data until an enforcement slice, ADR 0021), and the joined budget's
    // earliest live account ADOPTED as the capture default — a Wallet is
    // minted only when none exists.
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
    // joiner's ops (the identity is already the root, so a torn join resumes
    // as a plain sync, never a re-join).
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
    clear_join(home)?;

    let receipt = sync(world, session, &identity)?;
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
    world: &World,
    session: &Session,
    identity: &Identity,
) -> Result<u64, SyncError> {
    let home = world.home.as_path();
    let file = load_sync_file(home)?;
    let mut count: u64 = 0;
    for (scope, _) in scopes_of(identity) {
        if !crate::home::scope_log(home, scope).exists() {
            continue;
        }
        let store = world.open_log(scope)?;
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
fn drain_pull<C: PayloadCipher>(
    relay: &Relay<'_>,
    scope: ScopeId,
    store: &mut LocalStore<C>,
    sync_session: &mut SyncSession,
    since: u64,
    cipher: &C,
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
                // Open the envelope first (ADR 0028): a key problem is a
                // distinct teaching failure, never a decode error that
                // would read as damaged bytes.
                let plaintext =
                    cipher
                        .open(&wire.meta, &wire.payload)
                        .map_err(|source| SyncError::Cipher {
                            scope: scope_key(scope),
                            seq: wire.seq,
                            detail: source.to_string(),
                        })?;
                let payload = decode_payload(&plaintext).map_err(|source| SyncError::Decode {
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

/// The earliest live account in a budget state (ADR 0016's deterministic
/// earliest-created convention) — the joiner's default.
fn earliest_live_account(state: &pursecraft_core::ops::ScopeState) -> Option<(EntityId, String)> {
    crate::capture::live_accounts(state).first().cloned()
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

/// The unfinished-join marker (ADR 0028): a join whose data step has not run
/// yet. It exists so a keyless joiner can resume, and so a resumed join never
/// redeems a single-use pairing code twice (ADR 0025).
const JOIN_FILE: &str = "join.json";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct JoinMark {
    org_id: OrgId,
    budget_id: BudgetId,
}

fn load_join(home: &Path) -> Result<Option<JoinMark>, SyncError> {
    let path = home.join(JOIN_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| SyncError::BadState {
            path,
            detail: format!("does not decode: {e}"),
        })
}

fn save_join(home: &Path, mark: JoinMark) -> Result<(), SyncError> {
    use std::io::Write;
    let path = home.join(JOIN_FILE);
    let tmp = home.join(format!("{JOIN_FILE}.{}.tmp", std::process::id()));
    {
        let mut out = std::fs::File::create(&tmp)?;
        out.write_all(
            &serde_json::to_vec(&mark).map_err(|e| SyncError::Io(std::io::Error::other(e)))?,
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

fn clear_join(home: &Path) -> Result<(), SyncError> {
    match std::fs::remove_file(home.join(JOIN_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
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
