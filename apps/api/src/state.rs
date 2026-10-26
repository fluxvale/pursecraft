//! The relay's server state (ADR 0024): the auth database plus one
//! lazily-opened [`OpaqueStore`] per scope.
//!
//! One process per data directory is the contract (ADR 0024): the stores
//! are single-writer files and fail loudly otherwise (ADR 0018). All
//! handlers run under short `std` mutex holds — append commits fsync, but
//! a household relay's contention is nil.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pursecraft_core::ids::ScopeId;
use pursecraft_core::store::{OpaqueStore, StoreError};

use crate::auth::AuthDb;

/// How long one readiness probe result stays fresh (ADR 0026): the
/// probe is an honest durable write, so the route must not let a client
/// command unbounded fsyncs. One probe per second bounds abuse while
/// staying far inside the fleet's 5s probe cadence — a failing store is
/// still reported within a single probe period.
pub const READINESS_PROBE_TTL: Duration = Duration::from_secs(1);

/// The relay's whole state: the auth database and the open scope logs.
#[derive(Debug)]
pub struct AppState {
    data_dir: PathBuf,
    pub auth: Mutex<AuthDb>,
    logs: Mutex<HashMap<ScopeId, Arc<Mutex<OpaqueStore>>>>,
    /// The last readiness outcome and when it was taken (ADR 0026) —
    /// `None`/`Some(err)` per outcome; the TTL bounds fsync cost.
    readiness_cache: Mutex<Option<(Instant, Option<String>)>>,
}

/// A state failure — anything but an auth refusal: damaged stores fail
/// loudly rather than serving from partial data (ADRs 0018, 0024).
#[derive(Debug)]
pub enum StateError {
    Store(StoreError),
    Setup(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "scope log failure: {e}"),
            Self::Setup(e) => write!(f, "server state failure: {e}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<StoreError> for StateError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl AppState {
    /// Open a data directory (creating its layout): `auth.json`,
    /// `enrollment.secret`, and `logs/`.
    pub fn open(data_dir: &Path) -> Result<Self, StateError> {
        std::fs::create_dir_all(data_dir.join("logs"))
            .map_err(|e| StateError::Setup(format!("cannot create {}: {e}", data_dir.display())))?;
        let auth = AuthDb::open(data_dir)
            .map_err(|e| StateError::Setup(format!("cannot open the auth database: {e}")))?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            auth: Mutex::new(auth),
            logs: Mutex::new(HashMap::new()),
            readiness_cache: Mutex::new(None),
        })
    }

    fn log_path(&self, scope: ScopeId) -> PathBuf {
        let name = match scope {
            ScopeId::Org(id) => format!("org-{}", id.as_uuid().simple()),
            ScopeId::Budget(id) => format!("budget-{}", id.as_uuid().simple()),
        };
        self.data_dir.join("logs").join(format!("{name}.pcoplog"))
    }

    /// Whether the scope's log file exists (a push creates it lazily).
    pub fn log_exists(&self, scope: ScopeId) -> bool {
        self.log_path(scope).exists()
    }

    /// The scope's store, opening (and, with `create`, first creating) it
    /// on demand. Damaged files fail loudly (ADR 0018).
    pub fn scope_log(
        &self,
        scope: ScopeId,
        create: bool,
    ) -> Result<Option<Arc<Mutex<OpaqueStore>>>, StateError> {
        let mut logs = self.logs.lock().expect("scope log map lock");
        if let Some(store) = logs.get(&scope) {
            return Ok(Some(Arc::clone(store)));
        }
        let path = self.log_path(scope);
        if !create && !path.exists() {
            return Ok(None);
        }
        let store = Arc::new(Mutex::new(OpaqueStore::open(&path)?));
        logs.insert(scope, Arc::clone(&store));
        Ok(Some(store))
    }

    /// Whether the relay can durably persist right now (ADR 0026): a
    /// write-then-fsync probe into each on-disk home — the data directory
    /// (the auth db) and `logs/` (the scope logs) — a directory-level
    /// canary: it fails exactly when no write to those directories could
    /// succeed; per-file damage inside a writable directory stays loud
    /// at request time (ADR 0024). This is readiness, not liveness: a
    /// failing probe means the pod leaves rotation, never restarts — a
    /// read-only volume cannot be restarted into health. Results are
    /// cached for [`READINESS_PROBE_TTL`] so the route cannot be used as
    /// an fsync firehose.
    pub fn readiness(&self) -> std::io::Result<()> {
        let mut cached = self.readiness_cache.lock().expect("readiness cache lock");
        if let Some((at, outcome)) = cached.as_ref()
            && at.elapsed() < READINESS_PROBE_TTL
        {
            return probe_outcome(outcome.clone());
        }
        let outcome = probe_readiness(&self.data_dir);
        *cached = Some((Instant::now(), outcome.clone()));
        probe_outcome(outcome)
    }
}

/// Run both probe writes; the first failure wins, as a real write would.
fn probe_readiness(data_dir: &Path) -> Option<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the epoch")
        .as_nanos()
        .to_string();
    if let Err(e) = probe_dir(data_dir, &stamp) {
        return Some(e.to_string());
    }
    probe_dir(&data_dir.join("logs"), &stamp)
        .err()
        .map(|e| e.to_string())
}

/// A cached outcome back into a Result — `None` is health.
fn probe_outcome(outcome: Option<String>) -> std::io::Result<()> {
    match outcome {
        None => Ok(()),
        Some(err) => Err(std::io::Error::other(err)),
    }
}

/// One honest write into `dir`: create, write, fsync — the same media and
/// the same durability the relay's real writes need, so the probe fails
/// exactly when serving would (ADR 0026).
fn probe_dir(dir: &Path, stamp: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(dir.join("health.probe"))?;
    file.write_all(stamp.as_bytes())?;
    file.sync_all()
}
