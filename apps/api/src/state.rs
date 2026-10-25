//! The relay's server state (ADR 0024): the auth database plus one
//! lazily-opened [`OpaqueStore`] per scope.
//!
//! One process per data directory is the contract (ADR 0024): the stores
//! are single-writer files and fail loudly otherwise (ADR 0018). All
//! handlers run under short `std` mutex holds — append commits fsync, but
//! a household relay's contention is nil.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pursecraft_core::ids::ScopeId;
use pursecraft_core::store::{OpaqueStore, StoreError};

use crate::auth::AuthDb;

/// The relay's whole state: the auth database and the open scope logs.
#[derive(Debug)]
pub struct AppState {
    data_dir: PathBuf,
    pub auth: Mutex<AuthDb>,
    logs: Mutex<HashMap<ScopeId, Arc<Mutex<OpaqueStore>>>>,
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
}
