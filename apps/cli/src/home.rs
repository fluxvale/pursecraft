//! Data-home resolution and the identity file (ADR 0023): where the local
//! stores live, and the persisted ids that make bootstrap retries idempotent
//! (a retry reuses entity ids, never mints twins).

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pursecraft_core::ids::{BudgetId, DeviceId, EntityId, OrgId, UserId};
use serde::{Deserialize, Serialize};

use crate::idmint::mint_uuid;

/// The identity file name under the data home.
const IDENTITY_FILE: &str = "identity.json";
/// The org-log directory under the data home.
const ORG_DIR: &str = "orgs";
/// The budget-log directory under the data home.
const BUDGET_DIR: &str = "budgets";
/// The identity file version this CLI writes and reads.
const IDENTITY_VERSION: u16 = 1;

/// The persisted ids of the bootstrapped world (ADR 0023): the device and
/// user (auth is a later slice; both are locally minted opaque UUIDs), and
/// the org, membership, budget, and account bootstrap minted. This file is
/// the root: deleting it orphans the stores.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub version: u16,
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub org_id: OrgId,
    pub membership_id: EntityId,
    pub budget_id: BudgetId,
    pub account_id: EntityId,
}

/// An identity-file failure — corrupt or future-version files are refused
/// loudly, never overwritten (ADR 0023).
#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    /// The file does not decode as an identity.
    Decode {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The (practically unreachable) failure to encode a minted identity.
    Encode(serde_json::Error),
    /// The file's version is not this CLI's.
    Unsupported {
        path: PathBuf,
        found: u16,
    },
    /// A concurrent creator published a different identity and ours lost
    /// the rename race; retry the command (ADR 0023 — the loser must not
    /// mint ops into a world whose root it does not hold).
    Raced {
        path: PathBuf,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "identity io error: {e}"),
            Self::Decode { path, source } => {
                write!(f, "{path:?} is not a readable identity file: {source}")
            }
            Self::Encode(e) => write!(f, "a minted identity does not encode: {e}"),
            Self::Unsupported { path, found } => write!(
                f,
                "{path:?} has identity version {found}, this pursecraft supports {IDENTITY_VERSION}"
            ),
            Self::Raced { path } => write!(
                f,
                "{path:?} was created concurrently by another pursecraft; rerun the command"
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// No data home could be resolved: neither `PURSECRAFT_HOME`, nor
/// `XDG_DATA_HOME`, nor `HOME` is set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NoHomeError;

impl fmt::Display for NoHomeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no data home: set PURSECRAFT_HOME, XDG_DATA_HOME, or HOME")
    }
}

impl std::error::Error for NoHomeError {}

/// Resolve the data home from explicit overrides (ADR 0023): the pure core
/// of [`data_home`] so resolution is testable without touching the process
/// environment. `env` wins outright; then XDG + `pursecraft` (a relative
/// XDG value is ignored, per the XDG spec); then the user home + the
/// platform suffix.
pub fn resolve_home(
    env: Option<&str>,
    xdg: Option<&str>,
    user: Option<&str>,
) -> Result<PathBuf, NoHomeError> {
    if let Some(env) = env.filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(env));
    }
    if let Some(xdg) = xdg
        .filter(|s| !s.is_empty())
        .filter(|s| Path::new(s).is_absolute())
    {
        return Ok(PathBuf::from(xdg).join("pursecraft"));
    }
    match user.filter(|s| !s.is_empty()) {
        Some(user) => Ok(PathBuf::from(user).join(home_suffix())),
        None => Err(NoHomeError),
    }
}

/// The per-user data suffix under the home directory.
#[cfg(unix)]
fn home_suffix() -> &'static str {
    ".local/share/pursecraft"
}

/// The per-user data suffix under the home directory.
#[cfg(not(unix))]
fn home_suffix() -> &'static str {
    ".pursecraft"
}

/// The data home of this process (ADR 0023): `PURSECRAFT_HOME`, then
/// `$XDG_DATA_HOME/pursecraft`, then `~/.local/share/pursecraft` (unix).
/// Non-UTF-8 variables count as unset.
pub fn data_home() -> Result<PathBuf, NoHomeError> {
    let read = |name: &str| std::env::var_os(name).and_then(|v| v.into_string().ok());
    resolve_home(
        read("PURSECRAFT_HOME").as_deref(),
        read("XDG_DATA_HOME").as_deref(),
        read("HOME").as_deref(),
    )
}

/// The identity file path under `home`.
pub fn identity_path(home: &Path) -> PathBuf {
    home.join(IDENTITY_FILE)
}

/// The org log path for `org` under `home` (ADR 0021: one file per log).
pub fn org_log(home: &Path, org: OrgId) -> PathBuf {
    home.join(ORG_DIR).join(format!("{org}.ops"))
}

/// The budget log path for `budget` under `home`.
pub fn budget_log(home: &Path, budget: BudgetId) -> PathBuf {
    home.join(BUDGET_DIR).join(format!("{budget}.ops"))
}

/// Load the identity file if it exists (`None` when absent). Read-only —
/// [`list`](crate::list) and other readers never create anything.
pub fn load_identity(home: &Path) -> Result<Option<Identity>, IdentityError> {
    let path = identity_path(home);
    if path.try_exists()? {
        Ok(Some(read_identity(&path)?))
    } else {
        Ok(None)
    }
}

/// Load the identity file, creating it (atomically, before any store op
/// exists — ADR 0023) when absent. Returns the identity and whether this
/// call created it. A present-but-unreadable file is a loud error, never
/// recreated over.
pub fn load_or_create_identity(home: &Path) -> Result<(Identity, bool), IdentityError> {
    if let Some(identity) = load_identity(home)? {
        return Ok((identity, false));
    }
    fs::create_dir_all(home)?;
    let identity = Identity {
        version: IDENTITY_VERSION,
        device_id: DeviceId::new(mint_uuid()).expect("any version accepted"),
        user_id: UserId::new(mint_uuid()).expect("any version accepted"),
        org_id: OrgId::new(mint_uuid()).expect("minted v7"),
        membership_id: EntityId::new(mint_uuid()).expect("minted v7"),
        budget_id: BudgetId::new(mint_uuid()).expect("minted v7"),
        account_id: EntityId::new(mint_uuid()).expect("minted v7"),
    };
    publish_identity(home, &identity)?;
    Ok((identity, true))
}

/// Publish a freshly minted identity durably and alone: a process-unique
/// tmp file (a concurrent creator writes its own), file fsync, atomic
/// rename, then a directory fsync — the core store's create discipline
/// (ADR 0018). Finally the published file is read back: if a concurrent
/// creator's rename landed after ours, ours lost, and the caller fails
/// loudly instead of minting ops against a root it does not hold.
fn publish_identity(home: &Path, identity: &Identity) -> Result<(), IdentityError> {
    let path = identity_path(home);
    let tmp = home.join(format!("{IDENTITY_FILE}.{}.tmp", std::process::id()));
    let mut file = fs::File::create(&tmp)?;
    let encoded = serde_json::to_string_pretty(identity).map_err(IdentityError::Encode)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    sync_dir(home);
    if read_identity(&path)? != *identity {
        return Err(IdentityError::Raced { path });
    }
    Ok(())
}

/// Best-effort durability of a freshly created file's directory entry
/// (POSIX; the core's `sync_parent_dir` discipline, ADR 0018).
fn sync_dir(home: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(home) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = home;
}

/// Read and validate the identity file at `path`.
fn read_identity(path: &Path) -> Result<Identity, IdentityError> {
    let bytes = fs::read(path)?;
    let identity: Identity =
        serde_json::from_slice(&bytes).map_err(|source| IdentityError::Decode {
            path: path.to_owned(),
            source,
        })?;
    if identity.version != IDENTITY_VERSION {
        return Err(IdentityError::Unsupported {
            path: path.to_owned(),
            found: identity.version,
        });
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testsupport::TempDir;

    #[test]
    fn resolution_order_is_env_then_xdg_then_home() {
        let env = resolve_home(Some("/x/env"), Some("/x/xdg"), Some("/x/home"));
        assert_eq!(env.unwrap(), PathBuf::from("/x/env"));
        let xdg = resolve_home(None, Some("/x/xdg"), Some("/x/home"));
        assert_eq!(xdg.unwrap(), PathBuf::from("/x/xdg/pursecraft"));
        // A relative XDG value is ignored per the XDG spec.
        let relative = resolve_home(None, Some("rel/xdg"), Some("/x/home"));
        assert_eq!(
            relative.unwrap(),
            PathBuf::from("/x/home").join(home_suffix())
        );
        let home = resolve_home(None, None, Some("/x/home"));
        assert_eq!(home.unwrap(), PathBuf::from("/x/home").join(home_suffix()));
        assert_eq!(resolve_home(None, None, None), Err(NoHomeError));
        // Empty strings count as unset.
        assert!(resolve_home(Some(""), Some("/x/xdg"), None).is_ok());
    }

    #[test]
    fn store_paths_sit_under_their_directories() {
        let home = Path::new("/x/pursecraft");
        let org = OrgId::new(mint_uuid()).unwrap();
        let budget = BudgetId::new(mint_uuid()).unwrap();
        assert!(org_log(home, org).starts_with("/x/pursecraft/orgs"));
        assert_eq!(org_log(home, org).extension(), Some("ops".as_ref()));
        assert!(budget_log(home, budget).starts_with("/x/pursecraft/budgets"));
        assert_eq!(budget_log(home, budget).extension(), Some("ops".as_ref()));
    }

    #[test]
    fn identity_creates_once_then_round_trips() {
        let tmp = TempDir::new("identity");
        let (first, created) = load_or_create_identity(tmp.path()).unwrap();
        assert!(created);
        let (again, created) = load_or_create_identity(tmp.path()).unwrap();
        assert!(!created, "the second call reads, never remints");
        assert_eq!(first, again);
        // The file landed atomically: no tmp straggler, real content.
        let strays: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(strays, ["identity.json"]);
    }

    #[test]
    fn corrupt_and_future_identities_are_refused() {
        let tmp = TempDir::new("identity-corrupt");
        load_or_create_identity(tmp.path()).unwrap();
        let path = identity_path(tmp.path());
        std::fs::write(&path, b"{ not an identity").unwrap();
        assert!(matches!(
            load_or_create_identity(tmp.path()),
            Err(IdentityError::Decode { .. })
        ));
        let (identity, _) = {
            let tmp2 = TempDir::new("identity-version");
            load_or_create_identity(tmp2.path()).unwrap()
        };
        let future = serde_json::to_string(&Identity {
            version: identity.version + 1,
            ..identity
        })
        .unwrap();
        std::fs::write(&path, future).unwrap();
        assert!(matches!(
            load_or_create_identity(tmp.path()),
            Err(IdentityError::Unsupported { .. })
        ));
    }
}
