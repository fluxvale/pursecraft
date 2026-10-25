//! The relay's auth database (ADR 0024): devices, per-scope grants, and
//! pairing codes — the minimal pre-accounts model.
//!
//! One small JSON file per server (`auth.json`), written atomically
//! (tmp + fsync + rename); every mutation is saved before it is
//! acknowledged, so a relay restart never forgets a device or grant.
//! Tokens and pairing codes are 122-bit random strings stored
//! SHA-256-hashed: a leaked database yields no usable credentials.
//! Enrollment is gated by the operator's enrollment secret, generated at
//! first boot into `enrollment.secret` (mode 0600).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use pursecraft_core::ids::{DeviceId, ScopeId};

/// How long a pairing code may be redeemed after minting (ADR 0024).
pub const PAIRING_TTL_SECS: u64 = 3600;

/// The auth file's shape — everything except the enrollment secret, which
/// lives in its own file the operator reads.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct AuthFile {
    devices: Vec<DeviceRecord>,
    grants: Vec<GrantRecord>,
    pairing_codes: Vec<PairingRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DeviceRecord {
    device_id: DeviceId,
    token_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct GrantRecord {
    /// The scope as its compact key (`org:{uuid}` / `budget:{uuid}`) —
    /// [`ScopeId`] is not a JSON map key, and grants are keyed by scope.
    scope: String,
    device_id: DeviceId,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PairingRecord {
    code_hash: String,
    scope: String,
    expires_at_unix: u64,
}

/// An auth refusal — the relay's only authorization answers (ADR 0024).
#[derive(Debug)]
pub enum AuthError {
    WrongEnrollmentSecret,
    NotGranted,
    ScopeExists,
    InvalidPairingCode,
    PairingCodeExpired,
    Io(io::Error),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongEnrollmentSecret => f.write_str("wrong enrollment secret"),
            Self::NotGranted => f.write_str("device is not granted this scope"),
            Self::ScopeExists => f.write_str("scope already exists"),
            Self::InvalidPairingCode => f.write_str("pairing code is invalid"),
            Self::PairingCodeExpired => f.write_str("pairing code has expired"),
            Self::Io(e) => write!(f, "auth store io error: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<io::Error> for AuthError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The compact string key for a scope — injective and readable in `auth.json`.
pub fn scope_key(scope: ScopeId) -> String {
    match scope {
        ScopeId::Org(id) => format!("org:{}", id.as_uuid()),
        ScopeId::Budget(id) => format!("budget:{}", id.as_uuid()),
    }
}

fn sha256_hex(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the epoch")
        .as_secs()
}

fn mint_token(prefix: &str) -> String {
    format!("{}{}", prefix, Uuid::new_v4().simple())
}

/// The pre-accounts auth database (ADR 0024): device tokens, per-scope
/// grants, single-use pairing codes. All lookups are by SHA-256 hash of
/// the presented secret; the plaintext exists only in the mint response.
#[derive(Debug)]
pub struct AuthDb {
    path: PathBuf,
    enrollment_secret: String,
    file: AuthFile,
}

impl AuthDb {
    /// Load (or initialize) the database under `data_dir`, which must
    /// exist. The enrollment secret file is created at first boot with
    /// mode 0600 for the operator to read once; expired pairing codes are
    /// pruned.
    pub fn open(data_dir: &Path) -> Result<Self, AuthError> {
        let path = data_dir.join("auth.json");
        let file = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<AuthFile>(&bytes).map_err(|e| {
                AuthError::Io(io::Error::other(format!(
                    "{} does not decode: {e}",
                    path.display()
                )))
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => AuthFile::default(),
            Err(e) => return Err(e.into()),
        };
        let enrollment_secret = ensure_enrollment_secret(data_dir)?;
        let now = now_unix();
        let mut db = Self {
            path,
            enrollment_secret,
            file,
        };
        db.file.pairing_codes.retain(|c| c.expires_at_unix > now);
        Ok(db)
    }

    /// Enroll a device: presenting the operator's enrollment secret mints
    /// a device id and its token (shown exactly once).
    pub fn enroll(&mut self, presented_secret: &str) -> Result<(DeviceId, String), AuthError> {
        if presented_secret != self.enrollment_secret {
            return Err(AuthError::WrongEnrollmentSecret);
        }
        let device_id = DeviceId::new(Uuid::new_v4()).expect("v4 is an accepted device id");
        let token = mint_token("dev_");
        let mut next = self.file.clone();
        next.devices.push(DeviceRecord {
            device_id,
            token_hash: sha256_hex(&token),
        });
        self.commit(next)?;
        Ok((device_id, token))
    }

    /// Resolve a presented token to its device.
    pub fn authenticate(&self, token: &str) -> Option<DeviceId> {
        let hash = sha256_hex(token);
        self.file
            .devices
            .iter()
            .find(|d| d.token_hash == hash)
            .map(|d| d.device_id)
    }

    /// Create a scope: the creator is granted, and one single-use pairing
    /// code is minted for the next device. An already-granted scope is a
    /// refusal — scope ids are client-minted and must not be squattable
    /// (ADR 0024).
    pub fn create_scope(
        &mut self,
        scope: ScopeId,
        creator: DeviceId,
    ) -> Result<(String, u64), AuthError> {
        if self.any_grant(scope) {
            return Err(AuthError::ScopeExists);
        }
        let mut next = self.file.clone();
        next.grants.push(GrantRecord {
            scope: scope_key(scope),
            device_id: creator,
        });
        let expires_at_unix = now_unix() + PAIRING_TTL_SECS;
        let code = mint_token("pair_");
        next.pairing_codes.push(PairingRecord {
            code_hash: sha256_hex(&code),
            scope: scope_key(scope),
            expires_at_unix,
        });
        self.commit(next)?;
        Ok((code, expires_at_unix))
    }

    /// Mint another pairing code for an already-paired scope (a granted
    /// device brings in the next one).
    pub fn mint_pairing_code(
        &mut self,
        scope: ScopeId,
        minter: DeviceId,
    ) -> Result<(String, u64), AuthError> {
        if !self.is_granted(scope, minter) {
            return Err(AuthError::NotGranted);
        }
        let expires_at_unix = now_unix() + PAIRING_TTL_SECS;
        let code = mint_token("pair_");
        let mut next = self.file.clone();
        next.pairing_codes.push(PairingRecord {
            code_hash: sha256_hex(&code),
            scope: scope_key(scope),
            expires_at_unix,
        });
        self.commit(next)?;
        Ok((code, expires_at_unix))
    }

    /// Redeem a pairing code: single-use, scoped, expiring. A successful
    /// redeem grants the device the code's scope.
    pub fn redeem_pairing_code(
        &mut self,
        scope: ScopeId,
        code: &str,
        device: DeviceId,
    ) -> Result<(), AuthError> {
        let hash = sha256_hex(code);
        let key = scope_key(scope);
        let found = self
            .file
            .pairing_codes
            .iter()
            .position(|c| c.code_hash == hash);
        let Some(at) = found else {
            return Err(AuthError::InvalidPairingCode);
        };
        let record = &self.file.pairing_codes[at];
        if record.scope != key {
            return Err(AuthError::InvalidPairingCode);
        }
        if record.expires_at_unix <= now_unix() {
            return Err(AuthError::PairingCodeExpired);
        }
        let mut next = self.file.clone();
        next.pairing_codes.remove(at);
        if !next
            .grants
            .iter()
            .any(|g| g.scope == key && g.device_id == device)
        {
            next.grants.push(GrantRecord {
                scope: key,
                device_id: device,
            });
        }
        self.commit(next)?;
        Ok(())
    }

    /// Whether the device may push and pull this scope's log.
    pub fn is_granted(&self, scope: ScopeId, device: DeviceId) -> bool {
        let key = scope_key(scope);
        self.file
            .grants
            .iter()
            .any(|g| g.scope == key && g.device_id == device)
    }

    fn any_grant(&self, scope: ScopeId) -> bool {
        let key = scope_key(scope);
        self.file.grants.iter().any(|g| g.scope == key)
    }

    /// Persist a mutation atomically before it is acknowledged; only a
    /// durable write updates the in-memory database.
    fn commit(&mut self, next: AuthFile) -> Result<(), AuthError> {
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = File::create(&tmp)?;
            file.write_all(
                &serde_json::to_vec_pretty(&next)
                    .map_err(|e| AuthError::Io(io::Error::other(e)))?,
            )?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Some(parent) = self.path.parent()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }
        self.file = next;
        Ok(())
    }
}

/// Read the enrollment secret, creating it at first boot (mode 0600 —
/// the operator reads it once and keeps it off the network).
fn ensure_enrollment_secret(data_dir: &Path) -> Result<String, AuthError> {
    let path = data_dir.join("enrollment.secret");
    match File::open(&path) {
        Ok(mut file) => {
            let mut secret = String::new();
            file.read_to_string(&mut secret)?;
            return Ok(secret.trim_end().to_owned());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let secret = mint_token("enroll_");
    #[cfg(unix)]
    let write = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
    };
    #[cfg(not(unix))]
    let write = File::create(&path);
    let mut file = write?;
    file.write_all(secret.as_bytes())?;
    file.sync_all()?;
    Ok(secret)
}
