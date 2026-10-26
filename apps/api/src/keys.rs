//! The relay's key-record store (ADR 0028): the org-scoped set of opaque
//! key records a device publishes for its peers, plus the authenticated
//! device that pushed each one.
//!
//! One file per org under `<data>/keys/`, written atomically (tmp + fsync +
//! rename + directory fsync — the auth database's discipline, ADR 0024) and
//! loaded lazily. The relay never parses a record: a record is bytes with a
//! length cap and a dedupe key, exactly like a payload (ADRs 0009, 0024). The
//! one thing it adds is `pushed_by` — the caller it authenticated, which is
//! the only provenance a payload-blind relay can honestly assert.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use pursecraft_core::ids::{DeviceId, OrgId};

/// Records one org may hold. Devices times epochs is small; the cap keeps a
/// granted device from bloating the data directory (ADR 0028).
pub const MAX_KEY_RECORDS: usize = 4096;
/// One record's byte ceiling — an envelope-sized cap, not a policy knob.
pub const MAX_KEY_RECORD_BYTES: usize = 64 * 1024;

/// One stored key record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct KeyRow {
    /// The record string, verbatim — never parsed here.
    pub key: String,
    /// The device the relay authenticated when it was pushed.
    pub pushed_by: DeviceId,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    v: u16,
    keys: Vec<KeyRow>,
}

/// The key-file version this relay speaks.
const KEY_FILE_VERSION: u16 = 1;

/// A refusal from the key store (ADR 0028).
#[derive(Debug)]
pub enum KeyStoreError {
    Io(io::Error),
    /// The org's record set is at its cap.
    Full,
    /// A record is longer than the byte cap.
    TooLarge,
    /// The file does not decode or speaks another version — loud, never
    /// reset (damaged key material must not vanish silently).
    BadFile {
        path: PathBuf,
        detail: String,
    },
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "key store io error: {e}"),
            Self::Full => write!(
                f,
                "this org already holds {MAX_KEY_RECORDS} key records; the set is full"
            ),
            Self::TooLarge => write!(f, "a key record exceeds {MAX_KEY_RECORD_BYTES} bytes"),
            Self::BadFile { path, detail } => {
                write!(f, "{path:?} is not a usable key file: {detail}")
            }
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<io::Error> for KeyStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Append-only-by-record set semantics: pushing an exact string twice is a
/// no-op (at-least-once delivery, ADR 0022's channel contract), and the first
/// pusher of a given string keeps its stamp.
///
/// Every access holds the one lock: a publish is a read-modify-write over a
/// whole file, so two concurrent syncs (the ordinary two-device case) would
/// otherwise lose acked records or rename a half-written file into place —
/// exactly the failure the logs' per-scope mutex prevents (ADR 0024).
#[derive(Debug)]
pub struct KeyStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl KeyStore {
    /// The key store rooted at `<data>/keys/`.
    pub fn open(data_dir: &Path) -> Result<Self, KeyStoreError> {
        let dir = data_dir.join("keys");
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn path(&self, org: OrgId) -> PathBuf {
        self.dir
            .join(format!("org-{}.json", org.as_uuid().simple()))
    }

    /// The unlocked read; every public entry point holds [`Self::lock`].
    fn read(&self, org: OrgId) -> Result<Vec<KeyRow>, KeyStoreError> {
        let path = self.path(org);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let file: KeyFile = serde_json::from_slice(&bytes).map_err(|e| KeyStoreError::BadFile {
            path: path.clone(),
            detail: e.to_string(),
        })?;
        if file.v != KEY_FILE_VERSION {
            return Err(KeyStoreError::BadFile {
                path,
                detail: format!("version {} is not this relay's {KEY_FILE_VERSION}", file.v),
            });
        }
        Ok(file.keys)
    }

    /// Store `records` pushed by `device`. Each new record must fit the caps;
    /// exact duplicates are skipped (their original pusher stays). Returns how
    /// many of THIS request's records the org holds after the write — the
    /// client's ack check: a short answer means a record the pusher believes
    /// delivered is not on disk.
    pub fn publish(
        &self,
        org: OrgId,
        device: DeviceId,
        records: &[String],
    ) -> Result<usize, KeyStoreError> {
        for record in records {
            if record.len() > MAX_KEY_RECORD_BYTES {
                return Err(KeyStoreError::TooLarge);
            }
        }
        let _guard = self.lock.lock().expect("key store lock");
        let mut rows = self.read(org)?;
        let mut seen: HashSet<String> = rows.iter().map(|row| row.key.clone()).collect();
        for record in records {
            if seen.insert(record.clone()) {
                rows.push(KeyRow {
                    key: record.clone(),
                    pushed_by: device,
                });
            }
        }
        if rows.len() > MAX_KEY_RECORDS {
            return Err(KeyStoreError::Full);
        }
        let path = self.path(org);
        let file = KeyFile {
            v: KEY_FILE_VERSION,
            keys: rows,
        };
        // A process-unique tmp: concurrent publishes (serialized by the lock
        // above) and any future multi-threaded caller each own their file.
        static TMP: AtomicU64 = AtomicU64::new(0);
        let tmp = self.dir.join(format!(
            "org-{}.{}.{}.tmp",
            org.as_uuid().simple(),
            std::process::id(),
            TMP.fetch_add(1, Ordering::Relaxed),
        ));
        {
            let mut out = File::create(&tmp)?;
            out.write_all(
                &serde_json::to_vec(&file).map_err(|e| KeyStoreError::Io(io::Error::other(e)))?,
            )?;
            out.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        // Re-read to answer from the durable bytes, so a lying answer cannot
        // outlive a failed rename.
        let held: HashSet<String> = self.read(org)?.into_iter().map(|row| row.key).collect();
        Ok(records
            .iter()
            .filter(|record| held.contains(*record))
            .count())
    }

    /// Every record the org holds, with its pusher.
    pub fn records(&self, org: OrgId) -> Result<Vec<KeyRow>, KeyStoreError> {
        let _guard = self.lock.lock().expect("key store lock");
        self.read(org)
    }
}
