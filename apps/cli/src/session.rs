//! The enrollment record (ADR 0025): `session.json` under the data home —
//! the relay URL, the server-minted device id, and the bearer token.
//!
//! The file's presence IS the gate: every data command requires it, and no
//! command checks it by network — enrolled-but-offline is full function.
//! Published with the identity file's atomic discipline (ADR 0023) at mode
//! 0600 (the token is a credential). The token never appears in any output.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pursecraft_core::ids::DeviceId;
use serde::{Deserialize, Serialize};

/// The session file name under the data home.
const SESSION_FILE: &str = "session.json";
/// The session file version this CLI writes and reads.
const SESSION_VERSION: u16 = 1;

/// The enrollment record (ADR 0025): what a client needs to reach its sync
/// home. `device_id` is the SERVER's mint (enrollment response), not a
/// local one — the relay enforces that pushed ops carry it.
// No `Debug`: a derived printer would make the token one `{:?}` away
// from a log line (ADR 0025: the token appears only in the header).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub version: u16,
    /// The relay base URL in ADR 0029's canonical form
    /// (`http(s)://host[:port][/prefix]`).
    pub server: String,
    /// The device the relay knows; ops are minted under it.
    pub device_id: DeviceId,
    /// The bearer token — a credential; never printed, never logged.
    pub token: String,
}

/// A session-file failure — corrupt or future-version files are refused
/// loudly, never overwritten (the identity discipline, ADR 0023).
#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Decode {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The (practically unreachable) failure to encode a session.
    Encode(serde_json::Error),
    Unsupported {
        path: PathBuf,
        found: u16,
    },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "session io error: {e}"),
            Self::Decode { path, source } => {
                write!(f, "{path:?} is not a readable session file: {source}")
            }
            Self::Encode(e) => write!(f, "a session does not encode: {e}"),
            Self::Unsupported { path, found } => write!(
                f,
                "{path:?} has session version {found}, this pursecraft supports {SESSION_VERSION}"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The gate's refusal (ADR 0025): one teaching block, exit 1. Every data
/// command — `list` included — answers with this until `session.json`
/// exists.
pub const GATE_MESSAGE: &str = "this pursecraft is not enrolled yet\n\
     \nenroll once — capture stays fully offline afterwards:\n\
     \n  pursecraft login <relay-url>\n\
     \nthe enrollment secret is in the relay's data directory (enrollment.secret)";

/// The session file path under `home`.
pub fn session_path(home: &Path) -> PathBuf {
    home.join(SESSION_FILE)
}

/// Load the session if it exists (`None` when absent — the gate's answer).
/// A present-but-unreadable file is a loud error, never recreated over.
pub fn load(home: &Path) -> Result<Option<Session>, SessionError> {
    let path = session_path(home);
    if !path.try_exists()? {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let session: Session =
        serde_json::from_slice(&bytes).map_err(|source| SessionError::Decode {
            path: path.clone(),
            source,
        })?;
    if session.version != SESSION_VERSION {
        return Err(SessionError::Unsupported {
            path,
            found: session.version,
        });
    }
    Ok(Some(session))
}

/// Publish an enrollment durably and atomically (the identity discipline,
/// ADR 0023): process-unique tmp, file fsync, rename, directory fsync —
/// mode 0600 so the token rides no wider than the oplog beside it.
pub fn publish(home: &Path, session: &Session) -> Result<(), SessionError> {
    fs::create_dir_all(home)?;
    let path = session_path(home);
    let tmp = home.join(format!("{SESSION_FILE}.{}.tmp", std::process::id()));
    {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut file = fs::File::create(&tmp)?;
        let encoded = serde_json::to_string_pretty(session).map_err(SessionError::Encode)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(home) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idmint::mint_uuid;

    fn session() -> Session {
        Session {
            version: SESSION_VERSION,
            server: "http://127.0.0.1:8080".into(),
            device_id: DeviceId::new(mint_uuid()).unwrap(),
            token: "dev_probe".into(),
        }
    }

    #[test]
    fn publish_then_load_round_trips_and_gate_answers_none_before() {
        let tmp = crate::testsupport::TempDir::new("session");
        assert!(load(tmp.path()).unwrap().is_none(), "no session, no gate");
        let session = session();
        publish(tmp.path(), &session).unwrap();
        let loaded = load(tmp.path()).unwrap();
        assert!(loaded == Some(session), "round-trips");
        // Atomic: no tmp straggler.
        let names: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, ["session.json"]);
    }

    #[test]
    fn corrupt_and_future_sessions_are_refused() {
        let tmp = crate::testsupport::TempDir::new("session-corrupt");
        publish(tmp.path(), &session()).unwrap();
        std::fs::write(session_path(tmp.path()), b"{ nope").unwrap();
        assert!(matches!(load(tmp.path()), Err(SessionError::Decode { .. })));
        let future = serde_json::to_string(&Session {
            version: SESSION_VERSION + 1,
            ..session()
        })
        .unwrap();
        std::fs::write(session_path(tmp.path()), future).unwrap();
        assert!(matches!(
            load(tmp.path()),
            Err(SessionError::Unsupported { .. })
        ));
    }
}
