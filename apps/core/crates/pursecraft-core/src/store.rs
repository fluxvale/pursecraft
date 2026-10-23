//! The durable local oplog store (ADRs 0007, 0009, 0017, 0018): the
//! append-only framed file a real client boots the engine from.
//!
//! [`LocalStore`] wraps the 0017 [`OpLog`] — records carry their canonical
//! sequences, the `op_id` dedupe index is rebuilt on boot, and an append
//! commits when its frame and the header's commit marker land under one
//! `sync_data`. Applied state is never persisted: boot is replay through
//! the ordinary [`crate::sync::SyncSession`] path, so boot-from-store
//! equals in-memory replay by construction (ADR 0018).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ids::BudgetId;
use crate::ops::Op;
use crate::sync::{LogError, OpLog, SequencedOp};
use crate::wire::{self, OpMeta};

/// File magic; a strict prefix of it is a torn create (ADR 0018).
const MAGIC: [u8; 8] = *b"PCOPLOG\0";
const FORMAT_VERSION: u16 = 1;
/// magic (8) + version (2) + reserved (2) + commit marker (8).
const HEADER_LEN: usize = 20;
/// Offset of the commit marker within the header.
const HWM_OFFSET: usize = 12;
/// Frame overhead: body length (4) + checksum (8).
const FRAME_OVERHEAD: usize = 12;

/// FNV-1a-64 over the frame body — torn-write detection, not cryptography
/// (ADR 0018); the at-rest encryption layer brings authenticated bytes.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

/// The commit marker: the highest sequence whose frame-and-marker write
/// was synced (ADR 0018). Stored as `[seq][!seq]` so a torn marker write
/// is detectable — and safely ignored, because a torn marker means the
/// commit never acked.
fn marker_bytes(seq: u64) -> Result<[u8; 8], StoreError> {
    let seq = u32::try_from(seq).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "store sequence exceeds the u32 commit marker",
        )
    })?;
    let mut marker = [0u8; 8];
    marker[..4].copy_from_slice(&seq.to_le_bytes());
    marker[4..].copy_from_slice(&(!seq).to_le_bytes());
    Ok(marker)
}

/// The commit marker, if it is intact. `None` means torn or absent — the
/// commit it belonged to never acked, so boot resumes from the loaded
/// frames alone (ADR 0018).
fn parse_marker(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let seq = u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"));
    let inverted = u32::from_le_bytes(bytes[4..].try_into().expect("4 bytes"));
    (seq == !inverted).then_some(u64::from(seq))
}

/// One stored op: its canonical sequence (a repair can leave gaps, so
/// sequences cannot be re-derived from position), the server-visible
/// metadata verbatim, and the payload as the choke-point string (ADRs
/// 0009, 0018) — the future at-rest encryption layer changes what that
/// string holds, not this shape.
#[derive(Serialize, Deserialize)]
struct StoredOp {
    seq: u64,
    meta: OpMeta,
    payload: String,
}

/// Serialize one op into its frame under `seq` (ADR 0018).
fn encode_frame(op: &Op, seq: u64) -> Result<Vec<u8>, StoreError> {
    let (meta, payload) = op.clone().into_parts();
    let body = serde_json::to_vec(&StoredOp {
        seq,
        meta,
        payload: wire::encode_payload(&payload)?,
    })?;
    let len = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stored record exceeds the u32 frame length",
        )
    })?;
    let mut frame = Vec::with_capacity(body.len() + FRAME_OVERHEAD);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&fnv1a64(&body).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// What the boot scan found at one offset.
enum Scan {
    /// A valid frame, decoded with its recorded sequence; the offset just
    /// past it.
    Op(SequencedOp, usize),
    /// Structurally incomplete or checksum-failed — a torn tail or
    /// mid-file damage; the caller classifies by resync (ADR 0018).
    Invalid,
    /// Checksum-valid bytes that cannot be a stored op — the writer never
    /// frames such bytes; loud without resync.
    Corrupt(&'static str),
}

/// Validate and decode the frame at `offset` (ADR 0018's framing rules).
fn scan_frame(bytes: &[u8], offset: usize) -> Scan {
    let remaining = bytes.len() - offset;
    if remaining < FRAME_OVERHEAD {
        return Scan::Invalid;
    }
    let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("length field"));
    if u64::from(len) > (remaining - FRAME_OVERHEAD) as u64 {
        return Scan::Invalid;
    }
    let end = offset + FRAME_OVERHEAD + len as usize;
    let body = &bytes[offset + FRAME_OVERHEAD..end];
    let checksum = u64::from_le_bytes(
        bytes[offset + 4..offset + FRAME_OVERHEAD]
            .try_into()
            .expect("checksum field"),
    );
    if fnv1a64(body) != checksum {
        return Scan::Invalid;
    }
    let stored: StoredOp = match serde_json::from_slice(body) {
        Ok(stored) => stored,
        Err(_) => return Scan::Corrupt("stored op does not decode"),
    };
    match wire::decode_payload(&stored.payload) {
        Ok(payload) => Scan::Op(
            SequencedOp {
                seq: stored.seq,
                op: Op::from_parts(stored.meta, payload),
            },
            end,
        ),
        Err(_) => Scan::Corrupt("op payload does not decode"),
    }
}

/// Whether a checksum-valid frame chain starts somewhere after `from` and
/// runs exactly to EOF — proof that the writer produced frames beyond
/// `from`, so damage at `from` is mid-file corruption, not the torn tail
/// (ADR 0018). Bodies need not decode for this decision: valid framing
/// alone is writer structure.
fn valid_chain_follows(bytes: &[u8], from: usize) -> bool {
    (from..bytes.len()).any(|start| chain_reaches_eof(bytes, start))
}

fn chain_reaches_eof(bytes: &[u8], start: usize) -> bool {
    let mut offset = start;
    let mut frames = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < FRAME_OVERHEAD {
            return false;
        }
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("length field"));
        if u64::from(len) > (remaining - FRAME_OVERHEAD) as u64 {
            return false;
        }
        let end = offset + FRAME_OVERHEAD + len as usize;
        let body = &bytes[offset + FRAME_OVERHEAD..end];
        let checksum = u64::from_le_bytes(
            bytes[offset + 4..offset + FRAME_OVERHEAD]
                .try_into()
                .expect("checksum field"),
        );
        if fnv1a64(body) != checksum {
            return false;
        }
        offset = end;
        frames += 1;
    }
    offset == bytes.len() && frames > 0
}

/// A store failure — foreign, corrupt, or future-version stores fail
/// loudly, never merge (ADR 0018).
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Encode(serde_json::Error),
    /// The file is not a pursecraft store (magic mismatch) — refused, not
    /// clobbered.
    Foreign {
        path: PathBuf,
    },
    /// A store using format features this core does not support.
    UnsupportedVersion {
        path: PathBuf,
        found: u16,
        supported: u16,
    },
    /// Structural damage at `offset`; boot is refused.
    Corrupt {
        path: PathBuf,
        offset: u64,
        reason: &'static str,
    },
    /// A failed append could not roll back; reopen to recover.
    Poisoned {
        path: PathBuf,
    },
    /// A scoping violation from the underlying log ([ADR 0008]).
    Scope(LogError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "store io error: {e}"),
            Self::Encode(e) => write!(f, "store record does not encode: {e}"),
            Self::Foreign { path } => write!(f, "{path:?} is not a pursecraft oplog store"),
            Self::UnsupportedVersion {
                path,
                found,
                supported,
            } => write!(
                f,
                "{path:?} uses store format features this core does not support (found {found}, supported {supported})"
            ),
            Self::Corrupt {
                path,
                offset,
                reason,
            } => write!(f, "{path:?} is corrupt at byte {offset}: {reason}"),
            Self::Poisoned { path } => write!(
                f,
                "{path:?} was left unusable by a failed append; reopen it to recover"
            ),
            Self::Scope(e) => write!(f, "op rejected by the log: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encode(e) => Some(e),
            Self::Scope(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Encode(e)
    }
}

impl From<LogError> for StoreError {
    fn from(e: LogError) -> Self {
        Self::Scope(e)
    }
}

/// The durable local oplog store (ADR 0018): the 0017 [`OpLog`] with an
/// append-only framed file under it. File order is canonical order; ops
/// dedupe by `op_id` exactly as in memory; the commit point of an append
/// is its frame and the header's commit marker landing under one
/// `sync_data`.
#[derive(Debug)]
pub struct LocalStore {
    log: OpLog,
    path: PathBuf,
    file: File,
    /// The file length the last successful commit covers — the boundary a
    /// failed append rolls back to.
    durable_len: u64,
    /// The last committed sequence — what the header marker holds.
    hwm: u64,
    /// Set when a failed append could not roll back (ADR 0018).
    poisoned: bool,
}

impl LocalStore {
    /// Open (creating if absent) the store at `path`, rebuilding the
    /// in-memory log from disk. An uncommitted torn tail is repaired;
    /// foreign, corrupt, and unsupported files fail loudly; committed
    /// sequences are never reused (ADR 0018).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::create(path),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        // A strict prefix of the magic is a torn create: no committed data
        // can predate the header fsync, so recreate (ADR 0018).
        if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
            if MAGIC.starts_with(&bytes) {
                Self::recreate(&mut file)?;
                return Ok(Self::empty(path, file));
            }
            return Err(StoreError::Foreign {
                path: path.to_owned(),
            });
        }
        if bytes.len() < HEADER_LEN {
            Self::recreate(&mut file)?;
            return Ok(Self::empty(path, file));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("version field"));
        let reserved = u16::from_le_bytes(bytes[10..12].try_into().expect("reserved field"));
        let marker = parse_marker(&bytes[HWM_OFFSET..HEADER_LEN]);
        // Version 0 with no marker is a torn create (numbering starts at
        // 1; a fresh file's unwritten bytes are zero). Anything else off
        // is a format this core does not understand — loud, never
        // clobbered (ADR 0018).
        if version == 0 && reserved == 0 && marker.is_none() {
            Self::recreate(&mut file)?;
            return Ok(Self::empty(path, file));
        }
        if version != FORMAT_VERSION || reserved != 0 {
            return Err(StoreError::UnsupportedVersion {
                path: path.to_owned(),
                found: if version != FORMAT_VERSION {
                    version
                } else {
                    reserved
                },
                supported: FORMAT_VERSION,
            });
        }

        let mut records = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < bytes.len() {
            match scan_frame(&bytes, offset) {
                Scan::Op(record, end) => {
                    records.push(record);
                    offset = end;
                }
                Scan::Invalid => {
                    // Classify by resync: valid frames beyond the damage
                    // prove mid-file corruption — loud, file untouched.
                    // No chain after it is the crash window's torn tail:
                    // cut it and make the cut durable (ADR 0018).
                    if valid_chain_follows(&bytes, offset + 1) {
                        return Err(StoreError::Corrupt {
                            path: path.to_owned(),
                            offset: offset as u64,
                            reason: "frame is invalid but valid frames follow it",
                        });
                    }
                    file.set_len(offset as u64)?;
                    file.sync_all()?;
                    break;
                }
                Scan::Corrupt(reason) => {
                    return Err(StoreError::Corrupt {
                        path: path.to_owned(),
                        offset: offset as u64,
                        reason,
                    });
                }
            }
        }

        // Resume the sequence space above everything ever committed: the
        // loaded tip, or the marker if committed frames were lost to
        // damage — a gap then, which stalls watermarks visibly by design
        // (ADR 0017) and never reuses a sequence a peer may have seen
        // (ADR 0018). A torn marker means its commit never acked; the
        // loaded frames are all that was observable.
        let tip = records.last().map(|r| r.seq).unwrap_or(0);
        let hwm = marker.map_or(tip, |marker| marker.max(tip));
        let mut log = OpLog::resuming_at(hwm + 1);
        for record in records {
            log.append_sequenced(record.seq, record.op)
                .map_err(StoreError::Scope)?;
        }
        Ok(Self {
            log,
            path: path.to_owned(),
            file,
            durable_len: offset as u64,
            hwm,
            poisoned: false,
        })
    }

    /// Append one op durably; returns its canonical sequence. Scoping and
    /// `op_id` dedupe follow the in-memory log exactly (ADR 0017): a
    /// mis-scoped op is rejected, a re-append returns the original
    /// sequence and writes nothing. The commit point is the single
    /// `sync_data` after the frame and the header marker land; a failed
    /// commit rolls both back — and poisons the store if even that fails
    /// (ADR 0018).
    pub fn append(&mut self, op: Op) -> Result<u64, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned {
                path: self.path.clone(),
            });
        }
        // The single-writer contract: the file must still end where the
        // last commit left it.
        if self.file.metadata()?.len() != self.durable_len {
            return Err(StoreError::Corrupt {
                path: self.path.clone(),
                offset: self.durable_len,
                reason: "file no longer ends at the committed boundary (single-writer contract violated)",
            });
        }
        if let Some(log_budget) = self.log.budget_id()
            && log_budget != op.budget_id
        {
            return Err(LogError::BudgetMismatch {
                op_budget: op.budget_id,
                log_budget,
            }
            .into());
        }
        if let Some(seq) = self.log.seq_of(&op.op_id) {
            return Ok(seq);
        }
        let seq = self.log.next_seq();
        let frame = encode_frame(&op, seq)?;
        let marker = marker_bytes(seq)?;
        let committed = self.durable_len;
        let previous_marker = marker_bytes(self.hwm)?;
        if let Err(e) = commit_bytes(&mut self.file, committed, &frame, &marker) {
            // Restore the previous marker, drop any partial frame, and
            // make both durable; if even the rollback fails the store is
            // unusable until reopened (ADR 0018).
            if rollback(&mut self.file, &previous_marker, committed).is_err() {
                self.poisoned = true;
            }
            return Err(e.into());
        }
        self.durable_len = committed + frame.len() as u64;
        self.hwm = seq;
        // Scope and dedupe were checked above; this append cannot fail.
        self.log.append(op).map_err(StoreError::Scope)
    }

    /// The ops with sequence greater than `since`, in canonical order —
    /// the same contract as [`OpLog::delta_since`] (ADR 0007).
    pub fn delta_since(&self, since: u64) -> impl Iterator<Item = &SequencedOp> {
        self.log.delta_since(since)
    }

    /// The highest assigned sequence.
    pub fn tip(&self) -> u64 {
        self.log.tip()
    }

    /// The budget this store is scoped to, once the first op fixes it.
    pub fn budget_id(&self) -> Option<BudgetId> {
        self.log.budget_id()
    }

    fn empty(path: &Path, file: File) -> Self {
        Self {
            log: OpLog::new(),
            path: path.to_owned(),
            file,
            durable_len: HEADER_LEN as u64,
            hwm: 0,
            poisoned: false,
        }
    }

    /// Create a fresh store: the header (version, zero marker) goes down
    /// durably first, then the directory entry (ADR 0018). The caller has
    /// just seen the path not exist (single writer per path is the
    /// caller's contract).
    fn create(path: &Path) -> Result<Self, StoreError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&header())?;
        file.sync_data()?;
        sync_parent_dir(path);
        Ok(Self::empty(path, file))
    }

    /// Rewrite the header over a torn create (no committed data exists).
    fn recreate(file: &mut File) -> Result<(), StoreError> {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header())?;
        Ok(file.sync_data()?)
    }
}

/// The one durable write of an append: the frame at the committed
/// boundary, then the commit marker in the header, then a single sync —
/// both land or neither (ADR 0018).
fn commit_bytes(file: &mut File, at: u64, frame: &[u8], marker: &[u8; 8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.write_all(frame)?;
    file.seek(SeekFrom::Start(HWM_OFFSET as u64))?;
    file.write_all(marker)?;
    file.sync_data()
}

/// Undo a failed commit: previous marker back, file cut to the committed
/// boundary, made durable (ADR 0018).
fn rollback(file: &mut File, previous_marker: &[u8; 8], committed: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(HWM_OFFSET as u64))?;
    file.write_all(previous_marker)?;
    file.set_len(committed)?;
    file.sync_all()
}

fn header() -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(&MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    // The reserved word stays zero; a future extension must set it, and
    // readers refuse non-zero rather than misread (ADR 0018).
    header[HWM_OFFSET..HEADER_LEN].copy_from_slice(&marker_bytes(0).expect("zero marker"));
    header
}

/// Best-effort durability of a freshly created file's directory entry
/// (POSIX; other platforms rely on the create-fsync alone — ADR 0018).
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Field, Value};
    use crate::sync::SyncSession;
    use crate::testkit::conv::{self, DEVICES, OPS_PER_DEVICE};
    use crate::testkit::{Rng, TempDir, v7};
    use uuid::Uuid;

    /// A session booted from the store — the product operation (ADR 0018):
    /// replay through the ordinary engine path.
    fn boot_session(store: &LocalStore) -> SyncSession {
        let mut session = SyncSession::new();
        session
            .apply_delta(store.delta_since(0))
            .expect("stored ops are well-formed");
        session
    }

    /// An in-memory session fed the same ops in canonical order — the
    /// replay every boot must equal.
    fn in_memory_session(ops: &[Op]) -> SyncSession {
        let sequenced: Vec<SequencedOp> = ops
            .iter()
            .enumerate()
            .map(|(i, op)| conv::sequenced(i as u64 + 1, op.clone()))
            .collect();
        let mut session = SyncSession::new();
        session
            .apply_delta(&sequenced)
            .expect("generated ops are well-formed");
        session
    }

    fn store_path(tmp: &TempDir, label: &str) -> PathBuf {
        tmp.path().join(format!("{label}.ops"))
    }

    /// A store holding `count` deterministic ops, and the ops.
    fn filled_store(path: &Path, count: u64) -> (LocalStore, Vec<Op>) {
        let (field, value) = conv::amount(5);
        let ops: Vec<Op> = (1..=count)
            .map(|i| conv::op(i, 10 + i, 0, field, value.clone()))
            .collect();
        let mut store = LocalStore::open(path).unwrap();
        for op in &ops {
            store.append(op.clone()).unwrap();
        }
        (store, ops)
    }

    #[test]
    fn a_fresh_store_is_an_empty_durable_log() {
        let tmp = TempDir::new("fresh");
        let path = store_path(&tmp, "budget");
        let store = LocalStore::open(&path).unwrap();
        assert_eq!(store.tip(), 0);
        assert_eq!(store.budget_id(), None);
        // The header — magic, version, zero marker — is on disk already,
        // and a reopen stays empty.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[..MAGIC.len()], b"PCOPLOG\0");
        assert_eq!(
            u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            FORMAT_VERSION
        );
        assert_eq!(
            parse_marker(&bytes[HWM_OFFSET..HEADER_LEN]),
            Some(0),
            "a fresh store's marker reads zero"
        );
        drop(store);
        assert_eq!(LocalStore::open(&path).unwrap().tip(), 0);
    }

    #[test]
    fn appended_ops_boot_back_in_canonical_order() {
        let tmp = TempDir::new("append");
        let path = store_path(&tmp, "budget");
        let (field, value) = conv::amount(1);
        let ops = [
            conv::op(1, 10, 0, field, value.clone()),
            conv::op(2, 20, 0, field, value),
            conv::op(3, 30, 0, Field::Deleted, Value::Bool(true)),
        ];
        let mut store = LocalStore::open(&path).unwrap();
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(store.append(op.clone()).unwrap(), i as u64 + 1);
        }
        assert_eq!(store.tip(), 3);
        assert_eq!(store.budget_id(), Some(conv::budget()));
        drop(store);

        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(reopened.tip(), 3);
        assert_eq!(reopened.budget_id(), Some(conv::budget()));
        let seqs: Vec<u64> = reopened.delta_since(0).map(|s| s.seq).collect();
        assert_eq!(seqs, [1, 2, 3], "file order is canonical order");
        let booted: Vec<Op> = reopened.delta_since(0).map(|s| s.op.clone()).collect();
        assert_eq!(booted, ops.to_vec());
    }

    #[test]
    fn a_duplicate_append_writes_nothing() {
        let tmp = TempDir::new("dup");
        let path = store_path(&tmp, "budget");
        let (field, value) = conv::amount(7);
        let first = conv::op(1, 10, 0, field, value);
        let mut store = LocalStore::open(&path).unwrap();
        assert_eq!(store.append(first.clone()).unwrap(), 1);
        let len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            store.append(first).unwrap(),
            1,
            "a retry returns the original sequence"
        );
        // The log dedupes by op_id alone — under E2EE a re-encrypted retry
        // carries different payload bytes and must still dedupe (ADR 0017).
        let (_, reencrypted_value) = conv::amount(9);
        let mut retry = conv::op(2, 20, 0, conv::amount(0).0, reencrypted_value);
        retry.op_id = store.delta_since(0).next().unwrap().op.op_id;
        assert_eq!(store.append(retry).unwrap(), 1);
        assert_eq!(store.tip(), 1);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len,
            "dedupe writes no bytes"
        );
    }

    #[test]
    fn a_foreign_budget_append_is_rejected_loudly() {
        let tmp = TempDir::new("scope");
        let path = store_path(&tmp, "budget");
        let (field, value) = conv::amount(1);
        let mut store = LocalStore::open(&path).unwrap();
        store.append(conv::op(1, 10, 0, field, value)).unwrap();
        let mut foreign = conv::op(2, 20, 0, conv::amount(0).0, conv::amount(2).1);
        foreign.budget_id = BudgetId::new(v7(9, 9)).unwrap();
        assert!(matches!(
            store.append(foreign),
            Err(StoreError::Scope(LogError::BudgetMismatch { .. }))
        ));
        assert_eq!(store.tip(), 1);
        drop(store);
        assert_eq!(LocalStore::open(&path).unwrap().tip(), 1);
    }

    #[test]
    fn external_truncation_of_the_file_is_loud_at_append() {
        // The single-writer contract: if anything else moves the file end,
        // the store refuses to append rather than write into a hole.
        let tmp = TempDir::new("external");
        let path = store_path(&tmp, "budget");
        let mut store = LocalStore::open(&path).unwrap();
        let (field, value) = conv::amount(1);
        store.append(conv::op(1, 10, 0, field, value)).unwrap();
        drop(store);
        // Shrink the file behind the store's back, then append.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..HEADER_LEN + 5]).unwrap();
        let mut store = LocalStore::open(&path).unwrap();
        // open() repaired the torn tail; a fresh append must work.
        assert_eq!(store.tip(), 0);
        let (field, value) = conv::amount(2);
        store.append(conv::op(9, 90, 0, field, value)).unwrap();
        drop(store);
        // Now truncate WHILE the store is open — the append must refuse.
        let mut store = LocalStore::open(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut shorter = bytes.clone();
        shorter.truncate(HEADER_LEN + 3);
        std::fs::write(&path, &shorter).unwrap();
        let (field, value) = conv::amount(3);
        let result = store.append(conv::op(10, 99, 0, field, value));
        assert!(
            matches!(result, Err(StoreError::Corrupt { .. })),
            "append into a moved file end is refused, got {result:?}"
        );
    }

    #[test]
    fn booting_from_the_store_equals_a_fresh_in_memory_replay() {
        for seed in 1..=3u64 {
            let ops = conv::generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let expected = in_memory_session(&ops);
            let tmp = TempDir::new("boot");
            let path = store_path(&tmp, "budget");
            let mut store = LocalStore::open(&path).unwrap();
            for op in &ops {
                store.append(op.clone()).unwrap();
            }
            // Boot from DISK, not the live handle — open() must re-read
            // and re-validate every frame (ADR 0018).
            drop(store);
            let store = LocalStore::open(&path).unwrap();
            let booted = boot_session(&store);
            assert_eq!(booted.state(), expected.state(), "seed {seed}");
            assert_eq!(booted.last_seen(), store.tip());
            assert_eq!(store.tip(), ops.len() as u64);
        }
    }

    #[test]
    fn reordered_and_duplicated_appends_boot_to_the_replay_state() {
        for seed in 1..=3u64 {
            let ops = conv::generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9));
            let expected = in_memory_session(&ops);
            // Delivery order is shuffled and carries duplicates — a
            // retrying, at-least-once writer (ADR 0007).
            let mut rng = Rng::new(seed.wrapping_mul(0x94D0_49BB_1331_11EB));
            let mut delivery = ops.clone();
            conv::shuffle(&mut rng, &mut delivery);
            for _ in 0..delivery.len() / 3 {
                let at = rng.below(delivery.len() as u64 + 1) as usize;
                let copy = delivery[rng.below(delivery.len() as u64) as usize].clone();
                delivery.insert(at, copy);
            }
            let tmp = TempDir::new("reorder");
            let path = store_path(&tmp, "budget");
            let mut store = LocalStore::open(&path).unwrap();
            for op in &delivery {
                store.append(op.clone()).unwrap();
            }
            assert_eq!(store.tip(), ops.len() as u64, "dedupe collapses duplicates");
            drop(store);
            let booted = boot_session(&LocalStore::open(&path).unwrap());
            assert_eq!(
                booted.state(),
                expected.state(),
                "boot equals canonical replay (seed {seed})"
            );
            assert_eq!(booted.last_seen(), ops.len() as u64);
        }
    }

    #[test]
    fn restart_round_trips_across_reopens() {
        let tmp = TempDir::new("restart");
        let path = store_path(&tmp, "budget");
        let (field, value) = conv::amount(3);
        let mut store = LocalStore::open(&path).unwrap();
        let mut appended = 0u64;
        for _ in 0..3 {
            for _ in 0..5 {
                appended += 1;
                let op = conv::op(appended, 10 + appended, 0, field, value.clone());
                assert_eq!(store.append(op).unwrap(), appended);
            }
            // Crash-and-restart: drop the handle, boot from disk.
            drop(store);
            store = LocalStore::open(&path).unwrap();
            assert_eq!(store.tip(), appended);
        }
        let ops: Vec<Op> = store.delta_since(0).map(|s| s.op.clone()).collect();
        assert_eq!(ops.len(), 15);
        assert_eq!(
            boot_session(&store).state(),
            in_memory_session(&ops).state()
        );
    }

    #[test]
    fn a_torn_tail_is_repaired_at_every_truncation_offset() {
        let tmp = TempDir::new("torn");
        let path = store_path(&tmp, "src");
        let (store, ops) = filled_store(&path, 6);
        drop(store);
        let bytes = std::fs::read(&path).unwrap();

        // Independent oracle: how many complete frames fit in `cut` bytes.
        let complete_frames = |cut: usize| -> u64 {
            let mut offset = HEADER_LEN;
            let mut frames = 0u64;
            while offset < cut {
                if cut - offset < FRAME_OVERHEAD {
                    break;
                }
                let len =
                    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
                if FRAME_OVERHEAD + len > cut - offset {
                    break;
                }
                frames += 1;
                offset += FRAME_OVERHEAD + len;
            }
            frames
        };

        // Crash at any byte: the store opens, boots exactly the frames
        // that fit — a prefix of the canonical order, never an error —
        // and never reuses a committed sequence.
        for cut in 0..bytes.len() {
            let cut_path = tmp.path().join(format!("cut-{cut}.ops"));
            std::fs::write(&cut_path, &bytes[..cut]).unwrap();
            let mut store = LocalStore::open(&cut_path).unwrap();
            let expected = if cut < HEADER_LEN {
                0
            } else {
                complete_frames(cut)
            };
            assert_eq!(store.tip(), expected, "cut at byte {cut}");
            // All six ops were committed before the "crash": the next
            // append resumes above the marker — a gap, not a reuse
            // (ADR 0018).
            let (field, value) = conv::amount(11);
            let next = store.append(conv::op(99, 99, 0, field, value)).unwrap();
            let expect_next = if cut < HEADER_LEN { 1 } else { 7 };
            assert_eq!(next, expect_next, "cut at byte {cut}");
            drop(store);
        }

        // Cutting inside the last frame loses only that op, and the
        // repaired store re-delivers cleanly.
        let cut = bytes.len() - 7;
        let cut_path = tmp.path().join("tail-cut.ops");
        std::fs::write(&cut_path, &bytes[..cut]).unwrap();
        let store = LocalStore::open(&cut_path).unwrap();
        assert_eq!(store.tip(), 5, "the torn frame is the only loss");
        let session = boot_session(&store);
        assert_eq!(session.last_seen(), 5);
        assert_eq!(ops.len(), 6);
    }

    #[test]
    fn a_damaged_length_field_is_corruption_not_a_torn_tail() {
        // One flipped bit in a MIDDLE frame's length field must not
        // silently truncate every committed frame after it: valid frames
        // follow the damage, so the resync classifier fails loudly
        // (ADR 0018).
        let tmp = TempDir::new("length-rot");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 6);
        drop(store);
        let good = std::fs::read(&path).unwrap();

        let mut starts = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < good.len() {
            starts.push(offset);
            let len = u32::from_le_bytes(good[offset..offset + 4].try_into().unwrap()) as usize;
            offset += FRAME_OVERHEAD + len;
        }
        assert_eq!(starts.len(), 6);

        for &(frame, byte) in &[(0usize, 2usize), (2, 0), (3, 3)] {
            let mut bytes = good.clone();
            // A bit flip in the length field: 414-ish becomes 65950-ish.
            bytes[starts[frame] + byte] ^= 0x40;
            let path = store_path(&tmp, &format!("flip-{frame}-{byte}"));
            std::fs::write(&path, &bytes).unwrap();
            match LocalStore::open(&path) {
                Err(StoreError::Corrupt { offset, .. }) => {
                    assert_eq!(offset, starts[frame] as u64);
                }
                other => panic!("expected corruption, got {other:?}"),
            }
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "the loud path never rewrites the file"
            );
        }

        // An absurd length anywhere but the last frame is the same class.
        let mut bytes = good.clone();
        bytes[starts[2]..starts[2] + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let path = store_path(&tmp, "huge-length");
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            LocalStore::open(&path),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn an_appended_garbage_tail_is_repaired_as_torn() {
        // A crash's delayed allocation can leave stray zero bytes after
        // the last frame: no valid chain follows, so it is the torn tail
        // — repaired, not corruption (ADR 0018).
        let tmp = TempDir::new("garbage-tail");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 6);
        drop(store);
        let mut bytes = std::fs::read(&path).unwrap();
        let good_len = bytes.len();
        bytes.extend_from_slice(&[0u8; 13]);
        std::fs::write(&path, &bytes).unwrap();

        let store = LocalStore::open(&path).unwrap();
        assert_eq!(store.tip(), 6, "all committed ops survive");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            good_len,
            "the stray tail is cut"
        );
    }

    #[test]
    fn sequences_are_never_reused_after_a_repair_drops_a_committed_op() {
        // Bit rot on the LAST committed frame: the checksum fails at the
        // physical tail, the repair drops it — and the store must resume
        // above the commit marker, never reusing the lost sequence. A
        // caught-up peer (cursor at the marker) keeps receiving; a peer
        // behind stalls visibly at the gap (ADR 0017's designed stall).
        let tmp = TempDir::new("no-reuse");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 5);
        drop(store);
        let mut bytes = std::fs::read(&path).unwrap();

        // A peer pulls everything before the damage.
        let mut caught_up = boot_session(&LocalStore::open(&path).unwrap());
        assert_eq!(caught_up.last_seen(), 5);

        // Rot the last frame's body: checksum failure at the tail.
        let mut offset = HEADER_LEN;
        let mut last_frame = 0;
        while offset < bytes.len() {
            last_frame = offset;
            let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += FRAME_OVERHEAD + len;
        }
        bytes[last_frame + FRAME_OVERHEAD] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let mut store = LocalStore::open(&path).unwrap();
        assert_eq!(store.tip(), 4, "the rotted frame is gone");
        let (field, value) = conv::amount(21);
        let replacement = conv::op(50, 50, 0, field, value);
        assert_eq!(
            store.append(replacement.clone()).unwrap(),
            6,
            "the lost sequence 5 is never reused"
        );
        // The caught-up peer still receives the new op.
        caught_up
            .apply_delta(store.delta_since(caught_up.last_seen()))
            .unwrap();
        assert!(caught_up.state().entity(&replacement.entity_id).is_some());
        assert_eq!(caught_up.last_seen(), 6);

        // A peer that had only reached the gap stalls visibly on it.
        let mut stalled = SyncSession::new();
        let prefix: Vec<SequencedOp> = store.delta_since(0).take(4).cloned().collect();
        stalled.apply_delta(&prefix).unwrap();
        assert_eq!(stalled.last_seen(), 4);
        stalled.apply_delta(store.delta_since(4)).unwrap();
        assert_eq!(stalled.last_seen(), 4, "the watermark cannot cross the gap");
        assert_eq!(stalled.pending_len(), 1, "the stall is visible");

        // And the gap survives a reopen: the record carries its sequence.
        drop(store);
        let mut store = LocalStore::open(&path).unwrap();
        let seqs: Vec<u64> = store.delta_since(0).map(|s| s.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 6], "the gap persists across reopens");
        let (field, value) = conv::amount(22);
        assert_eq!(store.append(conv::op(51, 51, 0, field, value)).unwrap(), 7);
    }

    #[test]
    fn mid_file_corruption_fails_loudly() {
        let tmp = TempDir::new("corrupt");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 4);
        drop(store);
        let good = std::fs::read(&path).unwrap();

        // Frame start offsets, by walking the good file.
        let mut starts = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < good.len() {
            starts.push(offset);
            let len = u32::from_le_bytes(good[offset..offset + 4].try_into().unwrap()) as usize;
            offset += FRAME_OVERHEAD + len;
        }
        assert_eq!(starts.len(), 4);

        let write = |label: &str, bytes: &[u8]| {
            std::fs::write(store_path(&tmp, label), bytes).unwrap();
        };

        // (a) A flipped body byte inside frame 2: the checksum fails with
        // valid frames after it — corruption, loud.
        let mut bytes = good.clone();
        bytes[starts[1] + FRAME_OVERHEAD] ^= 0xff;
        write("bad-checksum", &bytes);
        match LocalStore::open(&store_path(&tmp, "bad-checksum")) {
            Err(StoreError::Corrupt { .. }) => {}
            other => panic!("expected corruption, got {other:?}"),
        }

        // (b) A forged frame with a VALID checksum over undecodable bytes:
        // the writer never frames such bytes — loud.
        let body = b"not a stored op".to_vec();
        let mut forged = Vec::with_capacity(FRAME_OVERHEAD + body.len());
        forged.extend_from_slice(&(body.len() as u32).to_le_bytes());
        forged.extend_from_slice(&fnv1a64(&body).to_le_bytes());
        forged.extend_from_slice(&body);
        let mut bytes = good.clone();
        let end = starts[1]
            + FRAME_OVERHEAD
            + u32::from_le_bytes(good[starts[1]..starts[1] + 4].try_into().unwrap()) as usize;
        bytes.splice(starts[1]..end, forged);
        write("forged-body", &bytes);
        match LocalStore::open(&store_path(&tmp, "forged-body")) {
            Err(StoreError::Corrupt { .. }) => {}
            other => panic!("expected corruption, got {other:?}"),
        }

        // (c) A valid frame whose record decodes but carries a non-v7
        // op_id: rejected at the wire boundary — loud.
        let frame_body = |index: usize| -> serde_json::Value {
            let start = starts[index] + FRAME_OVERHEAD;
            let len = u32::from_le_bytes(good[starts[index]..starts[index] + 4].try_into().unwrap())
                as usize;
            serde_json::from_slice(&good[start..start + len]).unwrap()
        };
        let reframe = |body: &serde_json::Value| -> Vec<u8> {
            let body = serde_json::to_vec(body).unwrap();
            let mut frame = Vec::with_capacity(FRAME_OVERHEAD + body.len());
            frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
            frame.extend_from_slice(&fnv1a64(&body).to_le_bytes());
            frame.extend_from_slice(&body);
            frame
        };
        let mut bad_id = frame_body(1);
        bad_id["meta"]["op_id"] = serde_json::json!(Uuid::nil().to_string());
        let mut bytes = good[..starts[1]].to_vec();
        bytes.extend_from_slice(&reframe(&bad_id));
        write("bad-op-id", &bytes);
        match LocalStore::open(&store_path(&tmp, "bad-op-id")) {
            Err(StoreError::Corrupt { .. }) => {}
            other => panic!("expected corruption, got {other:?}"),
        }

        // (d) A valid frame scoped to a foreign budget: loud through the
        // log's own scoping (ADR 0008).
        let mut foreign = frame_body(1);
        foreign["meta"]["budget_id"] = serde_json::json!(v7(9, 9).to_string());
        let mut bytes = good[..starts[1]].to_vec();
        bytes.extend_from_slice(&reframe(&foreign));
        write("foreign-budget", &bytes);
        match LocalStore::open(&store_path(&tmp, "foreign-budget")) {
            Err(StoreError::Scope(LogError::BudgetMismatch { .. })) => {}
            other => panic!("expected a scoping rejection, got {other:?}"),
        }

        // (e) A bad checksum in the LAST frame is the crash window's torn
        // write: repaired, not corruption.
        let mut bytes = good.clone();
        let last = starts[3] + FRAME_OVERHEAD;
        bytes[last] ^= 0xff;
        write("torn-last", &bytes);
        let store = LocalStore::open(&store_path(&tmp, "torn-last")).unwrap();
        assert_eq!(store.tip(), 3, "the uncommitted tail is dropped");
    }

    #[test]
    fn duplicate_records_collapse_to_the_first() {
        // Two records sharing an op_id with different content can only be
        // written by tampering — the API dedupes — and boot resolves them
        // the way the log must: first wins, by op_id alone (the E2EE-safe
        // rule; a re-encrypted retry carries different bytes, ADR 0017).
        let tmp = TempDir::new("dup-records");
        let one = store_path(&tmp, "one");
        let two = store_path(&tmp, "two");
        let (field, _) = conv::amount(0);
        let op_a = conv::op(1, 10, 0, field, conv::amount(111).1);
        let mut op_b = op_a.clone();
        op_b.value = conv::amount(222).1;
        let mut store = LocalStore::open(&one).unwrap();
        store.append(op_a).unwrap();
        drop(store);
        let mut store = LocalStore::open(&two).unwrap();
        store.append(op_b).unwrap();
        drop(store);

        let a = std::fs::read(&one).unwrap();
        let b = std::fs::read(&two).unwrap();
        let mut spliced = a[..HEADER_LEN].to_vec();
        // Store one's frame, then store two's.
        spliced.extend_from_slice(&a[HEADER_LEN..]);
        spliced.extend_from_slice(&b[HEADER_LEN..]);
        let spliced_path = store_path(&tmp, "spliced");
        std::fs::write(&spliced_path, &spliced).unwrap();

        let store = LocalStore::open(&spliced_path).unwrap();
        assert_eq!(store.tip(), 1, "the second record collapses");
        let ops: Vec<Op> = store.delta_since(0).map(|s| s.op.clone()).collect();
        assert_eq!(ops[0].value, conv::amount(111).1, "first record wins");
    }

    #[test]
    fn foreign_and_future_version_files_are_refused_loudly() {
        let tmp = TempDir::new("foreign");
        // A file that is not ours.
        let foreign = store_path(&tmp, "foreign");
        std::fs::write(&foreign, b"definitely not a pursecraft store").unwrap();
        match LocalStore::open(&foreign) {
            Err(StoreError::Foreign { .. }) => {}
            other => panic!("expected foreign, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&foreign).unwrap(),
            b"definitely not a pursecraft store",
            "refused, not clobbered"
        );
        // A header from a future format version.
        let future = store_path(&tmp, "future");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&9u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&marker_bytes(0).unwrap());
        std::fs::write(&future, &bytes).unwrap();
        match LocalStore::open(&future) {
            Err(StoreError::UnsupportedVersion { found: 9, .. }) => {}
            other => panic!("expected a version rejection, got {other:?}"),
        }
        assert_eq!(bytes, std::fs::read(&future).unwrap(), "untouched");
        // A set reserved word: a format extension this core must not
        // misread as a plain log.
        let extended = store_path(&tmp, "extended");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes.extend_from_slice(&marker_bytes(0).unwrap());
        std::fs::write(&extended, &bytes).unwrap();
        match LocalStore::open(&extended) {
            Err(StoreError::UnsupportedVersion { .. }) => {}
            other => panic!("expected a version rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_torn_create_is_recreated_empty() {
        let tmp = TempDir::new("torn-create");
        let mut partials: Vec<Vec<u8>> = vec![b"".to_vec(), b"PCO".to_vec(), b"PCOPLOG\0".to_vec()];
        // A power cut inside the header: full magic, zero version, zero
        // marker (a fresh file's unwritten bytes are zero).
        let mut torn = MAGIC.to_vec();
        torn.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        partials.push(torn);
        for (i, partial) in partials.into_iter().enumerate() {
            let path = tmp.path().join(format!("partial-{i}.ops"));
            std::fs::write(&path, partial).unwrap();
            let store = LocalStore::open(&path).unwrap();
            assert_eq!(store.tip(), 0);
            drop(store);
            // And the store is usable afterwards.
            let mut store = LocalStore::open(&path).unwrap();
            let (field, value) = conv::amount(1);
            assert_eq!(store.append(conv::op(1, 10, 0, field, value)).unwrap(), 1);
        }
    }

    // ------------------------------------------------------------------
    // The 0017 convergence proofs, re-run against the backed engine
    // (ADR 0018): the log is a LocalStore, crashed and reopened mid-run;
    // the canonical reference is a session booted from the store.
    // ------------------------------------------------------------------

    const STORE_SEEDS: u64 = 10;

    #[test]
    fn n_devices_converge_through_the_store_backed_rendezvous_loop() {
        for seed in 1..=STORE_SEEDS {
            let ops = conv::generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut rng = Rng::new(seed.wrapping_mul(0x5851_F42D_4C95_7F2D));
            let tmp = TempDir::new("rendezvous");
            let path = store_path(&tmp, "budget");
            let mut store = LocalStore::open(&path).unwrap();
            let mut queues: Vec<std::collections::VecDeque<Op>> = (0..DEVICES)
                .map(|d| {
                    ops[d as usize * OPS_PER_DEVICE..(d as usize + 1) * OPS_PER_DEVICE]
                        .iter()
                        .cloned()
                        .collect()
                })
                .collect();
            let mut sessions: Vec<SyncSession> = (0..DEVICES).map(|_| SyncSession::new()).collect();
            let mut turns = 0u64;
            while queues.iter().any(|q| !q.is_empty()) {
                turns += 1;
                let d = rng.below(DEVICES) as usize;
                for _ in 0..1 + rng.below(4) {
                    if let Some(op) = queues[d].pop_front() {
                        store.append(op).expect("generated ops are well-formed");
                    }
                }
                for session in &mut sessions {
                    if rng.below(3) == 0 {
                        // Mostly pull only new ops; sometimes re-pull an
                        // overlap — at-least-once delivery.
                        let since = if rng.below(4) == 0 {
                            session.last_seen().saturating_sub(rng.below(5))
                        } else {
                            session.last_seen()
                        };
                        session
                            .apply_delta(store.delta_since(since))
                            .expect("generated ops are well-formed");
                    }
                }
                match turns {
                    // The rendezvous crashes and reboots from disk.
                    30 | 70 => store = LocalStore::open(&path).unwrap(),
                    // Device 0 reboots: a fresh session booted from the store.
                    50 => sessions[0] = boot_session(&store),
                    _ => {}
                }
            }
            for session in &mut sessions {
                // First full drain brings the session to the tip; a second
                // full re-delivery must be pure duplicates.
                let drained = session.apply_delta(store.delta_since(0)).unwrap();
                assert_eq!(drained.last_seen, store.tip());
                let summary = session.apply_delta(store.delta_since(0)).unwrap();
                assert_eq!(summary.last_seen, store.tip());
                assert_eq!(summary.applied, 0, "everything was already applied");
                assert_eq!(summary.stale, 0);
                assert_eq!(summary.duplicates, store.tip());
            }

            let reference = sessions[0].state().clone();
            for (i, session) in sessions.iter().enumerate() {
                assert_eq!(
                    session.state(),
                    &reference,
                    "device {i} diverged (seed {seed})"
                );
            }
            // The reference equals a session booted from the store itself.
            let canonical = boot_session(&store);
            assert_eq!(canonical.state(), &reference, "seed {seed}");
            assert_eq!(canonical.last_seen(), store.tip());
            assert_eq!(store.tip(), (DEVICES as usize * OPS_PER_DEVICE) as u64);

            // The forced equal-HLC tie: every replica's materialized value
            // is the op_id tie-break's pick (ADR 0016), asserted directly.
            let (tie_entity, tie_field, tie_value) = conv::expected_tie_value(&ops);
            let mut replicas = sessions.iter().map(|s| s.state());
            let first_tie = conv::materialized(
                replicas.next().expect("at least one session"),
                tie_entity,
                tie_field,
            );
            assert_eq!(first_tie, Some(tie_value), "seed {seed}");
            for state in replicas {
                assert_eq!(
                    conv::materialized(state, tie_entity, tie_field),
                    first_tie,
                    "seed {seed}"
                );
            }
            assert_eq!(
                conv::materialized(canonical.state(), tie_entity, tie_field),
                first_tie,
                "seed {seed}"
            );
        }
    }

    #[test]
    fn shuffled_delivery_converges_to_the_store_boot_state() {
        for seed in 1..=STORE_SEEDS {
            let ops = conv::generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9));
            let tmp = TempDir::new("delivery");
            let mut store = LocalStore::open(&store_path(&tmp, "budget")).unwrap();
            for op in &ops {
                store.append(op.clone()).unwrap();
            }
            // The reference is a session booted FROM the store (ADR 0018).
            let reference = boot_session(&store);
            let (tie_entity, tie_field, tie_value) = conv::expected_tie_value(&ops);
            assert_eq!(
                conv::materialized(reference.state(), tie_entity, tie_field),
                Some(tie_value.clone()),
                "reference tie-break (seed {seed})"
            );

            let mut rng = Rng::new(seed.wrapping_mul(0x94D0_49BB_1331_11EB));
            for device in 0..DEVICES {
                let mut delivery: Vec<SequencedOp> = ops
                    .iter()
                    .enumerate()
                    .map(|(i, op)| conv::sequenced(i as u64 + 1, op.clone()))
                    .collect();
                conv::shuffle(&mut rng, &mut delivery);
                let duplicates = delivery.len() / 8;
                for _ in 0..duplicates {
                    let at = rng.below(delivery.len() as u64 + 1) as usize;
                    let copy = delivery[rng.below(delivery.len() as u64) as usize].clone();
                    delivery.insert(at, copy);
                }
                let mut session = SyncSession::new();
                let mut rest = delivery.as_slice();
                while !rest.is_empty() {
                    let take = (1 + rng.below(7) as usize).min(rest.len());
                    let (batch, tail) = rest.split_at(take);
                    session
                        .apply_delta(batch)
                        .expect("generated ops are well-formed");
                    rest = tail;
                }
                assert_eq!(
                    session.state(),
                    reference.state(),
                    "device {device} diverged (seed {seed})"
                );
                assert_eq!(session.last_seen(), ops.len() as u64);
                assert_eq!(
                    conv::materialized(session.state(), tie_entity, tie_field),
                    Some(tie_value.clone()),
                    "device {device} tie-break (seed {seed})"
                );
            }
        }
    }
}
