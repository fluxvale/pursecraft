//! The durable local oplog store (ADRs 0007, 0009, 0017, 0018, 0020): the
//! append-only framed file a real client boots the engine from — one file
//! per log scope, an org's or a budget's, content-blind to the difference.
//!
//! [`LocalStore`] wraps the 0017 [`OpLog`] — records carry their canonical
//! sequences, the `op_id` dedupe index is rebuilt on boot, and an append
//! commits when its frame and the header's commit marker land under one
//! `sync_data`. Applied state is never persisted: boot is replay through
//! the ordinary [`crate::sync::SyncSession`] path, so boot-from-store
//! equals in-memory replay by construction (ADR 0018).
//!
//! [`OpaqueStore`] is the same file format string-native (ADR 0024): rows
//! keep the payload as the exact string the transport carried — never
//! decoded, never validated — which is what the rendezvous relay requires
//! (payload opacity holds for bytes that are not choke-point output, the
//! ciphertext E2EE will produce) and what ADR 0018's "the string changes,
//! the shape does not" evolution anticipated.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ids::{OpId, ScopeId};
use crate::ops::Op;
use crate::sync::{LogError, OpLog, SequencedOp};
use crate::wire::{self, OpMeta, PayloadCipher, PlainCipher};

/// File magic; a strict prefix of it is a torn create (ADR 0018).
const MAGIC: [u8; 8] = *b"PCOPLOG\0";
/// Version 2: `OpMeta.scope` replaced `OpMeta.budget_id` (ADR 0021). No
/// read-old migration ships — version 1 was never released and exists in
/// no store outside test fixtures; a v1 file is refused loudly per ADR
/// 0018's contract, never misread.
const FORMAT_VERSION: u16 = 2;
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

/// The two-phase commit marker in the header (ADR 0018). `[seq][!seq]`
/// commits through `seq` — and, because phase two only runs after phase
/// one's sync, a durable committed marker implies its frame was durable
/// first. `[seq][seq]` is phase one's PENDING marker: it grants nothing,
/// because a crash can tear either phase (fsync is a durability barrier,
/// not an atomic multi-write). Anything else is a torn write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Marker {
    Committed(u64),
    Pending(u64),
    Torn,
}

fn marker_bytes(marker: Marker) -> Result<[u8; 8], StoreError> {
    let seq = match marker {
        Marker::Committed(seq) | Marker::Pending(seq) => seq,
        Marker::Torn => unreachable!("a torn marker is never encoded"),
    };
    let seq = u32::try_from(seq).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "store sequence exceeds the u32 commit marker",
        )
    })?;
    let other = match marker {
        Marker::Committed(_) => !seq,
        Marker::Pending(_) => seq,
        Marker::Torn => unreachable!(),
    };
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&seq.to_le_bytes());
    bytes[4..].copy_from_slice(&other.to_le_bytes());
    Ok(bytes)
}

/// The marker, as the header holds it. `Torn` covers absent and torn
/// writes alike — neither grants anything.
fn parse_marker(bytes: &[u8]) -> Marker {
    if bytes.len() < 8 {
        return Marker::Torn;
    }
    let seq = u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"));
    let other = u32::from_le_bytes(bytes[4..].try_into().expect("4 bytes"));
    if seq == !other {
        Marker::Committed(u64::from(seq))
    } else if seq == other {
        Marker::Pending(u64::from(seq))
    } else {
        Marker::Torn
    }
}

/// One stored op: its canonical sequence (a repair can leave gaps, so
/// sequences cannot be re-derived from position), the server-visible
/// metadata verbatim, and the payload as the choke-point string (ADRs
/// 0009, 0018) — the envelope string under E2EE, plaintext otherwise
/// (ADR 0022); the store is content-blind to the difference.
#[derive(Serialize, Deserialize, Debug)]
struct StoredOp {
    seq: u64,
    meta: OpMeta,
    payload: String,
}

/// Serialize one op into its frame under `seq` (ADR 0018). The payload
/// rides the choke point sealed by `cipher` (ADR 0022) — the frame carries
/// whatever the cipher emits.
fn encode_frame<C: PayloadCipher>(cipher: &C, op: &Op, seq: u64) -> Result<Vec<u8>, StoreError> {
    let (meta, payload) = op.clone().into_parts();
    let sealed = cipher
        .seal(&meta, wire::encode_payload(&payload)?)
        .map_err(StoreError::Cipher)?;
    encode_frame_parts(seq, &meta, &sealed)
}

/// Frame a stored record from its wire parts (ADR 0024): the shared body
/// of both stores' commits — the payload stays the caller's string
/// verbatim, whatever it holds.
fn encode_frame_parts(seq: u64, meta: &OpMeta, payload: &str) -> Result<Vec<u8>, StoreError> {
    let body = serde_json::to_vec(&StoredOp {
        seq,
        meta: meta.clone(),
        payload: payload.to_owned(),
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
    /// The frame is sound but the payload cipher refused it — missing or
    /// stale keys, failed authentication, a foreign envelope (ADR 0022).
    /// Never repaired over and never mislabeled corruption: the bytes are
    /// intact, the reader just cannot open them.
    Sealed(wire::CipherError),
}

/// Validate and decode the frame at `offset` (ADR 0018's framing rules),
/// opening the payload through `cipher` (ADR 0022).
fn scan_frame<C: PayloadCipher>(cipher: &C, bytes: &[u8], offset: usize) -> Scan {
    match scan_frame_parts(bytes, offset) {
        ScanParts::Op(stored, end) => {
            let plaintext = match cipher.open(&stored.meta, &stored.payload) {
                Ok(plaintext) => plaintext,
                Err(e) => return Scan::Sealed(e),
            };
            match wire::decode_payload(&plaintext) {
                Ok(payload) => Scan::Op(
                    SequencedOp {
                        seq: stored.seq,
                        op: Op::from_parts(stored.meta, payload),
                    },
                    end,
                ),
                Err(_) => Scan::Corrupt("op payload does not decode for this store's cipher"),
            }
        }
        ScanParts::Invalid => Scan::Invalid,
        ScanParts::Corrupt(reason) => Scan::Corrupt(reason),
    }
}

/// What the shared frame scanner found at one offset (ADR 0024): the
/// record as stored — payload still the verbatim string.
enum ScanParts {
    /// A valid frame; the offset just past it.
    Op(StoredOp, usize),
    /// Structurally incomplete or checksum-failed — a torn tail or
    /// mid-file damage; the caller classifies by resync (ADR 0018).
    Invalid,
    /// Checksum-valid bytes that cannot be a stored record — the writer
    /// never frames such bytes; loud without resync.
    Corrupt(&'static str),
}

/// The shared half of the client store's [`scan_frame`] (ADRs 0022,
/// 0024): framing, checksum, and the record's JSON — the payload
/// interior stays an unopened string, whatever it holds.
fn scan_frame_parts(bytes: &[u8], offset: usize) -> ScanParts {
    let remaining = bytes.len() - offset;
    if remaining < FRAME_OVERHEAD {
        return ScanParts::Invalid;
    }
    let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("length field"));
    if u64::from(len) > (remaining - FRAME_OVERHEAD) as u64 {
        return ScanParts::Invalid;
    }
    let end = offset + FRAME_OVERHEAD + len as usize;
    let body = &bytes[offset + FRAME_OVERHEAD..end];
    let checksum = u64::from_le_bytes(
        bytes[offset + 4..offset + FRAME_OVERHEAD]
            .try_into()
            .expect("checksum field"),
    );
    if fnv1a64(body) != checksum {
        return ScanParts::Invalid;
    }
    match serde_json::from_slice::<StoredOp>(body) {
        Ok(stored) => ScanParts::Op(stored, end),
        Err(_) => ScanParts::Corrupt("stored op does not decode"),
    }
}

/// Whether a checksum-valid frame starts somewhere after `from` — proof
/// that the writer produced frames beyond `from`, so damage at `from` is
/// mid-file corruption, not the torn tail (ADR 0018). Checksum-valid
/// framing cannot occur inside a torn write's bytes or crash garbage (a
/// 64-bit collision), so ONE frame is proof — which is why a stray
/// trailing byte, the crash artifact delayed allocation leaves, cannot
/// disguise corruption as a torn tail.
fn valid_frame_follows(bytes: &[u8], from: usize) -> bool {
    (from..bytes.len()).any(|start| frame_valid_at(bytes, start))
}

fn frame_valid_at(bytes: &[u8], start: usize) -> bool {
    let remaining = bytes.len() - start;
    if remaining < FRAME_OVERHEAD {
        return false;
    }
    let len = u32::from_le_bytes(bytes[start..start + 4].try_into().expect("length field"));
    if u64::from(len) > (remaining - FRAME_OVERHEAD) as u64 {
        return false;
    }
    let end = start + FRAME_OVERHEAD + len as usize;
    let body = &bytes[start + FRAME_OVERHEAD..end];
    let checksum = u64::from_le_bytes(
        bytes[start + 4..start + FRAME_OVERHEAD]
            .try_into()
            .expect("checksum field"),
    );
    fnv1a64(body) == checksum
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
    /// The payload cipher refused a record — missing/stale keys, failed
    /// authentication, a foreign envelope (ADR 0022). Loud and distinct
    /// from corruption: the bytes are intact, so the repair paths must
    /// not touch them.
    Cipher(wire::CipherError),
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
            Self::Cipher(e) => write!(f, "payload cipher refused a record: {e}"),
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
            Self::Cipher(e) => Some(e.as_ref()),
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
/// `sync_data`. Payloads ride the choke point through `C` — [`PlainCipher`]
/// stores plaintext; a sealing cipher stores envelopes, at rest and in
/// flight, with no store change (ADR 0022).
#[derive(Debug)]
pub struct LocalStore<C: PayloadCipher = PlainCipher> {
    log: OpLog,
    path: PathBuf,
    file: File,
    /// The file length the last successful commit covers — the boundary a
    /// failed append rolls back to.
    durable_len: u64,
    /// The last acknowledged sequence — what the header's committed
    /// marker holds (or would).
    hwm: u64,
    /// Set when a failed append could not roll back (ADR 0018).
    poisoned: bool,
    /// The payload cipher sealing every record (ADR 0022).
    cipher: C,
}

impl LocalStore<PlainCipher> {
    /// Open (creating if absent) the store at `path` with plaintext
    /// payloads — the no-E2EE mode (ADR 0009). See [`LocalStore::open_with`]
    /// for the ciphered store; everything else about the two is identical.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with(path, PlainCipher)
    }
}

impl<C: PayloadCipher> LocalStore<C> {
    /// Open (creating if absent) the store at `path`, sealing payloads
    /// through `cipher`, rebuilding the in-memory log from disk. An
    /// uncommitted torn tail is repaired; foreign, corrupt, and
    /// unsupported files fail loudly; committed sequences are never
    /// reused (ADR 0018). A record the cipher cannot open fails as
    /// [`StoreError::Cipher`] — the repair paths never touch intact bytes
    /// a key would open (ADR 0022).
    pub fn open_with(path: &Path, cipher: C) -> Result<Self, StoreError> {
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Self::create(path, cipher),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let marker = match parse_header(&bytes, path)? {
            HeaderState::TornCreate => {
                Self::recreate(&mut file)?;
                return Ok(Self::empty(path, file, cipher));
            }
            HeaderState::Valid(marker) => marker,
        };

        let (records, offset, file_max) =
            walk_frames(&mut file, &bytes, path, |b, o| scan_op_frame(&cipher, b, o))?;

        // Resume the sequence space above everything ever acknowledged or
        // ever claimed by a record on disk — the loaded tip, or the
        // committed marker if committed frames were lost to damage — a
        // gap then, which stalls watermarks visibly by design (ADR 0017)
        // and never reuses a sequence a peer may have seen (ADR 0018). A
        // pending or torn marker grants nothing: its commit never acked,
        // so the loaded frames are all that was observable.
        let acked = resume_above(marker, file_max);
        let mut log = OpLog::resuming_at(acked + 1);
        for record in records {
            log.append_sequenced(record.seq, record.op)
                .map_err(StoreError::Scope)?;
        }
        Ok(Self {
            log,
            path: path.to_owned(),
            file,
            durable_len: offset,
            hwm: acked,
            poisoned: false,
            cipher,
        })
    }

    /// Append one op durably; returns its canonical sequence. Scoping and
    /// `op_id` dedupe follow the in-memory log exactly (ADR 0017): an op
    /// scoped to the wrong budget is rejected, a re-append returns the
    /// original sequence and writes nothing. The commit is two-phase (ADR 0018):
    /// the frame plus a PENDING marker under one sync, then the COMMITTED
    /// marker under a second — so a durable committed marker always
    /// implies a durable frame. A phase-one failure rolls the file back
    /// (poisoning the store if even that fails); a phase-two failure
    /// keeps the durable frame and reports the failed ack.
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
        if let Some(log_scope) = self.log.scope_id()
            && log_scope != op.scope
        {
            return Err(LogError::ScopeMismatch {
                op_scope: op.scope,
                log_scope,
            }
            .into());
        }
        if let Some(seq) = self.log.seq_of(&op.op_id) {
            return Ok(seq);
        }
        let seq = self.log.next_seq();
        let frame = encode_frame(&self.cipher, &op, seq)?;
        let committed_len = self.durable_len;
        let previous_marker = marker_bytes(Marker::Committed(self.hwm))?;
        // Phase one: the frame and its PENDING marker, durable together.
        // The pending marker grants nothing — a crash can tear either
        // phase (ADR 0018).
        let pending = marker_bytes(Marker::Pending(seq))?;
        if let Err(e) = commit_frame(&mut self.file, committed_len, &frame, &pending) {
            // Restore the previous marker, drop any partial frame, and
            // make both durable; if even the rollback fails the store is
            // unusable until reopened (ADR 0018).
            if rollback(&mut self.file, &previous_marker, committed_len).is_err() {
                self.poisoned = true;
            }
            return Err(e.into());
        }
        // Phase two: the COMMITTED marker — durable only after the frame
        // is, so a durable committed marker implies a durable frame.
        let committed_marker = marker_bytes(Marker::Committed(seq))?;
        let phase_two = commit_marker(&mut self.file, &committed_marker);
        self.durable_len = committed_len + frame.len() as u64;
        self.hwm = seq;
        // Scope and dedupe were checked above; this append cannot fail.
        // A phase-two failure still leaves the frame durable and the log
        // consistent — boot resolves any marker state — so the append
        // stands and the error reports the failed ack (ADR 0018).
        let assigned = self.log.append(op).map_err(StoreError::Scope)?;
        phase_two?;
        Ok(assigned)
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

    /// The scope this store is scoped to — an org or a budget — once the
    /// first op fixes it (ADR 0021).
    pub fn scope_id(&self) -> Option<ScopeId> {
        self.log.scope_id()
    }

    fn empty(path: &Path, file: File, cipher: C) -> Self {
        Self {
            log: OpLog::new(),
            path: path.to_owned(),
            file,
            durable_len: HEADER_LEN as u64,
            hwm: 0,
            poisoned: false,
            cipher,
        }
    }

    /// Create a fresh store: the header (version, zero marker) goes down
    /// durably first, then the directory entry (ADR 0018). The caller has
    /// just seen the path not exist (single writer per path is the
    /// caller's contract).
    fn create(path: &Path, cipher: C) -> Result<Self, StoreError> {
        let file = create_log_file(path)?;
        Ok(Self::empty(path, file, cipher))
    }

    /// Rewrite the header over a torn create (no committed data exists).
    fn recreate(file: &mut File) -> Result<(), StoreError> {
        rewrite_header(file)
    }
}

/// Create a fresh log file: the header (version, zero marker) durable
/// first, then the directory entry (ADR 0018). Shared by both stores; the
/// caller has just seen the path not exist (single writer per path is the
/// caller's contract).
fn create_log_file(path: &Path) -> Result<File, StoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(&header())?;
    file.sync_data()?;
    sync_parent_dir(path);
    Ok(file)
}

/// Rewrite the header over a torn create — no committed data exists
/// (ADR 0018).
fn rewrite_header(file: &mut File) -> Result<(), StoreError> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header())?;
    Ok(file.sync_data()?)
}

/// What boot found in the header region (ADRs 0018, 0024 — shared by both
/// stores).
enum HeaderState {
    /// A full supported header; the commit marker it carries. Frames, if
    /// any, start at `HEADER_LEN`.
    Valid(Marker),
    /// A torn create: no committed data can predate the header fsync, so
    /// the caller recreates over it (ADR 0018).
    TornCreate,
}

/// Parse magic, version, reserved word, and the torn-create shapes
/// (ADR 0018). Version and reserved are checked the moment they are
/// readable — before any recreate decision — so a truncated file from a
/// future format is refused, never rewritten over.
fn parse_header(bytes: &[u8], path: &Path) -> Result<HeaderState, StoreError> {
    // A strict prefix of the magic is a torn create; anything else foreign.
    if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
        if MAGIC.starts_with(bytes) {
            return Ok(HeaderState::TornCreate);
        }
        return Err(StoreError::Foreign {
            path: path.to_owned(),
        });
    }
    let version = if bytes.len() >= 10 {
        Some(u16::from_le_bytes(
            bytes[8..10].try_into().expect("version field"),
        ))
    } else {
        None
    };
    if let Some(version) = version
        && version != 0
        && version != FORMAT_VERSION
    {
        return Err(StoreError::UnsupportedVersion {
            path: path.to_owned(),
            found: version,
            supported: FORMAT_VERSION,
        });
    }
    let reserved = (bytes.len() >= 12)
        .then(|| u16::from_le_bytes(bytes[10..12].try_into().expect("reserved field")));
    if let Some(reserved) = reserved
        && version == Some(FORMAT_VERSION)
        && reserved != 0
    {
        return Err(StoreError::UnsupportedVersion {
            path: path.to_owned(),
            found: reserved,
            supported: FORMAT_VERSION,
        });
    }
    // A torn create is a file that cannot hold committed data — the
    // header write is one prefix, and frames only ever follow its fsync:
    // a file too short to hold the header, or a full-length header that
    // carries nothing (zero version, zero reserved, a marker claiming no
    // commits — the crash-inside-create state, where the size is durable
    // but the page is not), is recreated (ADR 0018).
    if bytes.len() < HEADER_LEN {
        return Ok(HeaderState::TornCreate);
    }
    // `bytes.len() >= HEADER_LEN` holds here, so the reserved word was
    // readable above.
    let marker = parse_marker(&bytes[HWM_OFFSET..HEADER_LEN]);
    if version == Some(0) {
        if bytes.len() == HEADER_LEN
            && reserved == Some(0)
            && !matches!(marker, Marker::Committed(1..))
        {
            return Ok(HeaderState::TornCreate);
        }
        // A zero version beside frames — or beside a marker that claims
        // commits — is damage or foreign: refused, never recreated over,
        // or one flipped bit would silently wipe every committed op
        // (ADR 0018).
        return Err(StoreError::UnsupportedVersion {
            path: path.to_owned(),
            found: 0,
            supported: FORMAT_VERSION,
        });
    }
    Ok(HeaderState::Valid(marker))
}

/// One step of boot's frame walk (ADRs 0018, 0024): what the store-specific
/// decoder found at an offset.
enum Step<T> {
    /// A valid frame: its sequence, the store's lifted record, and the
    /// offset just past it.
    Op { seq: u64, record: T, end: usize },
    /// Structurally incomplete or checksum-failed — torn tail or mid-file
    /// damage; the walk classifies by resync.
    Invalid,
    /// Checksum-valid bytes that cannot be a stored record — loud without
    /// resync.
    Corrupt(&'static str),
    /// The frame is sound but the payload cipher refused it — intact
    /// bytes the reader cannot open (ADR 0022). Never repaired over,
    /// never mislabeled corruption. Only the ciphered client path
    /// produces this; the relay store's payload strings are never
    /// opened at all (ADR 0024).
    Sealed(wire::CipherError),
}

/// The client store's step: payload-decoded ops for replay, opened
/// through `cipher` (ADRs 0018, 0022).
fn scan_op_frame<C: PayloadCipher>(cipher: &C, bytes: &[u8], offset: usize) -> Step<SequencedOp> {
    match scan_frame(cipher, bytes, offset) {
        Scan::Op(record, end) => Step::Op {
            seq: record.seq,
            record,
            end,
        },
        Scan::Invalid => Step::Invalid,
        Scan::Corrupt(reason) => Step::Corrupt(reason),
        Scan::Sealed(e) => Step::Sealed(e),
    }
}

/// The relay store's step: the record verbatim, payload string unopened
/// (ADR 0024).
fn scan_parts_frame(bytes: &[u8], offset: usize) -> Step<StoredOp> {
    match scan_frame_parts(bytes, offset) {
        ScanParts::Op(stored, end) => Step::Op {
            seq: stored.seq,
            record: stored,
            end,
        },
        ScanParts::Invalid => Step::Invalid,
        ScanParts::Corrupt(reason) => Step::Corrupt(reason),
    }
}

/// Boot's frame walk (ADR 0018), shared by both stores: records in file
/// order with their sequences checked monotonic and in the u32 marker's
/// reach, the torn tail cut and the cut made durable, mid-file damage loud
/// by resync proof. Returns the lifted records, the offset committed data
/// ends at, and the highest sequence ever framed.
fn walk_frames<T, F: Fn(&[u8], usize) -> Step<T>>(
    file: &mut File,
    bytes: &[u8],
    path: &Path,
    step: F,
) -> Result<(Vec<T>, u64, u64), StoreError> {
    let mut records = Vec::new();
    let mut offset = HEADER_LEN;
    let mut prev_seq = 0u64;
    while offset < bytes.len() {
        match step(bytes, offset) {
            Step::Op { seq, record, end } => {
                // Records carry their sequences; the writer's are strictly
                // increasing, 1-based, within the u32 marker's reach —
                // anything else is tampering, loud (ADR 0018).
                if seq == 0 || seq <= prev_seq || seq > u64::from(u32::MAX) {
                    return Err(StoreError::Corrupt {
                        path: path.to_owned(),
                        offset: offset as u64,
                        reason: "record sequence must increase within 1..=u32::MAX",
                    });
                }
                prev_seq = seq;
                records.push(record);
                offset = end;
            }
            Step::Invalid => {
                // Classify by resync: ONE checksum-valid frame beyond the
                // damage proves mid-file corruption — loud, file
                // untouched. No valid frame after it is the crash window's
                // torn tail: cut it and make the cut durable (ADR 0018).
                if valid_frame_follows(bytes, offset + 1) {
                    return Err(StoreError::Corrupt {
                        path: path.to_owned(),
                        offset: offset as u64,
                        reason: "frame is invalid but a valid frame follows it",
                    });
                }
                file.set_len(offset as u64)?;
                file.sync_all()?;
                break;
            }
            Step::Sealed(e) => {
                // Intact bytes the reader cannot open — a key problem,
                // not file damage (ADR 0022): refuse without touching
                // the file.
                return Err(StoreError::Cipher(e));
            }
            Step::Corrupt(reason) => {
                return Err(StoreError::Corrupt {
                    path: path.to_owned(),
                    offset: offset as u64,
                    reason,
                });
            }
        }
    }
    Ok((records, offset as u64, prev_seq))
}

/// The sequence a fresh append resumes from, per the marker and the
/// highest framed sequence (ADR 0018): above everything ever acknowledged
/// or ever claimed by a record on disk. A pending or torn marker grants
/// nothing — its commit never acked.
fn resume_above(marker: Marker, file_max: u64) -> u64 {
    match marker {
        Marker::Committed(committed) => committed.max(file_max),
        Marker::Pending(_) | Marker::Torn => file_max,
    }
}

/// One relay-served record (ADR 0024): sequence, server-visible metadata,
/// and the payload as the exact string the transport carried.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PartsRow<'a> {
    pub seq: u64,
    pub meta: &'a OpMeta,
    pub payload: &'a str,
}

/// The string-native oplog store (ADR 0024): [ADR 0018]'s durable format
/// with the payload kept as the verbatim string the transport carried —
/// never decoded, never validated. This is the rendezvous relay's whole
/// durable state per scope, and the shape [ADR 0018] anticipated for the
/// day the payload string holds ciphertext: what the string holds changes,
/// the framing does not. Sequencing, `op_id` dedupe, scope fixity, the
/// two-phase commit, torn-tail repair, and never-reuse-a-sequence follow
/// [`LocalStore`] exactly — the one difference is that no payload
/// interior is ever opened.
#[derive(Debug)]
pub struct OpaqueStore {
    rows: Vec<StoredOp>,
    seen: HashMap<OpId, u64>,
    scope: Option<ScopeId>,
    path: PathBuf,
    file: File,
    /// The file length the last successful commit covers — the boundary a
    /// failed append rolls back to.
    durable_len: u64,
    /// The last acknowledged sequence — what the header's committed
    /// marker holds (or would).
    hwm: u64,
    /// The sequence the next append assigns — resumed above everything
    /// ever acknowledged or framed (ADR 0018).
    next_seq: u64,
    /// Set when a failed append could not roll back (ADR 0018).
    poisoned: bool,
}

impl OpaqueStore {
    /// Open (creating if absent) the store at `path`, rebuilding the
    /// in-memory rows, `op_id` index, and scope from disk. An uncommitted
    /// torn tail is repaired; foreign, corrupt, and unsupported files
    /// fail loudly; committed sequences are never reused (ADR 0018). A
    /// file mixing scopes is a loud [`StoreError::Scope`], exactly as a
    /// client store's boot replay would refuse one.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::empty(path, create_log_file(path)?));
            }
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let marker = match parse_header(&bytes, path)? {
            HeaderState::TornCreate => {
                rewrite_header(&mut file)?;
                return Ok(Self::empty(path, file));
            }
            HeaderState::Valid(marker) => marker,
        };
        let (mut rows, durable_len, file_max) =
            walk_frames(&mut file, &bytes, path, scan_parts_frame)?;
        let acked = resume_above(marker, file_max);
        // Scope fixity: every row must carry the same scope — a mixed
        // file is loud, exactly as LocalStore's boot replay refuses one
        // (ADRs 0018, 0024).
        let mut scope = None;
        for row in &rows {
            if let Some(log_scope) = scope
                && log_scope != row.meta.scope
            {
                return Err(LogError::ScopeMismatch {
                    op_scope: row.meta.scope,
                    log_scope,
                }
                .into());
            }
            scope = Some(row.meta.scope);
        }
        // Dedupe follows [`LocalStore`]'s boot (ADR 0024): the FIRST row
        // for an op_id wins — a crafted file's later twin is skipped,
        // never served.
        let mut seen = HashMap::new();
        rows.retain(|row| match seen.entry(row.meta.op_id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(row.seq);
                true
            }
        });
        Ok(Self {
            rows,
            seen,
            scope,
            path: path.to_owned(),
            file,
            durable_len,
            hwm: acked,
            next_seq: acked + 1,
            poisoned: false,
        })
    }

    /// Append one record from its wire parts; returns its canonical
    /// sequence. The payload string is stored verbatim — no decode, no
    /// validation, whatever it holds (ADR 0024). Scoping checks first (the
    /// scope is metadata), then dedupe by `op_id`: re-appending returns
    /// the original sequence and writes nothing, regardless of payload
    /// bytes (safe retries, ADR 0007). The commit is two-phase exactly as
    /// [`LocalStore::append`] (ADR 0018).
    pub fn append_parts(&mut self, meta: OpMeta, payload: &str) -> Result<u64, StoreError> {
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
        if let Some(log_scope) = self.scope
            && log_scope != meta.scope
        {
            return Err(LogError::ScopeMismatch {
                op_scope: meta.scope,
                log_scope,
            }
            .into());
        }
        if self.scope.is_none() {
            self.scope = Some(meta.scope);
        }
        if let Some(seq) = self.seen.get(&meta.op_id) {
            return Ok(*seq);
        }
        let seq = self.next_seq;
        let frame = encode_frame_parts(seq, &meta, payload)?;
        let committed_len = self.durable_len;
        let previous_marker = marker_bytes(Marker::Committed(self.hwm))?;
        // Phase one: the frame and its PENDING marker, durable together.
        // The pending marker grants nothing — a crash can tear either
        // phase (ADR 0018).
        let pending = marker_bytes(Marker::Pending(seq))?;
        if let Err(e) = commit_frame(&mut self.file, committed_len, &frame, &pending) {
            // Restore the previous marker, drop any partial frame, and
            // make both durable; if even the rollback fails the store is
            // unusable until reopened (ADR 0018).
            if rollback(&mut self.file, &previous_marker, committed_len).is_err() {
                self.poisoned = true;
            }
            return Err(e.into());
        }
        // Phase two: the COMMITTED marker — durable only after the frame
        // is, so a durable committed marker implies a durable frame.
        let committed_marker = marker_bytes(Marker::Committed(seq))?;
        let phase_two = commit_marker(&mut self.file, &committed_marker);
        self.durable_len = committed_len + frame.len() as u64;
        self.hwm = seq;
        // Scope and dedupe were checked above; this append cannot fail. A
        // phase-two failure still leaves the frame durable and the rows
        // consistent — boot resolves any marker state — so the append
        // stands and the error reports the failed ack (ADR 0018).
        self.seen.insert(meta.op_id, seq);
        self.rows.push(StoredOp {
            seq,
            meta,
            payload: payload.to_owned(),
        });
        self.next_seq = seq + 1;
        phase_two?;
        Ok(seq)
    }

    /// The records with sequence greater than `since`, in canonical
    /// order, payloads verbatim (ADRs 0007, 0024) — the same contract as
    /// [`LocalStore::delta_since`].
    pub fn delta_parts_since(&self, since: u64) -> impl Iterator<Item = PartsRow<'_>> {
        self.rows
            .iter()
            .skip_while(move |row| row.seq <= since)
            .map(|row| PartsRow {
                seq: row.seq,
                meta: &row.meta,
                payload: &row.payload,
            })
    }

    /// The highest assigned sequence.
    pub fn tip(&self) -> u64 {
        self.rows.last().map(|row| row.seq).unwrap_or(0)
    }

    /// The scope this store is fixed to — an org's or a budget's — once
    /// the first record fixes it (ADR 0021).
    pub fn scope_id(&self) -> Option<ScopeId> {
        self.scope
    }

    /// The canonical sequence already assigned to `op_id`, if this store
    /// holds it — the dedupe lookup behind a push response's `stored`
    /// flag (ADR 0024).
    pub fn seq_of(&self, op_id: &OpId) -> Option<u64> {
        self.seen.get(op_id).copied()
    }

    fn empty(path: &Path, file: File) -> Self {
        Self {
            rows: Vec::new(),
            seen: HashMap::new(),
            scope: None,
            path: path.to_owned(),
            file,
            durable_len: HEADER_LEN as u64,
            hwm: 0,
            next_seq: 1,
            poisoned: false,
        }
    }
}

/// Phase one of a commit: the frame at the committed boundary plus the
/// PENDING marker in the header, made durable together (ADR 0018).
fn commit_frame(file: &mut File, at: u64, frame: &[u8], pending: &[u8; 8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.write_all(frame)?;
    file.seek(SeekFrom::Start(HWM_OFFSET as u64))?;
    file.write_all(pending)?;
    file.sync_data()
}

/// Phase two: the COMMITTED marker, durable only after phase one's sync —
/// so a durable committed marker implies a durable frame (ADR 0018).
fn commit_marker(file: &mut File, committed: &[u8; 8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(HWM_OFFSET as u64))?;
    file.write_all(committed)?;
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
    header[HWM_OFFSET..HEADER_LEN]
        .copy_from_slice(&marker_bytes(Marker::Committed(0)).expect("zero marker"));
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
        assert_eq!(store.scope_id(), None);
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
            Marker::Committed(0),
            "a fresh store's marker commits through zero"
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
        assert_eq!(store.scope_id(), Some(ScopeId::Budget(conv::budget())));
        drop(store);

        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(reopened.tip(), 3);
        assert_eq!(reopened.scope_id(), Some(ScopeId::Budget(conv::budget())));
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
        foreign.scope = ScopeId::Budget(crate::ids::BudgetId::new(v7(9, 9)).unwrap());
        assert!(matches!(
            store.append(foreign),
            Err(StoreError::Scope(LogError::ScopeMismatch { .. }))
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
        for scope in conv::scopes() {
            for seed in 1..=3u64 {
                let ops = conv::generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), scope);
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
    }

    #[test]
    fn reordered_and_duplicated_appends_boot_to_the_replay_state() {
        for scope in conv::scopes() {
            for seed in 1..=3u64 {
                let ops = conv::generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9), scope);
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
            // (ADR 0018). A cut into the header destroys the marker
            // with the file — external destruction, not a crash state —
            // and the path starts a fresh 1-based space (ADR 0018's
            // carve-out).
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
    fn a_stray_tail_byte_cannot_disguise_mid_file_corruption() {
        // Rot in a middle frame plus ONE stray crash-artifact byte at EOF:
        // a checksum-valid frame still follows the damage, and that alone
        // proves corruption — the resync must not demand a chain ending
        // exactly at EOF, or the stray byte silently truncates every
        // committed frame after the damage (ADR 0018).
        let tmp = TempDir::new("stray-byte");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 8);
        drop(store);
        let good = std::fs::read(&path).unwrap();

        let mut starts = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < good.len() {
            starts.push(offset);
            let len = u32::from_le_bytes(good[offset..offset + 4].try_into().unwrap()) as usize;
            offset += FRAME_OVERHEAD + len;
        }

        for damaged in [0usize, 4] {
            let mut bytes = good.clone();
            bytes[starts[damaged] + FRAME_OVERHEAD] ^= 0xff;
            bytes.push(0x00);
            let path = store_path(&tmp, &format!("stray-{damaged}"));
            std::fs::write(&path, &bytes).unwrap();
            match LocalStore::open(&path) {
                Err(StoreError::Corrupt { offset, .. }) => {
                    assert_eq!(offset, starts[damaged] as u64);
                }
                other => panic!("expected corruption, got {other:?}"),
            }
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "the loud path never rewrites the file"
            );
        }
    }

    #[test]
    fn a_pending_marker_grants_nothing() {
        // A crash between the two phases can leave a PENDING marker on
        // disk — even one whose frame never landed, if the disk persisted
        // the 8 marker bytes and lost the frame. Pending never grants, so
        // boot resumes densely — the phantom-gap wedge is unreachable
        // through the commit protocol (ADR 0018).
        let tmp = TempDir::new("pending");
        let src = store_path(&tmp, "src");
        let (store, _) = filled_store(&src, 3);
        drop(store);
        let good = std::fs::read(&src).unwrap();

        for (label, pending_seq) in [("frame-lost", 4u64), ("far-ahead", 99u64)] {
            let mut bytes = good.clone();
            bytes[HWM_OFFSET..HEADER_LEN]
                .copy_from_slice(&marker_bytes(Marker::Pending(pending_seq)).unwrap());
            let path = store_path(&tmp, label);
            std::fs::write(&path, &bytes).unwrap();
            let mut store = LocalStore::open(&path).unwrap();
            assert_eq!(store.tip(), 3, "pending marker {pending_seq} adds nothing");
            let (field, value) = conv::amount(31);
            assert_eq!(
                store.append(conv::op(90, 90, 0, field, value)).unwrap(),
                4,
                "the space resumes densely after pending marker {pending_seq}"
            );
            drop(store);
            // And the appended op stands with its dense sequence.
            let store = LocalStore::open(&path).unwrap();
            let seqs: Vec<u64> = store.delta_since(0).map(|s| s.seq).collect();
            assert_eq!(seqs, [1, 2, 3, 4]);
        }
    }

    #[test]
    fn tampered_record_sequences_are_refused() {
        // Records carry their sequences; the writer's are strictly
        // increasing, 1-based, within the u32 marker's reach. Anything
        // else is tampering — loud (ADR 0018).
        let tmp = TempDir::new("bad-seqs");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 3);
        drop(store);
        let good = std::fs::read(&path).unwrap();

        let mut starts = Vec::new();
        let mut offset = HEADER_LEN;
        while offset < good.len() {
            starts.push(offset);
            let len = u32::from_le_bytes(good[offset..offset + 4].try_into().unwrap()) as usize;
            offset += FRAME_OVERHEAD + len;
        }

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
        for (label, record_index, seq) in [
            ("zero", 1usize, serde_json::json!(0u64)),
            ("duplicate", 1, serde_json::json!(1u64)),
            ("backwards", 1, serde_json::json!(99u64)),
        ] {
            let mut body = frame_body(record_index);
            body["seq"] = seq;
            let mut bytes = good[..starts[record_index]].to_vec();
            bytes.extend_from_slice(&reframe(&body));
            // Keep the following frames so a too-large sequence is
            // actually observed to break the increase.
            if record_index + 1 < starts.len() {
                bytes.extend_from_slice(&good[starts[record_index + 1]..]);
            }
            let path = store_path(&tmp, label);
            std::fs::write(&path, &bytes).unwrap();
            match LocalStore::open(&path) {
                Err(StoreError::Corrupt { .. }) => {}
                other => panic!("expected corruption for {label} seq, got {other:?}"),
            }
        }
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

        // (d) A valid frame scoped to a foreign log: loud through the
        // log's own scoping (ADRs 0008, 0020).
        let mut foreign = frame_body(1);
        foreign["meta"]["scope"] = serde_json::json!({"Budget": v7(9, 9).to_string()});
        let mut bytes = good[..starts[1]].to_vec();
        bytes.extend_from_slice(&reframe(&foreign));
        write("foreign-budget", &bytes);
        match LocalStore::open(&store_path(&tmp, "foreign-budget")) {
            Err(StoreError::Scope(LogError::ScopeMismatch { .. })) => {}
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
        // Two records sharing an op_id can only be written by tampering —
        // the API dedupes — and boot resolves them the way the log must:
        // first wins, by op_id alone (the E2EE-safe rule; a re-encrypted
        // retry carries different payload bytes, ADR 0017). Identical
        // duplicated bytes would also collide on sequence and fail the
        // boot-time increase check; the crafted different-sequence shape
        // here is the one that exercises the collapse.
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
        // Give store two's record a fresh sequence (2) so the splice is a
        // pure op_id collision.
        let len = u32::from_le_bytes(b[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize;
        let mut body: serde_json::Value = serde_json::from_slice(
            &b[HEADER_LEN + FRAME_OVERHEAD..HEADER_LEN + FRAME_OVERHEAD + len],
        )
        .unwrap();
        body["seq"] = serde_json::json!(2u64);
        let body = serde_json::to_vec(&body).unwrap();
        let mut reframed = Vec::with_capacity(FRAME_OVERHEAD + body.len());
        reframed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        reframed.extend_from_slice(&fnv1a64(&body).to_le_bytes());
        reframed.extend_from_slice(&body);

        let mut spliced = a[..HEADER_LEN].to_vec();
        spliced.extend_from_slice(&a[HEADER_LEN..]);
        spliced.extend_from_slice(&reframed);
        let spliced_path = store_path(&tmp, "spliced");
        std::fs::write(&spliced_path, &spliced).unwrap();

        let mut store = LocalStore::open(&spliced_path).unwrap();
        assert_eq!(store.tip(), 1, "one op serves, at its own sequence");
        let seqs: Vec<u64> = store.delta_since(0).map(|s| s.seq).collect();
        assert_eq!(seqs, [1]);
        let ops: Vec<Op> = store.delta_since(0).map(|s| s.op.clone()).collect();
        assert_eq!(ops[0].value, conv::amount(111).1, "first record wins");
        // The collapsed record still claimed sequence 2 on disk, so the
        // space resumes above it — a later append cannot collide and
        // corrupt the next reopen.
        let (field, value) = conv::amount(41);
        assert_eq!(store.append(conv::op(70, 70, 0, field, value)).unwrap(), 3);
        drop(store);
        LocalStore::open(&spliced_path).unwrap();
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
        // A header from a future format version — refused even when the
        // file is too short to hold the full header (ADR 0018).
        let future = store_path(&tmp, "future");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&9u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&marker_bytes(Marker::Committed(0)).unwrap());
        std::fs::write(&future, &bytes).unwrap();
        match LocalStore::open(&future) {
            Err(StoreError::UnsupportedVersion { found: 9, .. }) => {}
            other => panic!("expected a version rejection, got {other:?}"),
        }
        assert_eq!(bytes, std::fs::read(&future).unwrap(), "untouched");
        // A truncated future header: magic + version 9 + reserved, 12
        // bytes — refused, not recreated over.
        let short = store_path(&tmp, "short-future");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&9u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        std::fs::write(&short, &bytes).unwrap();
        match LocalStore::open(&short) {
            Err(StoreError::UnsupportedVersion { found: 9, .. }) => {}
            other => panic!("expected a version rejection, got {other:?}"),
        }
        assert_eq!(bytes, std::fs::read(&short).unwrap(), "untouched");
        // A set reserved word: a format extension this core must not
        // misread as a plain log.
        let extended = store_path(&tmp, "extended");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes.extend_from_slice(&marker_bytes(Marker::Committed(0)).unwrap());
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
        // Power cuts inside the 20-byte header: the write is one prefix,
        // so these carry nothing after the header by construction.
        for tail in [4usize, 8] {
            let mut torn = MAGIC.to_vec();
            torn.extend(std::iter::repeat_n(0u8, tail));
            partials.push(torn);
        }
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
        // A crash inside create() itself: the file's size is durable but
        // its page is not — exactly HEADER_LEN bytes, zero-filled after
        // the magic. A torn create by the ADR's own definition (nothing
        // is committed), so it is recreated, not bricked.
        let mut crashed_create = MAGIC.to_vec();
        crashed_create.extend(std::iter::repeat_n(0u8, 12));
        let path = tmp.path().join("crashed-create.ops");
        std::fs::write(&path, &crashed_create).unwrap();
        let mut store = LocalStore::open(&path).unwrap();
        assert_eq!(store.tip(), 0);
        let (field, value) = conv::amount(1);
        assert_eq!(store.append(conv::op(1, 10, 0, field, value)).unwrap(), 1);
        drop(store);

        // The same shape with the fresh marker intact (a version-byte rot
        // on an empty store): still nothing to lose — recreated.
        let mut empty_rot = MAGIC.to_vec();
        empty_rot.extend_from_slice(&[0, 0, 0, 0]);
        empty_rot.extend_from_slice(&marker_bytes(Marker::Committed(0)).unwrap());
        let path = tmp.path().join("empty-rot.ops");
        std::fs::write(&path, &empty_rot).unwrap();
        assert_eq!(LocalStore::open(&path).unwrap().tip(), 0);

        // But a full-length header that CLAIMS commits is refused — the
        // claimed sequences were observable, and recreating would discard
        // that knowledge (ADR 0018).
        let mut claims = MAGIC.to_vec();
        claims.extend_from_slice(&[0, 0, 0, 0]);
        claims.extend_from_slice(&marker_bytes(Marker::Committed(5)).unwrap());
        let path = tmp.path().join("claims.ops");
        std::fs::write(&path, &claims).unwrap();
        assert!(matches!(
            LocalStore::open(&path),
            Err(StoreError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_rotted_version_byte_is_refused_not_wiped() {
        // One flipped bit in the version of a populated store must never
        // recreate it — that would silently discard every committed op.
        // Only the version's low byte decodes to zero, so only it could
        // have been the silent wipe; both bytes are refused (ADR 0018).
        let tmp = TempDir::new("version-rot");
        let path = store_path(&tmp, "src");
        let (store, _) = filled_store(&path, 20);
        drop(store);
        let good = std::fs::read(&path).unwrap();
        assert!(good.len() > HEADER_LEN, "the store holds committed ops");

        for (label, byte) in [("low", 8usize), ("high", 9)] {
            let mut bytes = good.clone();
            bytes[byte] ^= 0x01;
            let path = store_path(&tmp, label);
            std::fs::write(&path, &bytes).unwrap();
            match LocalStore::open(&path) {
                Err(StoreError::UnsupportedVersion { .. }) => {}
                other => panic!("expected a version rejection, got {other:?}"),
            }
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "untouched");
        }
    }

    // ------------------------------------------------------------------
    // The 0017 convergence proofs, re-run against the backed engine
    // (ADR 0018): the log is a LocalStore, crashed and reopened mid-run;
    // the canonical reference is a session booted from the store.
    // ------------------------------------------------------------------

    const STORE_SEEDS: u64 = 10;

    /// Both scopes (ADR 0021): the budget log's proof, re-run as an org
    /// log's — same engine, same store, org-entity pools.
    #[test]
    fn n_devices_converge_through_the_store_backed_rendezvous_loop() {
        for scope in conv::scopes() {
            for seed in 1..=STORE_SEEDS {
                let ops = conv::generate_ops(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), scope);
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
                let mut sessions: Vec<SyncSession> =
                    (0..DEVICES).map(|_| SyncSession::new()).collect();
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
    }

    /// Both scopes (ADR 0021): shuffled delivery against the store boot
    /// state.
    #[test]
    fn shuffled_delivery_converges_to_the_store_boot_state() {
        for scope in conv::scopes() {
            for seed in 1..=STORE_SEEDS {
                let ops = conv::generate_ops(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9), scope);
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

    /// Boot-from-store for an org log specifically (ADR 0021): org ops
    /// persist, boot, and resolve exactly as budget ops do — here
    /// asserted on the org projections, not just state equality.
    #[test]
    fn an_org_store_boots_into_the_resolved_org_state() {
        use crate::domain::{EntityKind, Field, OrgField, Value};
        use crate::ids::{EntityId, OrgId, UserId};
        use crate::ops::Op;

        let ms: u64 = 1 << 40;
        let org = OrgId::new(v7(ms, 1)).unwrap();
        let scope = ScopeId::Org(org);
        let terence = UserId::new(v7(ms, 90)).unwrap();
        let partner = UserId::new(v7(ms, 91)).unwrap();
        let write = |i: u64, kind: EntityKind, entity_rand: u64, field: Field, value: Value| Op {
            op_id: crate::ids::OpId::new(v7(ms + i, i)).unwrap(),
            scope,
            device_id: crate::ids::DeviceId::new(Uuid::nil()).unwrap(),
            user_id: terence,
            entity_kind: kind,
            entity_id: EntityId::new(v7(ms, entity_rand)).unwrap(),
            field,
            value,
            hlc: crate::hlc::Hlc {
                physical_ms: ms + i,
                logical: 0,
            },
        };
        let ops = vec![
            write(
                1,
                EntityKind::Organization,
                1,
                Field::Organization(OrgField::PersonalFor),
                Value::User(terence),
            ),
            write(
                2,
                EntityKind::Membership,
                2,
                Field::Membership(crate::domain::MembershipField::UserId),
                Value::User(terence),
            ),
            write(
                3,
                EntityKind::Membership,
                2,
                Field::Membership(crate::domain::MembershipField::Role),
                Value::Role(crate::domain::MembershipRole::Owner),
            ),
            write(
                4,
                EntityKind::Membership,
                3,
                Field::Membership(crate::domain::MembershipField::UserId),
                Value::User(partner),
            ),
            write(
                5,
                EntityKind::Membership,
                3,
                Field::Membership(crate::domain::MembershipField::Role),
                Value::Role(crate::domain::MembershipRole::Viewer),
            ),
            write(
                6,
                EntityKind::Budget,
                4,
                Field::Budget(crate::domain::BudgetField::Name),
                Value::Text("Home".into()),
            ),
        ];

        let tmp = TempDir::new("orgstore");
        let path = store_path(&tmp, "org");
        let mut store = LocalStore::open(&path).unwrap();
        for op in &ops {
            store.append(op.clone()).unwrap();
        }
        assert_eq!(store.scope_id(), Some(scope));
        drop(store);

        // Boot: reopen from disk, replay, and resolve — the personal org
        // invariant and both roles survive the round trip.
        let reopened = LocalStore::open(&path).unwrap();
        assert_eq!(reopened.scope_id(), Some(scope));
        let session = boot_session(&reopened);
        let state = session.state();
        assert_eq!(crate::org::live_personal_orgs([state], terence), vec![org]);
        assert_eq!(
            crate::org::membership_role(state, terence),
            Some(crate::domain::MembershipRole::Owner)
        );
        assert_eq!(
            crate::org::membership_role(state, partner),
            Some(crate::domain::MembershipRole::Viewer)
        );
        assert_eq!(crate::org::visible_budgets(state).len(), 1);
    }

    /// Version 1 stores (the pre-scope meta shape) are refused loudly —
    /// never misread (ADRs 0018, 0020). Nothing was ever released on v1,
    /// so no read-old migration exists.
    #[test]
    fn a_version_1_store_is_refused_loudly() {
        let tmp = TempDir::new("v1");
        let path = store_path(&tmp, "v1");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PCOPLOG\0");
        bytes.extend_from_slice(&1u16.to_le_bytes()); // version 1
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&marker_bytes(Marker::Committed(0)).unwrap());
        std::fs::write(&path, &bytes).unwrap();
        match LocalStore::open(&path) {
            Err(StoreError::UnsupportedVersion { found, .. }) => assert_eq!(found, 1),
            other => panic!("expected a version refusal, got {other:?}"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "untouched");
    }

    // ------------------------------------------------------------------
    // OpaqueStore (ADR 0024): the same durable format, string-native —
    // the payload is never decoded, so bytes that are not choke-point
    // output (the ciphertext E2EE will produce) round-trip verbatim.
    // ------------------------------------------------------------------

    /// The meta half of a deterministic op, for building records from
    /// parts.
    fn meta(op_rand: u64, scope: ScopeId) -> OpMeta {
        let mut op = conv::op(op_rand, 10, 0, conv::amount(1).0, conv::amount(1).1);
        op.scope = scope;
        op.into_parts().0
    }

    fn budget_scope() -> ScopeId {
        ScopeId::Budget(conv::budget())
    }

    fn org_scope() -> ScopeId {
        ScopeId::Org(conv::org())
    }

    use crate::wire::OpPayload;

    #[test]
    fn opaque_rows_round_trip_verbatim_across_restarts() {
        let tmp = TempDir::new("opaque-roundtrip");
        let path = store_path(&tmp, "opaque");
        let scope = budget_scope();
        let payload = |text: &str| {
            wire::encode_payload(&OpPayload {
                entity_kind: crate::domain::EntityKind::Transaction,
                entity_id: crate::ids::EntityId::new(v7(conv::ID_MS, 50)).unwrap(),
                field: Field::Transaction(crate::domain::TransactionField::Memo),
                value: Value::Text(text.into()),
            })
            .unwrap()
        };
        // A canonical payload string, and two that are NOT choke-point
        // output — the ciphertext shapes E2EE will produce. All must ride
        // untouched.
        let plaintext = payload("groceries ₱");
        let ciphertext = "enc:v1:AAAA-not-json-at-all==".to_string();
        let keywrap = "{\"wrapped\":[\"opaque\",\"bytes\"]}".to_string();
        let records = [
            (meta(1, scope), plaintext),
            (meta(2, scope), ciphertext.clone()),
            (meta(3, scope), keywrap),
        ];
        let mut store = OpaqueStore::open(&path).unwrap();
        for (i, (meta, payload)) in records.iter().enumerate() {
            assert_eq!(
                store.append_parts(meta.clone(), payload).unwrap(),
                i as u64 + 1
            );
        }
        assert_eq!(store.tip(), 3);
        assert_eq!(store.scope_id(), Some(scope));
        drop(store);

        let reopened = OpaqueStore::open(&path).unwrap();
        let rows: Vec<(u64, String)> = reopened
            .delta_parts_since(0)
            .map(|row| (row.seq, row.payload.to_owned()))
            .collect();
        assert_eq!(
            rows,
            vec![
                (1, records[0].1.clone()),
                (2, ciphertext),
                (3, records[2].1.clone()),
            ],
            "payload strings ride verbatim, sequences dense"
        );
        // The cursor is exclusive, like the log's delta_since.
        assert_eq!(reopened.delta_parts_since(2).next().unwrap().seq, 3);
        assert!(reopened.delta_parts_since(3).next().is_none());
    }

    #[test]
    fn opaque_dedupe_is_by_op_id_alone_across_restarts() {
        let tmp = TempDir::new("opaque-dedupe");
        let path = store_path(&tmp, "opaque");
        let scope = budget_scope();
        let first = meta(7, scope);
        let mut store = OpaqueStore::open(&path).unwrap();
        assert_eq!(store.append_parts(first.clone(), "first-bytes").unwrap(), 1);
        // Same op_id, different payload bytes — the re-encrypted retry
        // (ADR 0017): the original sequence comes back, nothing is
        // written.
        assert_eq!(store.append_parts(first.clone(), "other-bytes").unwrap(), 1);
        assert_eq!(store.tip(), 1);
        assert_eq!(store.seq_of(&first.op_id), Some(1));
        drop(store);

        let mut reopened = OpaqueStore::open(&path).unwrap();
        assert_eq!(reopened.tip(), 1);
        assert_eq!(
            reopened.append_parts(first, "post-restart retry").unwrap(),
            1
        );
        assert_eq!(
            reopened.append_parts(meta(8, scope), "fresh").unwrap(),
            2,
            "the sequence space continues"
        );
    }

    #[test]
    fn a_foreign_scope_is_rejected_at_append_and_boot() {
        let tmp = TempDir::new("opaque-scope");
        let path = store_path(&tmp, "opaque");
        let mut store = OpaqueStore::open(&path).unwrap();
        store
            .append_parts(meta(1, budget_scope()), "bytes")
            .unwrap();
        // At append: the scope is metadata — exactly what a relay routes
        // on (ADR 0021).
        assert!(matches!(
            store.append_parts(meta(2, org_scope()), "bytes"),
            Err(StoreError::Scope(LogError::ScopeMismatch { .. }))
        ));
        assert_eq!(store.tip(), 1);
        drop(store);

        // At boot: a file mixing scopes is hand-crafted by appending a
        // foreign record's frame behind the store's back.
        let foreign = meta(2, org_scope());
        let frame = encode_frame_parts(2, &foreign, "smuggled").unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&frame).unwrap();
        drop(file);
        assert!(matches!(
            OpaqueStore::open(&path),
            Err(StoreError::Scope(LogError::ScopeMismatch { .. }))
        ));
    }

    #[test]
    fn both_stores_read_the_same_file_format() {
        // A relay-written file whose payloads happen to decode boots in
        // the client store and replays identically — one format, two
        // readers (ADRs 0018, 0024).
        let tmp = TempDir::new("opaque-format");
        let path = store_path(&tmp, "shared");
        let (field, value) = conv::amount(42);
        let ops: Vec<Op> = (1..=3)
            .map(|i| conv::op(i, 10 + i, 0, field, value.clone()))
            .collect();
        let mut relay = OpaqueStore::open(&path).unwrap();
        for op in &ops {
            let (meta, payload) = op.clone().into_parts();
            relay
                .append_parts(meta, &wire::encode_payload(&payload).unwrap())
                .unwrap();
        }
        drop(relay);

        let client = LocalStore::open(&path).unwrap();
        assert_eq!(
            boot_session(&client).state(),
            in_memory_session(&ops).state()
        );
    }

    #[test]
    fn an_opaque_boot_collapses_duplicate_op_id_rows_first_wins() {
        // A crafted file carrying the same op_id twice serves the FIRST
        // row only — the same first-wins rule the client store's boot
        // replay applies (ADRs 0018, 0024).
        let tmp = TempDir::new("opaque-dup");
        let path = store_path(&tmp, "opaque");
        let scope = budget_scope();
        let mut store = OpaqueStore::open(&path).unwrap();
        store.append_parts(meta(1, scope), "first").unwrap();
        drop(store);

        // Hand-append a later twin frame under the same op_id (honest
        // framing, monotonic sequence — only the id collides).
        let twin = meta(1, scope);
        let frame = encode_frame_parts(2, &twin, "smuggled-twin").unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&frame).unwrap();
        drop(file);

        let reopened = OpaqueStore::open(&path).unwrap();
        let rows: Vec<(u64, &str)> = reopened
            .delta_parts_since(0)
            .map(|row| (row.seq, row.payload))
            .collect();
        assert_eq!(rows, vec![(1, "first")], "the twin is skipped, not served");
        assert_eq!(reopened.tip(), 1);
        assert_eq!(reopened.seq_of(&twin.op_id), Some(1));
    }

    #[test]
    fn an_opaque_torn_tail_is_repaired_and_sequences_are_not_reused() {
        let tmp = TempDir::new("opaque-torn");
        let path = store_path(&tmp, "opaque");
        let scope = budget_scope();
        let mut store = OpaqueStore::open(&path).unwrap();
        store.append_parts(meta(1, scope), "one").unwrap();
        store.append_parts(meta(2, scope), "two").unwrap();
        drop(store);

        // Tear the tail mid-frame, inside record 3's frame.
        let mut bytes = std::fs::read(&path).unwrap();
        let full_len = bytes.len();
        store = OpaqueStore::open(&path).unwrap();
        store
            .append_parts(meta(3, scope), "three-plus-padding")
            .unwrap();
        drop(store);
        bytes = std::fs::read(&path).unwrap();
        bytes.truncate(full_len + 6);
        std::fs::write(&path, &bytes).unwrap();

        let mut reopened = OpaqueStore::open(&path).unwrap();
        assert_eq!(reopened.tip(), 2, "the torn frame grants nothing");
        assert_eq!(
            reopened
                .append_parts(meta(4, scope), "after-repair")
                .unwrap(),
            4,
            "the committed-but-lost sequence 3 is never reused — a visible \
             gap, exactly as the client store's repair contract (ADR 0018)"
        );
        let rows: Vec<u64> = reopened.delta_parts_since(0).map(|r| r.seq).collect();
        assert_eq!(rows, vec![1, 2, 4]);
    }
}
