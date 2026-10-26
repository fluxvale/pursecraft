//! The device's cryptographic home (ADR 0028): its X25519 device key, the key
//! records it holds, and the [`PayloadCipher`] every store and relay call is
//! opened through.
//!
//! Two files, both 0600 and both published with `session.json`'s atomic
//! discipline (ADR 0025): `device.key` holds the 32 raw bytes of the secret
//! and is never re-minted over; `keyring.json` holds the wrapped key records
//! the device received or minted — the same versioned strings the relay
//! carries, so local state and wire state are one format and no raw symmetric
//! key is ever written down.
//!
//! The mode is explicit. [`World::open`] takes the self-host switch, and both
//! directions of a ciphered/plaintext mismatch are refusals at the command's
//! front door rather than a store-level surprise — the envelope/plaintext
//! shape disjointness (ADR 0022) stays the backstop behind them.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use pursecraft_core::ids::{DeviceId, OrgId, ScopeId};
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::wire::{CipherError, OpMeta, PayloadCipher, PlainCipher};
use pursecraft_crypto::{CryptoError, DeviceKeypair, DevicePublicKey, Grant, KeyChain, KeyRecord};
use serde::{Deserialize, Serialize};

use crate::home::Identity;

/// The device secret's file name under the data home.
const DEVICE_FILE: &str = "device.key";
/// The key records' file name under the data home.
const KEYRING_FILE: &str = "keyring.json";
/// The keyring version this CLI writes and reads.
const KEYRING_VERSION: u16 = 1;

/// A failure building or using the device's key material. Every one is loud
/// and teaching; none ever guesses a mode (ADR 0028).
#[derive(Debug)]
pub enum KeysError {
    Io(std::io::Error),
    /// The self-host switch is off but this home's logs are ciphered.
    CipheredButOff {
        path: PathBuf,
    },
    /// E2EE is on but this home's logs were written without it.
    PlaintextButOn {
        path: PathBuf,
    },
    /// `device.key` is missing beside a keyring that holds key material —
    /// every wrap is bound to that key, so it is never re-minted over.
    MissingDeviceKey {
        path: PathBuf,
    },
    /// The device key is not 32 bytes — truncated or foreign.
    BadDeviceKey {
        path: PathBuf,
        len: usize,
    },
    /// The keyring holds records for this org that this device key cannot
    /// open — the key is not the one the world was created (or admitted)
    /// under. Every wrap is sealed to that key, so this is unrecoverable
    /// locally and must never be papered over with a fresh key.
    DeviceKeyMismatch {
        path: PathBuf,
    },
    /// `keyring.json` does not decode, or speaks another version.
    BadKeyring {
        path: PathBuf,
        detail: String,
    },
    /// A stored record does not install — the keyring and the device key
    /// disagree, or a wrap is missing the epoch key that opens it.
    KeyringRecord {
        index: usize,
        source: CryptoError,
    },
    /// This world holds no key material yet, so no op it holds can be read
    /// or written (ADR 0028's two-phase handoff).
    NoKeys,
    Crypto(CryptoError),
    Store(StoreError),
}

impl fmt::Display for KeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "key material io error: {e}"),
            Self::CipheredButOff { path } => write!(
                f,
                "{path:?} holds E2EE key material, so this home's logs are ciphered — \
                 unset PURSECRAFT_E2EE to read them"
            ),
            Self::PlaintextButOn { path } => write!(
                f,
                "{path:?} was written without E2EE — set PURSECRAFT_E2EE=off to read it, \
                 or start a fresh data home (a log never silently changes mode)"
            ),
            Self::MissingDeviceKey { path } => write!(
                f,
                "{path:?} is missing while this home's keyring holds key material — \
                 restore device.key from a backup; it is never re-minted over"
            ),
            Self::BadDeviceKey { path, len } => write!(
                f,
                "{path:?} is not a device key ({len} bytes, want 32) — restore it from a backup"
            ),
            Self::DeviceKeyMismatch { path } => write!(
                f,
                "{path:?} does not open this home's keyring — every key wrap is sealed to the \
                 device key that was there when the world was created, so this one is not it; \
                 restore device.key from a backup (re-minting it would make the world unreadable \
                 to every device, this one included)"
            ),
            Self::BadKeyring { path, detail } => {
                write!(f, "{path:?} is not a usable keyring: {detail}")
            }
            Self::KeyringRecord { index, source } => {
                write!(f, "keyring record {index} does not install: {source}")
            }
            Self::NoKeys => write!(
                f,
                "this world's key material is not here yet — run pursecraft sync on a device \
                 that holds this world, then pursecraft sync here"
            ),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeysError {}

impl From<std::io::Error> for KeysError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<StoreError> for KeysError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<CryptoError> for KeysError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// One device's held key material (ADR 0028). Cloning shares it, so every
/// store and every relay call in one command sees the same chain: a wrap
/// installed mid-command opens the ops pulled after it.
#[derive(Clone)]
pub struct Keys {
    sealed: Rc<KeyHolder>,
}

pub(crate) struct KeyHolder {
    chain: RefCell<KeyChain>,
    /// The installed records, verbatim — what `keyring.json` holds.
    records: RefCell<Vec<KeyringEntry>>,
    /// This home founded its world, so it mints missing keys. A joiner does
    /// not: its keys arrive wrapped from a key-holding device.
    founded: bool,
}

/// One keyring entry (ADR 0028): the record string verbatim, plus the org
/// that owns it — a budget log does not name its org (ADR 0021), so the owning
/// org is learned when the record arrives and remembered here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeyringEntry {
    org: Option<OrgId>,
    wire: String,
}

/// The mode a data home is in (ADR 0028). Three states, never two: "E2EE is on
/// but this world has no keys yet" is the joiner's honest state and must not
/// be confused with the self-host mode.
#[derive(Clone)]
enum Mode {
    /// `PURSECRAFT_E2EE=off`: plaintext payloads, no key material at all.
    Plain,
    /// E2EE, but this world holds no key material yet. `joining` tells the
    /// two honest cases apart: a fresh home (nothing exists, bootstrap will
    /// found it) and a joiner whose keyring is waiting for its wraps.
    Absent {
        joining: bool,
    },
    Sealed(Keys),
}

/// One data home and its key material — the value every command works on. Its
/// [`World::open_log`] is the CLI's ONLY store opener, so at rest and in
/// flight are the same cipher and no command can pick the wrong mode.
#[derive(Clone)]
pub struct World {
    pub home: PathBuf,
    mode: Mode,
}

impl fmt::Debug for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Key material never prints (ADR 0022); the mode and the home do.
        f.debug_struct("World")
            .field("home", &self.home)
            .field(
                "mode",
                &match self.mode {
                    Mode::Plain => "plain",
                    Mode::Absent { joining } => {
                        if joining {
                            "joining (no keys yet)"
                        } else {
                            "absent"
                        }
                    }
                    Mode::Sealed(_) => "sealed",
                },
            )
            .finish()
    }
}

impl World {
    /// The world at `home`, in the mode the caller selected (ADR 0028's
    /// self-host switch). A ciphered/plaintext mismatch refuses here, at the
    /// command's front door.
    pub fn open(home: impl Into<PathBuf>, e2ee: bool) -> Result<Self, KeysError> {
        let home = home.into();
        let mode = load_mode(&home, e2ee)?;
        Ok(Self { home, mode })
    }

    /// The self-host world: plaintext payloads, no key material (ADR 0009's
    /// no-E2EE mode). `PURSECRAFT_E2EE=off` and the plaintext tests build it.
    pub fn plain(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            mode: Mode::Plain,
        }
    }

    /// Whether payloads are sealed rather than plaintext — the *selected*
    /// mode, which is what the self-host switch and every guard speak about.
    pub fn is_sealed(&self) -> bool {
        !matches!(self.mode, Mode::Plain)
    }

    /// Whether this world can actually seal and open payloads right now.
    pub fn is_ready(&self) -> bool {
        matches!(self.mode, Mode::Plain | Mode::Sealed(_))
    }

    /// A join registered this device but the world's keys have not arrived
    /// yet (ADR 0028): every data command must say so, never render an empty
    /// budget that looks like a lost world. True for a keyring waiting to be
    /// filled and for a chain that holds no org epoch key at all.
    pub fn pending_join(&self) -> bool {
        match &self.mode {
            Mode::Absent { joining } => *joining,
            Mode::Plain => false,
            Mode::Sealed(keys) => {
                !keys.sealed.founded && keys.sealed.chain.borrow().held_orgs().is_empty()
            }
        }
    }

    /// The cipher for a store or a relay call — the same one on both sides.
    pub fn cipher(&self) -> Result<WorldCipher, KeysError> {
        match &self.mode {
            Mode::Plain => Ok(WorldCipher(WorldCipherInner::Plain)),
            Mode::Sealed(keys) => Ok(WorldCipher(WorldCipherInner::Sealed(Rc::clone(
                &keys.sealed,
            )))),
            Mode::Absent { .. } => Err(KeysError::NoKeys),
        }
    }

    /// Open (creating if absent) one of this world's logs (ADR 0021: one file
    /// per scope), sealed through this home's cipher.
    pub fn open_log(&self, scope: ScopeId) -> Result<LocalStore<WorldCipher>, KeysError> {
        // A keyless device refuses before touching the file: creating an
        // empty store for a scope it could never seal or open would leave
        // misleading evidence and a delayed failure (ADR 0028).
        if !self.holds_log_key(scope) {
            return Err(KeysError::NoKeys);
        }
        let path = crate::home::scope_log(&self.home, scope);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        Ok(LocalStore::open_with(&path, self.cipher()?)?)
    }

    /// The founding device's key mint (ADR 0028): create the device key and a
    /// founding keyring if absent, then mint epoch 0 for the org and one data
    /// key per log that has none. Idempotent and **resumable**: it runs on
    /// every capture of a home that founded its world, so a crash between the
    /// org key and a log key completes on the next command instead of leaving
    /// a permanently keyless home. Runs before the stores exist, so a crash
    /// leaves either a complete keyring or a resumable one, never an op sealed
    /// under a key that was not written down.
    pub fn found(&mut self, identity: &Identity, device: DeviceId) -> Result<(), KeysError> {
        match &self.mode {
            Mode::Plain => return Ok(()),
            Mode::Absent { .. } => {
                // A keyring with no device key (a crash inside `Keys::init`)
                // is completed here; nothing is bound yet.
                self.mode = Mode::Sealed(Keys::init(&self.home, true)?);
            }
            Mode::Sealed(keys) => {
                // Only a founding home mints; a joiner's keys arrive wrapped.
                if !keys.sealed.founded {
                    return Ok(());
                }
            }
        }
        if let Mode::Sealed(keys) = &self.mode {
            keys.ensure_founder_keys(&self.home, identity, device)?;
        }
        Ok(())
    }

    /// The joining device (ADR 0028's two-phase handoff): create the device
    /// key and an empty **joining** keyring. A joiner mints nothing — its keys
    /// arrive wrapped from a device that holds the world.
    pub fn join(&mut self) -> Result<(), KeysError> {
        match &self.mode {
            Mode::Plain => return Ok(()),
            Mode::Sealed(_) => return Ok(()),
            Mode::Absent { .. } => {}
        }
        self.mode = Mode::Sealed(Keys::init(&self.home, false)?);
        Ok(())
    }

    /// Whether this device can open `scope`'s log right now.
    pub fn holds_log_key(&self, scope: ScopeId) -> bool {
        match &self.mode {
            Mode::Plain => true,
            Mode::Absent { .. } => false,
            Mode::Sealed(keys) => keys.sealed.chain.borrow().holds_log_key(&scope),
        }
    }

    /// This device's public-key record — what the relay's registry carries so
    /// another member can wrap to it.
    pub fn device_record(&self, device: DeviceId) -> Option<String> {
        match &self.mode {
            Mode::Plain | Mode::Absent { .. } => None,
            Mode::Sealed(keys) => Some(
                KeyRecord::Device {
                    device,
                    public: keys.sealed.chain.borrow().device_public(),
                }
                .to_wire(),
            ),
        }
    }

    /// The epochs this device has already wrapped for `to` — read from its own
    /// keyring, so coverage is a fact the device controls rather than a claim
    /// it read off the relay (a member cannot suppress a peer's wrap this
    /// way; ADR 0028's consequence about wrap authenticity stands separately).
    pub fn wrapped_epochs_for(&self, org: OrgId, to: DeviceId) -> BTreeSet<u64> {
        let Mode::Sealed(keys) = &self.mode else {
            return BTreeSet::new();
        };
        keys.sealed
            .records
            .borrow()
            .iter()
            .filter_map(|entry| {
                let record = KeyRecord::parse(&entry.wire).ok()?;
                match record {
                    KeyRecord::Org { to: target, wrap } if target == to && wrap.org == org => {
                        Some(wrap.epoch)
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Wrap the org's held epoch keys to `to`, skipping the epochs this device
    /// has already wrapped for it (ADR 0028: coverage is real bookkeeping —
    /// without it every sync would mint a fresh wrap, and the relay's record
    /// set is append-only, so that would grow without bound toward the cap).
    ///
    /// The minted wraps are recorded in the keyring, which is what makes the
    /// next sync's coverage real. Coverage is read from this device's own
    /// keyring only, never from records the relay serves: a member could
    /// otherwise pre-empt a peer's wrap with a forged `to` and starve it.
    pub fn wraps_for(
        &self,
        org: OrgId,
        to: DeviceId,
        public: DevicePublicKey,
        _covered: &BTreeSet<u64>,
    ) -> Result<Vec<String>, KeysError> {
        let Mode::Sealed(keys) = &self.mode else {
            return Ok(Vec::new());
        };
        let covered = self.wrapped_epochs_for(org, to);
        let wraps = keys
            .sealed
            .chain
            .borrow()
            .wrap_org_keys_to(&org, &public, Grant::AllEpochs)?;
        let mut minted = Vec::new();
        for wrap in wraps {
            if covered.contains(&wrap.epoch) {
                continue;
            }
            let record = KeyRecord::Org { to, wrap };
            // Persist the mint: the next sync's coverage, and the record that
            // gets published, both come from here.
            keys.record(&self.home, Some(org), record.clone())?;
            minted.push(record.to_wire());
        }
        Ok(minted)
    }

    /// Install one pulled key record, persisting the keyring if it landed.
    /// Ownership is decided by the cryptography, not the record's labels: a
    /// wrap addressed to another device fails authentication and is a no-op.
    pub fn install(&self, wire: &str, org: OrgId) -> Result<bool, KeysError> {
        let Mode::Sealed(keys) = &self.mode else {
            return Ok(false);
        };
        keys.install(&self.home, wire, org)
    }

    /// The key records this device holds and the relay does not serve yet.
    pub fn unpublished(&self, published: &BTreeSet<String>) -> Vec<String> {
        match &self.mode {
            Mode::Plain | Mode::Absent { .. } => Vec::new(),
            Mode::Sealed(keys) => keys
                .sealed
                .records
                .borrow()
                .iter()
                .filter(|entry| {
                    // The keyring never holds a device record (they are not key
                    // material), but the parse makes the intent explicit.
                    !matches!(
                        KeyRecord::parse(&entry.wire).ok(),
                        Some(KeyRecord::Device { .. })
                    ) && !published.contains(&entry.wire)
                })
                .map(|entry| entry.wire.clone())
                .collect(),
        }
    }
}

/// Resolve a home's mode, refusing a ciphered/plaintext mismatch in either
/// direction (ADR 0028's no-silent-flip rule).
fn load_mode(home: &Path, e2ee: bool) -> Result<Mode, KeysError> {
    let keyring_path = home.join(KEYRING_FILE);
    let device_path = home.join(DEVICE_FILE);
    let has_keyring = keyring_path.try_exists()?;
    if !e2ee {
        if has_keyring {
            return Err(KeysError::CipheredButOff { path: keyring_path });
        }
        return Ok(Mode::Plain);
    }
    let device = read_device_key(&device_path)?;
    if !has_keyring {
        if device.is_some() {
            // The keyring publish precedes the device key's, so this state is
            // a damaged home, not a crash window.
            return Err(KeysError::BadKeyring {
                path: keyring_path,
                detail: "missing beside device.key".into(),
            });
        }
        if any_store_exists(home)? {
            return Err(KeysError::PlaintextButOn {
                path: home.to_owned(),
            });
        }
        return Ok(Mode::Absent { joining: false });
    }
    let (founded, stored) = read_keyring(&keyring_path)?;
    if device.is_none() {
        // The crash window inside `Keys::init` (keyring first, device key
        // second). A founding home completes it with the next capture; a
        // joiner completes it with the next `sync` (ADR 0028) — so the gate
        // must treat the two differently, or a founding home is locked out of
        // the very command that heals it.
        return Ok(Mode::Absent { joining: !founded });
    }
    let Some(device) = device else {
        if stored.is_empty() {
            // A joining device waiting for its wraps (or the crash window
            // inside `Keys::init`). Either way nothing is bound yet.
            return Ok(Mode::Absent { joining: true });
        }
        return Err(KeysError::MissingDeviceKey { path: device_path });
    };
    let mut chain = KeyChain::new(device);
    for (index, entry) in stored.iter().enumerate() {
        let record = KeyRecord::parse(&entry.wire).map_err(|source| KeysError::BadKeyring {
            path: keyring_path.clone(),
            detail: format!("record {index}: {source}"),
        })?;
        install_any(&mut chain, &record, entry.org)
            .map_err(|source| KeysError::KeyringRecord { index, source })?;
    }
    Ok(Mode::Sealed(Keys {
        sealed: Rc::new(KeyHolder {
            chain: RefCell::new(chain),
            records: RefCell::new(stored),
            founded,
        }),
    }))
}

impl Keys {
    /// Create the device key and an empty keyring of the given disposition,
    /// or adopt what exists. The keyring lands first and the device key
    /// second: an empty keyring binds no key material, so this order leaves
    /// exactly one resumable state (keyring present, device key absent) and
    /// never a wrap pointing at a key that never landed.
    fn init(home: &Path, founded: bool) -> Result<Self, KeysError> {
        fs::create_dir_all(home)?;
        let keyring_path = home.join(KEYRING_FILE);
        let (founded, stored) = match keyring_path.try_exists()? {
            true => read_keyring(&keyring_path)?,
            false => {
                let empty = KeyringWire {
                    v: KEYRING_VERSION,
                    founded,
                    records: Vec::new(),
                };
                publish(
                    &keyring_path,
                    &serde_json::to_vec_pretty(&empty).expect("a keyring encodes"),
                )?;
                (founded, Vec::new())
            }
        };
        let device_path = home.join(DEVICE_FILE);
        let device = match read_device_key(&device_path)? {
            Some(device) => device,
            None => {
                let device = DeviceKeypair::generate()?;
                publish(&device_path, &*device.to_secret_bytes())?;
                device
            }
        };
        Ok(Self {
            sealed: Rc::new(KeyHolder {
                chain: RefCell::new(KeyChain::new(device)),
                records: RefCell::new(stored),
                founded,
            }),
        })
    }

    /// A founder's key mint (ADR 0028): epoch 0 for the org it created, and
    /// one data key per log of the world. A scope is minted only when the
    /// chain lacks it *and* its store does not exist — a store whose key is
    /// missing is loud, never silently re-keyed into a log no peer can read.
    fn ensure_founder_keys(
        &self,
        home: &Path,
        identity: &Identity,
        device: DeviceId,
    ) -> Result<(), KeysError> {
        if !self.sealed.founded {
            return Ok(());
        }
        let org = identity.org_id;
        if self.sealed.chain.borrow().current_epoch(&org).is_none() {
            // A keyring that names this org while the chain holds no key for
            // it was sealed to a different device key. Minting a fresh epoch 0
            // would produce a world no peer (and no earlier op) can read, so
            // refuse and name the real problem (ADR 0028).
            if self
                .sealed
                .records
                .borrow()
                .iter()
                .any(|entry| entry.org == Some(org))
            {
                return Err(KeysError::DeviceKeyMismatch {
                    path: home.join(DEVICE_FILE),
                });
            }
            let wrap = self.sealed.chain.borrow_mut().create_org(org)?;
            self.record(home, Some(org), KeyRecord::Org { to: device, wrap })?;
        }
        for scope in scopes_of(identity) {
            if self.sealed.chain.borrow().holds_log_key(&scope) {
                continue;
            }
            if crate::home::scope_log(home, scope).try_exists()? {
                return Err(KeysError::Crypto(CryptoError::MissingEpoch {
                    scope,
                    epoch: 0,
                    held: None,
                }));
            }
            let wrap = self.sealed.chain.borrow_mut().add_log(org, scope)?;
            self.record(home, Some(org), KeyRecord::Log { wrap })?;
        }
        Ok(())
    }

    /// Install one record this device may hold, persisting the keyring when
    /// something new landed.
    fn install(&self, home: &Path, wire: &str, org: OrgId) -> Result<bool, KeysError> {
        let record = KeyRecord::parse(wire)?;
        if record.org().is_some_and(|named| named != org) {
            // Another org's record: not ours to judge, and never persisted
            // under the wrong owner.
            return Ok(false);
        }
        if self
            .sealed
            .records
            .borrow()
            .iter()
            .any(|entry| entry.wire == wire)
        {
            return Ok(false);
        }
        // Ownership is decided by the cryptography, not the labels — but only
        // "does not open for me" is a skip. A wrap addressed to this device
        // that fails with anything else is a loud conflict (ADR 0022: a held
        // slot holding different material is the rotation race, never a silent
        // no-op), and so is a log wrap whose epoch key this chain holds.
        match &record {
            KeyRecord::Device { .. } => return Ok(false),
            KeyRecord::Org { wrap, .. } => {
                match self.sealed.chain.borrow_mut().install_org_wrap(wrap) {
                    Ok(()) => {}
                    // A wrap sealed to another device's key derives the wrong
                    // wrap key and fails authentication. That is every other
                    // member's wrap, on every pull.
                    Err(CryptoError::Auth) => return Ok(false),
                    // Everything else — a held slot with different material above
                    // all — is the loud conflict ADR 0022 refuses to resolve
                    // silently, never a quiet skip.
                    Err(other) => return Err(KeysError::Crypto(other)),
                }
            }
            KeyRecord::Log { wrap } => {
                let holds_epoch_key = self
                    .sealed
                    .chain
                    .borrow()
                    .current_epoch(&org)
                    .is_some_and(|held| held >= wrap.epoch);
                match self
                    .sealed
                    .chain
                    .borrow_mut()
                    .install_log_wrap_for_org(wrap, &org)
                {
                    Ok(()) => {}
                    // A log wrap before its org wrap is the ordinary
                    // out-of-order pull; the two-pass install retries it, and
                    // the next sync retries again.
                    Err(CryptoError::MissingEpoch { .. }) if !holds_epoch_key => return Ok(false),
                    // Addressed at an epoch we hold, and it still refused:
                    // either a conflicting re-wrap of a held slot or a
                    // misroute — both loud (ADR 0022).
                    Err(other) => return Err(KeysError::Crypto(other)),
                }
            }
        }
        self.record(home, Some(org), record)?;
        Ok(true)
    }

    /// Persist one new keyring entry and keep it in memory — the single write
    /// path for both minting and installing.
    fn record(&self, home: &Path, org: Option<OrgId>, record: KeyRecord) -> Result<(), KeysError> {
        let entry = KeyringEntry {
            org,
            wire: record.to_wire(),
        };
        let mut records = self.sealed.records.borrow_mut();
        if records.contains(&entry) {
            return Ok(());
        }
        records.push(entry);
        let wire = KeyringWire {
            v: KEYRING_VERSION,
            founded: self.sealed.founded,
            records: records.clone(),
        };
        publish(
            &home.join(KEYRING_FILE),
            &serde_json::to_vec_pretty(&wire).expect("a keyring encodes"),
        )
    }
}

/// The `PayloadCipher` every CLI store and relay call goes through (ADRs 0009,
/// 0028): envelopes in E2EE mode, the identity in the self-host mode. A struct
/// over a private enum: the key holder stays unreachable from outside, while
/// `LocalStore<WorldCipher>` remains a nameable type.
#[derive(Clone)]
pub struct WorldCipher(WorldCipherInner);

#[derive(Clone)]
enum WorldCipherInner {
    Plain,
    Sealed(Rc<KeyHolder>),
}

impl fmt::Debug for WorldCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The store derives Debug over its cipher; key material never prints
        // (ADR 0022's hygiene clause), so this names the mode only.
        match self.0 {
            WorldCipherInner::Plain => f.write_str("WorldCipher::Plain"),
            WorldCipherInner::Sealed(_) => f.write_str("WorldCipher::Sealed"),
        }
    }
}

impl PayloadCipher for WorldCipher {
    fn seal(&self, meta: &OpMeta, plaintext: String) -> Result<String, CipherError> {
        match &self.0 {
            WorldCipherInner::Plain => PlainCipher.seal(meta, plaintext),
            WorldCipherInner::Sealed(sealed) => sealed
                .chain
                .borrow()
                .seal_payload(meta, plaintext.as_bytes())
                .map_err(|e| Box::new(e) as CipherError),
        }
    }

    fn open(&self, meta: &OpMeta, sealed: &str) -> Result<String, CipherError> {
        match &self.0 {
            WorldCipherInner::Plain => PlainCipher.open(meta, sealed),
            WorldCipherInner::Sealed(inner) => {
                let plaintext = inner
                    .chain
                    .borrow()
                    .open_payload(meta, sealed)
                    .map_err(|e| Box::new(e) as CipherError)?;
                String::from_utf8(plaintext).map_err(|e| Box::new(e) as CipherError)
            }
        }
    }
}

/// Fold one keyring record back into the chain at load (ADR 0028).
///
/// The keyring also holds wraps this device **minted for peers** — that is what
/// makes coverage real — and those do not open here. `Auth` is therefore the
/// ordinary "not addressed to me" answer and skips; everything else (a held
/// slot with different material above all) stays loud.
fn install_any(
    chain: &mut KeyChain,
    record: &KeyRecord,
    org: Option<OrgId>,
) -> Result<(), CryptoError> {
    match record {
        KeyRecord::Device { .. } => Ok(()),
        KeyRecord::Org { wrap, .. } => match chain.install_org_wrap(wrap) {
            Ok(()) | Err(CryptoError::Auth) => Ok(()),
            Err(other) => Err(other),
        },
        KeyRecord::Log { wrap } => {
            let org = org
                .or_else(|| record.org())
                .ok_or(CryptoError::WrongKeySlot)?;
            match chain.install_log_wrap_for_org(wrap, &org) {
                Ok(()) | Err(CryptoError::Auth) => Ok(()),
                Err(other) => Err(other),
            }
        }
    }
}

/// The world's two scopes (ADR 0021).
fn scopes_of(identity: &Identity) -> [ScopeId; 2] {
    [
        ScopeId::Org(identity.org_id),
        ScopeId::Budget(identity.budget_id),
    ]
}

/// Whether any log file exists under `home` — the evidence a plaintext home
/// leaves (ADR 0028's bind-by-evidence rule).
fn any_store_exists(home: &Path) -> Result<bool, KeysError> {
    for dir in ["orgs", "budgets"] {
        let entries = match fs::read_dir(home.join(dir)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            if entry?.path().extension().is_some_and(|ext| ext == "ops") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_device_key(path: &Path) -> Result<Option<DeviceKeypair>, KeysError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // The raw bytes are zeroized on drop; `StaticSecret` holds its own copy
    // (ADR 0022's hygiene clause).
    let len = bytes.len();
    let bytes = pursecraft_crypto::Zeroizing::new(bytes);
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeysError::BadDeviceKey {
            path: path.to_owned(),
            len,
        })?;
    Ok(Some(DeviceKeypair::from_secret_bytes(secret)))
}

/// The keyring's on-disk shape (ADR 0028).
#[derive(Serialize, Deserialize)]
struct KeyringWire {
    v: u16,
    founded: bool,
    records: Vec<KeyringEntry>,
}

fn read_keyring(path: &Path) -> Result<(bool, Vec<KeyringEntry>), KeysError> {
    let bytes = fs::read(path)?;
    let wire: KeyringWire = serde_json::from_slice(&bytes).map_err(|e| KeysError::BadKeyring {
        path: path.to_owned(),
        detail: e.to_string(),
    })?;
    if wire.v != KEYRING_VERSION {
        return Err(KeysError::BadKeyring {
            path: path.to_owned(),
            detail: format!(
                "version {} is not this pursecraft's {KEYRING_VERSION}",
                wire.v
            ),
        });
    }
    Ok((wire.founded, wire.records))
}

/// Publish a file durably and alone (the identity discipline, ADR 0023):
/// process-unique tmp, mode 0600, file fsync, rename, directory fsync. The
/// device key and the keyring are secrets; nothing here is wider than the
/// oplog beside them.
fn publish(path: &Path, bytes: &[u8]) -> Result<(), KeysError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    // A straggler from a crashed run under this pid would block the create;
    // it is a tmp file by name, never published content.
    let _ = fs::remove_file(&tmp);
    let write = || -> Result<(), KeysError> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    };
    write()?;
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idmint::mint_uuid;
    use crate::testsupport::TempDir;

    fn identity(home: &Path, device: DeviceId) -> Identity {
        crate::home::load_or_create_identity(home, device)
            .unwrap()
            .0
    }

    /// The founder's mint lands in the keyring and reloads into the same
    /// abilities — the at-rest half of ADR 0028's founder path.
    #[test]
    fn a_founder_mints_org_and_log_keys_that_reload() {
        let tmp = TempDir::new("keys-founder");
        let home = tmp.path();
        let device = DeviceId::new(mint_uuid()).unwrap();
        let identity = identity(home, device);
        let mut world = World::open(home, true).unwrap();
        assert!(world.is_sealed() && !world.is_ready(), "fresh, no keys yet");
        world.found(&identity, device).unwrap();
        assert!(world.holds_log_key(ScopeId::Org(identity.org_id)));
        assert!(world.holds_log_key(ScopeId::Budget(identity.budget_id)));

        let reloaded = World::open(home, true).unwrap();
        assert!(reloaded.is_ready(), "the keyring restores the chain");
        assert!(reloaded.holds_log_key(ScopeId::Budget(identity.budget_id)));
    }

    /// A world that holds no keys refuses to open a log — the loud joiner
    /// state, never a silent plaintext store (ADR 0028's third check).
    #[test]
    fn a_joiner_without_wraps_refuses_to_open_a_log() {
        let tmp = TempDir::new("keys-joiner");
        let home = tmp.path();
        let mut world = World::open(home, true).unwrap();
        world.join().unwrap();
        let scope = ScopeId::Org(OrgId::new(mint_uuid()).unwrap());
        let err = world.open_log(scope).unwrap_err();
        assert!(err.to_string().contains("not here yet"), "{err}");
    }

    /// Both directions of a mode mismatch refuse, and neither mints anything
    /// over the other's files.
    #[test]
    fn the_mode_guards_refuse_both_directions() {
        let tmp = TempDir::new("keys-mode");
        let home = tmp.path();
        let device = DeviceId::new(mint_uuid()).unwrap();
        let identity = identity(home, device);
        World::open(home, true)
            .unwrap()
            .found(&identity, device)
            .unwrap();

        let off = World::open(home, false).unwrap_err();
        assert!(off.to_string().contains("unset PURSECRAFT_E2EE"), "{off}");

        // A populated plaintext home, switch on: refused, naming the way out.
        let plain_home = TempDir::new("keys-mode-plain");
        let plain = World::plain(plain_home.path());
        plain
            .open_log(ScopeId::Budget(
                pursecraft_core::ids::BudgetId::new(mint_uuid()).unwrap(),
            ))
            .unwrap();
        let on = World::open(plain_home.path(), true).unwrap_err();
        assert!(on.to_string().contains("PURSECRAFT_E2EE=off"), "{on}");
    }

    /// `device.key` never lands before its keyring, so its presence without
    /// one is a damaged home — refused, never re-minted over.
    #[test]
    fn a_device_key_without_a_keyring_is_refused() {
        let tmp = TempDir::new("keys-orphan");
        let home = tmp.path();
        publish(&home.join(DEVICE_FILE), &[7u8; 32]).unwrap();
        assert!(matches!(
            World::open(home, true),
            Err(KeysError::BadKeyring { .. })
        ));
    }
}
