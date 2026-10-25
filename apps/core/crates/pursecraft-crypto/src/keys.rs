//! Symmetric keys, device keys, and the key-wrapping constructions
//! (ADR 0022): XChaCha20-Poly1305 everywhere, X25519-ephemeral + HKDF-SHA256
//! for the device-facing wrap (the `age` X25519-recipient shape).
//!
//! All primitives come from the RustCrypto crates ADR 0009 named; the
//! compositions are fixed-parameter and domain-separated, and every wrap
//! binds its own identity (org/scope/epoch) as HKDF info AND AEAD
//! associated data, so a wrap replayed into a different slot fails both
//! ways — wrong key derivation and failed authentication.

use std::fmt;

use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::b64serde;
use crate::error::CryptoError;

/// The wire version of every wrap and envelope this crate emits (ADR 0022).
pub const FORMAT_VERSION: u16 = 1;

/// A random 256-bit symmetric key: org epoch keys and per-log data keys
/// are both this (ADR 0022). Zeroized on drop; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);

impl DataKey {
    /// A fresh key from the OS random generator.
    pub fn generate() -> Result<Self, CryptoError> {
        let generated = Key::try_generate().map_err(|e| CryptoError::Rng(e.to_string()))?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(generated.as_slice());
        Ok(Self(bytes))
    }

    /// From raw bytes — the unwrap path (and tests); 256 bits is the
    /// whole domain, there is nothing to validate.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes — for wrapping and AEAD use.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataKey(redacted)")
    }
}

/// The cipher instance for a key — the one construction site.
fn aead(key: &DataKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key.as_bytes()))
}

/// XChaCha20-Poly1305 with a fresh random 24-byte nonce — the one
/// encryption core of this crate; every envelope and wrap funnels here.
pub(crate) fn aead_seal(
    key: &DataKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let cipher = aead(key);
    let nonce = XNonce::try_generate().map_err(|e| CryptoError::Rng(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Auth)?;
    let mut n = [0u8; 24];
    n.copy_from_slice(nonce.as_slice());
    Ok((n, ciphertext))
}

/// The open half of [`aead_seal`]. One error for everything the AEAD
/// refuses — tamper, wrong key, wrong binding — returned as zeroized
/// bytes the caller copies out.
pub(crate) fn aead_open(
    key: &DataKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != 24 || ciphertext.len() < 16 {
        // The tag is 16 bytes; shorter can never authenticate. The AEAD
        // would say the same thing less clearly.
        return Err(CryptoError::Auth);
    }
    let n: [u8; 24] = nonce.try_into().expect("length checked above");
    let plaintext = aead(key)
        .decrypt(
            &XNonce::from(n),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Auth)?;
    Ok(Zeroizing::new(plaintext))
}

/// A device's public X25519 key — the wrap target (ADR 0022). The only
/// key material that travels in the clear, by design.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicKey(#[serde(with = "b64serde::b32")] pub(crate) [u8; 32]);

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are not secrets; a short prefix identifies one in
        // logs without making whole keys greppable.
        write!(f, "DevicePublicKey({:02x}…)", self.0[0])
    }
}

/// A device's X25519 keypair. The private half is zeroized on drop and
/// leaves the device only through [`DeviceKeypair::to_secret_bytes`] for
/// the platform keystore (ADR 0009) — the app shell's adapter, later.
pub struct DeviceKeypair {
    secret: StaticSecret,
}

impl DeviceKeypair {
    /// A fresh keypair from the OS random generator. In line with the
    /// crate's no-panic RNG stance, an OS RNG failure surfaces as
    /// [`CryptoError::Rng`] — nothing is half-created when it fires.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(
            <[u8; 32]>::try_generate().map_err(|e| CryptoError::Rng(e.to_string()))?,
        );
        Ok(Self {
            secret: StaticSecret::from(*bytes),
        })
    }

    /// Restore from keystore bytes ([`DeviceKeypair::to_secret_bytes`]).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Export the private half for the platform keystore.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The public half — the key other members wrap to.
    pub fn public(&self) -> DevicePublicKey {
        DevicePublicKey(x25519_dalek::x25519(
            self.secret.to_bytes(),
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }
}

impl fmt::Debug for DeviceKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKeypair(secret redacted)")
    }
}

/// HKDF-SHA256 with 32 bytes of output, for turning an ECDH shared
/// secret into a wrap key under a domain label.
fn derive(ikm: &[u8], info: &[u8]) -> DataKey {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes of OKM with SHA-256 is always in range.
    hk.expand(info, &mut *okm)
        .expect("32 bytes of OKM fit SHA-256 HKDF");
    DataKey::new(*okm)
}

use pursecraft_core::ids::{OrgId, ScopeId};

/// The binding bytes for an org-key wrap: domain label plus the wrap's
/// identity. Doubles as HKDF info and AEAD AAD, welding the wrap to its
/// `(org, epoch)` slot from both directions.
fn org_binding(org: &OrgId, epoch: u64) -> Zeroizing<Vec<u8>> {
    let mut info = Zeroizing::new(b"pursecraft.e2ee.v1/org-key".to_vec());
    info.extend_from_slice(org.as_uuid().as_bytes());
    info.extend_from_slice(&epoch.to_le_bytes());
    info
}

/// The binding bytes for a log-key wrap (same dual role).
fn log_binding(scope: &ScopeId, epoch: u64) -> Zeroizing<Vec<u8>> {
    let mut info = Zeroizing::new(b"pursecraft.e2ee.v1/log-key".to_vec());
    match scope {
        ScopeId::Org(org) => {
            info.push(0x01);
            info.extend_from_slice(org.as_uuid().as_bytes());
        }
        ScopeId::Budget(budget) => {
            info.push(0x02);
            info.extend_from_slice(budget.as_uuid().as_bytes());
        }
    }
    info.extend_from_slice(&epoch.to_le_bytes());
    info
}

/// A versioned record wrapping one org epoch key to one device
/// (ADR 0022): X25519-ephemeral + HKDF-SHA256 + XChaCha20-Poly1305 —
/// opaque bytes to everything but the recipient device. The rendezvous
/// channel relays these without interpreting them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct WrappedOrgKey {
    /// Format version (ADR 0022): [`FORMAT_VERSION`].
    pub v: u16,
    /// The org whose epoch key this carries.
    pub org: OrgId,
    /// The epoch the wrapped key serves.
    pub epoch: u64,
    /// The wrap's ephemeral X25519 public key.
    #[serde(with = "b64serde::b32")]
    pub eph: [u8; 32],
    /// 24-byte nonce.
    #[serde(with = "b64serde::b24")]
    pub n: [u8; 24],
    /// Ciphertext‖tag over the 32-byte epoch key.
    #[serde(with = "b64serde::bytes")]
    pub c: Vec<u8>,
}

impl WrappedOrgKey {
    /// Serialize to the opaque bytes the distribution channel carries.
    pub fn to_wire(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Parse from channel bytes.
    pub fn from_wire(wire: &str) -> serde_json::Result<Self> {
        serde_json::from_str(wire)
    }
}

/// A versioned record wrapping one per-log data key under its org's
/// same-epoch epoch key (ADR 0022) — symmetric all the way down.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct WrappedLogKey {
    /// Format version (ADR 0022): [`FORMAT_VERSION`].
    pub v: u16,
    /// The log this key opens.
    pub scope: ScopeId,
    /// The epoch the wrapped key serves.
    pub epoch: u64,
    /// 24-byte nonce.
    #[serde(with = "b64serde::b24")]
    pub n: [u8; 24],
    /// Ciphertext‖tag over the 32-byte log key.
    #[serde(with = "b64serde::bytes")]
    pub c: Vec<u8>,
}

impl WrappedLogKey {
    /// Serialize to the opaque bytes the distribution channel carries.
    pub fn to_wire(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Parse from channel bytes.
    pub fn from_wire(wire: &str) -> serde_json::Result<Self> {
        serde_json::from_str(wire)
    }
}

/// Wrap `key` to `recipient` as an org-epoch-key record. Any key-holding
/// member can wrap — the sender's identity is not part of the
/// construction (wrap authenticity is the channel's contract, ADR 0022).
pub(crate) fn wrap_org_key(
    recipient: &DevicePublicKey,
    org: &OrgId,
    epoch: u64,
    key: &DataKey,
) -> Result<WrappedOrgKey, CryptoError> {
    let binding = org_binding(org, epoch);
    // A single-use ephemeral by construction: minted as random bytes (an
    // OS RNG failure surfaces as an error, not a panic), consumed by one
    // ECDH, zeroized on drop.
    let eph_secret = StaticSecret::from(
        <[u8; 32]>::try_generate().map_err(|e| CryptoError::Rng(e.to_string()))?,
    );
    let eph_public =
        x25519_dalek::x25519(eph_secret.to_bytes(), x25519_dalek::X25519_BASEPOINT_BYTES);
    let shared = eph_secret.diffie_hellman(&XPublicKey::from(recipient.0));
    if !shared.was_contributory() {
        // A degenerate shared secret; refusing is standard X25519 hygiene.
        return Err(CryptoError::Auth);
    }
    let wrap_key = derive(shared.as_bytes(), &binding);
    let (n, c) = aead_seal(&wrap_key, &binding, key.as_bytes())?;
    Ok(WrappedOrgKey {
        v: FORMAT_VERSION,
        org: *org,
        epoch,
        eph: eph_public,
        n,
        c,
    })
}

/// Open an org-key wrap addressed to this device. The wrap's
/// `(org, epoch)` identity is welded into both the HKDF info and the
/// AEAD associated data (ADR 0022), so a doctored wrap — relabeled onto
/// another org or epoch — derives the wrong key and fails
/// authentication; nothing misrouted is ever stored.
pub(crate) fn open_org_wrap(
    device: &DeviceKeypair,
    wrap: &WrappedOrgKey,
) -> Result<DataKey, CryptoError> {
    if wrap.v != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(wrap.v));
    }
    let binding = org_binding(&wrap.org, wrap.epoch);
    let shared = device_open(device, &wrap.eph)?;
    let wrap_key = derive(shared.as_slice(), &binding);
    unwrap_key(&wrap_key, &binding, &wrap.n, &wrap.c)
}

/// Wrap `key` under `epoch_key`, as a log-key record for `scope`.
pub(crate) fn wrap_log_key(
    epoch_key: &DataKey,
    scope: &ScopeId,
    epoch: u64,
    key: &DataKey,
) -> Result<WrappedLogKey, CryptoError> {
    let binding = log_binding(scope, epoch);
    let (n, c) = aead_seal(epoch_key, &binding, key.as_bytes())?;
    Ok(WrappedLogKey {
        v: FORMAT_VERSION,
        scope: *scope,
        epoch,
        n,
        c,
    })
}

/// Open a log-key wrap with the org's same-epoch epoch key. The
/// `(scope, epoch)` binding rides the HKDF info and the AEAD associated
/// data alike — relabeled wraps fail authentication.
pub(crate) fn open_log_wrap(
    epoch_key: &DataKey,
    wrap: &WrappedLogKey,
) -> Result<DataKey, CryptoError> {
    if wrap.v != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(wrap.v));
    }
    let binding = log_binding(&wrap.scope, wrap.epoch);
    unwrap_key(epoch_key, &binding, &wrap.n, &wrap.c)
}

/// The static side of the device exchange: our long-term secret, the
/// wrap's ephemeral public key.
fn device_open(device: &DeviceKeypair, eph: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let shared = device.secret.diffie_hellman(&XPublicKey::from(*eph));
    if !shared.was_contributory() {
        return Err(CryptoError::Auth);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// AEAD-open a wrap and require exactly 32 bytes of key inside.
fn unwrap_key(
    wrap_key: &DataKey,
    binding: &[u8],
    n: &[u8],
    c: &[u8],
) -> Result<DataKey, CryptoError> {
    let plaintext = aead_open(wrap_key, binding, n, c)?;
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Auth)?;
    Ok(DataKey::new(bytes))
}
