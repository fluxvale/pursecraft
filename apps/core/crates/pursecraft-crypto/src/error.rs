//! Crypto failures (ADR 0022) — every one is loud, and none of them ever
//! labels intact bytes as damage: the caller decides what to do with the
//! file, channel, or keychain; this side only says what went wrong.

use std::fmt;

use pursecraft_core::ids::ScopeId;

/// Why a crypto operation refused. Deliberately coarse where the
/// cryptography itself is coarse (AEAD failures do not distinguish tamper
/// from wrong key — by design), precise where the protocol can be.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CryptoError {
    /// Authentication failed — tampered ciphertext, wrong key, or wrong
    /// binding. The AEAD's answer, undifferentiated on purpose.
    Auth,
    /// The string is not an envelope this version understands — wrong
    /// version marker, wrong shape, undecodable base64 (ADR 0022: the
    /// strip/downgrade class; plaintext payload strings land here too).
    NotAnEnvelope,
    /// An envelope or wrap written by a future version (v != 1).
    UnsupportedVersion(u16),
    /// No key for `(scope, epoch)`: `held` is the highest epoch this
    /// keychain holds for the scope, so `None` means no key material at
    /// all and `Some(older)` means stale — rotation happened elsewhere
    /// (ADR 0022's membership revocation). The loud signal to fetch
    /// wraps through the key-distribution channel.
    MissingEpoch {
        scope: ScopeId,
        epoch: u64,
        held: Option<u64>,
    },
    /// A wrap names a different org/scope/epoch than the slot it was
    /// offered for — misrouted key material, refused rather than stored
    /// under the wrong identity.
    WrongKeySlot,
    /// The OS random generator failed. The ecosystem convention panics
    /// here; this crate surfaces it instead — no key was minted, so
    /// nothing is half-created.
    Rng(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => write!(
                f,
                "authentication failed: tampered ciphertext, wrong key, or wrong binding"
            ),
            Self::NotAnEnvelope => write!(
                f,
                "not an E2EE envelope (v1 shape) — plaintext or foreign bytes"
            ),
            Self::UnsupportedVersion(v) => {
                write!(f, "envelope/wrap version {v} is not supported (this is v1)")
            }
            Self::MissingEpoch { scope, epoch, held } => match held {
                None => write!(
                    f,
                    "no key material for {scope:?} (needed at epoch {epoch}) — fetch key wraps"
                ),
                Some(older) => write!(
                    f,
                    "stale keys for {scope:?}: envelope is epoch {epoch}, highest held is {older} — rotation happened elsewhere"
                ),
            },
            Self::WrongKeySlot => write!(
                f,
                "key wrap does not match the org/scope/epoch it was offered for"
            ),
            Self::Rng(e) => write!(f, "OS random generator failed: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}
