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
    /// A key record ([ADR 0028]) that is not a v1 record of a known kind —
    /// foreign bytes, an unknown kind, or a shape that does not match its
    /// own tag. Refused, never skipped: a device that ignored its own
    /// rotation wrap would keep sealing under a dead epoch.
    BadRecord(String),
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
            Self::BadRecord(detail) => write!(f, "not a v1 key record: {detail}"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use pursecraft_core::ids::{BudgetId, OrgId, ScopeId};

    /// Deterministic UUIDv7, same construction as the core testkit.
    fn v7(ms: u64, rand: u64) -> uuid::Uuid {
        let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
        uuid::Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
    }

    /// Every variant's Display — these strings are the operator-facing
    /// half of the loud-failure posture: they surface verbatim through
    /// `StoreError::Cipher` when a store refuses to open, so each says
    /// what went wrong and (where action exists) what to do about it.
    #[test]
    fn every_variant_names_its_cause_in_display() {
        let budget = BudgetId::new(v7(1 << 40, 1)).unwrap();
        let org = OrgId::new(v7(1 << 40, 2)).unwrap();

        assert_eq!(
            CryptoError::Auth.to_string(),
            "authentication failed: tampered ciphertext, wrong key, or wrong binding"
        );
        assert_eq!(
            CryptoError::NotAnEnvelope.to_string(),
            "not an E2EE envelope (v1 shape) — plaintext or foreign bytes"
        );
        assert_eq!(
            CryptoError::UnsupportedVersion(3).to_string(),
            "envelope/wrap version 3 is not supported (this is v1)"
        );
        assert_eq!(
            CryptoError::MissingEpoch {
                scope: ScopeId::Budget(budget),
                epoch: 2,
                held: None,
            }
            .to_string(),
            format!(
                "no key material for {:?} (needed at epoch 2) — fetch key wraps",
                ScopeId::Budget(budget)
            )
        );
        assert_eq!(
            CryptoError::MissingEpoch {
                scope: ScopeId::Org(org),
                epoch: 5,
                held: Some(2),
            }
            .to_string(),
            format!(
                "stale keys for {:?}: envelope is epoch 5, highest held is 2 — rotation happened elsewhere",
                ScopeId::Org(org)
            )
        );
        assert_eq!(
            CryptoError::WrongKeySlot.to_string(),
            "key wrap does not match the org/scope/epoch it was offered for"
        );
        assert_eq!(
            CryptoError::Rng("entropy exhausted".into()).to_string(),
            "OS random generator failed: entropy exhausted"
        );
        assert_eq!(
            CryptoError::BadRecord("unknown kind \"epoch\"".into()).to_string(),
            "not a v1 key record: unknown kind \"epoch\""
        );
    }
}
