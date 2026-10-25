//! Pursecraft E2EE (ADR 0022): client-side end-to-end encryption of op
//! payloads — envelope encryption over the core's single payload choke
//! point (ADRs 0009, 0017).
//!
//! The shape, in one breath: every log (an org's, or a budget's) has its
//! own random data key per epoch. Every org has one epoch key per epoch,
//! wrapped to each member's device (X25519-ephemeral + HKDF-SHA256 +
//! XChaCha20-Poly1305). The log keys are wrapped under that epoch key.
//! Payloads seal under the log key into versioned JSON envelopes whose
//! associated data binds them to their op's identity. Removing a member
//! rotates the org: fresh keys for every log, wrapped only to survivors,
//! so the removed member's cached keys are dead epochs — loudly
//! (ADR 0021's single revocation point).
//!
//! This crate is local wrap/unwrap only: no key transport, no channel —
//! wrapped keys are versioned records ([`WrappedOrgKey`],
//! [`WrappedLogKey`]) the rendezvous slice relays. The core seam is
//! [`ScopeCipher`], implementing `pursecraft-core`'s `PayloadCipher`.

pub mod b64serde;
pub mod chain;
pub mod cipher;
pub mod envelope;
pub mod error;
pub mod keys;

pub use chain::{Grant, KeyChain, Rotation};
pub use cipher::ScopeCipher;
pub use error::CryptoError;
pub use keys::FORMAT_VERSION;
pub use keys::{DataKey, DeviceKeypair, DevicePublicKey, WrappedLogKey, WrappedOrgKey};
