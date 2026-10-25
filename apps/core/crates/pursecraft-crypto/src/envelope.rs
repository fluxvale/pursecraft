//! The sealed payload envelope v1 (ADR 0022) — what the payload choke
//! point emits under encryption: XChaCha20-Poly1305 under the per-log
//! data key of `(scope, epoch)`, with the op's identity bound as AEAD
//! associated data so ciphertexts cannot be re-associated with other ops
//! or freshly stamped by the transport.
//!
//! ```json
//! {"v":1,"e":<epoch>,"n":"<base64 nonce>","c":"<base64 ct‖tag>"}
//! ```
//!
//! The shape is deliberately disjoint from a plaintext payload's (no
//! `entity_kind`/`entity_id`/`field`/`value`, none of `v`/`e`/`n`/`c` on
//! the plaintext side), and the envelope decoder refuses unknown fields,
//! so no string parses as both — an envelope handed to a plaintext
//! decoder, plaintext handed to an envelope decoder, or a doctored
//! union of the two all fail loudly, never silently: that is the
//! strip/downgrade defense (ADR 0022). Behind it, the AEAD remains the
//! real gate — nothing decodes without authenticating.

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{DataKey, FORMAT_VERSION, aead_open, aead_seal};

/// The wire shape of the envelope. Strict field types, and strict on
/// fields: unknown keys are refused, so no string parses as BOTH an
/// envelope and a plaintext payload — that disjointness is the
/// strip/downgrade defense (ADR 0022). (The plaintext payload decoder
/// stays deliberately lenient per ADR 0017; strictness here alone makes
/// the pair disjoint.) The version marker is the format gate.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    v: u16,
    e: u64,
    #[serde(with = "crate::b64serde::b24")]
    n: [u8; 24],
    #[serde(with = "crate::b64serde::bytes")]
    c: Vec<u8>,
}

/// The AEAD binding for one op's payload: the op's identity — `op_id`,
/// `scope`, `hlc` — under a domain label. Stable across re-encryption
/// (the same op sealed twice binds identically) and deliberately NOT the
/// whole `OpMeta`: `device_id`/`user_id` are attribution, which is
/// plaintext metadata the server can see and no client has signed yet
/// (ADR 0022's posture — attribution authenticity is the auth slice).
pub(crate) fn op_binding(meta: &pursecraft_core::wire::OpMeta) -> Zeroizing<Vec<u8>> {
    let binding = json!({
        "op_id": meta.op_id.as_uuid().hyphenated().to_string(),
        "scope": &meta.scope,
        "hlc": {"physical_ms": meta.hlc.physical_ms, "logical": meta.hlc.logical},
    });
    let mut aad = Zeroizing::new(b"pursecraft.e2ee.v1/op-binding".to_vec());
    aad.extend_from_slice(&serde_json::to_vec(&binding).expect("OpMeta parts serialize"));
    aad
}

/// Seal `plaintext` under `key` at `epoch`, bound to `meta`'s identity.
pub(crate) fn seal(
    key: &DataKey,
    epoch: u64,
    binding: &[u8],
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    let (n, c) = aead_seal(key, binding, plaintext)?;
    let wire = EnvelopeWire {
        v: FORMAT_VERSION,
        e: epoch,
        n,
        c,
    };
    // Numbers and base64 strings cannot fail serde_json serialization.
    Ok(serde_json::to_string(&wire).expect("envelope serialization cannot fail"))
}

/// A parsed envelope: its claimed epoch plus the still-sealed bytes.
/// Parsing is separate from opening so the caller can pick the key by
/// `(scope, epoch)` first — stale keys are answered before any
/// decryption is attempted (ADR 0022's `MissingEpoch`).
pub(crate) struct Sealed {
    pub epoch: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Parse an envelope string. Everything that is not a v1 envelope —
/// plaintext payloads included — is [`CryptoError::NotAnEnvelope`] or
/// [`CryptoError::UnsupportedVersion`], never a decryption attempt.
pub(crate) fn parse(sealed: &str) -> Result<Sealed, CryptoError> {
    let wire: EnvelopeWire =
        serde_json::from_str(sealed).map_err(|_| CryptoError::NotAnEnvelope)?;
    if wire.v != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(wire.v));
    }
    Ok(Sealed {
        epoch: wire.e,
        nonce: wire.n,
        ciphertext: wire.c,
    })
}

/// Open a parsed envelope under `key`, bound to `meta`'s identity.
pub(crate) fn open(
    key: &DataKey,
    sealed: &Sealed,
    binding: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead_open(key, binding, &sealed.nonce, &sealed.ciphertext)
}
