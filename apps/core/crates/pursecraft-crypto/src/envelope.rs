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
//! the plaintext side), so an envelope handed to a plaintext decoder — or
//! plaintext handed to an envelope decoder — fails loudly, never
//! silently: that is the strip/downgrade defense (ADR 0022).

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{DataKey, FORMAT_VERSION, aead_open, aead_seal};

/// The wire shape of the envelope. Strict field types; unknown fields
/// are ignored exactly like the lenient op decoder (ADR 0017) — the
/// version marker is the gate, not field presence.
#[derive(Serialize, Deserialize, Debug)]
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
