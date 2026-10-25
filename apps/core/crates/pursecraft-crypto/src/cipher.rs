//! The thin adapter (ADR 0022): [`KeyChain`] as `pursecraft-core`'s
//! `PayloadCipher` — the one seam
//! the store (and later the transport) seals payloads through. This is
//! the whole core-and-adapters boundary: core stays crypto-free, this
//! crate implements its trait.

use pursecraft_core::wire::{CipherError, OpMeta, PayloadCipher};

use crate::chain::KeyChain;

/// A [`KeyChain`] exposed as the core payload cipher (ADR 0022). Sealing
/// uses the scope's current-epoch data key; opening picks the key by the
/// envelope's claimed epoch and answers stale material loudly.
#[derive(Debug)]
pub struct ScopeCipher {
    chain: KeyChain,
}

impl ScopeCipher {
    /// Wrap a keychain.
    pub fn new(chain: KeyChain) -> Self {
        Self { chain }
    }

    /// The keychain back out (rotation and invites are chain operations).
    pub fn into_inner(self) -> KeyChain {
        self.chain
    }
}

impl PayloadCipher for ScopeCipher {
    fn seal(&self, meta: &OpMeta, plaintext: String) -> Result<String, CipherError> {
        self.chain
            .seal_payload(meta, plaintext.as_bytes())
            .map_err(|e| Box::new(e) as CipherError)
    }

    fn open(&self, meta: &OpMeta, sealed: &str) -> Result<String, CipherError> {
        let plaintext = self
            .chain
            .open_payload(meta, sealed)
            .map_err(|e| Box::new(e) as CipherError)?;
        String::from_utf8(plaintext).map_err(|e| Box::new(e) as CipherError)
    }
}
