//! The payload sink — the single mint path (ADR 0023).
//!
//! Every op this CLI mints reaches its [`LocalStore`] through [`sink`].
//! This is the CLI's ONLY caller of `LocalStore::append` and the seam the
//! E2EE lane's wrap slots into (ADR 0009): encrypting payloads later
//! changes this one function and nothing else. Nothing in this crate may
//! append to a store by any other route — tests and review hold that
//! invariant.

use pursecraft_core::ops::Op;
use pursecraft_core::store::{LocalStore, StoreError};

/// Commit one minted op to its store, durably, through the seam.
pub fn sink(store: &mut LocalStore, op: Op) -> Result<u64, StoreError> {
    // ADR 0009 / ADR 0023: the E2EE wrap lands here — the op's payload is
    // opaque ciphertext material from this point down.
    store.append(op)
}
