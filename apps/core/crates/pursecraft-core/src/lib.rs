//! Pursecraft core: budget engine, sync protocol, and persistence (ADR 0001).
//!
//! This slice covers the domain model and op semantics of ADR 0016: integer
//! money, ids, HLC timestamps, entities, per-field LWW op application, and
//! deterministic referential resolution.

pub mod date;
pub mod domain;
pub mod hlc;
pub mod ids;
pub mod money;
pub mod ops;
pub mod resolve;

/// Deterministic helpers for the crate's own tests (never public API).
#[cfg(test)]
pub(crate) mod testkit {
    use uuid::Uuid;

    /// Deterministic UUIDv7: `ms` timestamp plus an arbitrary disambiguator.
    pub(crate) fn v7(ms: u64, rand: u64) -> Uuid {
        let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
        Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
    }

    /// xorshift64* — deterministic, reproducible pseudo-randomness for
    /// property-test loops (ADR 0016: no proptest dependency).
    pub(crate) struct Rng(u64);

    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        pub(crate) fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        pub(crate) fn next_i64(&mut self) -> i64 {
            self.next_u64() as i64
        }

        /// Value in `0..n` (modulo bias is irrelevant for test properties).
        pub(crate) fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }
}
