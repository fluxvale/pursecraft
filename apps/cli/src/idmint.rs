//! UUIDv7 minting (ADR 0007's id rule; ADR 0023 puts minting in the capture
//! lane): unix milliseconds plus OS randomness, laid out per RFC 9562.
//! Hand-rolled so the `uuid` crate needs no `rng` feature — the `rand`
//! tree stays out of the lockfile (lean-deps rule).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

/// Mint a fresh UUIDv7: current unix millisecond, version 7, RFC 4122
/// variant, and — per RFC 9562's monotonicity recommendation — a 12-bit
/// per-process counter in `rand_a`, so ids minted by one process stay
/// strictly increasing within a millisecond until the counter wraps at
/// 4096 (beyond that rate, same-ms order falls back to the random bits —
/// downstream tiebreaks treat it as clock skew). The 48 `rand_b` bits are
/// OS randomness.
pub fn mint_uuid() -> Uuid {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ms = unix_ms();
    let counter = u128::from(COUNTER.fetch_add(1, Ordering::Relaxed) & 0xfff);
    let random = u128::from_be_bytes(random_bytes()) & 0xffff_ffff_ffff;
    Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (counter << 64) | (2u128 << 62) | random)
}

/// Unix milliseconds now — the same wall source the core's HLC reads.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the unix epoch")
        .as_millis() as u64
}

#[cfg(unix)]
fn random_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = File::open(Path::new("/dev/urandom"))
        && file.read_exact(&mut bytes).is_ok()
    {
        return bytes;
    }
    random_bytes_fallback()
}

#[cfg(not(unix))]
fn random_bytes() -> [u8; 16] {
    random_bytes_fallback()
}

/// Fallback entropy when `/dev/urandom` is unavailable (or off-unix):
/// time, pid, and a per-call counter avalanched through xorshift —
/// uniqueness, not cryptography (ids are not secrets).
fn random_bytes_fallback() -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut x = nanos
        ^ (u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        ^ COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_be_bytes()[..chunk.len()]);
    }
    bytes
}
