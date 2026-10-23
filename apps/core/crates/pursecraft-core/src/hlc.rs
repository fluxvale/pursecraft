//! Hybrid logical clock timestamps (ADR 0007, ADR 0016).
//!
//! The clock itself — not a sync engine: ops carry HLCs, and apply logic only
//! compares them. Total order is `(physical_ms, logical)`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A hybrid logical clock timestamp.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Hlc {
    /// Wall-clock milliseconds since the Unix epoch.
    pub physical_ms: u64,
    /// Monotonic counter within the same millisecond.
    pub logical: u32,
}

/// The wire shape of [`Hlc`], deserialized before validation.
#[derive(Deserialize)]
struct HlcWire {
    physical_ms: u64,
    logical: u32,
}

impl<'de> Deserialize<'de> for Hlc {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = HlcWire::deserialize(deserializer)?;
        // Boundary rule (ADR 0017): stamps off the u64 cliff are rejected
        // so `merge` can always bump the logical counter and `tick` can
        // always borrow the next millisecond — a wire value can never
        // exhaust the clock (corruption is a loud error, not a panic,
        // ADR 0016). `physical_ms` beyond i64::MAX is not a wall clock.
        if wire.physical_ms > i64::MAX as u64 || wire.logical == u32::MAX {
            return Err(serde::de::Error::custom(
                "hlc out of range: physical_ms must be <= i64::MAX and logical < u32::MAX",
            ));
        }
        Ok(Self {
            physical_ms: wire.physical_ms,
            logical: wire.logical,
        })
    }
}

impl Hlc {
    pub fn now() -> Self {
        Self {
            physical_ms: unix_ms_now(),
            logical: 0,
        }
    }

    /// Local event: strictly greater than the previous value of `self`.
    /// The top logical counter value is reserved (see [`Self::merge`]); a
    /// saturating counter borrows the next millisecond instead of
    /// producing it, so every stamp a device mints is decodable
    /// everywhere (ADR 0017).
    pub fn tick(&mut self) {
        let now = unix_ms_now();
        if now > self.physical_ms {
            self.physical_ms = now;
            self.logical = 0;
            return;
        }
        if self.logical >= u32::MAX - 1 {
            // At (or past) the reserved top counter: borrow the next ms —
            // 2^32 events within one millisecond, or a sentinel stamp.
            self.physical_ms = self.physical_ms.checked_add(1).expect("HLC exhausted");
            self.logical = 0;
        } else {
            self.logical += 1;
        }
    }

    /// Receive `remote`: strictly greater than both `self` and `remote`;
    /// when the wall clock dominates both, the logical counter resets to
    /// zero (canonical HLC). Receiving can never panic and never produces
    /// the reserved top counter value: at saturation it borrows the next
    /// millisecond like [`Self::tick`] — one validator-legal op delivered
    /// twice (at-least-once, ADR 0007) must never exhaust the clock
    /// (ADR 0017).
    pub fn merge(&mut self, remote: Hlc) {
        let now = unix_ms_now();
        let physical = self.physical_ms.max(remote.physical_ms).max(now);
        if physical > self.physical_ms && physical > remote.physical_ms {
            // The wall clock dominates both: canonical reset (ADR 0016).
            self.physical_ms = physical;
            self.logical = 0;
            return;
        }
        let merged = if physical == self.physical_ms && physical == remote.physical_ms {
            self.logical.max(remote.logical)
        } else if physical == self.physical_ms {
            self.logical
        } else {
            remote.logical
        };
        if merged >= u32::MAX - 1 {
            // The bump would hit the reserved top counter: borrow the
            // next millisecond instead of producing it — receiving one
            // validator-legal op twice must never exhaust the clock.
            self.physical_ms = physical.checked_add(1).expect("HLC exhausted");
            self.logical = 0;
        } else {
            self.logical = merged + 1;
            self.physical_ms = physical;
        }
    }
}

impl std::fmt::Debug for Hlc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hlc")
            .field("physical_ms", &self.physical_ms)
            .field("logical", &self.logical)
            .finish()
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic physical values far above any real wall clock keep these
    // tests deterministic regardless of when they run.
    const BASE: u64 = 1 << 60;

    #[test]
    fn ordering_is_physical_then_logical() {
        let early = Hlc {
            physical_ms: BASE,
            logical: 5,
        };
        let later_same_ms = Hlc {
            physical_ms: BASE,
            logical: 6,
        };
        let next_ms = Hlc {
            physical_ms: BASE + 1,
            logical: 0,
        };
        assert!(early < later_same_ms);
        assert!(later_same_ms < next_ms);
    }

    #[test]
    fn tick_is_strictly_monotonic() {
        let mut h = Hlc {
            physical_ms: BASE,
            logical: 7,
        };
        let before = h;
        h.tick(); // real now < BASE, so logical bumps
        assert!(h > before);
        let mid = h;
        h.tick();
        assert!(h > mid);
    }

    #[test]
    fn tick_borrows_next_millisecond_at_counter_saturation() {
        let mut h = Hlc {
            physical_ms: BASE,
            logical: u32::MAX,
        };
        h.tick();
        assert_eq!(
            h,
            Hlc {
                physical_ms: BASE + 1,
                logical: 0
            }
        );
    }

    #[test]
    fn merge_dominates_both_clocks() {
        let mut local = Hlc {
            physical_ms: BASE + 10,
            logical: 3,
        };
        let remote = Hlc {
            physical_ms: BASE + 20,
            logical: 1,
        };
        let before = local;
        local.merge(remote); // real now < BASE, so physical stays BASE+20
        assert!(local > before);
        assert!(local > remote);
        assert_eq!(local.physical_ms, BASE + 20);
        assert_eq!(local.logical, 2);

        // Equal timestamps: logical dominates and increments.
        let mut a = Hlc {
            physical_ms: BASE,
            logical: 9,
        };
        a.merge(Hlc {
            physical_ms: BASE,
            logical: 4,
        });
        assert_eq!(a.logical, 10);
    }

    #[test]
    fn merging_a_saturating_remote_repeatedly_borrows_rather_than_panicking() {
        // One validator-legal op (logical = u32::MAX - 1) delivered twice
        // — at-least-once delivery, ADR 0007 — must not exhaust the
        // clock, and no merge or tick may produce the reserved top
        // counter value: a stamp any device mints must stay decodable
        // everywhere (ADR 0017).
        let mut local = Hlc {
            physical_ms: BASE,
            logical: 0,
        };
        let remote = Hlc {
            physical_ms: BASE,
            logical: u32::MAX - 1,
        };
        let mut prev = local;
        for _ in 0..4 {
            local.merge(remote);
            assert!(local > prev, "receive must stay strictly monotonic");
            assert_ne!(local.logical, u32::MAX);
            prev = local;
        }
        for _ in 0..4 {
            local.tick();
            assert!(local > prev, "tick must stay strictly monotonic");
            assert_ne!(local.logical, u32::MAX);
            prev = local;
        }
        // The first saturating merge borrowed exactly one millisecond.
        assert_eq!(local.physical_ms, BASE + 1);
    }

    #[test]
    fn merge_resets_logical_when_wall_clock_dominates() {
        // Tiny synthetic clocks lose to the real wall clock, which pins the
        // canonical reset: fresh millisecond, logical counter to zero.
        let mut a = Hlc {
            physical_ms: 0,
            logical: 7,
        };
        let before = a;
        a.merge(Hlc {
            physical_ms: 0,
            logical: 3,
        });
        assert!(a > before);
        assert!(
            a > Hlc {
                physical_ms: 0,
                logical: 3
            }
        );
        assert_eq!(a.logical, 0);
        assert!(a.physical_ms > 1_000_000);
    }

    #[test]
    fn now_and_tick_progress_against_the_real_clock() {
        let a = Hlc::now();
        let mut b = a;
        b.tick();
        assert!(b > a);
        let mut c = b;
        c.merge(a);
        assert!(c > b);
    }
}
