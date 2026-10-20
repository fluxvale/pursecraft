//! Hybrid logical clock timestamps (ADR 0007, ADR 0016).
//!
//! The clock itself — not a sync engine: ops carry HLCs, and apply logic only
//! compares them. Total order is `(physical_ms, logical)`.

use std::time::{SystemTime, UNIX_EPOCH};

/// A hybrid logical clock timestamp.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    /// Wall-clock milliseconds since the Unix epoch.
    pub physical_ms: u64,
    /// Monotonic counter within the same millisecond.
    pub logical: u32,
}

impl Hlc {
    pub const MAX: Self = Self {
        physical_ms: u64::MAX,
        logical: u32::MAX,
    };

    pub fn now() -> Self {
        Self {
            physical_ms: unix_ms_now(),
            logical: 0,
        }
    }

    /// Local event: strictly greater than the previous value of `self`.
    pub fn tick(&mut self) {
        let now = unix_ms_now();
        if now > self.physical_ms {
            self.physical_ms = now;
            self.logical = 0;
            return;
        }
        match self.logical.checked_add(1) {
            Some(l) => self.logical = l,
            None => {
                // 2^32 events within one millisecond: borrow the next ms.
                self.physical_ms = self.physical_ms.checked_add(1).expect("HLC exhausted");
                self.logical = 0;
            }
        }
    }

    /// Receive `remote`: strictly greater than both `self` and `remote`.
    pub fn merge(&mut self, remote: Hlc) {
        let now = unix_ms_now();
        let physical = self.physical_ms.max(remote.physical_ms).max(now);
        let logical = if physical == self.physical_ms && physical == remote.physical_ms {
            self.logical.max(remote.logical)
        } else if physical == self.physical_ms {
            self.logical
        } else if physical == remote.physical_ms {
            remote.logical
        } else {
            0
        };
        self.logical = logical.checked_add(1).expect("HLC exhausted");
        self.physical_ms = physical;
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
        assert!(Hlc::MAX > next_ms);
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
