//! Integer money: `i64` milliunits, exact arithmetic (ADR 0006).
//!
//! No constructor accepts a float; the workspace clippy config denies
//! `f32`/`f64` outright so float leakage fails CI.

use std::fmt;
use std::iter::Sum;
use std::ops::{Add, Neg, Sub};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A monetary amount in integer milliunits (1 unit = 1000; ADR 0006).
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Milliunits(i64);

// Wire form: bare integer milliunits — never a float or decimal string
// (ADR 0006, ADR 0017).
impl Serialize for Milliunits {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for Milliunits {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        i64::deserialize(deserializer).map(Self)
    }
}

impl Milliunits {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(i64::MAX);
    pub const MIN: Self = Self(i64::MIN);

    /// From major units: `from_major(12)` is 12.000.
    ///
    /// Panics if `major * 1000` overflows `i64` (beyond ~9.2 quadrillion
    /// units) rather than wrapping silently.
    pub fn from_major(major: i64) -> Self {
        Self(
            major
                .checked_mul(1000)
                .expect("major units overflow i64 milliunits"),
        )
    }

    /// From raw milliunits.
    pub const fn from_milli(milli: i64) -> Self {
        Self(milli)
    }

    /// Raw milliunits.
    pub const fn milli(self) -> i64 {
        self.0
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        // Const-compatible: `?` is not const; match instead.
        match self.0.checked_add(rhs.0) {
            Some(m) => Some(Self(m)),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(m) => Some(Self(m)),
            None => None,
        }
    }

    /// Split `self` across non-negative `weights` so the parts sum to `self`
    /// exactly (ADR 0016): largest-remainder apportionment, leftover
    /// milliunits to the largest fractional remainders, ties to the lowest
    /// index.
    pub fn allocate(self, weights: &[u32]) -> Result<Vec<Self>, AllocationError> {
        if weights.is_empty() {
            return Err(AllocationError::Empty);
        }
        let total: i128 = weights.iter().map(|&w| w as u64).sum::<u64>() as i128;
        if total == 0 {
            return Err(AllocationError::ZeroTotalWeights);
        }
        let amount = self.0 as i128;

        let mut parts = Vec::with_capacity(weights.len());
        let mut order = Vec::with_capacity(weights.len());
        let mut base_sum: i128 = 0;
        for (i, &w) in weights.iter().enumerate() {
            let exact = amount * w as i128;
            let base = exact.div_euclid(total);
            base_sum += base;
            parts.push(base as i64);
            order.push((exact.rem_euclid(total), i));
        }

        // Leftover is in 0..weights.len(): sum of floors loses less than one
        // per part.
        let leftover = (amount - base_sum) as usize;
        debug_assert!(leftover < weights.len());
        order.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for &(_, i) in &order[..leftover] {
            parts[i] += 1;
        }
        Ok(parts.into_iter().map(Self).collect())
    }
}

/// Failed [`Milliunits::allocate`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationError {
    /// No weights given.
    Empty,
    /// All weights are zero.
    ZeroTotalWeights,
}

impl fmt::Display for AllocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("allocation needs at least one weight"),
            Self::ZeroTotalWeights => f.write_str("allocation weights sum to zero"),
        }
    }
}

impl std::error::Error for AllocationError {}

/// Failed [`Milliunits::from_str`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMoneyError;

impl fmt::Display for ParseMoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "invalid milliunits string (expected e.g. \"-12.345\", at most 3 fraction digits)",
        )
    }
}

impl std::error::Error for ParseMoneyError {}

impl FromStr for Milliunits {
    type Err = ParseMoneyError;

    /// Strict decimal grammar: `[+-]?[0-9]+(\.[0-9]{1,3})?` — at most three
    /// fraction digits; more precision is an error so input rounding is never
    /// silent (ADR 0016).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        let mut i = 0;
        let neg = match b.first() {
            Some(b'+') => {
                i = 1;
                false
            }
            Some(b'-') => {
                i = 1;
                true
            }
            _ => false,
        };

        let int_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == int_start {
            return Err(ParseMoneyError);
        }
        let mut value: i128 = 0;
        for &d in &b[int_start..i] {
            value = value * 10 + (d - b'0') as i128;
            if value > i64::MAX as i128 {
                return Err(ParseMoneyError);
            }
        }

        let mut fraction: i64 = 0;
        if i < b.len() && b[i] == b'.' {
            i += 1;
            let frac_start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let digits = i - frac_start;
            if !(1..=3).contains(&digits) {
                return Err(ParseMoneyError);
            }
            let mut scale = 1;
            for _ in 0..(3 - digits) {
                scale *= 10;
            }
            let mut frac: i64 = 0;
            for &d in &b[frac_start..i] {
                frac = frac * 10 + (d - b'0') as i64;
            }
            fraction = frac * scale;
        }

        if i != b.len() {
            return Err(ParseMoneyError);
        }

        let milli = value * 1000 + fraction as i128;
        // Negation first keeps `i64::MIN` parseable (its positive twin
        // overflows i64), then the range check bounds both ends.
        let signed = if neg { -milli } else { milli };
        i64::try_from(signed).map(Self).map_err(|_| ParseMoneyError)
    }
}

impl fmt::Display for Milliunits {
    /// Exactly three fraction digits; round-trips through `from_str`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let abs = self.0.unsigned_abs();
        if self.0 < 0 {
            f.write_str("-")?;
        }
        write!(f, "{}.{:03}", abs / 1000, abs % 1000)
    }
}

impl fmt::Debug for Milliunits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Milliunits")
            .field(&self.to_string())
            .finish()
    }
}

impl Add for Milliunits {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let Some(sum) = self.checked_add(rhs) else {
            panic!("milliunits add overflow");
        };
        sum
    }
}

impl Sub for Milliunits {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let Some(diff) = self.checked_sub(rhs) else {
            panic!("milliunits sub overflow");
        };
        diff
    }
}

impl Neg for Milliunits {
    type Output = Self;

    fn neg(self) -> Self {
        Self(self.0.checked_neg().expect("milliunits neg overflow"))
    }
}

impl Sum for Milliunits {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}

impl<'a> Sum<&'a Milliunits> for Milliunits {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + *b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_and_accessors() {
        assert_eq!(Milliunits::from_major(12).milli(), 12_000);
        assert_eq!(Milliunits::from_milli(-5).milli(), -5);
        assert_eq!(Milliunits::from_major(0), Milliunits::ZERO);
    }

    #[test]
    fn exact_decimal_arithmetic() {
        // The classic float failure, exact here (ADR 0006).
        let a: Milliunits = "0.1".parse().unwrap();
        let b: Milliunits = "0.2".parse().unwrap();
        assert_eq!(a + b, "0.3".parse().unwrap());
        assert_eq!("0.3".parse::<Milliunits>().unwrap().milli(), 300);
        assert_eq!(a - b, "-0.1".parse().unwrap());
        assert_eq!(-a, "-0.1".parse().unwrap());
        assert_eq!([a, b, a].iter().sum::<Milliunits>().milli(), 400);
    }

    #[test]
    fn display_is_exact_and_padded() {
        assert_eq!(Milliunits::from_milli(1_234).to_string(), "1.234");
        assert_eq!(Milliunits::from_milli(-5).to_string(), "-0.005");
        assert_eq!(Milliunits::from_milli(1_200).to_string(), "1.200");
        assert_eq!(Milliunits::ZERO.to_string(), "0.000");
        assert_eq!(Milliunits::from_milli(-1_000_000).to_string(), "-1000.000");
        assert_eq!(Milliunits::MIN.to_string(), "-9223372036854775.808");
        assert_eq!(Milliunits::MAX.to_string(), "9223372036854775.807");
    }

    #[test]
    fn parse_accepts_strict_grammar() {
        assert_eq!("12".parse::<Milliunits>().unwrap().milli(), 12_000);
        assert_eq!("12.3".parse::<Milliunits>().unwrap().milli(), 12_300);
        assert_eq!("+1.05".parse::<Milliunits>().unwrap().milli(), 1_050);
        assert_eq!("-0.001".parse::<Milliunits>().unwrap().milli(), -1);
        assert_eq!("-0".parse::<Milliunits>().unwrap().milli(), 0);
        assert_eq!("0.000".parse::<Milliunits>().unwrap().milli(), 0);
        assert_eq!(
            "-9223372036854775.808".parse::<Milliunits>().unwrap(),
            Milliunits::MIN
        );
    }

    #[test]
    fn parse_rejects_garbage_and_excess_precision() {
        for bad in [
            "",
            ".",
            "+",
            "-",
            "1.",
            ".5",
            "1.0000",
            "1,000",
            "1 000",
            "abc",
            "1.2.3",
            "1e3",
            "0x10",
            "１",
            " 1",
            "1 ",
            "-9223372036854775.809",
            "9223372036854776",
            "99999999999999999999",
        ] {
            let result = bad.parse::<Milliunits>();
            assert!(result.is_err(), "expected parse error for {bad:?}");
        }
    }

    #[test]
    fn checked_arithmetic_overflows_loudly() {
        assert_eq!(Milliunits::MAX.checked_add(Milliunits::from_milli(1)), None);
        assert_eq!(Milliunits::MIN.checked_sub(Milliunits::from_milli(1)), None);
        let sum = Milliunits::MAX + Milliunits::MIN;
        assert_eq!(sum.milli(), -1);
    }

    #[test]
    fn roundtrip_property() {
        let mut rng = crate::testkit::Rng::new(0xC0FFEE);
        for _ in 0..1000 {
            let m = Milliunits::from_milli(rng.next_i64());
            let parsed: Milliunits = m.to_string().parse().unwrap();
            assert_eq!(parsed, m);
        }
        for _ in 0..1000 {
            // Random digit strings parse exactly.
            let mut s = String::new();
            let digits = 1 + rng.below(18);
            for _ in 0..digits {
                s.push((b'0' + rng.below(10) as u8) as char);
            }
            s.push('.');
            let frac = 1 + rng.below(3);
            for _ in 0..frac {
                s.push((b'0' + rng.below(10) as u8) as char);
            }
            let parsed: Result<Milliunits, _> = s.parse();
            if let Ok(m) = parsed {
                assert_eq!(m.to_string().parse::<Milliunits>().unwrap(), m);
            }
        }
    }

    #[test]
    fn addition_properties() {
        let mut rng = crate::testkit::Rng::new(7);
        // Keep magnitudes clear of i64 edges so checked ops never fail.
        let next =
            |rng: &mut crate::testkit::Rng| Milliunits::from_milli(rng.next_u64() as i64 / 8);
        for _ in 0..1000 {
            let a = next(&mut rng);
            let b = next(&mut rng);
            let c = next(&mut rng);
            assert_eq!(a + b, b + a, "commutativity failed for {a:?} {b:?}");
            assert_eq!((a + b) + c, a + (b + c), "associativity failed");
            assert_eq!((a + b) - b, a, "inverse failed");
            assert_eq!((a - b) + b, a, "inverse failed");
        }
    }

    #[test]
    fn allocate_is_exact_and_deterministic() {
        assert_eq!(
            Milliunits::from_milli(1).allocate(&[1, 1]).unwrap(),
            vec![Milliunits::from_milli(1), Milliunits::ZERO]
        );
        // 100 split three ways: exact 33.333.. -> 33.334 to the first index.
        assert_eq!(
            Milliunits::from_major(100).allocate(&[1, 1, 1]).unwrap(),
            vec![
                Milliunits::from_milli(33_334),
                Milliunits::from_milli(33_333),
                Milliunits::from_milli(33_333),
            ]
        );
        // Negative totals apportion negatively.
        assert_eq!(
            Milliunits::from_milli(-4).allocate(&[1, 1, 1]).unwrap(),
            vec![
                Milliunits::from_milli(-1),
                Milliunits::from_milli(-1),
                Milliunits::from_milli(-2),
            ]
        );
        // Zero-weight parts get nothing.
        assert_eq!(
            Milliunits::from_milli(5).allocate(&[0, 1]).unwrap(),
            vec![Milliunits::ZERO, Milliunits::from_milli(5)]
        );
        // Full weight to one part.
        assert_eq!(
            Milliunits::from_major(-7).allocate(&[3]).unwrap(),
            vec![Milliunits::from_major(-7)]
        );
        assert_eq!(
            Milliunits::ZERO.allocate(&[2, 5, 9]).unwrap(),
            vec![Milliunits::ZERO, Milliunits::ZERO, Milliunits::ZERO]
        );
    }

    #[test]
    fn allocate_errors() {
        assert_eq!(
            Milliunits::from_major(1).allocate(&[]),
            Err(AllocationError::Empty)
        );
        assert_eq!(
            Milliunits::from_major(1).allocate(&[0, 0]),
            Err(AllocationError::ZeroTotalWeights)
        );
    }

    #[test]
    fn allocate_property_sum_is_exact_and_parts_bounded() {
        let mut rng = crate::testkit::Rng::new(99);
        for _ in 0..1000 {
            let total = Milliunits::from_milli(rng.next_i64() / 4);
            let n = 1 + rng.below(8) as usize;
            let weights: Vec<u32> = (0..n).map(|_| rng.below(5) as u32).collect();
            if weights.iter().all(|&w| w == 0) {
                continue; // error case covered above
            }
            let parts = total.allocate(&weights).unwrap();
            assert_eq!(
                parts.iter().copied().sum::<Milliunits>(),
                total,
                "sum mismatch for {total:?} {weights:?}"
            );
            let lo = Milliunits::ZERO.min(total);
            let hi = Milliunits::ZERO.max(total);
            for part in &parts {
                assert!(
                    *part >= lo && *part <= hi,
                    "part {part:?} out of bounds for {total:?}"
                );
            }
            // Deterministic: same inputs, same outputs.
            assert_eq!(total.allocate(&weights).unwrap(), parts);
        }
    }
}
