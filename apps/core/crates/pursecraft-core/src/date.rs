//! Civil dates and months (ADR 0016).
//!
//! A validated calendar date with no arithmetic: chronological `Ord` falls
//! straight out of `(year, month, day)`, so no date library is needed yet.

use std::fmt;
use std::str::FromStr;

/// A civil date, years 0000–9999.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// `None` unless `(year, month, day)` is a real calendar date.
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    pub const fn year(self) -> u16 {
        self.year
    }

    pub const fn month(self) -> u8 {
        self.month
    }

    pub const fn day(self) -> u8 {
        self.day
    }
}

/// Days in `month` (0 for an invalid month, which `Date::new` rejects).
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl fmt::Debug for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Date({self})")
    }
}

/// Failed to parse a [`Date`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseDateError;

impl fmt::Display for ParseDateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid date (expected strict YYYY-MM-DD)")
    }
}

impl std::error::Error for ParseDateError {}

impl FromStr for Date {
    type Err = ParseDateError;

    /// Strict `YYYY-MM-DD` (fixed width, ASCII digits).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        let ok_shape = b.len() == 10
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[7] == b'-'
            && b[8..].iter().all(u8::is_ascii_digit);
        if !ok_shape {
            return Err(ParseDateError);
        }
        let year = s[0..4].parse::<u16>().unwrap();
        let month = s[5..7].parse::<u8>().unwrap();
        let day = s[8..10].parse::<u8>().unwrap();
        Date::new(year, month, day).ok_or(ParseDateError)
    }
}

/// A calendar month, years 0000–9999.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Month {
    year: u16,
    month: u8,
}

impl Month {
    /// `None` unless `month` is 1–12.
    pub fn new(year: u16, month: u8) -> Option<Self> {
        if (1..=12).contains(&month) {
            Some(Self { year, month })
        } else {
            None
        }
    }

    pub const fn year(self) -> u16 {
        self.year
    }

    pub const fn month(self) -> u8 {
        self.month
    }
}

impl fmt::Display for Month {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

impl fmt::Debug for Month {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Month({self})")
    }
}

/// Failed to parse a [`Month`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMonthError;

impl fmt::Display for ParseMonthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid month (expected strict YYYY-MM)")
    }
}

impl std::error::Error for ParseMonthError {}

impl FromStr for Month {
    type Err = ParseMonthError;

    /// Strict `YYYY-MM` (fixed width, ASCII digits).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        let ok_shape = b.len() == 7
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[5..].iter().all(u8::is_ascii_digit);
        if !ok_shape {
            return Err(ParseMonthError);
        }
        let year = s[0..4].parse::<u16>().unwrap();
        let month = s[5..7].parse::<u8>().unwrap();
        Month::new(year, month).ok_or(ParseMonthError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_calendar_dates() {
        assert!(Date::new(2026, 10, 20).is_some());
        assert!(Date::new(2024, 2, 29).is_some()); // leap
        assert!(Date::new(2025, 2, 29).is_none());
        assert!(Date::new(2000, 2, 29).is_some()); // 400-year leap
        assert!(Date::new(1900, 2, 29).is_none()); // 100-year non-leap
        assert!(Date::new(2026, 0, 1).is_none());
        assert!(Date::new(2026, 13, 1).is_none());
        assert!(Date::new(2026, 10, 0).is_none());
        assert!(Date::new(2026, 10, 31).is_some());
        assert!(Date::new(2026, 10, 32).is_none());
        assert!(Date::new(2026, 11, 31).is_none());
    }

    #[test]
    fn ordering_is_chronological() {
        let a = Date::new(2026, 12, 31).unwrap();
        let b = Date::new(2027, 1, 1).unwrap();
        let feb29 = Date::new(2024, 2, 29).unwrap();
        let mar1 = Date::new(2024, 3, 1).unwrap();
        assert!(a < b);
        assert!(feb29 < mar1);
        assert!(Date::new(0, 1, 1).unwrap() < Date::new(9999, 12, 31).unwrap());
    }

    #[test]
    fn strict_iso_parse_and_display_roundtrip() {
        let d: Date = "2026-10-20".parse().unwrap();
        assert_eq!((d.year(), d.month(), d.day()), (2026, 10, 20));
        assert_eq!(d.to_string(), "2026-10-20");
        for bad in [
            "",
            "2026-10",
            "2026-10-20x",
            "2026/10/20",
            "20261020",
            "2026-1-05",
            "2026-01-5",
            "26-10-20",
            "2026-13-01",
            "2026-02-30",
            "x026-10-20",
        ] {
            assert!(bad.parse::<Date>().is_err(), "expected error for {bad:?}");
        }
        // 4-digit years keep the format fixed-width.
        assert_eq!(Date::new(26, 1, 2).unwrap().to_string(), "0026-01-02");
    }

    #[test]
    fn month_validates_orders_and_roundtrips() {
        let m = Month::new(2026, 10).unwrap();
        assert_eq!(m.to_string(), "2026-10");
        assert_eq!("2026-10".parse::<Month>().unwrap(), m);
        assert!(Month::new(2026, 0).is_none());
        assert!(Month::new(2026, 13).is_none());
        assert!(Month::new(2026, 12).unwrap() < Month::new(2027, 1).unwrap());
        for bad in ["", "2026-1", "2026-10-05", "202610", "2026/10", "abcd-ef"] {
            assert!(bad.parse::<Month>().is_err(), "expected error for {bad:?}");
        }
    }
}
