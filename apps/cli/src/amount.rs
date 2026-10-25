//! Signed-strict amount parsing (ADR 0023): trim whitespace, require a
//! sign, delegate to the core's exact Milliunits grammar. No separator or
//! symbol stripping — locale-ambiguous input is a loud error, never a
//! guess (`1,50` must not become `150`).

use std::fmt;

use pursecraft_core::money::Milliunits;

/// A failed [`parse`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AmountError {
    /// Parseable but unsigned — a direction was never chosen, so nothing
    /// is stored (no silent outflow/income default).
    Unsigned { input: String },
    /// Not an amount under the strict grammar.
    Invalid { input: String },
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned { input } => write!(
                f,
                "amount {input:?} needs a sign: -{input} records spending, +{input} records income"
            ),
            Self::Invalid { input } => write!(
                f,
                "invalid amount {input:?} (expected e.g. -1250.50: a sign, digits, \
                 an optional fraction of at most 3 digits, no separators or symbols)"
            ),
        }
    }
}

impl std::error::Error for AmountError {}

/// Parse an amount string into exact [`Milliunits`] (ADR 0023).
///
/// ```
/// use pursecraft_core::money::Milliunits;
/// let m = pursecraft_cli::amount::parse(" -4.50 ")?;
/// assert_eq!(m, Milliunits::from_milli(-4_500));
/// # Ok::<(), pursecraft_cli::amount::AmountError>(())
/// ```
pub fn parse(input: &str) -> Result<Milliunits, AmountError> {
    let trimmed = input.trim();
    let signed = trimmed.starts_with('-') || trimmed.starts_with('+');
    match (signed, trimmed.parse::<Milliunits>()) {
        (true, Ok(amount)) => Ok(amount),
        (false, Ok(_)) => Err(AmountError::Unsigned {
            input: trimmed.to_owned(),
        }),
        (_, Err(_)) => Err(AmountError::Invalid {
            input: trimmed.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn milli(input: &str) -> i64 {
        parse(input).unwrap().milli()
    }

    #[test]
    fn signed_amounts_parse_exactly() {
        assert_eq!(milli("-4.50"), -4_500);
        assert_eq!(milli("+4.50"), 4_500);
        assert_eq!(milli("-0.001"), -1);
        assert_eq!(milli("-1250.50"), -1_250_500);
        assert_eq!(milli("+0"), 0);
        assert_eq!(milli("-0"), 0);
        assert_eq!(milli(" +7.125 "), 7_125, "whitespace is trimmed");
        assert_eq!(milli("-9223372036854775.808"), i64::MIN);
    }

    #[test]
    fn unsigned_amounts_demand_a_direction() {
        for input in ["4.50", "12", "0.001"] {
            match parse(input) {
                Err(AmountError::Unsigned { .. }) => {}
                other => panic!("{input:?}: expected Unsigned, got {other:?}"),
            }
        }
        let err = parse("4.50").unwrap_err().to_string();
        assert!(err.contains("-4.50 records spending"), "{err}");
        assert!(err.contains("+4.50 records income"), "{err}");
    }

    #[test]
    fn ambiguous_and_malformed_amounts_are_rejected() {
        for input in [
            "",
            " ",
            "-",
            "+",
            ".",
            "1.",
            ".5",
            "-.5",
            "1,000",
            "1,000.50",
            "1.000,50",
            "₱500",
            "$5",
            "4.5050",
            "-4.5050",
            "1e3",
            "0x10",
            "abc",
            "1.2.3",
            " １ ",
            "-9223372036854775.809",
            "9223372036854776",
        ] {
            assert!(parse(input).is_err(), "{input:?} must not parse");
        }
    }

    /// The trim-then-delegate property, over deterministic random strings:
    /// whatever the core accepts, this module accepts signed and rejects
    /// unsigned — nothing else slips through either way.
    #[test]
    fn parsing_agrees_with_the_core_grammar() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let mut s = String::new();
            for _ in 0..1 + next() % 6 {
                s.push((b'0' + (next() % 10) as u8) as char);
            }
            if next() % 2 == 0 {
                s.push('.');
                for _ in 0..1 + next() % 4 {
                    s.push((b'0' + (next() % 10) as u8) as char);
                }
            }
            let core: Result<Milliunits, _> = s.parse();
            let signed = format!("-{s}");
            match core {
                Ok(expected) => {
                    assert_eq!(parse(&signed).unwrap(), -expected, "the signed mirror");
                    assert!(matches!(parse(&s), Err(AmountError::Unsigned { .. })));
                }
                Err(_) => {
                    assert!(parse(&signed).is_err(), "{signed:?} must not parse");
                    assert!(parse(&s).is_err(), "{s:?} must not parse");
                }
            }
        }
    }
}
