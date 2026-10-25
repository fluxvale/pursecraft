//! Hand-rolled argv parsing (ADR 0023): two commands, two flags — a
//! dependency-free parser instead of `clap`'s tree.
//!
//! Unrecognized arguments are positionals first and errors second: an amount
//! like `-4.50` is not a flag, so flags match by exact name only
//! (`--date`, `--account`).

use std::fmt;

/// One parsed command line (ADR 0023's surface).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cmd {
    /// `add <payee> <amount> [--date YYYY-MM-DD] [--account <name>]` —
    /// raw strings; amounts and dates are parsed in [`crate::capture`]
    /// where their error messages live.
    Add {
        payee: String,
        amount: String,
        date: Option<String>,
        account: Option<String>,
    },
    /// `list` — the minimal recap.
    List,
    /// `--help` / `help`.
    Help,
    /// `--version` / `version`.
    Version,
}

/// A usage failure — printed with the usage block, exit code 2.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UsageError(String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

/// The usage block every usage error carries.
pub const USAGE: &str = "usage: pursecraft add <payee> <amount> \
                         [--date YYYY-MM-DD] [--account <name>]\n       \
                         pursecraft list";

/// The `--help` text.
pub const HELP: &str = "\
pursecraft — fast local-first transaction capture

usage:
  pursecraft add <payee> <amount> [--date YYYY-MM-DD] [--account <name>]
  pursecraft list

commands:
  add    record a transaction; spending is negative, income positive
         (add coffee -4.50), amounts allow up to 3 fraction digits
  list   show the most recent transactions

options:
  --date YYYY-MM-DD   transaction date (default: today)
  --account <name>    account to file under (default: Wallet)

data lives under the pursecraft data home (PURSECRAFT_HOME overrides);
capture is offline by design — sync arrives in a later release.";

/// Parse the arguments after the program name.
///
/// ```
/// let cmd = pursecraft_cli::argv::parse(&["add".into(), "coffee".into(), "-4.50".into()])?;
/// assert!(matches!(cmd, pursecraft_cli::argv::Cmd::Add { .. }));
/// # Ok::<(), pursecraft_cli::argv::UsageError>(())
/// ```
pub fn parse(args: &[String]) -> Result<Cmd, UsageError> {
    let Some((first, rest)) = args.split_first() else {
        return Err(UsageError("missing command".into()));
    };
    match first.as_str() {
        "add" => parse_add(rest),
        "list" => {
            if rest.is_empty() {
                Ok(Cmd::List)
            } else {
                Err(UsageError(format!("list takes no arguments, got {rest:?}")))
            }
        }
        "--help" | "help" => {
            if rest.is_empty() {
                Ok(Cmd::Help)
            } else {
                Err(UsageError(format!(
                    "{first:?} takes no arguments, got {rest:?}"
                )))
            }
        }
        "--version" | "version" => {
            if rest.is_empty() {
                Ok(Cmd::Version)
            } else {
                Err(UsageError(format!(
                    "{first:?} takes no arguments, got {rest:?}"
                )))
            }
        }
        other => Err(UsageError(format!("unknown command {other:?}"))),
    }
}

fn parse_add(args: &[String]) -> Result<Cmd, UsageError> {
    let mut payee: Option<String> = None;
    let mut amount: Option<String> = None;
    let mut date: Option<String> = None;
    let mut account: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let value_after = |flag: &str| -> Result<String, UsageError> {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| UsageError(format!("{flag} needs a value")))
        };
        match args[i].as_str() {
            "--date" => {
                date = Some(value_after("--date")?);
                i += 2;
            }
            "--account" => {
                account = Some(value_after("--account")?);
                i += 2;
            }
            positional => {
                if payee.is_none() {
                    payee = Some(positional.to_owned());
                } else if amount.is_none() {
                    amount = Some(positional.to_owned());
                } else {
                    return Err(UsageError(format!(
                        "unexpected argument {positional:?} (add takes <payee> <amount>)"
                    )));
                }
                i += 1;
            }
        }
    }
    let payee = payee
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| UsageError("add needs <payee> <amount>".into()))?;
    let amount = amount
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| UsageError("add needs <payee> <amount>".into()))?;
    Ok(Cmd::Add {
        payee,
        amount,
        date,
        account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_add_with_positionals_and_flags() {
        let cmd = parse(&args(&["add", "coffee", "-4.50"])).unwrap();
        assert_eq!(
            cmd,
            Cmd::Add {
                payee: "coffee".into(),
                amount: "-4.50".into(),
                date: None,
                account: None
            }
        );
        let cmd = parse(&args(&[
            "add",
            "Meralco",
            "--date",
            "2026-10-24",
            "-890",
            "--account",
            "Wallet",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Cmd::Add {
                payee: "Meralco".into(),
                amount: "-890".into(),
                date: Some("2026-10-24".into()),
                account: Some("Wallet".into())
            }
        );
    }

    #[test]
    fn negative_amounts_are_positionals_not_flags() {
        let cmd = parse(&args(&["add", "coffee", "-4.50", "--account", "Wallet"])).unwrap();
        assert!(matches!(cmd, Cmd::Add { .. }));
    }

    #[test]
    fn usage_failures() {
        for (line, want) in [
            (args(&[]), "missing command"),
            (args(&["bogus"]), "unknown command"),
            (args(&["add"]), "add needs"),
            (args(&["add", "coffee"]), "add needs"),
            (args(&["add", "  ", "-4.50"]), "add needs"),
            (
                args(&["add", "coffee", "-4.50", "extra"]),
                "unexpected argument",
            ),
            (args(&["add", "coffee", "--date"]), "--date needs a value"),
            (args(&["add", "--account", "Wallet"]), "add needs"),
            (args(&["list", "x"]), "list takes no arguments"),
        ] {
            let err = parse(&line)
                .err()
                .unwrap_or_else(|| panic!("{line:?} parsed"));
            assert!(err.to_string().contains(want), "{err} lacks {want:?}");
        }
    }

    #[test]
    fn help_version_and_list_parse() {
        assert_eq!(parse(&args(&["list"])), Ok(Cmd::List));
        assert_eq!(parse(&args(&["--help"])), Ok(Cmd::Help));
        assert_eq!(parse(&args(&["help"])), Ok(Cmd::Help));
        assert_eq!(parse(&args(&["--version"])), Ok(Cmd::Version));
        // Trailing words are not swallowed, and the message names the
        // invoked alias.
        for (line, alias) in [
            (args(&["help", "me"]), "help"),
            (args(&["--version", "x"]), "--version"),
        ] {
            let err = parse(&line).err().unwrap();
            assert!(
                err.to_string()
                    .contains(&format!("{alias:?} takes no arguments")),
                "{err}"
            );
        }
    }
}
