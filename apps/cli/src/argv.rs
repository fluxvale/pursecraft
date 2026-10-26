//! Hand-rolled argv parsing (ADR 0023): two commands, two flags — a
//! dependency-free parser instead of `clap`'s tree.
//!
//! Unrecognized arguments are positionals first and errors second: an amount
//! like `-4.50` is not a flag, so flags match by exact name only
//! (`--date`, `--account`).

use std::fmt;

/// One parsed command line (ADR 0023's surface, grown by ADR 0025's
/// enrollment gate and first sync).
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
    /// `login <server-url>` — enroll against the relay; the enrollment
    /// secret rides stdin (ADR 0025).
    Login { server: String },
    /// `sync` — push the outbox and pull deltas through the relay
    /// (ADR 0025).
    Sync,
    /// `pair` — mint pairing codes and print the join command (ADR 0025).
    Pair,
    /// `join <org-id> <org-code> <budget-id> <budget-code>` — bring a
    /// second device into an existing world (ADR 0025).
    Join {
        org_id: String,
        org_code: String,
        budget_id: String,
        budget_code: String,
    },
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
                         pursecraft list\n       \
                         pursecraft login <relay-url>\n       \
                         pursecraft sync\n       \
                         pursecraft pair\n       \
                         pursecraft join <org-id> <org-code> <budget-id> <budget-code>";

/// The `--help` text.
pub const HELP: &str = "\
pursecraft — fast local-first transaction capture

usage:
  pursecraft add <payee> <amount> [--date YYYY-MM-DD] [--account <name>]
  pursecraft list
  pursecraft login <relay-url>
  pursecraft sync
  pursecraft pair
  pursecraft join <org-id> <org-code> <budget-id> <budget-code>

commands:
  add    record a transaction; spending is negative, income positive
         (add coffee -4.50), amounts allow up to 3 fraction digits
  list   show the most recent transactions

  login  enroll this device with the relay (once; the enrollment secret
         is read from stdin, one line); capture stays fully offline
  sync   push captured ops to the relay and pull deltas back
  pair   print a join command (fresh single-use pairing codes) for
         another device
  join   bring this fresh device into an existing relay world using the
         codes pursecraft pair printed there

options:
  --date YYYY-MM-DD   transaction date (default: today)
  --account <name>    account to file under (default: Wallet)

data lives under the pursecraft data home (PURSECRAFT_HOME overrides);
every command except help and version requires a one-time enrollment
(pursecraft login) — afterwards capture works fully offline, and
pursecraft sync sends and receives when the relay is reachable";

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
        "login" => {
            if rest.len() != 1 {
                Err(UsageError(format!(
                    "login takes exactly one relay url (http://host:port), got {rest:?}"
                )))
            } else {
                Ok(Cmd::Login {
                    server: rest[0].clone(),
                })
            }
        }
        "sync" => {
            if rest.is_empty() {
                Ok(Cmd::Sync)
            } else {
                Err(UsageError(format!("sync takes no arguments, got {rest:?}")))
            }
        }
        "pair" => {
            if rest.is_empty() {
                Ok(Cmd::Pair)
            } else {
                Err(UsageError(format!("pair takes no arguments, got {rest:?}")))
            }
        }
        "join" => {
            if rest.len() == 4 {
                let [org_id, org_code, budget_id, budget_code] = rest else {
                    unreachable!("checked length");
                };
                Ok(Cmd::Join {
                    org_id: org_id.clone(),
                    org_code: org_code.clone(),
                    budget_id: budget_id.clone(),
                    budget_code: budget_code.clone(),
                })
            } else {
                Err(UsageError(format!(
                    "join takes <org-id> <org-code> <budget-id> <budget-code>, got {rest:?}"
                )))
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

    /// The ADR 0025 surface: login/sync/pair/join parse exactly their
    /// shapes and teach on the wrong ones.
    #[test]
    fn enrollment_commands_parse() {
        assert_eq!(
            parse(&args(&["login", "http://127.0.0.1:8080"])),
            Ok(Cmd::Login {
                server: "http://127.0.0.1:8080".into()
            })
        );
        assert_eq!(parse(&args(&["sync"])), Ok(Cmd::Sync));
        assert_eq!(parse(&args(&["pair"])), Ok(Cmd::Pair));
        let join = parse(&args(&["join", "o", "co", "b", "cb"])).unwrap();
        assert_eq!(
            join,
            Cmd::Join {
                org_id: "o".into(),
                org_code: "co".into(),
                budget_id: "b".into(),
                budget_code: "cb".into()
            }
        );
        for (line, want) in [
            (args(&["login"]), "exactly one relay url"),
            (args(&["login", "a", "b"]), "exactly one relay url"),
            (args(&["sync", "x"]), "sync takes no arguments"),
            (args(&["pair", "x"]), "pair takes no arguments"),
            (args(&["join", "a", "b", "c"]), "join takes"),
            (args(&["join", "a", "b", "c", "d", "e"]), "join takes"),
        ] {
            let err = parse(&line)
                .err()
                .unwrap_or_else(|| panic!("{line:?} parsed"));
            assert!(err.to_string().contains(want), "{err} lacks {want:?}");
        }
    }
}
