//! Hand-rolled argv parsing (ADR 0023): two commands, two flags — a
//! dependency-free parser instead of `clap`'s tree.
//!
//! Unrecognized arguments are positionals first and errors second: an amount
//! like `-4.50` is not a flag, so flags match by exact name only
//! (`--date`, `--account`).

use std::fmt;

/// One parsed command line (ADR 0023's surface, grown by ADR 0025's
/// enrollment gate and first sync, and ADR 0027's budgeting commands).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Cmd {
    /// `add <payee> <amount> [--date YYYY-MM-DD] [--account <name>]
    /// [--category <name>]` — raw strings; amounts and dates are parsed
    /// in [`crate::capture`] where their error messages live.
    Add {
        payee: String,
        amount: String,
        date: Option<String>,
        account: Option<String>,
        category: Option<String>,
    },
    /// `list` — the minimal recap.
    List,
    /// `category new <name> [--group <name>]` (ADR 0027).
    CategoryNew { name: String, group: Option<String> },
    /// `category list` (ADR 0027).
    CategoryList,
    /// `categorize` (the inbox review listing) or `categorize <txn>
    /// <category>` (file one transaction) — ADR 0027.
    Categorize {
        txn: Option<String>,
        category: Option<String>,
    },
    /// `assign <category> <amount> [--month YYYY-MM]` — raw strings
    /// (ADR 0027).
    Assign {
        category: String,
        amount: String,
        month: Option<String>,
    },
    /// `budget [show] [YYYY-MM]` — the balances view (ADR 0027); the
    /// optional `show` word is dropped here.
    Budget { month: Option<String> },
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
pub const USAGE: &str = "usage: pursecraft add <payee> <amount> [--date YYYY-MM-DD] \
                        [--account <name>] [--category <name>]\n       \
                        pursecraft list\n       \
                        pursecraft category new <name> [--group <name>]\n       \
                        pursecraft category list\n       \
                        pursecraft categorize [<txn> <category>]\n       \
                        pursecraft assign <category> <amount> [--month YYYY-MM]\n       \
                        pursecraft budget [show] [YYYY-MM]\n       \
                        pursecraft login <relay-url>\n       \
                        pursecraft sync\n       \
                        pursecraft pair\n       \
                        pursecraft join <org-id> <org-code> <budget-id> <budget-code>";

/// The `--help` text.
pub const HELP: &str = "\
pursecraft — fast local-first budgeting

usage:
  pursecraft add <payee> <amount> [--date YYYY-MM-DD] [--account <name>] [--category <name>]
  pursecraft list
  pursecraft category new <name> [--group <name>]
  pursecraft category list
  pursecraft categorize [<txn> <category>]
  pursecraft assign <category> <amount> [--month YYYY-MM]
  pursecraft budget [show] [YYYY-MM]
  pursecraft login <relay-url>
  pursecraft sync
  pursecraft pair
  pursecraft join <org-id> <org-code> <budget-id> <budget-code>

commands:
  add         record a transaction; spending is negative, income positive
              (add coffee -4.50), amounts allow up to 3 fraction digits
  list        show the most recent transactions
  category    new <name> makes an envelope (--group files it under a
              label, created if needed); list shows them
  categorize  review uncaptured classification: bare, it lists the inbox;
              with <txn> <category> it files one transaction (the txn id
              is the 8-character short form the listing prints)
  assign      set what a category holds for a month (assign Food 500,
              --month defaults to the current month)
  budget      the can-I-buy-this view: per category assigned, activity,
              and available (assigned + activity), plus to-be-budgeted

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
  --category <name>   category to file under (default: the Inbox, where
                      uncategorized captures wait for pursecraft categorize)
  --group <name>      group label for category new (created if needed)
  --month YYYY-MM     month for assign (default: the current month)

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
        "category" => parse_category(rest),
        "categorize" => match rest {
            [] => Ok(Cmd::Categorize {
                txn: None,
                category: None,
            }),
            [txn, category] => Ok(Cmd::Categorize {
                txn: Some(txn.clone()),
                category: Some(category.clone()),
            }),
            other => Err(UsageError(format!(
                "categorize takes no arguments or <txn> <category>, got {other:?}"
            ))),
        },
        "assign" => parse_assign(rest),
        "budget" => parse_budget(rest),
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
    let mut category: Option<String> = None;
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
            "--category" => {
                category = Some(value_after("--category")?);
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
        category,
    })
}

/// `category new <name> [--group <name>]` | `category list` (ADR 0027).
fn parse_category(args: &[String]) -> Result<Cmd, UsageError> {
    match args.split_first() {
        Some((first, rest)) if first == "new" => {
            let mut name: Option<String> = None;
            let mut group: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--group" => {
                        group = Some(
                            rest.get(i + 1)
                                .cloned()
                                .ok_or_else(|| UsageError("--group needs a value".into()))?,
                        );
                        i += 2;
                    }
                    positional => {
                        if name.is_some() {
                            return Err(UsageError(format!(
                                "unexpected argument {positional:?} (category new takes <name>)"
                            )));
                        }
                        name = Some(positional.to_owned());
                        i += 1;
                    }
                }
            }
            let name = name
                .filter(|n| !n.trim().is_empty())
                .ok_or_else(|| UsageError("category new needs <name>".into()))?;
            Ok(Cmd::CategoryNew { name, group })
        }
        Some((first, rest)) if first == "list" && rest.is_empty() => Ok(Cmd::CategoryList),
        _ => Err(UsageError(
            "expected: category new <name> [--group <name>] or category list".into(),
        )),
    }
}

/// `assign <category> <amount> [--month YYYY-MM]` (ADR 0027).
fn parse_assign(args: &[String]) -> Result<Cmd, UsageError> {
    let mut category: Option<String> = None;
    let mut amount: Option<String> = None;
    let mut month: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--month" => {
                month = Some(
                    args.get(i + 1)
                        .cloned()
                        .ok_or_else(|| UsageError("--month needs a value".into()))?,
                );
                i += 2;
            }
            positional => {
                if category.is_none() {
                    category = Some(positional.to_owned());
                } else if amount.is_none() {
                    amount = Some(positional.to_owned());
                } else {
                    return Err(UsageError(format!(
                        "unexpected argument {positional:?} (assign takes <category> <amount>)"
                    )));
                }
                i += 1;
            }
        }
    }
    let category = category
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| UsageError("assign needs <category> <amount>".into()))?;
    let amount = amount
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| UsageError("assign needs <category> <amount>".into()))?;
    Ok(Cmd::Assign {
        category,
        amount,
        month,
    })
}

/// `budget [show] [YYYY-MM]` — the `show` word is optional anywhere
/// (ADR 0027); what remains is nothing or one month.
fn parse_budget(args: &[String]) -> Result<Cmd, UsageError> {
    let mut rest: Vec<&String> = args.iter().filter(|arg| arg.as_str() != "show").collect();
    let dropped = args.len() - rest.len();
    if dropped > 1 {
        return Err(UsageError("budget takes at most one \"show\"".into()));
    }
    match rest.len() {
        0 => Ok(Cmd::Budget { month: None }),
        1 => Ok(Cmd::Budget {
            month: Some(rest.remove(0).clone()),
        }),
        _ => Err(UsageError(
            "budget takes [show] [YYYY-MM] and nothing else".into(),
        )),
    }
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
                account: None,
                category: None
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
            "--category",
            "Power",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Cmd::Add {
                payee: "Meralco".into(),
                amount: "-890".into(),
                date: Some("2026-10-24".into()),
                account: Some("Wallet".into()),
                category: Some("Power".into())
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

    /// The ADR 0027 surface: category/categorize/assign/budget parse
    /// exactly their shapes and teach on the wrong ones.
    #[test]
    fn budgeting_commands_parse() {
        assert_eq!(
            parse(&args(&["category", "new", "Food"])),
            Ok(Cmd::CategoryNew {
                name: "Food".into(),
                group: None
            })
        );
        assert_eq!(
            parse(&args(&["category", "new", "Power", "--group", "Bills"])),
            Ok(Cmd::CategoryNew {
                name: "Power".into(),
                group: Some("Bills".into())
            })
        );
        assert_eq!(parse(&args(&["category", "list"])), Ok(Cmd::CategoryList));
        assert_eq!(
            parse(&args(&["categorize"])),
            Ok(Cmd::Categorize {
                txn: None,
                category: None
            })
        );
        assert_eq!(
            parse(&args(&["categorize", "0192ab", "Food"])),
            Ok(Cmd::Categorize {
                txn: Some("0192ab".into()),
                category: Some("Food".into())
            })
        );
        assert_eq!(
            parse(&args(&["assign", "Food", "500"])),
            Ok(Cmd::Assign {
                category: "Food".into(),
                amount: "500".into(),
                month: None
            })
        );
        assert_eq!(
            parse(&args(&["assign", "Food", "500", "--month", "2026-10"])),
            Ok(Cmd::Assign {
                category: "Food".into(),
                amount: "500".into(),
                month: Some("2026-10".into())
            })
        );
        for (line, month) in [
            (args(&["budget"]), None),
            (args(&["budget", "show"]), None),
            (args(&["budget", "2026-10"]), Some("2026-10")),
            (args(&["budget", "show", "2026-10"]), Some("2026-10")),
            (args(&["budget", "2026-10", "show"]), Some("2026-10")),
        ] {
            assert_eq!(
                parse(&line),
                Ok(Cmd::Budget {
                    month: month.map(str::to_owned)
                })
            );
        }
        for (line, want) in [
            (args(&["category"]), "expected: category new"),
            (args(&["category", "new"]), "category new needs"),
            (
                args(&["category", "new", "Food", "extra"]),
                "unexpected argument",
            ),
            (
                args(&["category", "new", "Food", "--group"]),
                "--group needs a value",
            ),
            (args(&["category", "list", "x"]), "expected: category new"),
            (
                args(&["categorize", "only"]),
                "no arguments or <txn> <category>",
            ),
            (
                args(&["categorize", "a", "b", "c"]),
                "no arguments or <txn> <category>",
            ),
            (args(&["assign"]), "assign needs"),
            (args(&["assign", "Food"]), "assign needs"),
            (args(&["assign", "Food", "500", "x"]), "unexpected argument"),
            (
                args(&["assign", "Food", "500", "--month"]),
                "--month needs a value",
            ),
            (args(&["budget", "2026-10", "2026-11"]), "nothing else"),
            (args(&["budget", "show", "show"]), "at most one"),
        ] {
            let err = parse(&line)
                .err()
                .unwrap_or_else(|| panic!("{line:?} parsed"));
            assert!(err.to_string().contains(want), "{err} lacks {want:?}");
        }
    }
}
