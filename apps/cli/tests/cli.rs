//! End-to-end tests (issue #21): whole command lines through
//! [`run`](pursecraft_cli::run) — with an injected home and date, never
//! the process environment (workspace `unsafe_code = forbid` rules out
//! `env::set_var` in tests).

use std::path::{Path, PathBuf};

use pursecraft_cli::{Context, run};
use pursecraft_core::date::Date;

/// A per-test scratch directory, removed on drop (the core testkit
/// convention: zero test dependencies).
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pursecraft-cli-e2e-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ctx(home: &Path) -> Context {
    Context {
        home: home.to_owned(),
        today: Date::new(2026, 10, 25).unwrap(),
    }
}

fn run_args(home: &Path, args: &[&str]) -> pursecraft_cli::Output {
    let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    run(&argv, &ctx(home))
}

#[test]
fn help_version_and_usage_exit_codes() {
    let tmp = TempDir::new("meta");
    let help = run_args(tmp.path(), &["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("usage:"), "{}", help.stdout);
    assert!(help.stdout.contains("spending is negative"));
    let version = run_args(tmp.path(), &["--version"]);
    assert_eq!(version.code, 0);
    assert_eq!(
        version.stdout,
        format!("pursecraft {}\n", env!("CARGO_PKG_VERSION"))
    );
    let usage = run_args(tmp.path(), &["bogus"]);
    assert_eq!(usage.code, 2);
    assert!(usage.stderr.contains("unknown command"), "{}", usage.stderr);
    assert!(usage.stderr.contains("usage: pursecraft add"));
}

#[test]
fn add_confirms_and_list_recaps_end_to_end() {
    let tmp = TempDir::new("e2e");
    let home = tmp.path();

    let first = run_args(home, &["add", "coffee", "-4.50"]);
    assert_eq!(first.code, 0, "{}{}", first.stdout, first.stderr);
    assert_eq!(
        first.stdout,
        "initialized org \"Personal\", budget \"Personal\", account \"Wallet\"\n\
         added coffee -4.500 on 2026-10-25 (Wallet, new payee)\n"
    );

    let second = run_args(home, &["add", "Meralco", "--date", "2026-10-24", "-890"]);
    assert_eq!(second.code, 0);
    assert_eq!(
        second.stdout,
        "added Meralco -890.000 on 2026-10-24 (Wallet, new payee)\n"
    );

    // Newest first, exact amounts, count footer.
    let list = run_args(home, &["list"]);
    assert_eq!(list.code, 0);
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert_eq!(
        lines[0],
        format!("{:<10}   {:<24} {:>12}", "DATE", "PAYEE", "AMOUNT")
    );
    assert_eq!(
        lines[1],
        format!("{:<10}   {:<24} {:>12}", "2026-10-25", "coffee", "-4.500")
    );
    assert_eq!(
        lines[2],
        format!(
            "{:<10}   {:<24} {:>12}",
            "2026-10-24", "Meralco", "-890.000"
        )
    );
    assert_eq!(*lines.last().unwrap(), "2 transactions");
    assert_eq!(
        lines.len(),
        5,
        "header, two rows, blank, footer\n{}",
        list.stdout
    );
}

#[test]
fn same_day_captures_list_newest_first() {
    let tmp = TempDir::new("order");
    let home = tmp.path();
    for payee in ["first", "second", "third"] {
        let out = run_args(home, &["add", payee, "-1"]);
        assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    }
    let list = run_args(home, &["list"]);
    let body: Vec<&str> = list.stdout.lines().skip(1).collect();
    // The payee column starts at 13 (10 date + 3 spaces) and spans 24.
    let first_payee = body[0][13..37].trim();
    assert_eq!(
        first_payee, "third",
        "the last capture leads\n{}",
        list.stdout
    );
    assert!(list.stdout.ends_with("3 transactions\n"));
}

#[test]
fn list_on_a_fresh_home_hint_and_does_not_create() {
    let tmp = TempDir::new("empty");
    let home = tmp.path();
    let list = run_args(home, &["list"]);
    assert_eq!(list.code, 0);
    assert_eq!(
        list.stdout,
        "no transactions yet\n\ntry: pursecraft add coffee -4.50\n"
    );
    assert!(
        !home.join("identity.json").exists(),
        "list never bootstraps"
    );
}

#[test]
fn amount_and_flag_errors_reach_the_user() {
    let tmp = TempDir::new("errors");
    let home = tmp.path();
    let unsigned = run_args(home, &["add", "coffee", "4.50"]);
    assert_eq!(unsigned.code, 1);
    assert!(
        unsigned.stderr.contains("needs a sign")
            && unsigned.stderr.contains("-4.50 records spending"),
        "{}",
        unsigned.stderr
    );
    assert!(
        !home.join("identity.json").exists(),
        "a bad amount creates nothing"
    );
    let garbage = run_args(home, &["add", "coffee", "1,000"]);
    assert_eq!(garbage.code, 1);
    assert!(
        garbage.stderr.contains("invalid amount"),
        "{}",
        garbage.stderr
    );
    let account = run_args(home, &["add", "coffee", "-4.50", "--account", "Nope"]);
    assert_eq!(account.code, 1);
    assert!(
        account.stderr.contains("known: Wallet"),
        "{}",
        account.stderr
    );
    let date = run_args(home, &["add", "coffee", "-4.50", "--date", "2026-02-30"]);
    assert_eq!(date.code, 1);
    assert!(date.stderr.contains("invalid date"), "{}", date.stderr);
}

#[test]
fn income_and_milliunit_precision_round_trip() {
    let tmp = TempDir::new("income");
    let home = tmp.path();
    let out = run_args(home, &["add", "salary", "+50000.125"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    // The core's exact display: positives carry no `+` sign (ADR 0016).
    assert!(
        out.stdout
            .contains("added salary 50000.125 on 2026-10-25 (Wallet, new payee)")
    );
    let list = run_args(home, &["list"]);
    assert!(list.stdout.contains("salary"));
    assert!(list.stdout.contains("50000.125"), "{}", list.stdout);
    // Four fraction digits are excess precision: loud, never rounded.
    let precise = run_args(home, &["add", "odd", "-0.0001"]);
    assert_eq!(precise.code, 1);
    assert!(
        precise.stderr.contains("invalid amount"),
        "{}",
        precise.stderr
    );
}
