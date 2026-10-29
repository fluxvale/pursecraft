//! End-to-end tests (issues #21, #26): whole command lines through
//! [`run`](pursecraft_cli::run) — with an injected home, date, and stdin,
//! never the process environment (workspace `unsafe_code = forbid` rules
//! out `env::set_var` in tests). ADR 0025: data commands run enrolled (a
//! synthetic session — no relay needed for capture-side behavior; the
//! relay-driven suite lives in `tests/sync.rs`).

use std::path::{Path, PathBuf};

use pursecraft_cli::run;
use pursecraft_cli::session::{self, Session};
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

/// A synthetic enrollment (ADR 0025): a real session file pointing at a
/// relay that does not exist — capture is offline; only sync would care.
fn enroll(home: &Path) {
    let device = pursecraft_core::ids::DeviceId::new(uuid::Uuid::new_v4()).unwrap();
    session::publish(
        home,
        &Session {
            version: 1,
            server: "http://127.0.0.1:9".into(),
            device_id: device,
            token: "test-only".into(),
        },
    )
    .unwrap();
}

fn run_with(home: &Path, stdin: &str, args: &[&str]) -> pursecraft_cli::Output {
    let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let text = stdin.to_owned();
    let piped =
        (!stdin.is_empty()).then(|| Box::new(move || text.clone()) as Box<dyn FnOnce() -> String>);
    run(&argv, || {
        Ok(pursecraft_cli::Context {
            home: home.to_owned(),
            today: Date::new(2026, 10, 25).unwrap(),
            piped_secret: piped,
            // The self-host mode (ADR 0028): these suites exercise the
            // plaintext path; the E2EE path has its own suite.
            e2ee: false,
            terminal: None,
        })
    })
}

fn run_args(home: &Path, args: &[&str]) -> pursecraft_cli::Output {
    run_with(home, "", args)
}

#[test]
fn help_version_and_usage_exit_codes() {
    let tmp = TempDir::new("meta");
    let help = run_args(tmp.path(), &["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("usage:"), "{}", help.stdout);
    assert!(help.stdout.contains("spending is negative"));
    assert!(help.stdout.contains("pursecraft sync"));
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

/// Help, version, and usage errors answer without touching the
/// environment: a failing context supplier must not break them (ADR 0023).
#[test]
fn meta_commands_need_no_environment() {
    let argv = |a: &[&str]| -> Vec<String> { a.iter().map(|s| s.to_string()).collect() };
    for meta in [["--help"], ["help"], ["--version"], ["version"], ["bogus"]] {
        let out = run(&argv(&meta), || Err(pursecraft_cli::home::NoHomeError));
        assert_eq!(out.code, if meta[0] == "bogus" { 2 } else { 0 }, "{meta:?}");
        assert!(
            !out.stderr.contains("data home"),
            "{meta:?}: {}",
            out.stderr
        );
    }
    // …while a data-needing command surfaces the environment failure —
    // still before the gate (the gate needs the home too).
    let out = run(&argv(&["list"]), || Err(pursecraft_cli::home::NoHomeError));
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("no data home"), "{}", out.stderr);
}

/// THE gate test (issue #26): un-enrolled, every data command — read-only
/// `list` included — refuses with the teaching message and creates
/// NOTHING. `login` stays open (it is the door), and help/version answer
/// untouched.
#[test]
fn gate_blocks_unenrolled() {
    let tmp = TempDir::new("gate");
    let home = tmp.path();
    for cmd in [
        vec!["add", "coffee", "-4.50"],
        vec!["list"],
        vec!["category", "new", "Food"],
        vec!["category", "list"],
        vec!["categorize"],
        vec!["assign", "Food", "500"],
        vec!["budget"],
        vec!["sync"],
        vec!["pair"],
        vec!["join", "o", "c1", "b", "c2"],
    ] {
        let out = run_args(home, &cmd);
        assert_eq!(out.code, 1, "{cmd:?}: {}{}", out.stdout, out.stderr);
        assert!(
            out.stderr.contains("not enrolled"),
            "{cmd:?}: {}",
            out.stderr
        );
        assert!(
            out.stderr.contains("pursecraft login"),
            "{cmd:?}: {}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "{cmd:?}: {}", out.stdout);
    }
    // The refusal creates nothing — no session, no identity, no stores.
    assert!(std::fs::read_dir(home).unwrap().next().is_none());
    // The gate's taught command is exactly what `parse` accepts (hostile
    // review's P1 class): the gate is the first thing a new user reads,
    // and its instruction must never exit 2.
    {
        let taught = run_args(home, &["list"]);
        let login_line = taught
            .stderr
            .lines()
            .find(|line| line.trim_start().starts_with("pursecraft login"))
            .expect("the gate teaches a login command");
        let words: Vec<String> = login_line.split_whitespace().map(str::to_owned).collect();
        let rest: Vec<String> = words.iter().skip(1).cloned().collect();
        assert_eq!(
            pursecraft_cli::argv::parse(&rest),
            Ok(pursecraft_cli::argv::Cmd::Login { server: None }),
            "the gate's taught {login_line:?} must parse as the bare login"
        );
    }
    // And the door itself teaches on a dead relay (ADR 0030: the probe
    // runs before the secret is read, so an unreachable URL fails with
    // the probe's naming error — a real login runs in tests/sync.rs).
    let login = run_args(home, &["login", "--server", "http://127.0.0.1:9"]);
    assert_eq!(login.code, 1, "{}", login.stderr);
    assert!(
        login
            .stderr
            .contains("cannot reach the relay at http://127.0.0.1:9"),
        "{}",
        login.stderr
    );
    // Meta commands never see the gate.
    assert_eq!(run_args(home, &["--version"]).code, 0);
}

/// Enrolled-but-offline is full function (ADR 0025): captures land, list
/// reads (with the pending badge, ADR 0011), and only sync fails —
/// teaching, exit 1, data intact.
#[test]
fn enrolled_offline_capture_and_list_work_and_sync_teaches() {
    let tmp = TempDir::new("enrolled-offline");
    let home = tmp.path();
    enroll(home);

    let add = run_args(home, &["add", "coffee", "-4.50"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);
    assert!(
        add.stdout.contains("initialized org") && add.stdout.contains("added coffee"),
        "{}",
        add.stdout
    );

    let list = run_args(home, &["list"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(list.stdout.contains("coffee"), "{}", list.stdout);
    assert!(
        list.stdout.contains("14 pending sync"),
        "the badge shows unsynced captures\n{}",
        list.stdout
    );

    let sync = run_args(home, &["sync"]);
    assert_eq!(sync.code, 1, "{}", sync.stdout);
    assert!(
        sync.stderr.contains("cannot reach the relay"),
        "{}",
        sync.stderr
    );
    assert!(
        sync.stderr.contains("captures stay queued"),
        "{}",
        sync.stderr
    );

    // Full function offline: nothing was lost, the badge persists.
    let again = run_args(home, &["list"]);
    assert!(again.stdout.contains("14 pending sync"), "{}", again.stdout);
    assert!(again.stdout.contains("1 transaction"), "{}", again.stdout);
}

#[test]
fn add_confirms_and_list_recaps_end_to_end() {
    let tmp = TempDir::new("e2e");
    let home = tmp.path();
    enroll(home);

    let first = run_args(home, &["add", "coffee", "-4.50"]);
    assert_eq!(first.code, 0, "{}{}", first.stdout, first.stderr);
    assert_eq!(
        first.stdout,
        "initialized org \"Personal\", budget \"Personal\", account \"Wallet\"\n\
         created the \"Inbox\" category — uncategorized captures land there \
         (review: pursecraft categorize)\n\
         added coffee -4.500 on 2026-10-25 (Wallet, new payee)\n\
         14 pending sync — run: pursecraft sync\n"
    );

    let second = run_args(home, &["add", "Meralco", "--date", "2026-10-24", "-890"]);
    assert_eq!(second.code, 0);
    assert_eq!(
        second.stdout,
        "added Meralco -890.000 on 2026-10-24 (Wallet, new payee)\n\
         20 pending sync — run: pursecraft sync\n"
    );

    // Newest first, exact amounts, count footer.
    let list = run_args(home, &["list"]);
    assert_eq!(list.code, 0);
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert_eq!(
        lines[0],
        format!(
            "{:<10}   {:<24} {:<16} {:>12}",
            "DATE", "PAYEE", "CATEGORY", "AMOUNT"
        )
    );
    assert_eq!(
        lines[1],
        format!(
            "{:<10}   {:<24} {:<16} {:>12}",
            "2026-10-25", "coffee", "Inbox", "-4.500"
        )
    );
    assert_eq!(
        lines[2],
        format!(
            "{:<10}   {:<24} {:<16} {:>12}",
            "2026-10-24", "Meralco", "Inbox", "-890.000"
        )
    );
    assert_eq!(
        *lines.last().unwrap(),
        "20 pending sync — run: pursecraft sync"
    );
    assert!(
        list.stdout.contains("2 transactions"),
        "the count footer stays\n{}",
        list.stdout
    );
}

#[test]
fn same_day_captures_list_newest_first() {
    let tmp = TempDir::new("order");
    let home = tmp.path();
    enroll(home);
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
    assert!(list.stdout.contains("3 transactions"));
}

#[test]
fn list_on_a_fresh_home_hint_and_does_not_create() {
    let tmp = TempDir::new("empty");
    let home = tmp.path();
    enroll(home);
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
    enroll(home);
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
    enroll(home);
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
