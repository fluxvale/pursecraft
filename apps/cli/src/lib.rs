//! The `pursecraft` command-line app (ADR 0023): fast local-first
//! transaction capture riding the shared core — one-shot argv commands,
//! offline by design, every minted op through the single payload sink
//! ([`sink`]). The library is fully injectable (home path, today's date,
//! argv slice); the thin binary `main.rs` is the only reader of the
//! process environment.

pub mod amount;
pub mod argv;
pub mod capture;
pub mod home;
pub mod idmint;
pub mod list;
pub mod sink;

use std::path::PathBuf;

use pursecraft_core::date::Date;

/// What the environment supplies a command (ADR 0023): the data home and
/// the local civil date captures default to. Injected so tests (and any
/// embedder) never touch the process environment.
pub struct Context {
    pub home: PathBuf,
    pub today: Date,
}

/// What one command produced: process exit code, stdout, stderr.
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    fn ok(stdout: String) -> Self {
        Self {
            code: 0,
            stdout,
            stderr: String::new(),
        }
    }

    fn fail(stderr: String) -> Self {
        Self {
            code: 1,
            stdout: String::new(),
            stderr,
        }
    }

    fn usage(message: &str) -> Self {
        Self {
            code: 2,
            stdout: String::new(),
            stderr: format!("error: {message}\n\n{}\n", argv::USAGE),
        }
    }
}

/// Run one command line to its printable outcome (ADR 0023). Exit codes:
/// `0` success, `2` usage errors, `1` everything else. `ctx` supplies the
/// data home and today only when a command actually needs them — help,
/// version, and usage errors answer without touching the environment.
pub fn run(args: &[String], ctx: impl FnOnce() -> Result<Context, home::NoHomeError>) -> Output {
    match argv::parse(args) {
        Ok(argv::Cmd::Help) => Output::ok(format!("{}\n", argv::HELP.trim_end())),
        Ok(argv::Cmd::Version) => Output::ok(format!("pursecraft {}\n", env!("CARGO_PKG_VERSION"))),
        Ok(argv::Cmd::List) => match ctx() {
            Ok(ctx) => match list::list(&ctx.home) {
                Ok(text) => Output::ok(text),
                Err(e) => Output::fail(format!("error: {e}\n")),
            },
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        Ok(argv::Cmd::Add {
            payee,
            amount,
            date,
            account,
        }) => match ctx() {
            Ok(ctx) => {
                let raw = capture::RawAdd {
                    payee: &payee,
                    amount: &amount,
                    date: date.as_deref(),
                    account: account.as_deref(),
                };
                match capture::add(&ctx.home, &raw, ctx.today) {
                    Ok(receipt) => Output::ok(receipt.confirmation()),
                    Err(e) => Output::fail(format!("error: {e}\n")),
                }
            }
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        Err(e) => Output::usage(&e.to_string()),
    }
}

/// A per-test scratch directory under the system temp dir, removed on
/// drop (test-only mirror of the core's testkit — never public API).
#[cfg(test)]
pub(crate) mod testsupport {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "pursecraft-cli-{label}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
