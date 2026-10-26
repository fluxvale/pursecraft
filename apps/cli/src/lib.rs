//! The `pursecraft` command-line app (ADR 0023): fast local-first
//! transaction capture riding the shared core — one-shot argv commands,
//! every minted op through the single payload [`sink`] — and, since ADR
//! 0025, authenticated-first: every data command requires a one-time
//! enrollment (`session.json`), and `sync` drives the rendezvous relay.
//! The library is fully injectable (home path, today's date, stdin, argv
//! slice); the thin binary `main.rs` is the only reader of the process
//! environment.

pub mod amount;
pub mod argv;
pub mod capture;
pub mod home;
pub mod idmint;
pub mod list;
pub mod relay;
pub mod session;
pub mod sink;
pub mod sync;

use std::path::{Path, PathBuf};

use pursecraft_core::date::Date;

/// What the environment supplies a command (ADR 0023; grown by ADR 0025):
/// the data home, the local civil date captures default to, and stdin —
/// `login`'s enrollment secret (read by `main` only for `login`; every
/// other command sees an empty string). Injected so tests (and any
/// embedder) never touch the process environment.
pub struct Context {
    pub home: PathBuf,
    pub today: Date,
    pub stdin: String,
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
/// data home, today, and stdin only when a command actually needs them —
/// help, version, and usage errors answer without touching the
/// environment.
///
/// The enrollment gate (ADR 0025) is the dispatch's one choke point: every
/// command that touches data — `add`, `list`, `sync`, `pair`, `join`,
/// read-only `list` included — answers with the teaching refusal until
/// `session.json` exists. The check is file presence, never a network
/// round-trip: enrolled-but-offline is full function.
pub fn run(args: &[String], ctx: impl FnOnce() -> Result<Context, home::NoHomeError>) -> Output {
    match argv::parse(args) {
        Ok(argv::Cmd::Help) => Output::ok(format!("{}\n", argv::HELP.trim_end())),
        Ok(argv::Cmd::Version) => Output::ok(format!("pursecraft {}\n", env!("CARGO_PKG_VERSION"))),
        Ok(argv::Cmd::Login { server }) => match ctx() {
            Ok(ctx) => match login(&ctx.home, &server, &ctx.stdin) {
                Ok(line) => Output::ok(line),
                Err(e) => Output::fail(format!("error: {e}\n")),
            },
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        // The gated surface (ADR 0025): no client interaction before
        // enrollment.
        Ok(
            gated @ (argv::Cmd::Add { .. }
            | argv::Cmd::List
            | argv::Cmd::Sync
            | argv::Cmd::Pair
            | argv::Cmd::Join { .. }),
        ) => match ctx() {
            Ok(ctx) => match session::load(&ctx.home) {
                Ok(Some(session)) => dispatch(gated, ctx, session),
                Ok(None) => Output::fail(format!("error: {}\n", session::GATE_MESSAGE)),
                Err(e) => Output::fail(format!("error: {e}\n")),
            },
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        Err(e) => Output::usage(&e.to_string()),
    }
}

/// Dispatch a gated command — the session exists by construction.
fn dispatch(cmd: argv::Cmd, ctx: Context, session: session::Session) -> Output {
    match cmd {
        argv::Cmd::Add {
            payee,
            amount,
            date,
            account,
        } => {
            let raw = capture::RawAdd {
                payee: &payee,
                amount: &amount,
                date: date.as_deref(),
                account: account.as_deref(),
            };
            match capture::add(&ctx.home, &session, &raw, ctx.today) {
                Ok(receipt) => match with_pending_badge(&ctx.home, &session, &receipt) {
                    Ok(text) => Output::ok(text),
                    Err(e) => Output::fail(format!(
                        "{}\nerror: {e}\n",
                        receipt.confirmation().trim_end()
                    )),
                },
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        argv::Cmd::List => match list::list(&ctx.home, &session) {
            Ok(text) => Output::ok(text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::Sync => match run_sync(&ctx.home, &session) {
            Ok(text) => Output::ok(text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::Pair => {
            let no_world =
                "nothing to pair yet — capture a transaction first: pursecraft add coffee -4.50";
            match home::load_identity(&ctx.home) {
                Ok(Some(identity)) => match sync::pair(&ctx.home, &session, &identity) {
                    Ok(text) => Output::ok(text),
                    Err(e) => Output::fail(format!("error: {e}\n")),
                },
                Ok(None) => Output::fail(format!("error: {no_world}\n")),
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        argv::Cmd::Join {
            org_id,
            org_code,
            budget_id,
            budget_code,
        } => {
            let args = sync::JoinArgs {
                org_id: &org_id,
                org_code: &org_code,
                budget_id: &budget_id,
                budget_code: &budget_code,
            };
            match sync::join(&ctx.home, &session, &args) {
                Ok(text) => Output::ok(text),
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        // Help/Version/login answered before the gate; parse errors never
        // reach dispatch.
        argv::Cmd::Help | argv::Cmd::Version | argv::Cmd::Login { .. } => {
            unreachable!("meta commands answer before the gate")
        }
    }
}

/// A capture's confirmation plus ADR 0011's badge (ADR 0025): one extra
/// line exactly when captures wait for the relay — a synced capture stays
/// one line. The count derives from the stores (never stored itself); a
/// failure computing it is LOUD (exit 1, matching `list`) — the caller
/// prints the confirmation alongside the error so the stored capture is
/// never hidden.
fn with_pending_badge(
    home: &Path,
    session: &session::Session,
    receipt: &capture::Receipt,
) -> Result<String, sync::SyncError> {
    let pending = match home::load_identity(home)? {
        Some(identity) => sync::pending_count(home, session, &identity)?,
        // Unreachable in practice (add just bootstrapped); quiet stays.
        None => 0,
    };
    let mut out = receipt.confirmation();
    if pending > 0 {
        out.push_str(&format!("{pending} pending sync — run: pursecraft sync\n"));
    }
    Ok(out)
}

/// `sync`'s preconditions: a world to sync (identity exists — capture
/// owns bootstrap, ADR 0023), then the ordinary sync (ADR 0025).
fn run_sync(home: &Path, session: &session::Session) -> Result<String, sync::SyncError> {
    match home::load_identity(home)? {
        Some(identity) => Ok(sync::sync(home, session, &identity)?.render()),
        None => Err(sync::SyncError::NotBootstrapped),
    }
}

/// Enroll this device (ADR 0025): validate the URL, present the operator's
/// secret (stdin, one line) to the relay, publish the session. The secret
/// and the returned token never appear in the output.
fn login(home: &Path, server: &str, stdin: &str) -> Result<String, LoginError> {
    let server = normalize_server(server)?;
    let secret = stdin.lines().next().unwrap_or("").trim();
    if secret.is_empty() {
        return Err(LoginError::NoSecret);
    }
    let (device_id, token) = relay::enroll(&server, secret)?;
    session::publish(
        home,
        &session::Session {
            version: 1,
            server: server.clone(),
            device_id,
            token,
        },
    )?;
    Ok(format!("enrolled with {server} — capture is unlocked\n"))
}

/// Validate and normalize a relay URL (ADR 0025): plain `http`, host and
/// optional port, no path — TLS arrives with the hosted-relay slice.
fn normalize_server(server: &str) -> Result<String, LoginError> {
    let server = server.trim().trim_end_matches('/');
    if server.starts_with("https://") {
        return Err(LoginError::BadServer(
            "v1 speaks plain http to a local relay; TLS arrives with the hosted-relay slice".into(),
        ));
    }
    let Some(rest) = server.strip_prefix("http://") else {
        return Err(LoginError::BadServer(
            "the relay url must look like http://host:port".into(),
        ));
    };
    if rest.is_empty() || rest.contains('/') {
        return Err(LoginError::BadServer(
            "the relay url must be a bare http://host:port (no path)".into(),
        ));
    }
    Ok(server.to_owned())
}

/// A failed enrollment (ADR 0025).
#[derive(Debug)]
enum LoginError {
    BadServer(String),
    NoSecret,
    Relay(relay::RelayError),
    Session(session::SessionError),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadServer(message) => write!(f, "{message}"),
            Self::NoSecret => write!(
                f,
                "login reads the enrollment secret from stdin (one line); it lives in the relay's data directory (enrollment.secret)"
            ),
            Self::Relay(e) => write!(f, "{e}"),
            Self::Session(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoginError {}

impl From<relay::RelayError> for LoginError {
    fn from(e: relay::RelayError) -> Self {
        Self::Relay(e)
    }
}

impl From<session::SessionError> for LoginError {
    fn from(e: session::SessionError) -> Self {
        Self::Session(e)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_are_normalized_and_refused_with_teaching() {
        assert_eq!(
            normalize_server("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(normalize_server(" http://host/ ").unwrap(), "http://host");
        assert!(
            normalize_server("https://host")
                .unwrap_err()
                .to_string()
                .contains("plain http")
        );
        assert!(
            normalize_server("host:8080")
                .unwrap_err()
                .to_string()
                .contains("http://host:port")
        );
        // "http://" loses its slashes to the trailing-slash trim and is
        // caught by the scheme check — same teaching outcome.
        assert!(
            normalize_server("http://")
                .unwrap_err()
                .to_string()
                .contains("http://host:port")
        );
        assert!(
            normalize_server("http://h/p")
                .unwrap_err()
                .to_string()
                .contains("no path")
        );
    }
}
