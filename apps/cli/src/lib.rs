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
pub mod budget;
pub mod capture;
pub mod categorize;
pub mod category;
pub mod home;
pub mod idmint;
pub mod keys;
pub mod list;
pub mod relay;
pub mod session;
pub mod sink;
pub mod sync;

use std::path::{Path, PathBuf};

use pursecraft_core::date::Date;

/// What the environment supplies a command (ADR 0023; grown by ADR 0025 and
/// ADR 0028): the data home, the local civil date captures default to, stdin —
/// `login`'s enrollment secret (read by `main` only for `login`; every other
/// command sees an empty string) — and the self-host E2EE switch. Injected so
/// tests (and any embedder) never touch the process environment.
pub struct Context {
    pub home: PathBuf,
    pub today: Date,
    pub stdin: String,
    /// `false` only when `PURSECRAFT_E2EE=off` (ADR 0028): plaintext payloads,
    /// the no-E2EE self-host mode ADR 0009 allows.
    pub e2ee: bool,
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
        // enrollment. ADR 0027's budgeting commands join it — they touch
        // data like every other.
        Ok(
            gated @ (argv::Cmd::Add { .. }
            | argv::Cmd::List
            | argv::Cmd::CategoryNew { .. }
            | argv::Cmd::CategoryList
            | argv::Cmd::Categorize { .. }
            | argv::Cmd::Assign { .. }
            | argv::Cmd::Budget { .. }
            | argv::Cmd::Sync
            | argv::Cmd::Pair
            | argv::Cmd::Join { .. }),
        ) => match ctx() {
            Ok(ctx) => match session::load(&ctx.home) {
                Ok(Some(session)) => match keys::World::open(&ctx.home, ctx.e2ee) {
                    // The mode's front door (ADR 0028): a ciphered/plaintext
                    // mismatch refuses here, before any command touches a log.
                    Ok(world) => {
                        // A joiner whose keys have not arrived yet says so
                        // instead of rendering an empty world (ADR 0028);
                        // `sync` is the way forward, so it is let through.
                        if world.pending_join() && !matches!(gated, argv::Cmd::Sync) {
                            Output::fail(format!("error: {}\n", keys::KeysError::NoKeys))
                        } else {
                            dispatch(gated, ctx, world, session)
                        }
                    }
                    Err(e) => Output::fail(format!("error: {e}\n")),
                },
                Ok(None) => Output::fail(format!("error: {}\n", session::GATE_MESSAGE)),
                Err(e) => Output::fail(format!("error: {e}\n")),
            },
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        Err(e) => Output::usage(&e.to_string()),
    }
}

/// Dispatch a gated command — the session exists and the world's mode has
/// been resolved by construction.
fn dispatch(
    cmd: argv::Cmd,
    ctx: Context,
    mut world: keys::World,
    session: session::Session,
) -> Output {
    match cmd {
        argv::Cmd::Add {
            payee,
            amount,
            date,
            account,
            category,
        } => {
            let raw = capture::RawAdd {
                payee: &payee,
                amount: &amount,
                date: date.as_deref(),
                account: account.as_deref(),
                category: category.as_deref(),
            };
            match capture::add(&mut world, &session, &raw, ctx.today) {
                Ok(receipt) => finish_write(&world, &session, receipt.confirmation()),
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        argv::Cmd::List => match list::list(&world, &session) {
            Ok(text) => Output::ok(text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::CategoryNew { name, group } => {
            match category::new_category(&world, &session, &name, group.as_deref()) {
                Ok(text) => finish_write(&world, &session, text),
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        argv::Cmd::CategoryList => match category::list(&world, &session) {
            Ok(text) => Output::ok(text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::Categorize { txn, category } => match (txn, category) {
            (None, _) => match categorize::review(&world, &session) {
                Ok(text) => Output::ok(text),
                Err(e) => Output::fail(format!("error: {e}\n")),
            },
            (Some(txn), Some(category)) => {
                match categorize::file(&world, &session, &txn, &category) {
                    Ok(text) => finish_write(&world, &session, text),
                    Err(e) => Output::fail(format!("error: {e}\n")),
                }
            }
            (Some(_), None) => unreachable!("argv pairs the selector with a category"),
        },
        argv::Cmd::Assign {
            category,
            amount,
            month,
        } => match budget::assign(
            &world,
            &session,
            &category,
            &amount,
            month.as_deref(),
            ctx.today,
        ) {
            Ok(text) => finish_write(&world, &session, text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::Budget { month } => {
            match budget::show(&world, &session, month.as_deref(), ctx.today) {
                Ok(text) => Output::ok(text),
                Err(e) => Output::fail(format!("error: {e}\n")),
            }
        }
        argv::Cmd::Sync => match run_sync(&mut world, &session) {
            Ok(text) => Output::ok(text),
            Err(e) => Output::fail(format!("error: {e}\n")),
        },
        argv::Cmd::Pair => {
            let no_world =
                "nothing to pair yet — capture a transaction first: pursecraft add coffee -4.50";
            match home::load_identity(&ctx.home) {
                Ok(Some(identity)) => match sync::pair(&world, &session, &identity) {
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
            match sync::join(&mut world, &session, &args) {
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

/// A write command's finish (ADR 0011's badge, ADR 0025): the
/// confirmation plus the pending line exactly when ops wait for the
/// relay. The count derives from the stores; a failure computing it is
/// LOUD (exit 1) — the caller's confirmation is printed alongside the
/// error so what was stored is never hidden.
fn finish_write(world: &keys::World, session: &session::Session, confirmation: String) -> Output {
    let pending = match home::load_identity(&world.home) {
        Ok(Some(identity)) => match sync::pending_count(world, session, &identity) {
            Ok(pending) => pending,
            Err(e) => return Output::fail(format!("{}\nerror: {e}\n", confirmation.trim_end())),
        },
        // Unreachable in practice (the write just bootstrapped); quiet
        // stays.
        Ok(None) => 0,
        Err(e) => return Output::fail(format!("{}\nerror: {e}\n", confirmation.trim_end())),
    };
    let mut out = confirmation;
    if pending > 0 {
        out.push_str(&format!("{pending} pending sync — run: pursecraft sync\n"));
    }
    Output::ok(out)
}

/// `sync`'s preconditions: a world to sync (identity exists — capture owns
/// bootstrap, ADR 0023), then the ordinary sync (ADR 0025). An unfinished
/// join has no identity yet by design and is the one exception (ADR 0028):
/// `sync` finishes it.
fn run_sync(
    world: &mut keys::World,
    session: &session::Session,
) -> Result<String, sync::SyncError> {
    match home::load_identity(&world.home)? {
        Some(identity) => Ok(sync::sync(world, session, &identity)?.render()),
        None if sync::has_pending_join(&world.home)? => {
            Ok(sync::resume_join(world, session)?.render())
        }
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

/// Validate and normalize a relay URL (ADR 0029): `http` or `https`,
/// `host[:port]` (name, IPv4, or bracketed IPv6), and at most one
/// base-path segment — the deployed `https://pursecraft.com/api`.
/// Strictness is the point: the typed scheme is the scheme used (no
/// silent fallback, no followed redirects), and anything else — deeper
/// paths, queries, fragments, userinfo — is a teaching error, never a
/// guess. The returned canonical form is what `session.json` stores;
/// `relay.rs` composes routes by plain concatenation against it.
fn normalize_server(server: &str) -> Result<String, LoginError> {
    const FORM: &str = "the relay url must look like https://pursecraft.com/api \
         or http://127.0.0.1:8099 — a host[:port], optionally under https";
    const PATH: &str = "the relay url may carry at most one base-path segment \
         (e.g. /api): ASCII letters, digits, '-', '_', interior dots only";
    const PORT: &str = "the relay url's port must be digits in 1..=65535, \
         e.g. http://127.0.0.1:8099";

    let server = server.trim().trim_end_matches('/');
    let (scheme, rest) = if let Some(rest) = server.strip_prefix("https://") {
        ("https://", rest)
    } else if let Some(rest) = server.strip_prefix("http://") {
        ("http://", rest)
    } else {
        return Err(LoginError::BadServer(FORM.into()));
    };

    // authority[/prefix]: one optional segment, nothing deeper.
    let (authority, prefix) = match rest.split_once('/') {
        None => (rest, None),
        Some((authority, prefix)) => {
            let segment_ok = !prefix.is_empty()
                && !prefix.starts_with('.')
                && !prefix.ends_with('.')
                && !prefix.contains("..")
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !segment_ok {
                return Err(LoginError::BadServer(PATH.into()));
            }
            (authority, Some(prefix))
        }
    };

    // host[:port] or [v6][:port], kept verbatim in the canonical form.
    // Userinfo (`u:p@host`) is a form error, not a port error — the `@`
    // is checked before any colon is mistaken for a port separator.
    if authority.is_empty() || authority.contains('@') {
        return Err(LoginError::BadServer(FORM.into()));
    }
    if let Some(inner) = authority.strip_prefix('[') {
        // A bracketed IPv6 literal, optionally with a port.
        let Some((addr, tail)) = inner.split_once(']') else {
            return Err(LoginError::BadServer(FORM.into()));
        };
        let host_ok = !addr.is_empty() && addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
        let port_ok = match tail.strip_prefix(':') {
            Some(digits) => valid_port(digits),
            None => tail.is_empty(),
        };
        if !host_ok || !port_ok {
            return Err(LoginError::BadServer(FORM.into()));
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
        if !host_ok || !valid_port(port) {
            return Err(LoginError::BadServer(PORT.into()));
        }
    } else {
        let host_ok = authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
        if !host_ok {
            return Err(LoginError::BadServer(FORM.into()));
        }
    }

    Ok(match prefix {
        Some(prefix) => format!("{scheme}{authority}/{prefix}"),
        None => format!("{scheme}{authority}"),
    })
}

/// A port is digits only, 1..=65535 (kept verbatim when valid — `:080`
/// stays `:080`; canonicalization is connect-time, not rewrite-time).
fn valid_port(digits: &str) -> bool {
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits
            .parse::<u32>()
            .is_ok_and(|p| (1..=65535).contains(&p))
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
        // The old plain-http shapes, byte-identical (ADR 0025 → 0029).
        assert_eq!(
            normalize_server("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(normalize_server(" http://host/ ").unwrap(), "http://host");
        assert_eq!(
            normalize_server("http://[::1]:8099").unwrap(),
            "http://[::1]:8099"
        );

        // The deployed shapes (ADR 0029): https, base path, defaults.
        assert_eq!(
            normalize_server("https://pursecraft.com/api").unwrap(),
            "https://pursecraft.com/api"
        );
        assert_eq!(
            normalize_server("https://pursecraft.com/api/").unwrap(),
            "https://pursecraft.com/api"
        );
        assert_eq!(normalize_server("https://host").unwrap(), "https://host");
        assert_eq!(
            normalize_server("https://host:8443/base-1_a.2").unwrap(),
            "https://host:8443/base-1_a.2"
        );

        // No scheme guessing, no case-insensitive spelling.
        assert!(
            normalize_server("host:8080")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );
        assert!(
            normalize_server("HTTPS://host")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );
        assert!(
            normalize_server("ftp://host")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );
        // "http://" loses its slashes to the trailing-slash trim and is
        // caught by the scheme check — same teaching outcome.
        assert!(
            normalize_server("http://")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );

        // Ports are digits in range or a teaching error.
        assert!(
            normalize_server("http://host:zero")
                .unwrap_err()
                .to_string()
                .contains("port")
        );
        assert!(
            normalize_server("http://host:99999")
                .unwrap_err()
                .to_string()
                .contains("port")
        );
        assert!(
            normalize_server("http://host:0")
                .unwrap_err()
                .to_string()
                .contains("port")
        );

        // At most one base-path segment, and it stays boring: no deeper
        // paths, no traversal, no junk characters, no queries, fragments,
        // or userinfo hiding in the tail.
        for junk in [
            "https://h/p/q",
            "https://h/.",
            "https://h/..",
            "https://h/a..b",
            "https://h/.a",
            "https://h/a.",
            "https://h/p?q=1",
            "https://h/p#f",
            "https://h/%20",
            "https://h/p q",
        ] {
            let message = normalize_server(junk).unwrap_err().to_string();
            assert!(
                message.contains("base-path") || message.contains("must look like"),
                "{junk}: {message}"
            );
            assert!(normalize_server(junk).is_err(), "{junk} refused");
        }
        assert!(
            normalize_server("https://user@host")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );
        // Userinfo with a colon must teach the FORM, not the port.
        assert!(
            normalize_server("http://u:p@host")
                .unwrap_err()
                .to_string()
                .contains("must look like")
        );
    }
}
