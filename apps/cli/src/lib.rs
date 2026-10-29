//! The `pursecraft` command-line app (ADR 0023): fast local-first
//! transaction capture riding the shared core — one-shot argv commands,
//! every minted op through the single payload [`sink`] — and, since ADR
//! 0025, authenticated-first: every data command requires a one-time
//! enrollment (`session.json`), and `sync` drives the rendezvous relay.
//! The library is fully injectable (home path, today's date, stdin, argv
//! slice, and the interactive terminal ADR 0030's login form rides); the
//! thin binary `main.rs` is the only reader of the process environment.

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

/// The interactive terminal (ADR 0030): `login`'s form channel, present
/// only when stdin is a terminal. The library never touches the process
/// environment — the thin binary wires the real terminal (prompts to
/// stderr, secrets hidden), and tests script a fake to assert the
/// conversation, not just the outcome.
pub trait Terminal {
    /// Say one informational line (the derived-url echo).
    fn say(&mut self, line: &str) -> std::io::Result<()>;
    /// Read one line, echoed — nothing secret is asked this way.
    fn read_line(&mut self, prompt: &str) -> std::io::Result<String>;
    /// Read one line, hidden — the enrollment secret.
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// What the environment supplies a command (ADR 0023; grown by ADR 0025 and
/// ADR 0028): the data home, the local civil date captures default to, stdin —
/// `login`'s enrollment secret when it is piped (read by `main` only for
/// `login` without a terminal; every other command sees an empty string) —
/// the self-host E2EE switch, and the interactive terminal when stdin is a
/// tty (ADR 0030). Injected so tests (and any embedder) never touch the
/// process environment.
pub struct Context {
    pub home: PathBuf,
    pub today: Date,
    pub stdin: String,
    /// `false` only when `PURSECRAFT_E2EE=off` (ADR 0028): plaintext payloads,
    /// the no-E2EE self-host mode ADR 0009 allows.
    pub e2ee: bool,
    /// The form channel (ADR 0030): `Some` only when stdin is a terminal.
    pub terminal: Option<Box<dyn Terminal>>,
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
            Ok(mut ctx) => {
                match login(&ctx.home, server.as_deref(), &ctx.stdin, &mut ctx.terminal) {
                    Ok(line) => Output::ok(line),
                    Err(e) => Output::fail(format!("error: {e}\n")),
                }
            }
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

/// The hosted relay (ADR 0030): the compiled-in default `login` offers
/// first — login's front door. One constant, rendered in the choice line,
/// used by the non-terminal default, and round-tripped through
/// `normalize_server` (pinned by test), so it flows the same single
/// validator as every other server string and no copy of the endpoint
/// participates in behavior.
pub const DEFAULT_SERVER: &str = "https://pursecraft.com/api";

/// The hosted constant, validated: it passes [`normalize_server`] by
/// construction (unit-pinned), so the default path rides the single
/// validator with no bypass.
fn hosted_server() -> String {
    normalize_server(DEFAULT_SERVER).expect("the hosted constant round-trips (pinned by test)")
}

/// Compose the server candidate from a domain-only form answer (ADR 0030
/// §4). Classification, never validation: a typed scheme is used verbatim;
/// otherwise the host's class picks the scheme — loopback gets `http` and
/// no prefix (a local relay serves at the router root), everything else
/// `https` with the `/api` prefix unless one was typed. [`normalize_server`]
/// alone accepts or refuses the result; this function judges nothing.
fn derive_server(input: &str) -> String {
    let input = input.trim();
    if input.starts_with("https://") || input.starts_with("http://") {
        return input.to_owned();
    }
    let (authority, prefix) = match input.split_once('/') {
        Some((authority, prefix)) => (authority, Some(prefix)),
        None => (input, None),
    };
    // A bare `::1` is bracketed on composition (ADR 0030): a host with
    // colons is an IPv6 literal and the grammar speaks brackets.
    let authority = if authority == "::1" {
        "[::1]"
    } else {
        authority
    };
    let loopback = is_loopback(host_of(authority));
    let prefix = match prefix.filter(|p| !p.is_empty()) {
        Some(prefix) => format!("/{prefix}"),
        None if loopback => String::new(),
        None => "/api".to_owned(),
    };
    let scheme = if loopback { "http://" } else { "https://" };
    format!("{scheme}{authority}{prefix}")
}

/// The host behind an authority, for loopback classification only (ADR
/// 0030): inside brackets, or before the last colon. Ports, charset, and
/// range stay [`normalize_server`]'s to judge.
fn host_of(authority: &str) -> &str {
    if let Some(inner) = authority.strip_prefix('[') {
        return inner.split_once(']').map_or(inner, |(host, _)| host);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// The loopback set (ADR 0030): `localhost`, `127.x.x.x` IPv4 literals,
/// and the IPv6 loopback `::1` — the hosts for which plain `http` is
/// derived. Nothing else ever gets less than `https`.
fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || (host.starts_with("127.") && host.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        || host == "::1"
}

/// Enroll this device (ADR 0025; the surface reshaped by ADR 0030).
/// Resolve the server — the `--server` flag wins, no terminal defaults to
/// the hosted relay, a terminal gets the choice form — then fail early:
/// the relay must answer `/health` BEFORE any secret is requested or
/// read. With the relay proven reachable, present the operator's secret
/// (hidden prompt on a terminal, first piped line otherwise) and publish
/// the session. The secret and the returned token never appear in the
/// output.
fn login(
    home: &Path,
    server_arg: Option<&str>,
    stdin: &str,
    terminal: &mut Option<Box<dyn Terminal>>,
) -> Result<String, LoginError> {
    let (server, typed_domain) = resolve_server(server_arg, terminal)?;
    relay::probe_health(&server).map_err(|e| LoginError::Probe(e, typed_domain))?;
    let secret = match terminal.as_mut() {
        Some(term) => term
            .read_secret("enrollment secret: ")
            .map_err(LoginError::Io)?
            .trim()
            .to_owned(),
        None => stdin.lines().next().unwrap_or("").trim().to_owned(),
    };
    if secret.is_empty() {
        return Err(LoginError::NoSecret);
    }
    let (device_id, token) = relay::enroll(&server, &secret)?;
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

/// Resolve the login server (ADR 0030 §1–§4): the `--server` flag's full
/// URL, the hosted constant without a terminal, or the choice form —
/// Enter/`1` for the hosted relay, `2` for the domain-only form whose
/// answer is derived and echoed before anything else happens. Returns the
/// canonical server and, on the domain path, the typed domain (probe
/// errors name both).
fn resolve_server(
    server_arg: Option<&str>,
    terminal: &mut Option<Box<dyn Terminal>>,
) -> Result<(String, Option<String>), LoginError> {
    match (server_arg, terminal.as_mut()) {
        (Some(url), _) => Ok((normalize_server(url)?, None)),
        (None, None) => Ok((hosted_server(), None)),
        (None, Some(term)) => {
            let choice = term
                .read_line(&format!(
                    "1) Log in to pursecraft.com — the hosted relay ({DEFAULT_SERVER})\n\
                     2) Use my own server\n\
                     Choose [1]: "
                ))
                .map_err(LoginError::Io)?;
            match choice.trim() {
                "" | "1" => Ok((hosted_server(), None)),
                "2" => {
                    let domain = term
                        .read_line("Your relay domain (e.g. example.com or 127.0.0.1:8099): ")
                        .map_err(LoginError::Io)?;
                    let candidate = derive_server(&domain);
                    let server = normalize_server(&candidate)?;
                    term.say(&format!("relay url: {server}"))
                        .map_err(LoginError::Io)?;
                    Ok((server, Some(domain.trim().to_owned())))
                }
                _ => Err(LoginError::Choice),
            }
        }
    }
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

/// A failed enrollment (ADR 0025; grown by ADR 0030's resolution, probe,
/// and terminal errors).
#[derive(Debug)]
enum LoginError {
    BadServer(String),
    /// The choice screen got something other than Enter/1/2 (ADR 0030):
    /// one shot, loud, rerun.
    Choice,
    /// The `/health` probe failed before any secret was requested (ADR
    /// 0030) — with the typed domain on the form path, so a typo is
    /// obvious.
    Probe(relay::ProbeError, Option<String>),
    /// The terminal died mid-form (EOF, closed stream).
    Io(std::io::Error),
    NoSecret,
    Relay(relay::RelayError),
    Session(session::SessionError),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadServer(message) => write!(f, "{message}"),
            Self::Choice => write!(
                f,
                "the form asks for 1 (the hosted relay, pursecraft.com) or 2 (your own \
                 server) — Enter means 1"
            ),
            Self::Probe(e, Some(domain)) => write!(
                f,
                "{e} — derived from domain \"{domain}\"; check the domain (the hosted \
                 relay is pursecraft.com)"
            ),
            Self::Probe(e, None) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "cannot read the terminal: {e}"),
            Self::NoSecret => write!(
                f,
                "login needs the enrollment secret — it lives in the relay's data \
                 directory (enrollment.secret); it is read hidden from a terminal \
                 prompt, or as the first line piped on stdin"
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

    use super::Terminal;

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

    /// The scripted terminal (ADR 0030): records every line, prompt, and
    /// secret request in one transcript, answering from a queue — tests
    /// assert the conversation (what was asked, in what order), not just
    /// the outcome. Shared through `Rc<RefCell<…>>` so the caller keeps
    /// reading the transcript after the form consumed the channel.
    pub(crate) struct ScriptedTerminal {
        pub(crate) transcript: Vec<String>,
        answers: std::collections::VecDeque<String>,
    }

    impl ScriptedTerminal {
        pub(crate) fn new(answers: &[&str]) -> Self {
            Self {
                transcript: Vec::new(),
                answers: answers.iter().map(|a| (*a).to_owned()).collect(),
            }
        }
    }

    /// The newtype that hands a shared [`ScriptedTerminal`] to the form
    /// channel: local, so the [`Terminal`] impl obeys the orphan rule.
    pub(crate) struct SharedTerminal(pub(crate) std::rc::Rc<std::cell::RefCell<ScriptedTerminal>>);

    impl Terminal for SharedTerminal {
        fn say(&mut self, line: &str) -> std::io::Result<()> {
            self.0.borrow_mut().transcript.push(format!("{line}\n"));
            Ok(())
        }

        fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
            let mut script = self.0.borrow_mut();
            script.transcript.push(prompt.to_owned());
            Ok(script.answers.pop_front().unwrap_or_default())
        }

        fn read_secret(&mut self, prompt: &str) -> std::io::Result<String> {
            let mut script = self.0.borrow_mut();
            script.transcript.push(format!("{prompt}<hidden>\n"));
            Ok(script.answers.pop_front().unwrap_or_default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::testsupport::ScriptedTerminal;

    /// The form channel for a unit test: a scripted terminal wrapped for
    /// the `Option<Box<dyn Terminal>>` the login flow takes.
    fn form(answers: &[&str]) -> (Option<Box<dyn Terminal>>, Rc<RefCell<ScriptedTerminal>>) {
        let script = Rc::new(RefCell::new(ScriptedTerminal::new(answers)));
        (
            Some(Box::new(crate::testsupport::SharedTerminal(script.clone()))),
            script,
        )
    }

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

    /// ADR 0030: the hosted constant is the deployed URL and passes the
    /// single validator unchanged — no bypass path, not even compiled in.
    #[test]
    fn the_hosted_constant_is_the_deployed_url_and_round_trips() {
        assert_eq!(DEFAULT_SERVER, "https://pursecraft.com/api");
        assert_eq!(normalize_server(DEFAULT_SERVER).unwrap(), DEFAULT_SERVER);
    }

    /// ADR 0030 §4: one deterministic candidate per domain answer, and
    /// every accepted candidate passes the single validator unchanged.
    #[test]
    fn domains_derive_one_deterministic_candidate() {
        for (input, want) in [
            ("pursecraft.com", "https://pursecraft.com/api"),
            (" example.com ", "https://example.com/api"),
            ("example.com:8443", "https://example.com:8443/api"),
            ("example.com/relay", "https://example.com/relay"),
            // An empty typed prefix is no prefix: the hosted default.
            ("example.com/", "https://example.com/api"),
            // Loopback: http, and nothing added — a local relay serves at
            // the router root; a typed prefix rides as typed.
            ("localhost", "http://localhost"),
            ("Localhost", "http://Localhost"),
            ("localhost:8099/api", "http://localhost:8099/api"),
            ("127.0.0.1", "http://127.0.0.1"),
            ("127.0.0.1:8099", "http://127.0.0.1:8099"),
            ("127.5.6.7", "http://127.5.6.7"),
            ("[::1]", "http://[::1]"),
            ("[::1]:8099", "http://[::1]:8099"),
            ("::1", "http://[::1]"),
            // No silent downgrades: a LAN host is not loopback — https,
            // and a plain-http LAN relay must be typed with its full URL.
            ("192.168.1.10:8099", "https://192.168.1.10:8099/api"),
            // `127.com` is a real domain, not a loopback literal: letters
            // after `127.` mean it is classified by name, not octet.
            ("127.com", "https://127.com/api"),
            // A typed scheme is the scheme used — verbatim, interpreted
            // never.
            ("https://typed.example/x", "https://typed.example/x"),
            ("http://plain.example", "http://plain.example"),
        ] {
            assert_eq!(derive_server(input), want, "input {input:?}");
            assert_eq!(
                normalize_server(&derive_server(input)).unwrap(),
                want,
                "{input:?}: the candidate must pass the single validator unchanged"
            );
        }
    }

    /// ADR 0030 §4: derivation validates nothing — garbage composes a
    /// candidate the single validator refuses, loudly.
    #[test]
    fn garbage_domains_compose_candidates_the_single_validator_refuses() {
        for input in [
            "",
            "127.0.0.1:zero",
            "example.com/a/b",
            "example.com/api?x=1",
            "host with spaces",
            "::1:8099",
        ] {
            let candidate = derive_server(input);
            assert!(
                normalize_server(&candidate).is_err(),
                "{input:?} -> {candidate:?} must be refused by the single validator"
            );
        }
    }

    /// ADR 0030 §3: the choice screen — Enter and `1` are the hosted
    /// relay (whose URL the prompt shows), `2` derives the typed domain
    /// and says the final URL, anything else teaches.
    #[test]
    fn the_form_resolves_hosted_or_derives_the_own_server() {
        for choice in ["", "1"] {
            let (mut terminal, script) = form(&[choice]);
            let (server, domain) = resolve_server(None, &mut terminal).unwrap();
            assert_eq!(server, DEFAULT_SERVER, "choice {choice:?}");
            assert_eq!(domain, None);
            let transcript = script.borrow().transcript.clone();
            assert_eq!(transcript.len(), 1, "one question, no more: {transcript:?}");
            assert!(
                transcript[0].contains(DEFAULT_SERVER),
                "the choice line shows the endpoint: {}",
                transcript[0]
            );
        }

        let (mut terminal, script) = form(&["2", "example.com"]);
        let (server, domain) = resolve_server(None, &mut terminal).unwrap();
        assert_eq!(server, "https://example.com/api");
        assert_eq!(domain.as_deref(), Some("example.com"));
        assert_eq!(
            script.borrow().transcript,
            vec![
                format!(
                    "1) Log in to pursecraft.com — the hosted relay ({DEFAULT_SERVER})\n\
                     2) Use my own server\n\
                     Choose [1]: "
                ),
                "Your relay domain (e.g. example.com or 127.0.0.1:8099): ".to_owned(),
                "relay url: https://example.com/api\n".to_owned(),
            ],
            "choice, domain, then the derived url — the whole conversation"
        );

        let (mut terminal, _) = form(&["3"]);
        let err = resolve_server(None, &mut terminal).unwrap_err().to_string();
        assert!(
            err.contains("1 (the hosted relay, pursecraft.com) or 2"),
            "{err}"
        );
    }

    /// ADR 0030 §1: the flag resolves through the single validator; no
    /// terminal at all resolves to the hosted default.
    #[test]
    fn the_flag_validates_and_no_terminal_defaults_to_the_hosted_relay() {
        let mut none: Option<Box<dyn Terminal>> = None;
        assert_eq!(
            resolve_server(None, &mut none).unwrap(),
            (DEFAULT_SERVER.to_owned(), None)
        );
        assert_eq!(
            resolve_server(Some("https://h/api"), &mut none).unwrap(),
            ("https://h/api".to_owned(), None)
        );
        assert!(resolve_server(Some("no-scheme"), &mut none).is_err());
    }

    /// ADR 0030 §5, as behavior: a failed probe names the derived URL and
    /// the typed domain — and the secret is never asked for.
    #[test]
    fn a_failed_probe_names_the_url_and_never_asks_for_the_secret() {
        let (mut terminal, script) = form(&["2", "127.0.0.1:9"]);
        let home = testsupport::TempDir::new("probe-order");
        let err = login(home.path(), None, "a-secret\n", &mut terminal)
            .unwrap_err()
            .to_string();
        assert!(err.contains("http://127.0.0.1:9"), "{err}");
        assert!(err.contains("derived from domain \"127.0.0.1:9\""), "{err}");
        let transcript = script.borrow().transcript.clone();
        assert!(
            !transcript
                .iter()
                .any(|line| line.contains("enrollment secret")),
            "the secret was never asked for: {transcript:?}"
        );
    }
}
