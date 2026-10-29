//! Relay-driven integration tests (issue #26, ADR 0025): whole CLI homes
//! against a REAL relay — the actual axum router over an actual localhost
//! socket, driven by the CLI's actual HTTP client. The headline is the
//! two-device dogfood: both homes capture offline, both sync, and
//! convergence is asserted through the engine's own state equality —
//! each home's state must equal the other's AND the relay's canonical
//! replay (ADR 0017's theorem, observed end to end).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pursecraft_api::{AppState, router};
use pursecraft_cli::Terminal;
use pursecraft_cli::home::{budget_log, load_identity, org_log};
use pursecraft_cli::session::{self, Session};
use pursecraft_cli::{Context, run};
use pursecraft_core::date::Date;
use pursecraft_core::ids::DeviceId;
use pursecraft_core::ops::{Op, ScopeState};
use pursecraft_core::store::{LocalStore, OpaqueStore};
use pursecraft_core::sync::{SequencedOp, SyncSession};
use pursecraft_core::wire::decode_payload;

// ---------------------------------------------------------------------
// A live relay: the real router on a real ephemeral socket (one thread,
// one runtime), plus the stop/restart surgery the auth tests need.
// ---------------------------------------------------------------------

struct LiveRelay {
    dir: PathBuf,
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Whether `drop` owns (and removes) the data directory — released
    /// when another relay takes over the same bytes (the restart tests).
    owns_dir: bool,
}

impl LiveRelay {
    fn start(label: &str) -> Self {
        Self::start_on(scratch_dir(label))
    }

    /// Serve the router nested under one base-path segment — the fleet's
    /// `/api` shape (ADR 0029): the proxy strips the prefix exactly as
    /// `nest` does, so the client's composed URLs meet the real routes.
    fn start_under_api(label: &str) -> Self {
        let dir = scratch_dir(label);
        let state = Arc::new(AppState::open(&dir).expect("open relay state"));
        let app = axum::Router::new().nest("/api", router(state));
        Self::spawn_serving(dir, app, "/api")
    }

    /// Serve the real router over `dir` on an ephemeral localhost port.
    fn start_on(dir: PathBuf) -> Self {
        let state = Arc::new(AppState::open(&dir).expect("open relay state"));
        Self::spawn_serving(dir, router(state), "")
    }

    fn spawn_serving(dir: PathBuf, app: axum::Router, url_prefix: &str) -> Self {
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(format!(
                "relay-{label}",
                label = dir.file_name().unwrap().to_string_lossy()
            ))
            .spawn(move || {
                let runtime = tokio::runtime::Runtime::new().expect("test runtime");
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("bind ephemeral");
                    addr_tx
                        .send(listener.local_addr().expect("local addr"))
                        .expect("test waits for the addr");
                    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                        let _ = stop_rx.await;
                    });
                    let _ = server.await;
                });
            })
            .expect("spawn relay thread");
        let addr = addr_rx.recv().expect("relay bound");
        Self {
            dir,
            url: format!("http://{addr}{url_prefix}"),
            stop: Some(stop_tx),
            thread: Some(thread),
            owns_dir: true,
        }
    }

    fn enrollment_secret(&self) -> String {
        std::fs::read_to_string(self.dir.join("enrollment.secret"))
            .unwrap()
            .trim_end()
            .to_owned()
    }

    /// Stop the server (dropping it from the port) but keep the data —
    /// the restart boundary the auth tests cross.
    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Hand the data directory to a successor relay — this one's `drop`
    /// must not delete what it no longer owns.
    fn detach(&mut self) {
        self.stop();
        self.owns_dir = false;
    }
}

impl Drop for LiveRelay {
    fn drop(&mut self) {
        self.stop();
        if self.owns_dir {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn scratch_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pursecraft-cli-relay-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A lazy piped secret from a string — the test mirror of the real
/// binary's `read_stdin` source (ADR 0030 §5): login calls it only after
/// the probe passes. Empty means nothing piped (the empty-stdin teaching).
fn piped(stdin: &str) -> Option<Box<dyn FnOnce() -> String>> {
    if stdin.is_empty() {
        return None;
    }
    let text = stdin.to_owned();
    Some(Box::new(move || text))
}

/// The scripted terminal (ADR 0030): records every line, prompt, and
/// secret request in one transcript, answering from a queue — tests
/// assert the conversation (what was asked, in what order), not just the
/// outcome. `secret_read_at` timestamps the hidden read (the probe-order
/// test: the read must precede the probe's answer).
struct ScriptedTerminal {
    transcript: Vec<String>,
    secret_read_at: Option<std::time::Instant>,
    answers: std::collections::VecDeque<String>,
}

impl ScriptedTerminal {
    fn new(answers: &[&str]) -> Self {
        Self {
            transcript: Vec::new(),
            secret_read_at: None,
            answers: answers.iter().map(|a| (*a).to_owned()).collect(),
        }
    }
}

/// The newtype that hands a shared [`ScriptedTerminal`] to the form
/// channel: local, so the `Terminal` impl obeys the orphan rule.
struct SharedTerminal(std::rc::Rc<std::cell::RefCell<ScriptedTerminal>>);

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

    fn hide_input(&mut self) -> std::io::Result<()> {
        self.0
            .borrow_mut()
            .transcript
            .push("<echo off>\n".to_owned());
        Ok(())
    }

    fn show_input(&mut self) -> std::io::Result<()> {
        self.0
            .borrow_mut()
            .transcript
            .push("<echo on>\n".to_owned());
        Ok(())
    }

    fn read_secret(&mut self, prompt: &str) -> std::io::Result<String> {
        let mut script = self.0.borrow_mut();
        script.secret_read_at = Some(std::time::Instant::now());
        script.transcript.push(format!("{prompt}<hidden>\n"));
        Ok(script.answers.pop_front().unwrap_or_default())
    }
}

/// A CLI home: a scratch directory, run through the real dispatch.
struct Home {
    dir: PathBuf,
    /// The self-host E2EE switch (ADR 0028): the plaintext suite runs with it
    /// off; the E2EE suite turns it on.
    e2ee: bool,
}

impl Home {
    fn new(label: &str) -> Self {
        Self {
            dir: scratch_dir(label),
            e2ee: false,
        }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    /// One command line, exactly as the binary would run it.
    fn run(&self, stdin: &str, args: &[&str]) -> pursecraft_cli::Output {
        let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        run(&argv, || {
            Ok(Context {
                home: self.dir.clone(),
                today: Date::new(2026, 10, 25).unwrap(),
                // Lazy, like the real binary's (ADR 0030 §5): the secret
                // text is only handed over when login asks for it.
                piped_secret: piped(stdin),
                e2ee: self.e2ee,
                terminal: None,
            })
        })
    }

    /// Run `login` with a scripted terminal (ADR 0030): the form channel
    /// plus its answers — the transcript (and the hidden read's timestamp,
    /// for the probe-order test) come back for asserts.
    fn run_form(
        &self,
        answers: &[&str],
        args: &[&str],
    ) -> (
        pursecraft_cli::Output,
        Vec<String>,
        Option<std::time::Instant>,
    ) {
        let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let script = std::rc::Rc::new(std::cell::RefCell::new(ScriptedTerminal::new(answers)));
        let terminal: Option<Box<dyn pursecraft_cli::Terminal>> =
            Some(Box::new(SharedTerminal(script.clone())));
        let out = run(&argv, || {
            Ok(Context {
                home: self.dir.clone(),
                today: Date::new(2026, 10, 25).unwrap(),
                piped_secret: None,
                e2ee: self.e2ee,
                terminal,
            })
        });
        let script = script.borrow();
        (out, script.transcript.clone(), script.secret_read_at)
    }

    fn login(&self, relay: &LiveRelay) -> pursecraft_cli::Output {
        self.run(
            &format!("{}\n", relay.enrollment_secret()),
            &["login", "--server", &relay.url],
        )
    }

    fn session(&self) -> Session {
        session::load(self.path()).unwrap().expect("enrolled")
    }

    fn reseat_session_server(&self, url: &str) {
        let mut session = self.session();
        session.server = url.to_owned();
        session::publish(self.path(), &session).unwrap();
    }

    /// The home's materialized budget state, replayed through the engine.
    fn budget_state(&self) -> ScopeState {
        let identity = load_identity(self.path()).unwrap().expect("world exists");
        let store = LocalStore::open(&budget_log(self.path(), identity.budget_id)).unwrap();
        let mut replay = SyncSession::new();
        replay.apply_delta(store.delta_since(0)).unwrap();
        replay.state().clone()
    }

    fn org_state(&self) -> ScopeState {
        let identity = load_identity(self.path()).unwrap().expect("world exists");
        let store = LocalStore::open(&org_log(self.path(), identity.org_id)).unwrap();
        let mut replay = SyncSession::new();
        replay.apply_delta(store.delta_since(0)).unwrap();
        replay.state().clone()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The relay's canonical replay of one scope's log — the independent
/// reference both homes must equal (ADR 0017: same op set, same state).
fn canonical_relay_state(relay: &LiveRelay, log_file: &str) -> ScopeState {
    let store = OpaqueStore::open(&relay.dir.join("logs").join(log_file)).unwrap();
    let mut replay = SyncSession::new();
    let delta: Vec<SequencedOp> = store
        .delta_parts_since(0)
        .map(|row| {
            let payload = decode_payload(row.payload).expect("relay payload decodes");
            SequencedOp {
                seq: row.seq,
                op: Op::from_parts(row.meta.clone(), payload),
            }
        })
        .collect();
    replay.apply_delta(&delta).unwrap();
    replay.state().clone()
}

fn budget_log_name(home: &Home) -> String {
    let identity = load_identity(home.path()).unwrap().expect("world exists");
    format!("budget-{}.pcoplog", identity.budget_id.as_uuid().simple())
}

fn org_log_name(home: &Home) -> String {
    let identity = load_identity(home.path()).unwrap().expect("world exists");
    format!("org-{}.pcoplog", identity.org_id.as_uuid().simple())
}

/// Parse `pursecraft join <org> <code> <budget> <code>` out of printed
/// output — the dogfood proof: the instructions the tool prints are the
/// instructions that work.
fn parse_join_line(stdout: &str) -> [String; 4] {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("pursecraft join"))
        .unwrap_or_else(|| panic!("no join line printed\n{stdout}"));
    let parts: Vec<&str> = line.split_whitespace().collect();
    let args = &parts[2..];
    assert_eq!(args.len(), 4, "{line}");
    std::array::from_fn(|i| args[i].to_owned())
}

// ---------------------------------------------------------------------
// Enrollment (login) — the gate's door (ADR 0025).
// ---------------------------------------------------------------------

#[test]
fn login_enrolls_once_and_refuses_wrong_secrets() {
    let mut relay = LiveRelay::start("login");
    let home = Home::new("login");

    let wrong = home.run("not-the-secret\n", &["login", "--server", &relay.url]);
    assert_eq!(wrong.code, 1, "{}", wrong.stderr);
    assert!(
        wrong.stderr.contains("refused the enrollment secret"),
        "{}",
        wrong.stderr
    );
    assert!(
        session::load(home.path()).unwrap().is_none(),
        "a refused login enrolls nothing"
    );

    let ok = home.login(&relay);
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    assert!(ok.stdout.contains("enrolled"), "{}", ok.stdout);
    // The credential surfaces nowhere: not the token, not the secret.
    let secret = relay.enrollment_secret();
    assert!(!ok.stdout.contains(&secret), "{}", ok.stdout);
    let enrolled = home.session();
    assert!(!ok.stdout.contains(&enrolled.token), "{}", ok.stdout);
    assert_eq!(enrolled.server, relay.url);

    // A dead relay and an https url teach rather than crash: https is
    // accepted grammar now (ADR 0029), so the refusal is the probe's
    // unreachable teaching — a dead local port keeps the test hermetic
    // (no DNS). The probe runs before the secret is read (ADR 0030), so
    // the piped secret is never consumed on these failures.
    let dead = Home::new("login-dead");
    let out = dead.run("s\n", &["login", "--server", "http://127.0.0.1:9"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("cannot reach"), "{}", out.stderr);
    assert!(
        out.stderr.contains("http://127.0.0.1:9"),
        "the error names the url\n{}",
        out.stderr
    );
    let tls = dead.run("s\n", &["login", "--server", "https://127.0.0.1:9"]);
    assert_eq!(tls.code, 1);
    assert!(tls.stderr.contains("cannot reach"), "{}", tls.stderr);
    // An empty piped stdin is caught after the probe (ADR 0030's order),
    // so this needs a reachable relay — the live one above.
    let empty = home.run("", &["login", "--server", &relay.url]);
    assert_eq!(empty.code, 1);
    assert!(
        empty.stderr.contains("enrollment secret"),
        "an empty stdin teaches the shape\n{}",
        empty.stderr
    );
    assert!(
        session::load(home.path()).unwrap().is_some(),
        "the empty attempt enrolls nothing new but keeps the session"
    );
    relay.stop();
}

/// ADR 0030's headline: the form. A terminal, choice `2`, and nothing but
/// a `host:port` answer — the CLI derives the URL, says it, probes it,
/// and only then asks for the secret (hidden). The transcript — not just
/// the outcome — is the assertion: what was asked, in what order, and
/// that the endpoint was on screen before anything secret.
#[test]
fn the_form_enrolls_from_a_domain_and_the_transcript_orders_everything() {
    let mut relay = LiveRelay::start("form");
    let home = Home::new("form");

    // What the user types: `2`, then just the local relay's host:port.
    let domain = relay
        .url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    let secret = relay.enrollment_secret();
    let (out, transcript, _secret_at) = home.run_form(&["2", &domain, &secret], &["login"]);

    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let derived = format!("http://{domain}"); // loopback: http, no prefix
    assert_eq!(
        out.stdout,
        format!("enrolled with {derived} — capture is unlocked\n")
    );
    assert_eq!(
        home.session().server,
        derived,
        "the session stores the derived url, not the typed answer"
    );
    // The whole conversation, in order: choice (endpoint shown), domain,
    // derived url, echo OFF across the probe (§6's span), and only then —
    // after the probe passed — the secret prompt, echo restored after.
    assert_eq!(
        transcript,
        vec![
            format!(
                "1) Log in to pursecraft.com — the hosted relay ({})\n\
                 2) Use my own server\n\
                 Choose [1]: ",
                pursecraft_cli::DEFAULT_SERVER
            ),
            "Your relay domain (e.g. example.com or 127.0.0.1:8099): ".to_owned(),
            format!("relay url: {derived}\n"),
            "<echo off>\n".to_owned(),
            "enrollment secret: <hidden>\n".to_owned(),
        ]
    );
    // The secret surfaces nowhere in the output.
    assert!(!out.stdout.contains(&secret), "{}", out.stdout);

    // The flag on a terminal asks only the secret (the server was given):
    // echo off, probe, hidden read.
    let second = Home::new("form-flag");
    let (out, transcript, _) = second.run_form(&[&secret], &["login", "--server", &relay.url]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    assert_eq!(
        transcript,
        vec![
            "<echo off>\n".to_owned(),
            "enrollment secret: <hidden>\n".to_owned()
        ]
    );
    relay.stop();
}

/// ADR 0030 §5, fix round 2: the fingerprint probe — a wrong base path is
/// a 404 at `/v1/devices` ("no relay serves this url"), so it fails
/// EARLY again, naming the URL, before any secret is collected.
#[test]
fn a_wrong_base_path_fails_early_at_the_fingerprint_naming_the_url() {
    let mut relay = LiveRelay::start("wrong-path"); // serves at the root
    let home = Home::new("wrong-path");
    let wrong = format!("{}/api", relay.url.trim_end_matches('/'));

    let out = home.run("the-secret\n", &["login", "--server", &wrong]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains(&format!(
            "the host at {wrong} answered 404 at /v1/devices — no relay serves this url"
        )),
        "the fingerprint error names the URL\n{}",
        out.stderr
    );
    assert!(
        session::load(home.path()).unwrap().is_none(),
        "a failed fingerprint enrolls nothing"
    );
    relay.stop();
}

/// Hostile review round 2's P1 pin, the ADR's own typo case: a host that
/// answers 404 at everything (any web server — `pursecraf.com` in the
/// wild) must never see a POST, never receive the secret, and the error
/// must name what was typed. Both paths: the form (typed domain) and the
/// piped `--server`.
#[test]
fn a_404_answering_host_never_receives_the_secret() {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    /// The wire log: (request line, body) per connection.
    type Wire = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Wire = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let Ok(mut stream) = stream else { continue };
            let mut scratch = [0u8; 8192];
            let _ = stream.read(&mut scratch);
            let text = String::from_utf8_lossy(&scratch);
            let request_line = text.lines().next().unwrap_or_default().to_owned();
            // The read buffer is larger than the request: trim at the
            // first NUL so an empty body IS empty.
            let body = text
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("")
                .split('\0')
                .next()
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            log.lock().unwrap().push((request_line, body));
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });

    // The form path: the user types just the domain; the probe alone runs.
    let home = Home::new("404-host-form");
    let domain = url.trim_start_matches("http://").to_owned();
    let (out, transcript, _) = home.run_form(&["2", &domain, "the-secret"], &["login"]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains(&format!(
            "the host at {url} answered 404 at /v1/devices — no relay serves this url"
        )),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains(&format!("derived from domain \"{domain}\"")),
        "the error names what was typed\n{}",
        out.stderr
    );
    // The secret was never demanded: echo off, probe, echo back — no
    // hidden read in the transcript.
    assert!(
        transcript.contains(&"<echo off>\n".to_owned())
            && transcript.contains(&"<echo on>\n".to_owned())
            && !transcript.iter().any(|l| l.contains("enrollment secret")),
        "a 404 host never gets to ask for the secret: {transcript:?}"
    );

    // The piped path: same URL, same guarantee — the source is never read.
    let piped_home = Home::new("404-host-piped");
    let out = piped_home.run("the-secret\n", &["login", "--server", &url]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr.contains("no relay serves this url"),
        "{}",
        out.stderr
    );

    // And the wire: exactly the fingerprint GET(s), never a POST, never
    // a body — the secret never left the process.
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .all(|(line, body)| { line.starts_with("GET /v1/devices") && body.is_empty() }),
        "only the fingerprint GET, no POST, no body: {requests:?}"
    );
    thread.join().unwrap();
}

/// Hostile review round 2's P2 arm: an enrollment failure names the URL
/// in EVERY response shape — here a JSON-bodied 404 (a CDN or app error
/// page), where the status arm used to drop the URL entirely.
#[test]
fn a_json_bodied_404_at_enrollment_names_the_url() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let Ok(mut stream) = stream else { continue };
            let mut scratch = [0u8; 8192];
            let _ = stream.read(&mut scratch);
            let head = String::from_utf8_lossy(&scratch);
            let response = if head.starts_with("GET /v1/devices") {
                // The fingerprint: this stand-in IS relay-shaped (405).
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned()
            } else {
                // Enrollment: a JSON error envelope, edge-style.
                let body = "{\"error\":\"not_found\",\"message\":\"no such route\"}";
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let home = Home::new("json-404");
    let out = home.run("the-secret\n", &["login", "--server", &url]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains(&format!(
            "the relay at {url} answered 404 (not_found): no such route"
        )),
        "the JSON-bodied status arm names the URL\n{}",
        out.stderr
    );
    assert!(session::load(home.path()).unwrap().is_none());
    thread.join().unwrap();
}

/// Hostile review N12/N14 pins: the probe's answered-status teachings are
/// contract, not prose — a 5xx at the fingerprint says exactly this.
#[test]
fn a_5xx_at_the_fingerprint_teaches_with_the_url_named() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let Ok(mut stream) = stream else { continue };
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch);
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let home = Home::new("probe-5xx");
    let out = home.run("the-secret\n", &["login", "--server", &url]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains(&format!(
            "the edge at {url} answered 503 at /v1/devices — something is \
             listening there, but no healthy relay"
        )),
        "the 5xx teaching, verbatim\n{}",
        out.stderr
    );
    thread.join().unwrap();
}

/// Hostile review P2c's compatibility case, fix-round-2 shape: a
/// `/v1`-only edge enrolls because the fingerprint route IS the v1
/// contract — a proxy that forwards `/v1/*` (but not `/health`) still
/// answers 405 at `GET /v1/devices`. Hand-rolled HTTP: the fingerprint's
/// 405, then a real-shaped enroll answer.
#[test]
fn a_v1_only_edge_still_enrolls() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let answer_device = uuid::Uuid::new_v4();
    let thread = std::thread::spawn(move || {
        let device = answer_device;
        let body = format!("{{\"device_id\":\"{device}\",\"token\":\"tok_1\"}}");
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch);
            let head = String::from_utf8_lossy(&scratch);
            let response = if head.starts_with("GET /v1/devices") {
                // The relay's answer for a GET on a POST-only route.
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n".to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let home = Home::new("v1-only");
    let out = home.run("the-secret\n", &["login", "--server", &url]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let enrolled = home.session();
    assert_eq!(enrolled.server, url);
    assert_eq!(enrolled.device_id.as_uuid(), answer_device);
    thread.join().unwrap();
}

/// Hostile review P2c: the probe is a pre-flight, not a transfer — a
/// black-holed port (accept, never answer) must fail on the probe's own
/// short budget, not the enrollment call's 30 s.
#[test]
fn the_probe_has_its_own_short_budget() {
    use std::time::Instant;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        // Accept and park: a connection that never answers.
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut scratch = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut scratch);
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    });
    let home = Home::new("probe-budget");
    let start = Instant::now();
    let out = home.run("s\n", &["login", "--server", &url]);
    let elapsed = start.elapsed();
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains("timeout"),
        "the probe's own timeout, named\n{}",
        out.stderr
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "the probe budget is 5 s, not the enrollment's 30 s — took {elapsed:?}"
    );
}

/// ADR 0030 §5–§6, fix round 2 (hostile review round 2's P2a goal
/// state): the fingerprint probe PRECEDES the hidden read — the secret is
/// never demanded before the relay is proven — and echo was already off
/// across the probe. A slow fingerprint answers slowly; the timestamped
/// terminal proves the read came after; the counting socket proves the
/// probe ran exactly once (never cached, never retried).
#[test]
fn the_probe_precedes_the_hidden_read_and_runs_once() {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (answered_tx, answered_rx) = mpsc::channel::<std::time::Instant>();
    let probe_hits = std::sync::Arc::new(std::sync::Mutex::new(0u32));
    let hits = probe_hits.clone();
    let device = uuid::Uuid::new_v4();
    let thread = std::thread::spawn(move || {
        let body = format!("{{\"device_id\":\"{device}\",\"token\":\"tok_1\"}}");
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch);
            let head = String::from_utf8_lossy(&scratch);
            if head.starts_with("GET /v1/devices") {
                *hits.lock().unwrap() += 1;
                std::thread::sleep(std::time::Duration::from_secs(2));
                // Timestamp BEFORE the write: the client cannot see the
                // answer before this instant, so the hidden read (which
                // follows the answer) is strictly later.
                let answered = std::time::Instant::now();
                let _ = stream.write_all(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = answered_tx.send(answered);
            } else {
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        }
    });

    let home = Home::new("probe-order");
    let domain = url.trim_start_matches("http://").to_owned();
    let (out, _transcript, secret_at) = home.run_form(&["2", &domain, "the-secret"], &["login"]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let probe_answered_at = answered_rx.recv().expect("the probe ran");
    let secret_at = secret_at.expect("the hidden read happened");
    assert!(
        probe_answered_at < secret_at,
        "the probe's answer must precede the hidden read (the 2 s slow \
         fingerprint makes the order unambiguous)"
    );
    assert_eq!(*probe_hits.lock().unwrap(), 1, "the probe runs once");
    thread.join().unwrap();
}

/// The dead-relay-before-secret regression pin (hostile review round 2's
/// P2a-a): on a tty against a dead URL, echo goes off, the probe fails,
/// echo is RESTORED, the error names the URL — and the hidden read never
/// happens. A dead relay never demands the secret.
#[test]
fn a_dead_relay_never_demands_the_secret_and_restores_echo() {
    let home = Home::new("dead-first");
    let (out, transcript, secret_at) = home.run_form(&["2", "127.0.0.1:9", "a-secret"], &["login"]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr
            .contains("cannot reach the relay at http://127.0.0.1:9"),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("derived from domain \"127.0.0.1:9\""),
        "{}",
        out.stderr
    );
    assert!(
        transcript.contains(&"<echo off>\n".to_owned())
            && transcript.contains(&"<echo on>\n".to_owned()),
        "the span closed on failure — the terminal is never left echo-off: {transcript:?}"
    );
    assert!(
        !transcript.iter().any(|l| l.contains("enrollment secret")),
        "the dead relay never asked for the secret: {transcript:?}"
    );
    assert!(secret_at.is_none(), "no hidden read happened");
    assert!(session::load(home.path()).unwrap().is_none());
}

/// Hostile review M7+M8 (the class the suite could not see): run the REAL
/// binary under a REAL pty and assert the two properties that live in
/// `main`'s tty branch — the form appears at all (terminal wired, not the
/// silent hosted-default fallback), and the typed secret never echoes
/// (rpassword's hidden read, not an echoing line read). `script(1)`
/// allocates the pty; the answers are fed line by line AFTER each prompt
/// is on screen, so an echoing implementation has every chance to leak.
#[test]
fn the_real_binary_under_a_pty_takes_the_form_and_hides_the_secret() {
    use std::io::Write;
    let mut relay = LiveRelay::start("pty");
    let home = Home::new("pty");
    let domain = relay
        .url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned();
    let secret = relay.enrollment_secret();

    let capture = scratch_dir("pty-capture").join("capture.log");
    let mut child = std::process::Command::new("script")
        .arg("-qec")
        .arg(format!("{} login", env!("CARGO_BIN_EXE_pursecraft")))
        .arg(&capture)
        .env("PURSECRAFT_HOME", home.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("script(1) allocates a pty");
    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        for line in ["2\n", &format!("{domain}\n"), &format!("{secret}\n")] {
            std::thread::sleep(std::time::Duration::from_millis(800));
            stdin.write_all(line.as_bytes()).expect("feed the form");
        }
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
    let out = child
        .wait_with_output()
        .expect("login under a pty finishes");
    let screen = std::fs::read_to_string(&capture).expect("the pty capture");

    // M7: the FORM ran — choice screen and derived line on the tty; only
    // main's IsTerminal wiring can produce this under a pty.
    assert!(
        screen.contains("Choose [1]:"),
        "the form appeared\n{screen}"
    );
    assert!(
        screen.contains(&format!("relay url: http://{domain}")),
        "the derived url line appeared\n{screen}"
    );
    // M8: the secret never echoes — anywhere in the capture.
    assert!(
        !screen.contains(&secret),
        "the secret must not echo; capture:\n{screen}"
    );
    assert!(
        screen.contains(&format!("enrolled with http://{domain}")),
        "the enrollment landed\n{screen}"
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(home.session().server, format!("http://{domain}"));
    relay.stop();
}

/// Hostile review round 2's P2a goal state, end to end under a REAL pty:
/// echo is OFF across the whole probe (bytes typed during it are neither
/// echoed nor the secret — the drain discards them), the secret prompt
/// appears only after the probe passed, and the relay receives exactly
/// the secret the user typed at the hidden prompt. A slow fingerprint
/// stand-in (1.5 s) creates the window the old orders leaked into.
#[test]
fn typed_during_the_probe_is_neither_echoed_nor_the_secret() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let domain = url.trim_start_matches("http://").to_owned();
    let secret = "enroll_the-real-secret-value";
    let posted_body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let body_log = posted_body.clone();
    let device = uuid::Uuid::new_v4();
    let thread = std::thread::spawn(move || {
        let body = format!("{{\"device_id\":\"{device}\",\"token\":\"tok_1\"}}");
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut scratch = [0u8; 8192];
            let mut read = stream.read(&mut scratch).unwrap_or(0);
            let mut text = String::from_utf8_lossy(&scratch[..read]).into_owned();
            if text.starts_with("GET /v1/devices") {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                let _ = stream.write_all(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            } else {
                // The body may follow the head: keep reading until the
                // enrollment JSON is complete.
                while !text.contains("enrollment_secret") {
                    read = stream.read(&mut scratch).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    text.push_str(&String::from_utf8_lossy(&scratch[..read]));
                }
                *body_log.lock().unwrap() = text
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or("")
                    .split('\0')
                    .next()
                    .unwrap_or("")
                    .to_owned();
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        }
    });

    let home = Home::new("pty-window");
    let capture = scratch_dir("pty-window").join("capture.log");
    let mut child = std::process::Command::new("script")
        .arg("-qec")
        .arg(format!("{} login", env!("CARGO_BIN_EXE_pursecraft")))
        .arg(&capture)
        .env("PURSECRAFT_HOME", home.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("script(1) allocates a pty");
    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        let mut feed = |line: &str, wait_ms: u64| {
            std::thread::sleep(std::time::Duration::from_millis(wait_ms));
            stdin.write_all(line.as_bytes()).expect("feed the form");
        };
        feed("2\n", 800); // the choice
        feed(&format!("{domain}\n"), 400); // the domain — the probe starts after this
        // Typed DURING the probe, into the echo-off span: discarded.
        feed("MARKER-XYZ-ECHO-PROBE\n", 600);
        // The probe (1.5 s) is done; the hidden prompt is up. The real
        // secret, typed where echo is off and the queue was drained.
        feed(&format!("{secret}\n"), 1200);
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
    let out = child.wait_with_output().expect("login finishes");
    let screen = std::fs::read_to_string(&capture).expect("the pty capture");

    // The marker was typed during the probe: echo was off — it never
    // appeared — and the drain discarded it — it is not the secret.
    assert!(
        !screen.contains("MARKER-XYZ-ECHO-PROBE"),
        "typed during the probe: not echoed\n{screen}"
    );
    assert!(
        !screen.contains(secret),
        "the secret stayed hidden\n{screen}"
    );
    assert!(
        screen.contains(&format!("enrolled with http://{domain}")),
        "the enrollment landed\n{screen}"
    );
    assert_eq!(out.status.code(), Some(0));
    let posted = posted_body.lock().unwrap().clone();
    assert!(
        posted.contains(secret) && !posted.contains("MARKER-XYZ"),
        "the relay got exactly the typed secret, not the drained marker: {posted:?}"
    );
    thread.join().unwrap();
}

#[test]
fn a_bodiless_redirect_teaches_the_redirect_not_a_strange_answer() {
    // Hostile review P3-4: the fleet's edge answers a plain-http probe
    // with a bodiless 308. The client never follows it (ADR 0029), and
    // the error must say what happened — the destination and the no-
    // following — not "answered strangely".
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        let mut scratch = [0u8; 1024];
        let _ = stream.read(&mut scratch); // drain the request head/body
        let response = "HTTP/1.1 308 Permanent Redirect\r\n\
                        Location: https://pursecraft.com/api\r\n\
                        Content-Length: 0\r\n\
                        \r\n";
        let _ = stream.write_all(response.as_bytes());
    });
    let url = format!("http://{addr}");
    let home = Home::new("redirect");
    let out = home.run("s\n", &["login", "--server", &url]);
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("redirected to https://pursecraft.com/api"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("does not follow"), "{}", out.stderr);
    thread.join().unwrap();
}

#[test]
fn login_and_sync_round_trip_through_a_base_path() {
    // The deployed shape (issue #34, ADR 0029): the fleet serves the
    // relay under /api; `nest` strips the prefix exactly as the proxy
    // does, so this exercises the client's composed URLs end to end —
    // enroll, capture, sync, and convergence against the relay's own
    // replay — with every route carrying the prefix.
    let relay = LiveRelay::start_under_api("basepath");
    let a = Home::new("basepath-a");

    assert_eq!(a.login(&relay).code, 0);
    let session = a.session();
    assert_eq!(
        session.server, relay.url,
        "the prefixed url stores verbatim"
    );
    assert!(session.server.ends_with("/api"), "{}", session.server);

    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    assert!(
        sync.stdout.contains("created the org and budget scopes"),
        "{}",
        sync.stdout
    );

    // The badge clears only if pull worked too — push alone would leave
    // the home blind to its own round trip.
    let list = a.run("", &["list"]);
    assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);

    let state = a.budget_state();
    assert_eq!(
        state,
        canonical_relay_state(&relay, &budget_log_name(&a)),
        "base-path sync diverged from the relay's canonical replay"
    );
}

#[test]
fn proxy_environment_variables_never_hijack_the_relay() {
    // ADR 0029: the agent pins `.proxy(None)`, so ureq's environment
    // lookup (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY and lowercase) is never
    // consulted — a behavior minreq never had, kept exactly (hostile
    // review P2-1). The library itself never reads the environment (the
    // workspace's no-env rule), so the only place these vars could leak
    // in is the transport: prove it by running the REAL binary with
    // every proxy var aimed at a dead port against a live relay.
    let relay = LiveRelay::start("proxy-env");
    let home = Home::new("proxy-env");
    let command = |args: &[&str]| -> std::process::Command {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_pursecraft"));
        cmd.env("PURSECRAFT_HOME", home.path())
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("all_proxy", "http://127.0.0.1:9")
            // An inherited NO_PROXY (corporate default: `localhost,127.0.0.1`
            // or `*`) would mask the very regression this test guards — the
            // child must see the proxy vars with NO exclusion in force.
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .args(args);
        cmd
    };

    // Login (secret on stdin), capture, sync — all through the hostile
    // environment.
    let secret = relay.enrollment_secret();
    let mut login = command(&["login", "--server", &relay.url])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the real binary");
    {
        use std::io::Write;
        login
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(format!("{secret}\n").as_bytes())
            .expect("feed the secret");
    }
    let out = login.wait_with_output().expect("login finishes");
    assert_eq!(
        out.status.code(),
        Some(0),
        "login ignores the proxy env\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    for args in [&["add", "coffee", "-4.50"][..], &["sync"][..]] {
        let out = command(args).output().expect("binary runs");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{} ignores the proxy env\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The sync was real: the pending badge is gone.
    let list = command(&["list"]).output().expect("binary runs");
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert_eq!(list.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains("pending sync"), "{stdout}");
}

// ---------------------------------------------------------------------
// THE headline (issue #26): two enrolled CLIs converge through a live
// relay after capturing offline on both sides.
// ---------------------------------------------------------------------

#[test]
fn two_devices_converge_through_a_live_relay() {
    let relay = LiveRelay::start("converge");
    let a = Home::new("converge-a");
    let b = Home::new("converge-b");

    // A enrolls and captures offline (no sync yet).
    assert_eq!(a.login(&relay).code, 0);
    let add = a.run("", &["add", "coffee", "-4.50"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);
    assert!(
        add.stdout.contains("14 pending sync"),
        "the capture-time badge\n{}",
        add.stdout
    );
    assert_eq!(a.run("", &["add", "bread", "-2"]).code, 0);

    // A's first sync creates the relay world and prints the join bundle.
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    assert!(
        sync.stdout.contains("created the org and budget scopes"),
        "{}",
        sync.stdout
    );
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);

    // The bundle's taught login line is exactly what `parse` accepts
    // (hostile review P1: this is the second device's onboarding text).
    {
        let login_line = sync
            .stdout
            .lines()
            .find(|line| line.trim_start().starts_with("pursecraft login"))
            .expect("the bundle teaches the login command");
        let words: Vec<String> = login_line.split_whitespace().map(str::to_owned).collect();
        let rest: Vec<String> = words.iter().skip(1).cloned().collect();
        assert_eq!(
            pursecraft_cli::argv::parse(&rest),
            Ok(pursecraft_cli::argv::Cmd::Login {
                server: Some(relay.url.clone())
            }),
            "the bundle's taught {login_line:?} must parse"
        );
    }

    // Synced: the badge is gone (ADR 0011).
    let list = a.run("", &["list"]);
    assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);

    // B enrolls and joins via the printed instructions — the dogfood path.
    assert_eq!(b.login(&relay).code, 0);
    let join = b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code]);
    assert_eq!(join.code, 0, "{}{}", join.stdout, join.stderr);
    assert!(join.stdout.contains("joined org"), "{}", join.stdout);

    // Both capture offline again — the divergent window.
    assert_eq!(b.run("", &["add", "lunch", "-6"]).code, 0);
    assert_eq!(a.run("", &["add", "Meralco", "-890"]).code, 0);

    // Both sync until drained (at-least-once; extra rounds are no-ops).
    for home in [&b, &a, &b, &a] {
        let sync = home.run("", &["sync"]);
        assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    }

    // Convergence through the engine's own proofs: A == B == the relay's
    // canonical replay, in BOTH logs.
    let (sa, sb) = (a.budget_state(), b.budget_state());
    assert_eq!(sa, sb, "budget states diverged");
    assert_eq!(
        sa,
        canonical_relay_state(&relay, &budget_log_name(&a)),
        "a home diverged from the relay's canonical order"
    );
    assert_eq!(a.org_state(), b.org_state(), "org states diverged");
    assert_eq!(
        a.org_state(),
        canonical_relay_state(&relay, &org_log_name(&a)),
        "org state diverged from the relay"
    );

    // Both lists show all four transactions, no pending badge.
    for home in [&a, &b] {
        let list = home.run("", &["list"]);
        assert_eq!(list.code, 0);
        for payee in ["coffee", "bread", "lunch", "Meralco"] {
            assert!(list.stdout.contains(payee), "{}", list.stdout);
        }
        assert!(list.stdout.contains("4 transactions"), "{}", list.stdout);
        assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);
    }
}

/// Budgeting through two devices (issue #29): categories, capture with
/// `--category`, offline `assign` on both sides, and a `categorize`
/// review — converging through the live relay, with the rendered budget
/// byte-identical on both devices (the projection is deterministic, not
/// just the state).
#[test]
fn two_devices_converge_with_category_ops() {
    let relay = LiveRelay::start("converge-budget");
    let a = Home::new("converge-budget-a");
    let b = Home::new("converge-budget-b");

    // A enrolls, bootstraps by capture, structures the budget.
    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "salary", "+5000"]).code, 0);
    assert_eq!(
        a.run("", &["category", "new", "Power", "--group", "Bills"])
            .code,
        0
    );
    assert_eq!(a.run("", &["category", "new", "Food"]).code, 0);
    assert_eq!(
        a.run("", &["add", "groceries", "-120.50", "--category", "Food"])
            .code,
        0
    );
    assert_eq!(a.run("", &["assign", "Food", "400"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);

    // B joins, then both diverge offline — B captures into Power,
    // assigns Power, and reviews its own inbox capture into Food.
    assert_eq!(b.login(&relay).code, 0);
    let join = b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code]);
    assert_eq!(join.code, 0, "{}{}", join.stdout, join.stderr);
    assert_eq!(
        b.run("", &["add", "meralco", "-890", "--category", "Power"])
            .code,
        0
    );
    assert_eq!(
        b.run("", &["assign", "Power", "1000", "--month", "2026-10"])
            .code,
        0
    );
    assert_eq!(b.run("", &["add", "load", "-100"]).code, 0);
    let review = b.run("", &["categorize"]);
    assert_eq!(review.code, 0, "{}", review.stderr);
    assert!(review.stdout.contains("load"), "{}", review.stdout);
    let short = review
        .stdout
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let filed = b.run("", &["categorize", &short, "Food"]);
    assert_eq!(filed.code, 0, "{}{}", filed.stdout, filed.stderr);

    // Both drain; extra rounds are no-ops.
    for home in [&b, &a, &b, &a] {
        let sync = home.run("", &["sync"]);
        assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    }

    // Convergence through the engine's own proofs, both logs.
    assert_eq!(a.budget_state(), b.budget_state(), "budget states diverged");
    assert_eq!(
        a.budget_state(),
        canonical_relay_state(&relay, &budget_log_name(&a)),
        "a home diverged from the relay's canonical order"
    );
    assert_eq!(a.org_state(), b.org_state(), "org states diverged");

    // The rendered budget is byte-identical on both devices and carries
    // the two-device numbers: Food 400 assigned, groceries + load
    // activity, Power 1000 − meralco, income 5000 still in the inbox as
    // inflow (TBB 3600).
    let (va, vb) = (a.run("", &["budget"]), b.run("", &["budget"]));
    assert_eq!(va.code, 0, "{}", va.stderr);
    assert_eq!(vb.code, 0, "{}", vb.stderr);
    assert_eq!(
        va.stdout, vb.stdout,
        "the same state must render identically"
    );
    let view = &va.stdout;
    let food = view.lines().find(|l| l.contains("Food")).unwrap();
    assert!(
        food.contains("400.000") && food.contains("-220.500") && food.contains("179.500"),
        "Food: assigned 400, activity -(120.50 + 100), available 179.50\n{view}"
    );
    let power = view.lines().find(|l| l.contains("Power")).unwrap();
    assert!(
        power.contains("1000.000") && power.contains("-890.000") && power.contains("110.000"),
        "Power: assigned 1000, activity -890, available 110\n{view}"
    );
    assert!(
        view.contains("to be budgeted 3600.000"),
        "5000 inflow − 1400 assigned\n{view}"
    );
    assert!(
        view.contains("Inbox (1 to review)"),
        "salary deliberately stays in the inbox as inflow — the nag names \
         it, its amount lives in to-be-budgeted\n{view}"
    );

    // And the recap's category column agrees on both devices.
    for home in [&a, &b] {
        let list = home.run("", &["list"]);
        assert_eq!(list.code, 0);
        assert!(list.stdout.contains("Food"), "{}", list.stdout);
        assert!(list.stdout.contains("Power"), "{}", list.stdout);
        assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);
    }
}

// ---------------------------------------------------------------------
// Late join (ADR 0024/0025): a second device joins an existing world and
// catches up from zero.
// ---------------------------------------------------------------------

#[test]
fn a_late_joiner_catches_up_and_round_trips() {
    let relay = LiveRelay::start("late-join");
    let a = Home::new("late-join-a");
    let b = Home::new("late-join-b");

    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    assert_eq!(a.run("", &["add", "bread", "-2"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);

    // The late joiner: enroll, join — the join's built-in pull is the
    // catch-up (since=0, ADR 0024).
    assert_eq!(b.login(&relay).code, 0);
    let join = b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code]);
    assert_eq!(join.code, 0, "{}{}", join.stdout, join.stderr);
    let list = b.run("", &["list"]);
    assert!(
        list.stdout.contains("coffee") && list.stdout.contains("bread"),
        "the joiner sees the history\n{}",
        list.stdout
    );
    assert_eq!(a.budget_state(), b.budget_state());

    // The joiner ADOPTED the founder's account (hostile-review finding:
    // the joiner's first capture must not mint a twin Wallet) — one
    // account after join, still one after the joiner captures.
    let account_count = |home: &Home| {
        home.budget_state()
            .entities()
            .filter(|e| matches!(e, pursecraft_core::domain::Entity::Account(_)))
            .count()
    };
    assert_eq!(account_count(&b), 1, "join adopts, never twins");
    assert_eq!(b.run("", &["add", "fare", "-12.5"]).code, 0);
    assert_eq!(
        account_count(&b),
        1,
        "the joiner's capture files into the adopted account"
    );

    // And the round trip: the joiner captures, the founder catches it.
    assert_eq!(b.run("", &["sync"]).code, 0);
    assert_eq!(a.run("", &["sync"]).code, 0);
    assert_eq!(a.budget_state(), b.budget_state());
    let list = a.run("", &["list"]);
    assert!(list.stdout.contains("fare"), "{}", list.stdout);
    assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);
}

// ---------------------------------------------------------------------
// Token refusal (ADR 0025): a dead credential teaches re-enrollment and
// never blocks local function.
// ---------------------------------------------------------------------

#[test]
fn a_refused_token_teaches_reenrollment() {
    let relay = LiveRelay::start("token");
    let home = Home::new("token");

    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);
    assert_eq!(home.run("", &["sync"]).code, 0);

    // The relay forgets this token (wiped auth, revoked device).
    let mut session = home.session();
    session.token = "dev_revoked".into();
    session::publish(home.path(), &session).unwrap();

    let sync = home.run("", &["sync"]);
    assert_eq!(sync.code, 1, "{}", sync.stdout);
    assert!(
        sync.stderr.contains("refused this device token"),
        "{}",
        sync.stderr
    );
    // The error's taught command is exactly what `parse` accepts (hostile
    // review P1: this line used to teach the deleted positional).
    {
        let taught_line = sync
            .stderr
            .lines()
            .find(|line| line.contains("pursecraft login"))
            .expect("the error teaches the fix");
        let words: Vec<String> = taught_line.split_whitespace().map(str::to_owned).collect();
        let rest: Vec<String> = words
            .iter()
            .skip_while(|w| *w != "login")
            .cloned()
            .collect();
        assert_eq!(
            pursecraft_cli::argv::parse(&rest),
            Ok(pursecraft_cli::argv::Cmd::Login {
                server: Some(relay.url.clone())
            }),
            "the taught {taught_line:?} must parse"
        );
    }
    // Local function is untouched (ADR 0025: the gate is not per-launch).
    let add = home.run("", &["add", "bread", "-2"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);
    assert!(add.stdout.contains("6 pending sync"), "{}", add.stdout);
}

// ---------------------------------------------------------------------
// Pairing-code expiry (ADR 0024's 1-hour TTL, surfaced by the CLI): the
// relay restart boundary crosses the clock.
// ---------------------------------------------------------------------

#[test]
fn an_expired_pairing_code_is_refused() {
    let mut relay = LiveRelay::start("expired");
    let a = Home::new("expired-a");
    let b = Home::new("expired-b");

    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    assert_eq!(a.run("", &["sync"]).code, 0);

    // Mint fresh codes on demand (ADR 0025's pair).
    let pair = a.run("", &["pair"]);
    assert_eq!(pair.code, 0, "{}", pair.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&pair.stdout);

    // Time passes: stop the relay, shrink every live pairing code's TTL to
    // two seconds (the auth file is the relay's whole state — ADR 0024),
    // restart over the same bytes, and let the clock cross the line: the
    // RUNNING relay must answer "expired", not silently forget.
    relay.stop();
    relay.detach();
    let auth_path = relay.dir.join("auth.json");
    let mut auth: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&auth_path).unwrap()).unwrap();
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    for code in auth["pairing_codes"]
        .as_array_mut()
        .expect("pairing codes exist")
    {
        code["expires_at_unix"] = serde_json::json!(soon);
    }
    std::fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
    let mut relay2 = LiveRelay::start_on(relay.dir.clone());
    drop(relay);
    std::thread::sleep(std::time::Duration::from_secs(3));

    // The joiner (enrolled before the restart, pointed at the new port)
    // redeems an expired code and is refused with the teaching message.
    assert_eq!(b.login(&relay2).code, 0);
    b.reseat_session_server(&relay2.url);
    let join = b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code]);
    assert_eq!(join.code, 1, "{}", join.stdout);
    assert!(join.stderr.contains("expired"), "{}", join.stderr);
    assert!(
        join.stderr.contains("pursecraft pair"),
        "the error teaches fresh codes\n{}",
        join.stderr
    );
    // A garbage code is invalid (not expired) — a different refusal.
    let join = b.run("", &["join", &org_id, "pair_nope", &budget_id, "pair_nope"]);
    assert_eq!(join.code, 1);
    assert!(join.stderr.contains("invalid"), "{}", join.stderr);
    relay2.stop();
}

// ---------------------------------------------------------------------
// The re-login edge (ADR 0025's stranded ops): honest, visible, never
// blocking.
// ---------------------------------------------------------------------

#[test]
fn re_login_stranded_ops_are_counted_never_hidden() {
    let relay = LiveRelay::start("stranded");
    let home = Home::new("stranded");

    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);

    // A relay wipe forces a re-enrollment: a NEW device token, same world.
    assert_eq!(home.login(&relay).code, 0);
    let add = home.run("", &["add", "bread", "-2"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);

    let sync = home.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    assert!(
        sync.stdout
            .contains("14 ops were minted by a previous enrollment"),
        "the stranded count is visible\n{}",
        sync.stdout
    );
    // The old capture is still here, still listed — unsyncable, not gone.
    let list = home.run("", &["list"]);
    assert!(list.stdout.contains("coffee"), "{}", list.stdout);
    assert!(list.stdout.contains("bread"), "{}", list.stdout);
}

/// A badge failure is loud, never a faked success (hostile-review
/// finding): with an unreadable `sync.json`, `add` still stores the
/// transaction — and says so on stderr, exit 1, confirmation included.
#[test]
fn add_with_corrupt_sync_state_stores_loudly() {
    let relay = LiveRelay::start("corrupt-state");
    let home = Home::new("corrupt-state");
    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);
    assert_eq!(home.run("", &["sync"]).code, 0);

    std::fs::write(home.path().join("sync.json"), b"{ nope").unwrap();
    let add = home.run("", &["add", "tea", "-3"]);
    assert_eq!(add.code, 1, "{}{}", add.stdout, add.stderr);
    assert!(
        add.stderr.contains("added tea"),
        "the stored capture is named, never hidden\n{}",
        add.stderr
    );
    assert!(
        add.stderr.contains("sync.json") && add.stderr.contains("sync state"),
        "{}",
        add.stderr
    );
    assert!(add.stdout.is_empty(), "{}", add.stdout);
    // The capture itself landed — verified through the engine, since
    // `list` refuses the same corrupt state (correctly: its badge IS
    // its job).
    let mut replay = SyncSession::new();
    let identity = load_identity(home.path()).unwrap().unwrap();
    let store = LocalStore::open(&budget_log(home.path(), identity.budget_id)).unwrap();
    replay.apply_delta(store.delta_since(0)).unwrap();
    assert_eq!(
        replay
            .state()
            .entities()
            .filter(|e| matches!(e, pursecraft_core::domain::Entity::Transaction(_)))
            .count(),
        2,
        "coffee and tea both stored"
    );
}
/// An ungranted device meeting an existing scope (delta-review finding:
/// the one teaching branch no test pinned). A home restored WITHOUT its
/// session (identity copied, fresh enrollment) syncs into scopes it no
/// longer holds — the relay's grant refusal must surface the pairing and
/// restore hints, end-to-end through the real relay's prose.
#[test]
fn an_ungranted_scope_refusal_teaches_pair_or_restore() {
    let relay = LiveRelay::start("ungranted");
    let a = Home::new("ungranted-a");
    let c = Home::new("ungranted-c");

    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    assert_eq!(a.run("", &["sync"]).code, 0);

    // The restored home: A's world (identity), a FRESH enrollment — a
    // device the relay has never granted anything.
    assert_eq!(c.login(&relay).code, 0);
    std::fs::copy(
        a.path().join("identity.json"),
        c.path().join("identity.json"),
    )
    .unwrap();

    let sync = c.run("", &["sync"]);
    assert_eq!(sync.code, 1, "{}{}", sync.stdout, sync.stderr);
    assert!(
        sync.stderr.contains("not granted"),
        "the relay's refusal surfaces\n{}",
        sync.stderr
    );
    assert!(
        sync.stderr.contains("pursecraft pair") && sync.stderr.contains("copy the whole data home"),
        "the teaching hints ride along\n{}",
        sync.stderr
    );
}

/// Session files carry the server's device mint (enrollment), not a local
/// one — the relay's caller-identity check depends on it (ADR 0025).
#[test]
fn enrolled_sessions_carry_the_server_device() {
    let relay = LiveRelay::start("device");
    let home = Home::new("device");
    assert_eq!(home.login(&relay).code, 0);
    let session = home.session();
    let known: Vec<DeviceId> = serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(relay.dir.join("auth.json")).unwrap(),
    )
    .map(|auth| {
        auth["devices"]
            .as_array()
            .expect("one device")
            .iter()
            .map(|d| serde_json::from_value(d["device_id"].clone()).unwrap())
            .collect()
    })
    .unwrap();
    assert_eq!(known, [session.device_id]);
}
