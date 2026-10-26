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

    /// Serve the real router over `dir` on an ephemeral localhost port.
    fn start_on(dir: PathBuf) -> Self {
        let state = Arc::new(AppState::open(&dir).expect("open relay state"));
        let app = router(state);
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
            url: format!("http://{addr}"),
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
                stdin: stdin.to_owned(),
                e2ee: self.e2ee,
            })
        })
    }

    fn login(&self, relay: &LiveRelay) -> pursecraft_cli::Output {
        self.run(
            &format!("{}\n", relay.enrollment_secret()),
            &["login", &relay.url],
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

    let wrong = home.run("not-the-secret\n", &["login", &relay.url]);
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

    // A dead relay and an https url teach rather than crash.
    let dead = Home::new("login-dead");
    let out = dead.run("s\n", &["login", "http://127.0.0.1:9"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("cannot reach"), "{}", out.stderr);
    let tls = dead.run("s\n", &["login", "https://relay.example"]);
    assert_eq!(tls.code, 1);
    assert!(tls.stderr.contains("plain http"), "{}", tls.stderr);
    let empty = dead.run("", &["login", "http://127.0.0.1:9"]);
    assert_eq!(empty.code, 1);
    assert!(
        empty.stderr.contains("stdin"),
        "an empty stdin teaches the shape\n{}",
        empty.stderr
    );
    relay.stop();
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
    assert!(
        sync.stderr.contains("pursecraft login"),
        "the error teaches the fix\n{}",
        sync.stderr
    );
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
