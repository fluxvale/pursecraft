//! E2EE integration tests (ADR 0028): whole CLI homes in the sealed mode
//! against a REAL relay — the plaintext proof, two-device convergence with
//! ciphered payloads, and the loud failure of a device without keys.
//!
//! The `sync` suite runs the same shapes in the self-host mode; these are the
//! tests that make "the relay sees only ciphertext" true of the shipping
//! build, so the headline is the grep, not a state assertion.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pursecraft_api::{AppState, router};
use pursecraft_cli::home::load_identity;
use pursecraft_cli::keys::World;

use pursecraft_cli::{Context, run};
use pursecraft_core::date::Date;
use pursecraft_core::ids::ScopeId;
use pursecraft_core::ops::ScopeState;
use pursecraft_core::sync::SyncSession;

// ---------------------------------------------------------------------
// A live relay and sealed CLI homes (the sync suite's kit, in the E2EE mode).
// ---------------------------------------------------------------------

struct LiveRelay {
    dir: PathBuf,
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LiveRelay {
    fn start(label: &str) -> Self {
        let dir = scratch_dir(label);
        let state = Arc::new(AppState::open(&dir).expect("open relay state"));
        let app = router(state);
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(format!("relay-{label}"))
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
        }
    }

    fn enrollment_secret(&self) -> String {
        std::fs::read_to_string(self.dir.join("enrollment.secret"))
            .unwrap()
            .trim_end()
            .to_owned()
    }
}

impl Drop for LiveRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scratch_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pursecraft-e2ee-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A CLI home in the E2EE mode (ADR 0028).
struct Home {
    dir: PathBuf,
}

impl Home {
    fn new(label: &str) -> Self {
        Self {
            dir: scratch_dir(label),
        }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn run(&self, stdin: &str, args: &[&str]) -> pursecraft_cli::Output {
        let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        run(&argv, || {
            Ok(Context {
                home: self.dir.clone(),
                today: Date::new(2026, 10, 25).unwrap(),
                stdin: stdin.to_owned(),
                e2ee: true,
            })
        })
    }

    fn login(&self, relay: &LiveRelay) -> pursecraft_cli::Output {
        self.run(
            &format!("{}\n", relay.enrollment_secret()),
            &["login", &relay.url],
        )
    }

    /// The home's budget state, replayed through the real cipher — the only
    /// way to read a sealed store (ADR 0028).
    fn budget_state(&self) -> ScopeState {
        let identity = load_identity(self.path()).unwrap().expect("world exists");
        let world = World::open(self.path(), true).unwrap();
        let store = world.open_log(ScopeId::Budget(identity.budget_id)).unwrap();
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

fn parse_join_line(stdout: &str) -> [String; 4] {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("pursecraft join"))
        .unwrap_or_else(|| panic!("no join line printed\n{stdout}"));
    let parts: Vec<&str> = line.split_whitespace().collect();
    std::array::from_fn(|i| parts[2 + i].to_owned())
}

/// Every file under `dir`, concatenated — the raw-bytes evidence the
/// plaintext proof needs. Binary-safe: reads bytes, not text.
fn read_all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).expect("read dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.extend(std::fs::read(&path).expect("read file"));
            }
        }
    }
    out
}

/// The v1 envelope's opening bytes as they appear *inside* a stored record:
/// the payload string is JSON-embedded, so its quotes are escaped (ADR 0022's
/// envelope shape, ADR 0024's string-native store).
const ENVELOPE_PREFIX: &str = r#"{\"v\":1,\"e\":"#;

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

// ---------------------------------------------------------------------
// THE acceptance check (ADR 0028): the plaintext proof.
// ---------------------------------------------------------------------

/// A distinctive payee captured on a sealed home never reaches the relay's
/// disk — in any spelling, in any file — while the client still lists it.
/// The op metadata (ids, HLCs, scope) does reach the relay, by design.
#[test]
fn a_sealed_capture_never_lands_on_the_relay_as_plaintext() {
    let relay = LiveRelay::start("plaintext-proof");
    let home = Home::new("plaintext-proof-home");
    assert_eq!(home.login(&relay).code, 0);

    // A payee no other operation could produce.
    let payee = "Zanzibarian Tiffinwala";
    let add = home.run("", &["add", payee, "-4.50"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);
    let sync = home.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    // The op really went: the budget log exists on the relay and holds ops.
    let identity = load_identity(home.path()).unwrap().expect("world");
    let budget_log = relay.dir.join("logs").join(format!(
        "budget-{}.pcoplog",
        identity.budget_id.as_uuid().simple()
    ));
    assert!(budget_log.exists(), "the relay received the budget log");
    assert!(
        std::fs::metadata(&budget_log).unwrap().len() > 100,
        "the relay's log is not empty"
    );

    // The proof: nothing anywhere under the relay's data directory holds the
    // payee — and the ciphertext really is ciphertext.
    let bytes = read_all_bytes(&relay.dir);
    assert!(
        !contains(&bytes, payee),
        "the payee reached the relay's disk"
    );
    assert!(
        !contains(&bytes, "Tiffinwala"),
        "part of the payee reached the relay's disk"
    );
    assert!(
        !contains(&bytes, "\"value\""),
        "a plaintext payload shape reached the relay's disk"
    );
    assert!(
        contains(&bytes, ENVELOPE_PREFIX),
        "the relay holds a v1 envelope (the ciphertext is really there)"
    );

    // The client still reads its own data, through the cipher.
    let list = home.run("", &["list"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(list.stdout.contains(payee), "{}", list.stdout);
    assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);
}

// ---------------------------------------------------------------------
// Two devices (ADR 0028's second check): A founds and seals, B joins and
// reads; a transaction minted after the join reads on both.
// ---------------------------------------------------------------------

#[test]
fn two_devices_converge_through_the_key_channel() {
    let relay = LiveRelay::start("e2ee-converge");
    let a = Home::new("e2ee-converge-a");
    let b = Home::new("e2ee-converge-b");

    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);

    // B joins: it registers its public key and mints nothing.
    assert_eq!(b.login(&relay).code, 0);
    let join = b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code]);
    assert_eq!(join.code, 0, "{}{}", join.stdout, join.stderr);
    assert!(
        join.stdout.contains("the world's keys are not here yet"),
        "the joiner is told exactly what to do next\n{}",
        join.stdout
    );

    // Before A wraps, B fails loudly — never an empty budget, never a silent
    // plaintext read (ADR 0028's third check).
    let stranded = b.run("", &["list"]);
    assert_eq!(stranded.code, 1, "{}{}", stranded.stdout, stranded.stderr);
    assert!(
        stranded.stderr.contains("no key material") || stranded.stderr.contains("not here yet"),
        "a keyless device fails distinctly\n{}",
        stranded.stderr
    );

    // A's next sync sees B's device record and wraps the org's keys to it.
    let a_sync = a.run("", &["sync"]);
    assert_eq!(a_sync.code, 0, "{}{}", a_sync.stdout, a_sync.stderr);
    // B's next sync installs them and reads the log.
    let b_sync = b.run("", &["sync"]);
    assert_eq!(b_sync.code, 0, "{}{}", b_sync.stdout, b_sync.stderr);
    assert!(
        b_sync.stdout.contains("joined org"),
        "B finishes joining once its keys land\n{}",
        b_sync.stdout
    );
    let b_list = b.run("", &["list"]);
    assert_eq!(b_list.code, 0, "{}", b_list.stderr);
    assert!(
        b_list.stdout.contains("coffee"),
        "B reads A's op through the key channel\n{}",
        b_list.stdout
    );

    // A transaction minted after the join reads on both.
    assert_eq!(b.run("", &["add", "lunch", "-6"]).code, 0);
    for home in [&a, &b, &b, &a] {
        let sync = home.run("", &["sync"]);
        assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    }
    for home in [&a, &b] {
        let list = home.run("", &["list"]);
        assert_eq!(list.code, 0, "{}", list.stderr);
        assert!(list.stdout.contains("coffee"), "{}", list.stdout);
        assert!(list.stdout.contains("lunch"), "{}", list.stdout);
        assert!(!list.stdout.contains("pending sync"), "{}", list.stdout);
    }
    assert_eq!(
        a.budget_state(),
        b.budget_state(),
        "both devices read the same state"
    );

    // And the relay still holds no plaintext of either payee.
    let bytes = read_all_bytes(&relay.dir);
    for secret in ["coffee", "lunch", "\"value\""] {
        assert!(
            !contains(&bytes, secret),
            "{secret} reached the relay's disk"
        );
    }
}

// ---------------------------------------------------------------------
// The mode guards (ADR 0028): no silent flip, in either direction.
// ---------------------------------------------------------------------

#[test]
fn a_plaintext_home_refuses_to_open_with_e2ee_on() {
    let home = Home::new("e2ee-flip");
    let relay = LiveRelay::start("e2ee-flip-relay");
    // A plaintext world (the switch off) with real data on disk.
    let plain = |stdin: &str, args: &[&str]| {
        let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        run(&argv, || {
            Ok(Context {
                home: home.dir.clone(),
                today: Date::new(2026, 10, 25).unwrap(),
                stdin: stdin.to_owned(),
                e2ee: false,
            })
        })
    };
    let secret = format!("{}\n", relay.enrollment_secret());
    assert_eq!(plain(&secret, &["login", &relay.url]).code, 0);
    assert_eq!(plain("", &["add", "coffee", "-4.50"]).code, 0);

    // The same home with E2EE on: refused, naming the escape (ADR 0028).
    let out = home.run("", &["list"]);
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains("PURSECRAFT_E2EE=off"),
        "the refusal names the switch\n{}",
        out.stderr
    );
}

/// A sealed home refuses the switch-off, naming the way back — and the
/// refusal lands before any store is touched.
#[test]
fn a_sealed_home_refuses_the_switch_off() {
    let home = Home::new("e2ee-guard");
    let relay = LiveRelay::start("e2ee-guard-relay");
    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);

    let argv = vec!["list".to_owned()];
    let out = run(&argv, || {
        Ok(Context {
            home: home.dir.clone(),
            today: Date::new(2026, 10, 25).unwrap(),
            stdin: String::new(),
            e2ee: false,
        })
    });
    assert_eq!(out.code, 1, "{}{}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains("unset PURSECRAFT_E2EE"),
        "the refusal names the switch\n{}",
        out.stderr
    );
}
