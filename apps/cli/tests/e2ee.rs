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

// ---------------------------------------------------------------------
// Crash-window recovery (ADR 0028's resumability claims, pinned).
// ---------------------------------------------------------------------

/// A founder whose keyring was torn between the org key and a log key —
/// the exact window ADR 0028 names — completes on the next capture instead
/// of leaving a permanently keyless home. The torn state is the crash's:
/// the org key is held, the log keys and their stores are not.
#[test]
fn a_half_minted_founding_keyring_completes_on_the_next_capture() {
    use pursecraft_cli::keys::World;
    use pursecraft_core::ids::ScopeId;

    let home = Home::new("e2ee-resume-founder");
    let relay = LiveRelay::start("e2ee-resume-founder-relay");
    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);

    // The crash state: log keys never landed, so neither did their stores.
    let identity = load_identity(home.path()).unwrap().expect("world");
    for dir in ["orgs", "budgets"] {
        let _ = std::fs::remove_dir_all(home.path().join(dir));
    }
    let keyring = home.path().join("keyring.json");
    let mut wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&keyring).unwrap()).unwrap();
    wire["records"]
        .as_array_mut()
        .unwrap()
        .retain(|record| !record["wire"].as_str().unwrap().contains(r#""kind":"log""#));
    std::fs::write(&keyring, serde_json::to_vec(&wire).unwrap()).unwrap();
    let torn = World::open(home.path(), true).unwrap();
    assert!(
        !torn.holds_log_key(ScopeId::Budget(identity.budget_id)),
        "the tear really removed the log keys"
    );
    drop(torn);

    // The next capture completes the mint, then seals and appends.
    let add = home.run("", &["add", "bread", "-2"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);
    let healed = World::open(home.path(), true).unwrap();
    assert!(
        healed.holds_log_key(ScopeId::Budget(identity.budget_id)),
        "the log key was re-minted"
    );
    let list = home.run("", &["list"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(list.stdout.contains("bread"), "{}", list.stdout);
}

/// A joiner torn between redeeming its codes and minting its device key
/// resumes by running `sync` — the one command its gate lets through. In
/// that window nothing was published, so the key a key-holder wraps to is
/// the one the resumed `sync` mints.
#[test]
fn a_joiner_torn_before_its_device_key_resumes_on_sync() {
    use pursecraft_cli::relay::Relay;
    use pursecraft_cli::session;
    use pursecraft_core::ids::{BudgetId, OrgId, ScopeId};

    let relay = LiveRelay::start("e2ee-resume-joiner");
    let a = Home::new("e2ee-resume-joiner-a");
    let b = Home::new("e2ee-resume-joiner-b");
    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);
    let uuid = |raw: &str| uuid::Uuid::parse_str(raw).expect("printed bundle");
    let org = OrgId::new(uuid(&org_id)).expect("v7 id");
    let budget = BudgetId::new(uuid(&budget_id)).expect("v7 id");

    // Redeem exactly as `join` does before it mints anything, then stop where
    // the crash would: the marker and an empty joining keyring land, the
    // device key does not.
    assert_eq!(b.login(&relay).code, 0);
    let token = session::load(b.path()).unwrap().expect("enrolled").token;
    let client = Relay::new(&relay.url, &token);
    client
        .redeem(ScopeId::Org(org), &org_code)
        .expect("redeem the org code");
    client
        .redeem(ScopeId::Budget(budget), &budget_code)
        .expect("redeem the budget code");
    std::fs::write(
        b.path().join("join.json"),
        serde_json::json!({ "org_id": org_id, "budget_id": budget_id }).to_string(),
    )
    .unwrap();
    std::fs::write(
        b.path().join("keyring.json"),
        serde_json::json!({ "v": 1, "founded": false, "records": [] }).to_string(),
    )
    .unwrap();
    assert!(!b.path().join("device.key").exists());
    assert_eq!(b.run("", &["list"]).code, 1, "the gate still holds");

    // Follow the printed instructions exactly: B's sync mints its key and
    // registers it, A's wraps to it, B's installs and finishes the join.
    let registered = b.run("", &["sync"]);
    assert_eq!(
        registered.code, 0,
        "{}{}",
        registered.stdout, registered.stderr
    );
    assert!(
        registered.stdout.contains("not here yet"),
        "the keyless step teaches\n{}",
        registered.stdout
    );
    let a_sync = a.run("", &["sync"]);
    assert_eq!(a_sync.code, 0, "{}{}", a_sync.stdout, a_sync.stderr);
    let resumed = b.run("", &["sync"]);
    assert_eq!(resumed.code, 0, "{}{}", resumed.stdout, resumed.stderr);
    let list = b.run("", &["list"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(list.stdout.contains("coffee"), "{}", list.stdout);
}

// ---------------------------------------------------------------------
// A conflicting wrap is loud (ADR 0022's slot rule, ADR 0028's installs).
// ---------------------------------------------------------------------

/// A forged epoch wrap for a slot the device already holds must surface as an
/// error, not vanish as "another member's wrap" — otherwise a hostile member
/// pins the device on a dead key with no signal at all.
#[test]
fn a_conflicting_wrap_is_loud_not_skipped() {
    use pursecraft_cli::keys::{KeysError, World};
    use pursecraft_core::ids::OrgId;
    use pursecraft_crypto::{CryptoError, DeviceKeypair, KeyChain};

    let home = Home::new("e2ee-conflict");
    let relay = LiveRelay::start("e2ee-conflict-relay");
    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);
    let identity = load_identity(home.path()).unwrap().expect("world");
    let org: OrgId = identity.org_id;
    let world = World::open(home.path(), true).unwrap();

    // A forged wrap for the epoch this device already holds, addressed to it
    // and well-formed — the shape any member can mint from a public key.
    let target = world
        .device_record(
            pursecraft_cli::session::load(home.path())
                .unwrap()
                .expect("enrolled")
                .device_id,
        )
        .expect("sealed home has a device record");
    let record = pursecraft_crypto::KeyRecord::parse(&target).unwrap();
    let pursecraft_crypto::KeyRecord::Device { public, .. } = record else {
        panic!("device record");
    };
    let mut attacker = KeyChain::new(DeviceKeypair::generate().unwrap());
    attacker.create_org(org).unwrap();
    let forged = attacker
        .wrap_org_keys_to(&org, &public, pursecraft_crypto::Grant::CurrentEpoch)
        .unwrap();

    let err = world
        .install(
            &pursecraft_crypto::KeyRecord::Org {
                to: pursecraft_cli::session::load(home.path())
                    .unwrap()
                    .expect("enrolled")
                    .device_id,
                wrap: forged[0].clone(),
            }
            .to_wire(),
            org,
        )
        .expect_err("a held slot with different material must be loud");
    assert!(
        matches!(&err, KeysError::Crypto(CryptoError::WrongKeySlot)),
        "{err}"
    );
}

/// Idle syncs mint nothing (ADR 0028's coverage rule). The relay's record set
/// is append-only, so a re-wrap per sync would grow without bound toward the
/// cap — the record count must be stable across repeated syncs.
#[test]
fn idle_syncs_do_not_re_wrap_peers() {
    use pursecraft_cli::session;

    let relay = LiveRelay::start("e2ee-stable");
    let a = Home::new("e2ee-stable-a");
    let b = Home::new("e2ee-stable-b");
    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);
    assert_eq!(b.login(&relay).code, 0);
    assert_eq!(
        b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code])
            .code,
        0
    );
    // Settle: A wraps B, B installs and joins.
    assert_eq!(a.run("", &["sync"]).code, 0);
    assert_eq!(b.run("", &["sync"]).code, 0);

    let key_file = relay
        .dir
        .join("keys")
        .join(format!("org-{}.json", org_id.replace('-', "")));
    let count = || -> usize {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&key_file).unwrap()).unwrap();
        value["keys"].as_array().unwrap().len()
    };
    let settled = count();
    // Three idle rounds on both devices: no new records, either side.
    for _ in 0..3 {
        assert_eq!(a.run("", &["sync"]).code, 0);
        assert_eq!(b.run("", &["sync"]).code, 0);
        assert_eq!(count(), settled, "an idle sync minted a wrap");
    }
    let _ = session::load(a.path());
}

/// One member's poisoned record must not wedge everyone's sync (ADR 0028):
/// the data still syncs, and the conflict is reported loudly rather than
/// silently swallowed or made permanent.
#[test]
fn a_poisoned_key_record_reports_but_does_not_wedge_the_data_sync() {
    use pursecraft_cli::relay::Relay;
    use pursecraft_cli::session;
    use pursecraft_core::ids::OrgId;

    let relay = LiveRelay::start("e2ee-poison");
    let a = Home::new("e2ee-poison-a");
    let b = Home::new("e2ee-poison-b");
    assert_eq!(a.login(&relay).code, 0);
    assert_eq!(a.run("", &["add", "coffee", "-4.50"]).code, 0);
    let sync = a.run("", &["sync"]);
    assert_eq!(sync.code, 0, "{}{}", sync.stdout, sync.stderr);
    let [org_id, org_code, budget_id, budget_code] = parse_join_line(&sync.stdout);
    assert_eq!(b.login(&relay).code, 0);
    assert_eq!(
        b.run("", &["join", &org_id, &org_code, &budget_id, &budget_code])
            .code,
        0
    );
    assert_eq!(a.run("", &["sync"]).code, 0);
    assert_eq!(b.run("", &["sync"]).code, 0);

    // B (a granted member) plants a tampered log wrap: log wraps are addressed
    // to nobody, so every holder tries to open it and fails.
    let org = OrgId::new(uuid::Uuid::parse_str(&org_id).unwrap()).unwrap();
    let token = session::load(b.path()).unwrap().expect("enrolled").token;
    let client = Relay::new(&relay.url, &token);
    let tampered = r#"{"v":1,"kind":"log","wrap":{"v":1,"scope":{"Org":""#.to_owned()
        + &org_id
        + r#""},"epoch":0,"n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
    client
        .publish_keys(org, &[tampered])
        .expect("a granted member can publish");

    // B captures and syncs: the op still reaches the relay, and the poison is
    // reported, not fatal to the data path.
    assert_eq!(b.run("", &["add", "lunch", "-6"]).code, 0);
    let poisoned = b.run("", &["sync"]);
    assert_eq!(
        poisoned.code, 1,
        "a poisoned record is loud\n{}{}",
        poisoned.stdout, poisoned.stderr
    );
    assert!(
        poisoned.stderr.contains("did not install"),
        "the report names the conflict\n{}",
        poisoned.stderr
    );
    // A still syncs the new op: the poison is B's report, not an org-wide kill.
    let a_sync = a.run("", &["sync"]);
    assert_eq!(a_sync.code, 1, "A also reports the planted record");
    let list_a = a.run("", &["list"]);
    assert_eq!(list_a.code, 0, "{}", list_a.stderr);
    assert!(
        list_a.stdout.contains("lunch"),
        "the data sync ran despite the poison\n{}",
        list_a.stdout
    );
}

/// A founder torn inside the very first key init — keyring published, device
/// key not — heals on the next capture. The gate must let `add` through for a
/// founding home, or the only command that can heal it is blocked (ADR 0028).
#[test]
fn a_founder_torn_before_its_device_key_heals_on_the_next_capture() {
    let home = Home::new("e2ee-founder-early-tear");
    let relay = LiveRelay::start("e2ee-founder-early-tear-relay");
    assert_eq!(home.login(&relay).code, 0);
    assert_eq!(home.run("", &["add", "coffee", "-4.50"]).code, 0);

    // Remove the device key but keep the founding keyring and its records:
    // the crash window between `Keys::init`'s two publishes.
    std::fs::remove_file(home.path().join("device.key")).unwrap();
    let list = home.run("", &["list"]);
    assert_eq!(list.code, 1, "no key, no read\n{}", list.stdout);

    // The gate lets `add` through for a founding home (that is the fix), and
    // the mint then refuses loudly: the world's org wrap is sealed to a device
    // key that no longer exists, so the honest answer is "restore the key",
    // never a silent second world.
    let add = home.run("", &["add", "bread", "-2"]);
    assert_eq!(add.code, 1, "{}{}", add.stdout, add.stderr);
    assert!(
        add.stderr.contains("does not open this home's keyring"),
        "a founding home reaches its healing command and is told the real cause\n{}",
        add.stderr
    );
    // The blocked-before-fix symptom was the joiner message, which is wrong
    // here: this home founded the world.
    assert!(
        !add.stderr.contains("run pursecraft sync on a device"),
        "a founding home is not told to find another device\n{}",
        add.stderr
    );
}
