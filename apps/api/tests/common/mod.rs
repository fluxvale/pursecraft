//! The relay integration test kit (ADR 0024): an in-process relay driven
//! through full HTTP semantics (tower `oneshot` on the real router — no
//! test HTTP client dependency), a simulated device wrapping the core's
//! [`SyncSession`], and deterministic op minting per the ADR 0016
//! convention (xorshift, no test dependencies).

#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Deserialize;
use tower::ServiceExt;
use uuid::Uuid;

use pursecraft_api::AppState;
use pursecraft_core::domain::{
    BudgetField, Cleared, EntityKind, Field, MembershipField, MembershipRole, OrgField,
    TransactionField, Value,
};
use pursecraft_core::hlc::Hlc;
use pursecraft_core::ids::{BudgetId, DeviceId, EntityId, OpId, OrgId, ScopeId, UserId};
use pursecraft_core::money::Milliunits;
use pursecraft_core::ops::{ApplyError, Op};
use pursecraft_core::sync::{SequencedOp, SyncSession};
use pursecraft_core::wire::{OpMeta, decode_payload};

/// The one transaction entity all budget-scope ops race over — LWW
/// contention is the interesting path.
fn txn_entity() -> EntityId {
    EntityId::new(v7(ID_MS, 50)).unwrap()
}

// ---------------------------------------------------------------------
// Deterministic primitives (the ADR 0016 convention, test-side).
// ---------------------------------------------------------------------

const ID_MS: u64 = 1 << 40;
const HLC_BASE: u64 = 1 << 50;

/// Deterministic UUIDv7: `ms` timestamp plus an arbitrary disambiguator.
pub fn v7(ms: u64, rand: u64) -> Uuid {
    let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
    Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
}

/// xorshift64* — deterministic, reproducible pseudo-randomness.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

pub fn budget_scope() -> ScopeId {
    ScopeId::Budget(BudgetId::new(v7(ID_MS, 1)).unwrap())
}

pub fn org_scope() -> ScopeId {
    ScopeId::Org(OrgId::new(v7(ID_MS, 2)).unwrap())
}

/// A fresh scratch directory under the temp dir, unique per call — the
/// shared base of the in-process [`TestRelay`] and the binary-spawning
/// [`RelayProcess`] tests. Callers clean up best-effort.
pub fn scratch_dir(label: &str) -> PathBuf {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "pursecraft-api-{label}-{}-{}",
        std::process::id(),
        COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ))
}

/// The scope's log file under `dir` — the relay's naming, shared by the
/// in-process and binary tests.
pub fn log_path(dir: &Path, scope: ScopeId) -> PathBuf {
    let name = match scope {
        ScopeId::Org(id) => format!("org-{}", id.as_uuid().simple()),
        ScopeId::Budget(id) => format!("budget-{}", id.as_uuid().simple()),
    };
    dir.join("logs").join(format!("{name}.pcoplog"))
}

/// One well-formed pushable op for a device (the ADR 0016 minting
/// convention, deterministic ids) — the binary tests' single-op version
/// of the in-process tests' simulated devices.
pub fn a_mint_style_op(device: DeviceId, scope: ScopeId) -> pursecraft_core::ops::Op {
    pursecraft_core::ops::Op {
        op_id: OpId::new(v7(1 << 40, 4444)).unwrap(),
        scope,
        device_id: device,
        user_id: UserId::new(v7(1 << 40, 777)).unwrap(),
        entity_kind: pursecraft_core::domain::EntityKind::Transaction,
        entity_id: EntityId::new(v7(1 << 40, 50)).unwrap(),
        field: pursecraft_core::domain::Field::Transaction(
            pursecraft_core::domain::TransactionField::Memo,
        ),
        value: pursecraft_core::domain::Value::Text("serving probe".into()),
        hlc: pursecraft_core::hlc::Hlc {
            physical_ms: 1 << 50,
            logical: 0,
        },
    }
}

/// The path (and URI) segments for a scope — the routes are typed by kind
/// (ADR 0021).
pub fn scope_path(scope: ScopeId) -> String {
    match scope {
        ScopeId::Org(id) => format!("orgs/{}", id.as_uuid()),
        ScopeId::Budget(id) => format!("budgets/{}", id.as_uuid()),
    }
}

// ---------------------------------------------------------------------
// The relay under test: a data directory plus the router built from it —
// dropping and rebuilding the router is the crash/restart simulation.
// ---------------------------------------------------------------------

pub struct TestRelay {
    pub dir: PathBuf,
    pub router: Router,
}

impl TestRelay {
    /// A fresh relay with its own scratch data directory (the only
    /// constructor — `at` is private so a `Drop` that cleans up can never
    /// delete a directory a caller handed in).
    pub fn new(label: &str) -> Self {
        Self::at(&scratch_dir(label))
    }

    fn at(dir: &Path) -> Self {
        let router = pursecraft_api::router(Arc::new(AppState::open(dir).unwrap()));
        Self {
            dir: dir.to_owned(),
            router,
        }
    }

    /// The crash/restart boundary: a brand-new process over the same
    /// bytes (ADR 0024's durability test).
    pub fn restart(&mut self) {
        self.router = pursecraft_api::router(Arc::new(AppState::open(&self.dir).unwrap()));
    }

    pub fn enrollment_secret(&self) -> String {
        std::fs::read_to_string(self.dir.join("enrollment.secret"))
            .unwrap()
            .trim_end()
            .to_owned()
    }

    /// The path of the scope's log file — tampering tests edit this.
    pub fn log_path(&self, scope: ScopeId) -> PathBuf {
        log_path(&self.dir, scope)
    }

    /// One full HTTP round trip through the real router.
    pub async fn request(
        &mut self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<String>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, json)
    }
}

impl Drop for TestRelay {
    /// Best-effort scratch cleanup, like the core testkit's `TempDir`:
    /// a panicking test that leaks its directory is harmless. `Drop::drop`
    /// runs BEFORE the fields (router, open store files) drop, so the
    /// removal may unlink still-open files — fine on POSIX, and cleanup
    /// is best-effort anyway.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------
// The relay binary under test (ADR 0026): spawn the real process, talk
// raw HTTP over a socket, signal it — the data-dir and graceful-shutdown
// contracts are process-level behaviors, not router-level ones.
// ---------------------------------------------------------------------

/// An unoccupied loopback port (bind `:0`, read the port, drop) — the
/// tiny race between drop and the spawned relay's bind is accepted, as
/// everywhere else that needs a test port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local addr")
        .port()
}

/// The relay as a real OS process (ADR 0026): the binary Cargo builds
/// for this test run, configured by the same env vars production rides.
pub struct RelayProcess {
    pub child: std::process::Child,
    pub dir: PathBuf,
    pub port: u16,
}

impl RelayProcess {
    pub fn spawn(dir: &Path, port: u16) -> Self {
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_pursecraft-api"))
            .env("PURSECRAFT_DATA_DIR", dir)
            .env("PURSECRAFT_BIND", format!("127.0.0.1:{port}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the relay binary");
        Self {
            child,
            dir: dir.to_owned(),
            port,
        }
    }

    /// One request-response round trip on a fresh connection
    /// (`Connection: close`, so EOF delimits the response — no HTTP
    /// client dependency).
    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, String) {
        let mut stream = self.connect();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("set read timeout");
        write_request(&mut stream, method, path, headers, body);
        let raw = read_response(&mut stream);
        parse_response(&raw)
    }

    /// Poll until `GET path` answers `status` — the binary's boot beat.
    pub fn wait_for(&mut self, path: &str, status: u16) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", self.port)) {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .ok();
                write_request(&mut stream, "GET", path, &[], "");
                let raw = read_response(&mut stream);
                if let (got, _) = parse_response(&raw)
                    && got == status
                {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the relay never answered {status} on {path}\n{}",
                self.stderr_after_kill(),
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// A raw connection the test drives byte by byte — the mid-flight
    /// request the drain test holds open across a SIGTERM.
    pub fn connect(&self) -> std::net::TcpStream {
        std::net::TcpStream::connect(("127.0.0.1", self.port)).expect("connect to the relay")
    }

    /// SIGTERM — the fleet's drain trigger (ADR 0026). Via `/bin/kill`
    /// to avoid a libc dependency for one syscall the tests need.
    #[cfg(unix)]
    pub fn sigterm(&mut self) {
        let pid = self.child.id().to_string();
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("send SIGTERM");
        assert!(status.success(), "kill -TERM {pid}");
    }

    /// Wait for exit within `secs` — an assert on the way out dumps
    /// stderr, the binary's own log line for what it was doing.
    pub fn wait_exit(&mut self, secs: u64) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the relay") {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the relay did not exit within {secs}s\n{}",
                self.stderr_after_kill(),
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// The captured stderr — for assertion messages; kills the child
    /// first because a pipe reads to EOF only once the writer is gone.
    /// Failure-path only (assert arguments evaluate lazily).
    fn stderr_after_kill(&mut self) -> String {
        let pid = self.child.id().to_string();
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid])
            .status();
        let _ = self.child.wait();
        let mut err = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            use std::io::Read as _;
            let _ = pipe.read_to_string(&mut err);
        }
        err
    }
}

/// Write one HTTP/1.1 request — headers, then body — with
/// `Connection: close` so the server's response ends at EOF.
pub fn write_request(
    stream: &mut std::net::TcpStream,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) {
    use std::io::Write as _;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!(
            "content-type: application/json\r\ncontent-length: {}\r\n",
            body.len()
        ));
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write request head");
    stream
        .write_all(body.as_bytes())
        .expect("write request body");
}

/// Read the response to EOF (`Connection: close` on our side).
pub fn read_response(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read as _;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read the response");
    raw
}

/// `(status, body)` out of a raw HTTP/1.1 response.
pub fn parse_response(raw: &str) -> (u16, String) {
    let status = raw
        .split_whitespace()
        .nth(1)
        .expect("a status line")
        .parse()
        .expect("a status code");
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// Poll until fresh connects to `port` are refused — the drain test's
/// observable for "the listener is closed, SIGTERM landed" (ADR 0026).
#[cfg(unix)]
pub fn wait_connect_refused(port: u16) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => drop(stream),
            Err(_) => return,
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the relay kept accepting connections after SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------
// A simulated device: credentials plus the core's sync session.
// ---------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct PullOpWire {
    pub seq: u64,
    pub meta: OpMeta,
    pub payload: String,
}

#[derive(Deserialize, Debug)]
pub struct PullWire {
    pub v: u16,
    pub ops: Vec<PullOpWire>,
    pub tip: u64,
    pub has_more: bool,
}

/// How a sync failed — every failure mode is loud (ADR 0024's test
/// contract: the relay cannot make a device diverge silently).
#[derive(Debug)]
pub enum SyncError {
    /// The relay answered an error status.
    Status(StatusCode, serde_json::Value),
    /// A served payload does not decode — tampered or truncated bytes.
    Decode(String),
    /// The engine refused an op (e.g. `OpIdConflict` on swapped payloads).
    Apply(ApplyError),
}

pub struct Device {
    pub token: String,
    pub id: DeviceId,
}

impl Device {
    pub async fn enroll(relay: &mut TestRelay) -> Self {
        let (status, body) = relay
            .request(
                "POST",
                "/v1/devices",
                None,
                Some(
                    serde_json::json!({
                        "v": 1,
                        "enrollment_secret": relay.enrollment_secret(),
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        Self {
            token: body["token"].as_str().unwrap().to_owned(),
            id: serde_json::from_value(body["device_id"].clone()).unwrap(),
        }
    }

    /// Create the scope and return its first pairing code.
    pub async fn create_scope(&self, relay: &mut TestRelay, scope: ScopeId) -> String {
        let (status, body) = relay
            .request(
                "POST",
                &format!("/v1/{}", scope_path(scope)),
                Some(&self.token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["pairing_code"].as_str().unwrap().to_owned()
    }

    pub async fn mint_code(&self, relay: &mut TestRelay, scope: ScopeId) -> String {
        let (status, body) = relay
            .request(
                "POST",
                &format!("/v1/{}/pairing-codes", scope_path(scope)),
                Some(&self.token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["pairing_code"].as_str().unwrap().to_owned()
    }

    pub async fn pair(&self, relay: &mut TestRelay, scope: ScopeId, code: &str) {
        let (status, body) = relay
            .request(
                "POST",
                &format!("/v1/{}/devices", scope_path(scope)),
                Some(&self.token),
                Some(serde_json::json!({ "v": 1, "code": code }).to_string()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// Push ops as wire parts (meta + the choke-point payload string —
    /// exactly what a client sends; the relay never sees more).
    pub async fn push(
        &self,
        relay: &mut TestRelay,
        scope: ScopeId,
        ops: &[Op],
    ) -> (StatusCode, serde_json::Value) {
        let wire_ops: Vec<serde_json::Value> = ops
            .iter()
            .map(|op| {
                let (meta, payload) = op.clone().into_parts();
                serde_json::json!({
                    "meta": serde_json::to_value(&meta).unwrap(),
                    "payload": pursecraft_core::wire::encode_payload(&payload).unwrap(),
                })
            })
            .collect();
        relay
            .request(
                "POST",
                &format!("/v1/{}/ops", scope_path(scope)),
                Some(&self.token),
                Some(serde_json::json!({ "v": 1, "ops": wire_ops }).to_string()),
            )
            .await
    }

    pub async fn pull(
        &self,
        relay: &mut TestRelay,
        scope: ScopeId,
        since: u64,
        limit: usize,
    ) -> Result<PullWire, SyncError> {
        let (status, body) = relay
            .request(
                "GET",
                &format!("/v1/{}/ops?since={since}&limit={limit}", scope_path(scope)),
                Some(&self.token),
                None,
            )
            .await;
        if status != StatusCode::OK {
            return Err(SyncError::Status(status, body));
        }
        Ok(serde_json::from_value(body).unwrap())
    }
}

/// A device with its engine state: the session that applies deltas and
/// the outbox of locally-minted ops waiting to be pushed.
pub struct SimDevice {
    pub device: Device,
    pub session: SyncSession,
    outbox: VecDeque<Op>,
    /// This device's op-id disambiguator space.
    rand_base: u64,
    /// This device's clock skew, in ms — ADR 0017's skew posture.
    skew_ms: u64,
    counter: u64,
}

impl SimDevice {
    pub async fn enroll(relay: &mut TestRelay, rand_base: u64, skew_ms: u64) -> Self {
        Self {
            device: Device::enroll(relay).await,
            session: SyncSession::new(),
            outbox: VecDeque::new(),
            rand_base,
            skew_ms,
            counter: 0,
        }
    }

    /// Mint one well-formed op for the scope, per-device skewed. Budget
    /// scope draws from the transaction pool; org scope from the org
    /// pool (ADR 0021's kind-vs-scope validity, including the reserved
    /// organization slot).
    pub fn mint(&mut self, scope: ScopeId, rng: &mut Rng) -> Op {
        self.counter += 1;
        let (entity_kind, entity_id, field, value) = match scope {
            ScopeId::Budget(_) => {
                let field = match rng.below(4) {
                    0 => Field::Transaction(TransactionField::Memo),
                    1 => Field::Transaction(TransactionField::Amount),
                    2 => Field::Transaction(TransactionField::Cleared),
                    _ => Field::Deleted,
                };
                let value = match &field {
                    Field::Transaction(TransactionField::Memo) => {
                        Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].into())
                    }
                    Field::Transaction(TransactionField::Amount) => {
                        Value::Milliunits(Milliunits::from_milli(rng.next_i64() / 8))
                    }
                    Field::Transaction(TransactionField::Cleared) => {
                        Value::Cleared(match rng.below(3) {
                            0 => Cleared::Uncleared,
                            1 => Cleared::Cleared,
                            _ => Cleared::Reconciled,
                        })
                    }
                    _ => Value::Bool(rng.below(2) == 0),
                };
                (EntityKind::Transaction, txn_entity(), field, value)
            }
            ScopeId::Org(org) => match rng.below(3) {
                0 => (
                    EntityKind::Organization,
                    EntityId::new(org.as_uuid()).unwrap(),
                    Field::Organization(OrgField::Name),
                    Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].into()),
                ),
                1 => (
                    EntityKind::Membership,
                    EntityId::new(v7(ID_MS, 300 + rng.below(3))).unwrap(),
                    Field::Membership(MembershipField::Role),
                    Value::Role(match rng.below(3) {
                        0 => MembershipRole::Owner,
                        1 => MembershipRole::Editor,
                        _ => MembershipRole::Viewer,
                    }),
                ),
                _ => (
                    EntityKind::Budget,
                    EntityId::new(v7(ID_MS, 400 + rng.below(2))).unwrap(),
                    Field::Budget(BudgetField::Name),
                    Value::Text(TEXTS[rng.below(TEXTS.len() as u64) as usize].into()),
                ),
            },
        };
        Op {
            op_id: OpId::new(v7(ID_MS, self.rand_base * 100_000 + self.counter)).unwrap(),
            scope,
            device_id: self.device.id,
            user_id: UserId::new(v7(ID_MS, 900 + self.rand_base)).unwrap(),
            entity_kind,
            entity_id,
            field,
            value,
            hlc: Hlc {
                physical_ms: HLC_BASE + self.skew_ms + self.counter * 3,
                logical: rng.below(2) as u32,
            },
        }
    }

    pub fn queue(&mut self, op: Op) {
        self.outbox.push_back(op);
    }

    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Apply a push response's acks: every pushed op must come back
    /// acked, in order, under its own id — a short or lying ack batch is
    /// a loud client failure, never a silent outbox drop (ADR 0024's
    /// hostile-server contract on the ack channel).
    pub fn apply_push_ack(&mut self, body: &serde_json::Value, ops: &[Op]) {
        let results = body["results"].as_array().expect("the ack lists results");
        assert_eq!(
            results.len(),
            ops.len(),
            "a short ack batch is loud: {} acks for {} pushed ops",
            results.len(),
            ops.len()
        );
        let sequenced: Vec<SequencedOp> = results
            .iter()
            .zip(ops)
            .map(|(result, op)| {
                let acked: OpId =
                    serde_json::from_value(result["op_id"].clone()).expect("ack op_id decodes");
                assert_eq!(acked, op.op_id, "an ack must echo the op it claims");
                SequencedOp {
                    seq: result["seq"].as_u64().expect("ack seq decodes"),
                    op: op.clone(),
                }
            })
            .collect();
        self.session.apply_delta(&sequenced).unwrap();
    }

    /// Push the outbox, then pull-and-apply until caught up (paging by
    /// `limit`; the received batch may be shuffled first — arrival order
    /// must not matter, ADR 0017). Returns `last_seen`.
    pub async fn sync(
        &mut self,
        relay: &mut TestRelay,
        scope: ScopeId,
        limit: usize,
        shuffle: bool,
        rng: &mut Rng,
    ) -> Result<u64, SyncError> {
        if !self.outbox.is_empty() {
            let ops: Vec<Op> = self.outbox.drain(..).collect();
            let (status, body) = self.device.push(relay, scope, &ops).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            // A pushed op is the sender's own next input: apply it locally
            // too (capture semantics — the minting device already holds
            // the op, so its session's watermark must advance).
            self.apply_push_ack(&body, &ops);
        }
        loop {
            let pull = self
                .device
                .pull(relay, scope, self.session.last_seen(), limit)
                .await?;
            if pull.ops.is_empty() {
                assert!(!pull.has_more, "has_more cannot outlive the ops");
                return Ok(self.session.last_seen());
            }
            let mut batch: Vec<SequencedOp> = Vec::with_capacity(pull.ops.len());
            for wire in &pull.ops {
                let payload =
                    decode_payload(&wire.payload).map_err(|e| SyncError::Decode(e.to_string()))?;
                batch.push(SequencedOp {
                    seq: wire.seq,
                    op: Op::from_parts(wire.meta.clone(), payload),
                });
            }
            if shuffle {
                shuffle_slice(rng, &mut batch);
            }
            self.session.apply_delta(&batch).map_err(SyncError::Apply)?;
            if !pull.has_more {
                return Ok(self.session.last_seen());
            }
        }
    }
}

const TEXTS: [&str; 5] = ["", "GCash", "groceries ₱", "Meralco", "uña"];

pub fn shuffle_slice<T>(rng: &mut Rng, slice: &mut [T]) {
    for i in (1..slice.len()).rev() {
        let j = rng.below((i + 1) as u64) as usize;
        slice.swap(i, j);
    }
}

impl Rng {
    pub fn next_i64(&mut self) -> i64 {
        self.next_u64() as i64
    }
}

// ---------------------------------------------------------------------
// Log-file surgery (ADR 0024's hostile-relay tests): parse the framed
// store (ADR 0018 format), rewrite records, keep the framing honest —
// the disk-level powers an attacker with file access would have.
// ---------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const FRAME_OVERHEAD: usize = 12;

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

/// One parsed frame: its record JSON and its span in the file.
pub struct Frame {
    pub record: serde_json::Value,
    pub start: usize,
    pub end: usize,
}

/// Parse every frame in a log file (header is 20 bytes; frames follow).
pub fn parse_frames(path: &Path) -> Vec<Frame> {
    let bytes = std::fs::read(path).unwrap();
    let mut frames = Vec::new();
    let mut offset = 20;
    while offset + FRAME_OVERHEAD <= bytes.len() {
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let end = offset + FRAME_OVERHEAD + len;
        let body = &bytes[offset + FRAME_OVERHEAD..end];
        frames.push(Frame {
            record: serde_json::from_slice(body).unwrap(),
            start: offset,
            end,
        });
        offset = end;
    }
    frames
}

fn frame_bytes(record: &serde_json::Value) -> Vec<u8> {
    let body = serde_json::to_vec(record).unwrap();
    let mut frame = Vec::with_capacity(body.len() + FRAME_OVERHEAD);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&fnv1a64(&body).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Rewrite the log from the given records — re-framed with honest
/// checksums, so the server cannot tell the bytes were touched: exactly
/// a malicious operator's powers (ADR 0024's tamper tests).
pub fn rewrite_frames(path: &Path, frames: &[serde_json::Value]) {
    let original = std::fs::read(path).unwrap();
    let mut out = original[..20].to_vec();
    for record in frames {
        out.extend_from_slice(&frame_bytes(record));
    }
    std::fs::write(path, &out).unwrap();
}
