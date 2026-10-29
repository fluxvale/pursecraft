//! The https round trip (issue #34, ADR 0029): the real axum relay behind
//! real TLS — tokio-rustls serving a fresh rcgen-minted self-signed
//! certificate — driven by the CLI's real ureq client. The client agent
//! trusts exactly the test certificate (`RootCerts::Specific`), and the
//! test first proves the production posture holds on the SHIPPED
//! `default_agent` — its strictness pinned at the config level, and its
//! refusal of this server asserted specifically as a certificate
//! failure, so TLS verification is provably on, never disabled for the
//! test's sake. The live relay remains the final acceptance step, never
//! a CI dependency.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::serve::Listener;
use pursecraft_api::{AppState, router};
use pursecraft_cli::home::{budget_log, load_identity, org_log};
use pursecraft_cli::relay::{self, Relay};
use pursecraft_cli::session::{self, Session};
use pursecraft_cli::{Context, run};
use pursecraft_core::date::Date;
use pursecraft_core::ids::ScopeId;
use pursecraft_core::ops::Op;
use pursecraft_core::store::OpaqueStore;
use pursecraft_core::wire::{PlainCipher, decode_payload};

// ---------------------------------------------------------------------
// A TLS relay: the real router on an ephemeral localhost socket, every
// connection wrapped by tokio-rustls with the self-signed test cert.
// ---------------------------------------------------------------------

struct TlsRelay {
    dir: PathBuf,
    url: String,
    /// The server certificate in PEM — the test agent's ONLY trust root.
    cert_pem: Vec<u8>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TlsRelay {
    fn start(label: &str) -> Self {
        let dir = scratch_dir(label);
        let state = Arc::new(AppState::open(&dir).expect("open relay state"));
        let app = router(state);

        // One self-signed certificate per run — never a committed fixture
        // that could silently expire. The SAN is the literal loopback IP:
        // rustls matches IP SANs only, and the client connects by address.
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self-signed cert");
        let cert_pem = cert.pem().into_bytes();
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der())
                    .into(),
            )
            .expect("server cert config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(format!("tls-relay-{label}"))
            .spawn(move || {
                let runtime = tokio::runtime::Runtime::new().expect("test runtime");
                runtime.block_on(async move {
                    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("bind ephemeral");
                    addr_tx
                        .send(tcp.local_addr().expect("local addr"))
                        .expect("test waits for the addr");
                    let listener = TlsListener { tcp, acceptor };
                    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                        let _ = stop_rx.await;
                    });
                    let _ = server.await;
                })
            })
            .expect("spawn tls relay thread");
        let addr = addr_rx.recv().expect("tls relay bound");
        Self {
            dir,
            url: format!("https://{addr}"),
            cert_pem,
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

impl Drop for TlsRelay {
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

/// axum's `Listener` over accepted TLS streams — the documented shape for
/// serving axum on a non-plain-TCP transport.
struct TlsListener {
    tcp: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let Ok((stream, addr)) = self.tcp.accept().await else {
                continue;
            };
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                // A handshake that dies mid-flight is the CLIENT's error,
                // never the server's — keep serving.
                Err(_) => continue,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

// ---------------------------------------------------------------------
// The client side: agents, homes, and stores.
// ---------------------------------------------------------------------

/// The test client (ADR 0029): the SHIPPED strict chain (via
/// [`relay::agent_with_roots`]) with the test certificate as the only
/// trust root — no builder is duplicated here, so the test agent cannot
/// drift from the production one (hostile review round 2).
fn test_agent(cert_pem: &[u8]) -> ureq::Agent {
    let certificate = ureq::tls::Certificate::from_pem(cert_pem).expect("test cert parses");
    relay::agent_with_roots(ureq::tls::RootCerts::new_with_certs(&[certificate]))
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pursecraft-cli-https-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
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

fn scratch_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pursecraft-cli-https-relay-{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run_home(home: &Path, stdin: &str, args: &[&str]) -> pursecraft_cli::Output {
    let argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let text = stdin.to_owned();
    let piped =
        (!stdin.is_empty()).then(|| Box::new(move || text.clone()) as Box<dyn FnOnce() -> String>);
    run(&argv, || {
        Ok(Context {
            home: home.to_owned(),
            today: Date::new(2026, 10, 25).unwrap(),
            piped_secret: piped,
            e2ee: false,
            terminal: None,
        })
    })
}

/// The store's ops as wire `Op`s — the exact bytes a real sync pushes.
fn stored_ops(log_path: &Path) -> Vec<Op> {
    OpaqueStore::open(log_path)
        .expect("open store")
        .delta_parts_since(0)
        .map(|row| {
            let payload = decode_payload(row.payload).expect("payload decodes");
            Op::from_parts(row.meta.clone(), payload)
        })
        .collect()
}

// ---------------------------------------------------------------------
// The round trip.
// ---------------------------------------------------------------------

#[test]
fn enroll_push_and_pull_round_trip_over_tls() {
    let relay = TlsRelay::start("roundtrip");
    let secret = relay.enrollment_secret();

    // The shipped agent's strictness, pinned on the constructor itself —
    // mutating `default_agent` toward lenience (following redirects,
    // statuses-as-errors, env proxies) turns these red.
    let shipped = relay::default_agent();
    let config = shipped.config();
    assert_eq!(config.max_redirects(), 0, "redirects are never followed");
    assert!(
        !config.http_status_as_error(),
        "statuses flow to the teaching decoder"
    );
    assert!(
        config.proxy().is_none(),
        "no environment proxy lookup, ever"
    );

    // The production posture refuses a self-signed server — asserted on
    // the shipped agent, and specifically as a certificate refusal (a
    // dead port or DNS failure must NOT satisfy this). Verification is
    // never loosened to make the test pass.
    let refused = relay::enroll_with_agent(&shipped, &relay.url, &secret);
    let detail = refused
        .expect_err("the shipped agent must refuse the self-signed relay")
        .to_string();
    assert!(
        detail.contains("invalid peer certificate"),
        "a TLS certificate refusal, not any transport failure: {detail}"
    );

    // Enroll over TLS through the test-CA agent.
    let agent = test_agent(&relay.cert_pem);
    let (device_id, token) =
        relay::enroll_with_agent(&agent, &relay.url, &secret).expect("enroll over tls");

    // A real home under this enrollment: a synthetic session (the gate),
    // then a real capture whose ops are minted under the enrolled device.
    let home = TempDir::new("roundtrip-home");
    session::publish(
        home.path(),
        &Session {
            version: 1,
            server: relay.url.clone(),
            device_id,
            token: token.clone(),
        },
    )
    .unwrap();
    let add = run_home(home.path(), "", &["add", "coffee", "-4.50"]);
    assert_eq!(add.code, 0, "{}{}", add.stdout, add.stderr);

    // Push the home's own ops through the TLS relay, scope by scope, and
    // pull them back: the same ops, same order, byte-identical payloads.
    let identity = load_identity(home.path()).unwrap().expect("world exists");
    let client = Relay::with_agent(&relay.url, &token, test_agent(&relay.cert_pem));
    let scopes = [
        (
            ScopeId::Org(identity.org_id),
            org_log(home.path(), identity.org_id),
        ),
        (
            ScopeId::Budget(identity.budget_id),
            budget_log(home.path(), identity.budget_id),
        ),
    ];
    for (scope, log_path) in scopes {
        let ops = stored_ops(&log_path);
        assert!(!ops.is_empty(), "a booted world has ops to push");
        client.create_scope(scope).expect("create scope over tls");
        client
            .push(scope, &ops, &PlainCipher)
            .expect("push over tls");
        let mut page = client.pull(scope, 0, ops.len()).expect("pull over tls");
        assert!(!page.has_more, "one page covers the log");
        assert_eq!(page.ops.len(), ops.len(), "every op came back");
        for (index, (wire, op)) in page.ops.iter_mut().zip(&ops).enumerate() {
            assert_eq!(wire.seq, (index + 1) as u64, "dense relay sequences");
            assert_eq!(wire.meta, op.clone().into_parts().0, "meta round-trips");
            assert_eq!(wire.payload, wire_payload(op), "payload bytes round-trip");
        }
    }
}

/// The wire payload string of an op — what the relay stores and returns.
fn wire_payload(op: &Op) -> String {
    let (_, payload) = op.clone().into_parts();
    pursecraft_core::wire::encode_payload(&payload).expect("encode payload")
}

#[test]
fn agent_with_roots_shares_the_shipped_strictness_field_by_field() {
    // Opportunistic close (hostile review's non-blocking P3):
    // `agent_with_roots` is shipped public API — a second closure that
    // could drift. Its OUTPUT is pinned to the shipped agent on the
    // reviewer's six-field set (max_redirects, status-as-error, proxy,
    // timeout, disable_verification, sni), so a future edit inside the
    // seam cannot quietly loosen the test client while `default_agent`
    // stays strict. The seam may differ from production in trust roots
    // ONLY.
    let key = rcgen::KeyPair::generate().expect("key pair");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key)
        .expect("cert");
    let certificate = ureq::tls::Certificate::from_pem(cert.pem().as_bytes()).expect("pem");
    let seam = relay::agent_with_roots(ureq::tls::RootCerts::new_with_certs(&[certificate]));
    let shipped = relay::default_agent();
    let (seam_config, shipped_config) = (seam.config(), shipped.config());

    // Field-by-field equality with the shipped agent.
    assert_eq!(
        seam_config.max_redirects(),
        shipped_config.max_redirects(),
        "redirects drift in the seam"
    );
    assert_eq!(
        seam_config.http_status_as_error(),
        shipped_config.http_status_as_error(),
        "status handling drift in the seam"
    );
    assert_eq!(
        seam_config.proxy().is_none(),
        shipped_config.proxy().is_none(),
        "proxy pin drift in the seam"
    );
    assert_eq!(
        seam_config.timeouts().global,
        shipped_config.timeouts().global,
        "timeout drift in the seam"
    );
    let (seam_tls, shipped_tls) = (seam_config.tls_config(), shipped_config.tls_config());
    assert_eq!(
        seam_tls.disable_verification(),
        shipped_tls.disable_verification(),
        "verification drift in the seam"
    );
    assert!(!seam_tls.disable_verification(), "verification stays on");
    assert_eq!(
        seam_tls.use_sni(),
        shipped_tls.use_sni(),
        "sni drift in the seam"
    );

    // The three strict pins as literals, so lenience is caught even if
    // both agents were ever loosened together.
    assert_eq!(seam_config.max_redirects(), 0, "no redirects, ever");
    assert!(
        !seam_config.http_status_as_error(),
        "statuses flow to the teaching decoder"
    );
    assert!(seam_config.proxy().is_none(), "no environment proxy, ever");
}
