//! The serving-contract tests (ADR 0026): the fleet's two-route health
//! (liveness dependency-free, readiness reflecting the store's write
//! health), `PURSECRAFT_DATA_DIR`, and SIGTERM drain — the last two
//! against the real binary, because they are process-level behaviors.

mod common;

use axum::http::StatusCode;
use pursecraft_api::AppState;
use pursecraft_core::ids::DeviceId;

use common::{RelayProcess, TestRelay, free_port, log_path, scratch_dir};

#[tokio::test]
async fn health_is_alive_without_touching_the_store() {
    let mut relay = TestRelay::new("health");
    let (status, body) = relay.request("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ok", "liveness carries no store dependency");
}

#[tokio::test]
async fn readiness_tracks_the_store_and_recovers() {
    let mut relay = TestRelay::new("readiness");
    let (status, body) = relay.request("GET", "/health/ready", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ready");

    // The oplog home gone: the probe must report what a real append
    // would hit, not what the process believes (ADR 0026).
    std::fs::remove_dir_all(relay.dir.join("logs")).unwrap();
    let (status, body) = relay.request("GET", "/health/ready", None, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["status"], "unavailable");
    let (status, body) = relay.request("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["status"], "ok",
        "liveness stays green while readiness fails"
    );

    // Recovery is live, not cached: the moment the home is writable
    // again the probe says so.
    std::fs::create_dir_all(relay.dir.join("logs")).unwrap();
    let (status, body) = relay.request("GET", "/health/ready", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
#[cfg(unix)]
async fn readiness_fails_while_the_data_dir_is_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let mut relay = TestRelay::new("readonly");
    let dirs = [relay.dir.clone(), relay.dir.join("logs")];
    for dir in &dirs {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    // chmod binds only for non-root runners; a root run cannot make a
    // directory unwritable this way — verify the setup instead of
    // asserting on a fiction (ADR 0026's read-only-volume scenario).
    if std::fs::write(relay.dir.join(".setup-check"), b"").is_ok() {
        eprintln!("skipping: running as root, chmod cannot make the dir unwritable");
        for dir in &dirs {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        return;
    }
    let (ready, body) = relay.request("GET", "/health/ready", None, None).await;
    let (alive, alive_body) = relay.request("GET", "/health", None, None).await;
    for dir in &dirs {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(ready, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["status"], "unavailable");
    assert_eq!(alive, StatusCode::OK, "{alive_body}");
    // A read-only volume cannot be restarted into health: the pod leaves
    // rotation (503 readiness) without dying (200 liveness) — ADR 0026.
}

/// The binary honors `PURSECRAFT_DATA_DIR` and serves both health routes
/// (ADR 0026): the whole state lands under the configured directory.
#[test]
#[cfg(unix)]
fn the_binary_honors_pursecraft_data_dir_and_serves_two_route_health() {
    let dir = scratch_dir("data-dir");
    let port = free_port();
    let mut relay = RelayProcess::spawn(&dir, port);
    relay.wait_for("/health", 200);

    let (status, body) = relay.request("GET", "/health", &[], "");
    assert_eq!(status, 200, "{body}");
    let (status, body) = relay.request("GET", "/health/ready", &[], "");
    assert_eq!(status, 200, "{body}");

    for rel in ["enrollment.secret", "logs"] {
        assert!(
            dir.join(rel).exists(),
            "{rel} must live under PURSECRAFT_DATA_DIR"
        );
    }

    relay.sigterm();
    let exit = relay.wait_exit(30);
    assert!(exit.success(), "a drained relay exits cleanly: {exit}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// SIGTERM drains in-flight requests and leaves the log sound (ADR 0026):
/// a request half-arrived when the signal lands is still served, the
/// acked push stays durable with its commit marker closed, and a fresh
/// process over the same bytes boots it all back (ADRs 0018, 0024).
#[test]
#[cfg(unix)]
fn sigterm_drains_in_flight_requests_and_leaves_the_log_sound() {
    use std::io::Write as _;
    let dir = scratch_dir("drain");
    let port = free_port();
    let mut relay = RelayProcess::spawn(&dir, port);
    relay.wait_for("/health/ready", 200);

    // A device, a scope, one acked push — the auth db's atomic write and
    // the oplog's two-phase commit both exercised before the signal.
    let secret = std::fs::read_to_string(dir.join("enrollment.secret"))
        .unwrap()
        .trim_end()
        .to_owned();
    let enroll_body = serde_json::json!({"v": 1, "enrollment_secret": secret}).to_string();
    let (status, body) = relay.request("POST", "/v1/devices", &[], &enroll_body);
    assert_eq!(status, 201, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token = json["token"].as_str().unwrap().to_owned();
    let device: DeviceId = serde_json::from_value(json["device_id"].clone()).unwrap();
    let auth = format!("Bearer {token}");

    let scope = common::budget_scope();
    let (status, body) = relay.request(
        "POST",
        &format!("/v1/{}", common::scope_path(scope)),
        &[("authorization", auth.as_str())],
        "",
    );
    assert_eq!(status, 201, "{body}");

    let op = common::a_mint_style_op(device, scope);
    let (meta, payload) = op.clone().into_parts();
    let payload_string = pursecraft_core::wire::encode_payload(&payload).unwrap();
    let push_body = serde_json::json!({
        "v": 1,
        "ops": [{
            "meta": serde_json::to_value(&meta).unwrap(),
            "payload": payload_string,
        }]
    })
    .to_string();
    let (status, body) = relay.request(
        "POST",
        &format!("/v1/{}/ops", common::scope_path(scope)),
        &[("authorization", auth.as_str())],
        &push_body,
    );
    assert_eq!(status, 200, "{body}");
    let push: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        push["results"][0]["seq"], 1,
        "the push was acked at sequence 1"
    );

    // The in-flight request across the SIGTERM boundary: half a POST
    // body on the wire when the signal lands, the rest after — drain
    // means the relay finishes what it admitted (ADR 0026).
    let enroll2_body = serde_json::json!({"v": 1, "enrollment_secret": secret}).to_string();
    let mut mid = relay.connect();
    let head = format!(
        "POST /v1/devices HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        enroll2_body.len()
    );
    mid.write_all(head.as_bytes()).unwrap();
    let half = enroll2_body.len() / 2;
    mid.write_all(&enroll2_body.as_bytes()[..half]).unwrap();

    relay.sigterm();
    common::wait_connect_refused(port); // the listener is closed: drain is live
    mid.write_all(&enroll2_body.as_bytes()[half..]).unwrap();
    mid.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let raw = common::read_response(&mut mid);
    let (status, body) = common::parse_response(&raw);
    assert_eq!(
        status, 201,
        "an in-flight request is served through the drain: {body}"
    );
    let drained: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token2 = drained["token"].as_str().unwrap().to_owned();

    let exit = relay.wait_exit(30);
    assert!(exit.success(), "a drained relay exits cleanly: {exit}");

    // Marker soundness (ADR 0018): the acked append's commit marker
    // closed phase two — [seq][!seq] commits through 1.
    let bytes = std::fs::read(log_path(&dir, scope)).unwrap();
    let seq = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let inv = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    assert_eq!(
        (seq, inv),
        (1, !1),
        "the commit marker must be Committed(1)"
    );

    // A fresh process over the same bytes boots it all back: the push
    // (opaque store), and both enrollments — including the one drained
    // across the signal (the auth db's atomic write, ADR 0024).
    let state = AppState::open(&dir).unwrap();
    let store = state.scope_log(scope, false).unwrap().unwrap();
    let store = store.lock().unwrap();
    assert_eq!(store.tip(), 1);
    let row = store.delta_parts_since(0).next().unwrap();
    assert_eq!(row.seq, 1);
    assert_eq!(
        row.meta, &meta,
        "the served row is the pushed op's metadata"
    );
    assert_eq!(
        row.payload, payload_string,
        "the payload round-trips verbatim"
    );
    drop(store);
    let auth_db = state.auth.lock().unwrap();
    assert!(
        auth_db.authenticate(&token).is_some(),
        "the pre-signal enrollment persists"
    );
    assert!(
        auth_db.authenticate(&token2).is_some(),
        "the drained enrollment persists"
    );
    drop(auth_db);
    drop(state);
    let _ = std::fs::remove_dir_all(&dir);
}
