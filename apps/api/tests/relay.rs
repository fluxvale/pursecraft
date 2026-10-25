//! The rendezvous relay's integration proofs (ADR 0024): devices
//! converge through the relay, a late joiner catches up via deltas, a
//! restart loses nothing, and — the security contract — the relay cannot
//! make a device diverge silently.

mod common;

use axum::http::StatusCode;
use common::{
    Device, Rng, SimDevice, SyncError, TestRelay, budget_scope, org_scope, parse_frames,
    rewrite_frames,
};
use pursecraft_core::ids::ScopeId;
use pursecraft_core::ops::ApplyError;
use pursecraft_core::wire::encode_payload;

/// Both scope kinds — org logs and budget logs relay identically (ADR
/// 0021: the same machinery, one typed scope).
fn scopes() -> [ScopeId; 2] {
    [budget_scope(), org_scope()]
}

#[tokio::test]
async fn two_devices_converge_through_the_relay() {
    for scope in scopes() {
        let mut relay = TestRelay::new("converge");
        let mut rng = Rng::new(7);

        let mut a = SimDevice::enroll(&mut relay, 1, 0).await;
        let code = a.device.create_scope(&mut relay, scope).await;
        let mut b = SimDevice::enroll(&mut relay, 2, 31_536_000_000).await; // a year ahead
        b.device.pair(&mut relay, scope, &code).await;

        // Interleaved churn: mint, push, pull with shuffled batches and
        // at-least-once re-pulls (the cursor sometimes rewound —
        // duplicated delivery must be a no-op, ADR 0017).
        for round in 0..24 {
            for device in [&mut a, &mut b] {
                for _ in 0..rng.below(4) {
                    let op = device.mint(scope, &mut rng);
                    device.queue(op);
                }
                device
                    .sync(&mut relay, scope, 5, round % 2 == 0, &mut rng)
                    .await
                    .unwrap();
                if rng.below(4) == 0 {
                    // Re-pull an overlap: duplicated delivery.
                    let rewind = device.session.last_seen().saturating_sub(rng.below(3));
                    let pull = device
                        .device
                        .pull(&mut relay, scope, rewind, 4)
                        .await
                        .unwrap();
                    let mut batch = Vec::new();
                    for wire in &pull.ops {
                        let payload = pursecraft_core::wire::decode_payload(&wire.payload).unwrap();
                        batch.push(pursecraft_core::sync::SequencedOp {
                            seq: wire.seq,
                            op: pursecraft_core::ops::Op::from_parts(wire.meta.clone(), payload),
                        });
                    }
                    common::shuffle_slice(&mut rng, &mut batch);
                    device.session.apply_delta(&batch).unwrap();
                }
            }
        }

        // Final drain: everyone at the tip, then a full re-pull is pure
        // duplicates.
        let tip = a
            .sync(&mut relay, scope, 100, false, &mut rng)
            .await
            .unwrap();
        assert_eq!(a.outbox_len(), 0);
        b.sync(&mut relay, scope, 100, false, &mut rng)
            .await
            .unwrap();
        let drain = a
            .device
            .pull(&mut relay, scope, 0, u64::MAX as usize)
            .await
            .unwrap();
        assert_eq!(drain.tip, tip);
        let replay = a
            .session
            .apply_delta(
                &drain
                    .ops
                    .iter()
                    .map(|wire| {
                        let payload = pursecraft_core::wire::decode_payload(&wire.payload).unwrap();
                        pursecraft_core::sync::SequencedOp {
                            seq: wire.seq,
                            op: pursecraft_core::ops::Op::from_parts(wire.meta.clone(), payload),
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(
            replay.duplicates, drain.tip,
            "everything was already applied"
        );
        assert_eq!(replay.applied, 0);

        // The reference: a fresh device pulling everything.
        let mut reference = SimDevice::enroll(&mut relay, 3, 0).await;
        let code = a.device.mint_code(&mut relay, scope).await;
        reference.device.pair(&mut relay, scope, &code).await;
        let caught = reference
            .sync(&mut relay, scope, 100, false, &mut rng)
            .await
            .unwrap();
        assert_eq!(caught, tip);
        assert_eq!(
            a.session.state(),
            reference.session.state(),
            "device a diverged"
        );
        assert_eq!(
            b.session.state(),
            reference.session.state(),
            "device b diverged"
        );
    }
}

#[tokio::test]
async fn a_late_joiner_catches_up_via_paged_deltas() {
    let scope = budget_scope();
    let mut relay = TestRelay::new("latejoin");
    let mut rng = Rng::new(11);

    let mut a = SimDevice::enroll(&mut relay, 1, 0).await;
    let code = a.device.create_scope(&mut relay, scope).await;
    let mut b = SimDevice::enroll(&mut relay, 2, 0).await;
    b.device.pair(&mut relay, scope, &code).await;
    for device in [&mut a, &mut b] {
        for _ in 0..30 {
            let op = device.mint(scope, &mut rng);
            device.queue(op);
        }
        device
            .sync(&mut relay, scope, 8, true, &mut rng)
            .await
            .unwrap();
    }
    // Drain both to the tip before the joiner appears.
    for device in [&mut a, &mut b] {
        device
            .sync(&mut relay, scope, 100, false, &mut rng)
            .await
            .unwrap();
    }
    assert_eq!(a.session.state(), b.session.state());
    let tip = a.device.pull(&mut relay, scope, 0, 1).await.unwrap().tip;
    assert!(tip > 20, "the churn produced a real log (tip {tip})");

    // The late joiner: never saw anything, small pages, no snapshot —
    // pure deltas since 0 (ADR 0024).
    let mut c = SimDevice::enroll(&mut relay, 3, 86_400_000).await;
    let code = a.device.mint_code(&mut relay, scope).await;
    c.device.pair(&mut relay, scope, &code).await;
    let caught = c.sync(&mut relay, scope, 7, false, &mut rng).await.unwrap();
    assert_eq!(caught, tip, "the late joiner reached the tip");
    assert_eq!(c.session.pending_len(), 0);
    assert_eq!(c.session.state(), a.session.state(), "late joiner diverged");
    assert_eq!(
        c.session.state(),
        b.session.state(),
        "late joiner diverged from b"
    );
}

#[tokio::test]
async fn a_relay_restart_loses_nothing_and_dedupes() {
    let scope = org_scope();
    let mut relay = TestRelay::new("restart");
    let mut rng = Rng::new(13);

    let mut a = SimDevice::enroll(&mut relay, 1, 0).await;
    let code = a.device.create_scope(&mut relay, scope).await;
    let mut b = SimDevice::enroll(&mut relay, 2, 3_600_000).await;
    b.device.pair(&mut relay, scope, &code).await;
    let mut pushed_by_a: Vec<pursecraft_core::ops::Op> = Vec::new();
    let mut pushed_by_b: Vec<pursecraft_core::ops::Op> = Vec::new();
    for _ in 0..12 {
        let op = a.mint(scope, &mut rng);
        a.queue(op.clone());
        pushed_by_a.push(op);
    }
    a.sync(&mut relay, scope, 100, false, &mut rng)
        .await
        .unwrap();
    for _ in 0..12 {
        let op = b.mint(scope, &mut rng);
        b.queue(op.clone());
        pushed_by_b.push(op);
    }
    b.sync(&mut relay, scope, 100, false, &mut rng)
        .await
        .unwrap();
    let before = a
        .device
        .pull(&mut relay, scope, 0, u64::MAX as usize)
        .await
        .unwrap();

    // The crash/restart boundary: a brand-new process over the same bytes.
    relay.restart();

    let after = a
        .device
        .pull(&mut relay, scope, 0, u64::MAX as usize)
        .await
        .unwrap();
    assert_eq!(after.tip, before.tip, "the tip survived");
    assert_eq!(after.ops.len(), before.ops.len(), "the whole log survived");
    assert_eq!(
        after.ops, before.ops,
        "every record round-trips bit for bit"
    );

    // Retries after restart dedupe to the original sequences (ADR 0007) —
    // each device retries its own ops (metadata honesty: a device may
    // append only its own).
    for (device, pushed) in [(&a, &pushed_by_a), (&b, &pushed_by_b)] {
        let (status, body) = device.device.push(&mut relay, scope, pushed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for (result, op) in body["results"].as_array().unwrap().iter().zip(pushed) {
            assert_eq!(result["stored"], false, "a retry is never a re-store");
            let seq = result["seq"].as_u64().unwrap();
            let wire = after.ops.iter().find(|w| w.seq == seq).unwrap();
            assert_eq!(wire.meta.op_id, op.op_id);
        }
    }

    // New appends continue the sequence space; auth survived the restart.
    let op = a.mint(scope, &mut rng);
    let (status, body) = a
        .device
        .push(&mut relay, scope, std::slice::from_ref(&op))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tip"].as_u64().unwrap(), after.tip + 1);
    a.sync(&mut relay, scope, 100, false, &mut rng)
        .await
        .unwrap();
    b.sync(&mut relay, scope, 100, false, &mut rng)
        .await
        .unwrap();
    assert_eq!(a.session.state(), b.session.state());
}

// ---------------------------------------------------------------------
// The security contract (ADR 0024): no server misbehavior short of
// fabrication produces silent divergence — tampering, truncation, and
// corruption all surface as errors or visible stalls.
// ---------------------------------------------------------------------

/// Two synced devices with `count` ops each in the log, at the tip.
async fn synced_pair(scope: ScopeId, count: usize) -> (TestRelay, SimDevice, SimDevice, Rng) {
    let mut relay = TestRelay::new("hostile");
    let mut rng = Rng::new(17);
    let mut a = SimDevice::enroll(&mut relay, 1, 0).await;
    let code = a.device.create_scope(&mut relay, scope).await;
    let mut b = SimDevice::enroll(&mut relay, 2, 0).await;
    b.device.pair(&mut relay, scope, &code).await;
    for device in [&mut a, &mut b] {
        for _ in 0..count {
            let op = device.mint(scope, &mut rng);
            device.queue(op);
        }
        device
            .sync(&mut relay, scope, 100, false, &mut rng)
            .await
            .unwrap();
    }
    (relay, a, b, rng)
}

#[tokio::test]
async fn a_tampered_payload_is_loud_on_every_client() {
    let scope = budget_scope();
    let (mut relay, _a, b, mut rng) = synced_pair(scope, 6).await;

    // A malicious operator rewrites one stored payload — honest framing,
    // new bytes (the disk-level power ADR 0024 assumes).
    let path = relay.log_path(scope);
    let frames = parse_frames(&path);
    let mut records: Vec<serde_json::Value> = frames.iter().map(|f| f.record.clone()).collect();
    records[2]["payload"] = serde_json::Value::String("tampered-not-the-op".into());
    rewrite_frames(&path, &records);
    relay.restart();

    // The tampered bytes are well-framed, so the pull succeeds — and
    // every client that syncs through the real machinery hits the loud
    // decode failure, never a silent skip. (The caught-up-device variant
    // is the swap test below.)
    let mut c = SimDevice::enroll(&mut relay, 3, 0).await;
    let code = b.device.mint_code(&mut relay, scope).await;
    c.device.pair(&mut relay, scope, &code).await;
    let result = c.sync(&mut relay, scope, 100, false, &mut rng).await;
    assert!(
        matches!(result, Err(SyncError::Decode(_))),
        "a fresh device hits the loud decode error, got {result:?}"
    );
}

#[tokio::test]
async fn a_swapped_payload_trips_the_op_id_conflict() {
    let scope = budget_scope();
    let (mut relay, a, _b, _rng) = synced_pair(scope, 6).await;

    // Swap two stored ops' payloads (re-checksummed): each op_id now
    // claims content it never had. A device that already applied the
    // originals gets the loud fingerprint error, never silent divergence
    // (ADR 0017's op_id ↔ content check).
    let path = relay.log_path(scope);
    let frames = parse_frames(&path);
    let mut records: Vec<serde_json::Value> = frames.iter().map(|f| f.record.clone()).collect();
    let first = records[1]["payload"].clone();
    let second = records[3]["payload"].clone();
    records[1]["payload"] = second;
    records[3]["payload"] = first;
    rewrite_frames(&path, &records);
    relay.restart();

    // A device that already applied the originals (a full device restore
    // replays the log through its session): the swap is caught where
    // plaintext lives — the fingerprint check, ADR 0017.
    let pull = a
        .device
        .pull(&mut relay, scope, 0, u64::MAX as usize)
        .await
        .unwrap();
    let mut restored = a.session.clone();
    let mut error = None;
    for wire in &pull.ops {
        let payload = pursecraft_core::wire::decode_payload(&wire.payload).unwrap();
        let op = pursecraft_core::ops::Op::from_parts(wire.meta.clone(), payload);
        if let Err(e) =
            restored.apply_delta(&[pursecraft_core::sync::SequencedOp { seq: wire.seq, op }])
        {
            error = Some(e);
            break;
        }
    }
    assert!(
        matches!(error, Some(ApplyError::OpIdConflict { .. })),
        "the swapped payload must trip OpIdConflict, got {error:?}"
    );
}

#[tokio::test]
async fn a_truncated_middle_op_stalls_the_watermark_visibly() {
    let scope = budget_scope();
    let (mut relay, a, _b, mut rng) = synced_pair(scope, 8).await;
    let full = a
        .device
        .pull(&mut relay, scope, 0, u64::MAX as usize)
        .await
        .unwrap();
    let tip = full.tip;
    let middle = full.ops[3].seq;

    // The relay drops a middle op from the log entirely (honest framing
    // for what remains).
    let path = relay.log_path(scope);
    let frames = parse_frames(&path);
    let records: Vec<serde_json::Value> = frames
        .iter()
        .map(|f| f.record.clone())
        .enumerate()
        .filter(|(i, _)| *i != 3)
        .map(|(_, record)| record)
        .collect();
    rewrite_frames(&path, &records);
    relay.restart();

    // A device syncing from scratch applies everything around the gap but
    // its watermark stalls below the tip — in plain sight, stably, on
    // every re-pull. The wedge is visible; nothing is silently skipped.
    let mut c = SimDevice::enroll(&mut relay, 3, 0).await;
    let code = a.device.mint_code(&mut relay, scope).await;
    c.device.pair(&mut relay, scope, &code).await;
    let result = c.sync(&mut relay, scope, 100, false, &mut rng).await;
    match result {
        Ok(seen) => {
            // The loop ended "caught up" only if has_more stayed false;
            // the watermark must still refuse to cross the gap.
            assert_eq!(seen, middle - 1, "the watermark stops before the gap");
            assert!(c.session.pending_len() > 0, "ops past the gap are pending");
        }
        Err(e) => panic!("truncation must stall, not error: {e:?}"),
    }
    // The tip still advertises the ops beyond the gap — the stall is
    // visible to any client comparing cursor to tip.
    let state = c.device.pull(&mut relay, scope, 0, 1).await.unwrap();
    assert_eq!(state.tip, tip);
    assert!(c.session.last_seen() < state.tip);
    // Re-pulling cannot silently fix or silently skip: stable stall.
    let again = c
        .device
        .pull(&mut relay, scope, c.session.last_seen(), 100)
        .await
        .unwrap();
    assert!(again.ops.iter().any(|op| op.seq > middle));
}

#[tokio::test]
async fn a_damaged_log_serves_nothing_loudly() {
    let scope = budget_scope();
    let (mut relay, a, _b, _rng) = synced_pair(scope, 4).await;

    // A torn or damaged frame the checksum catches: the scope's log fails
    // loudly at open — the relay serves that scope nothing (a 500, never
    // partial data), while the process and its other scopes live on
    // (ADRs 0018, 0024: logs open lazily, one damaged budget does not
    // take the household down).
    let path = relay.log_path(scope);
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2 + 30;
    bytes[mid] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    relay.restart();

    let result = a.device.pull(&mut relay, scope, 0, u64::MAX as usize).await;
    assert!(
        matches!(
            result,
            Err(SyncError::Status(StatusCode::INTERNAL_SERVER_ERROR, _))
        ),
        "a damaged log must fail loudly, got {result:?}"
    );

    // The containment claim is pinned, not just stated: the same relay
    // serves the undamaged scope next door.
    let other = org_scope();
    a.device.create_scope(&mut relay, other).await;
    let (status, body) = relay
        .request(
            "GET",
            &format!("/v1/{}/ops", common::scope_path(other)),
            Some(&a.device.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A lying ack channel is loud client-side: the ack application refuses
/// a batch shorter than the push — a server that acks ops it did not
/// store cannot make the simulated client silently drop its outbox tail
/// (ADR 0024's hostile-server contract, ack path).
#[tokio::test]
#[should_panic(expected = "a short ack batch is loud")]
async fn a_short_ack_batch_is_loud_client_side() {
    let scope = budget_scope();
    let (_relay, mut a, _b, mut rng) = synced_pair(scope, 2).await;
    let first = a.mint(scope, &mut rng);
    let second = a.mint(scope, &mut rng);
    let lying = serde_json::json!({
        "v": 1,
        "results": [{
            "op_id": serde_json::to_value(first.op_id).unwrap(),
            "seq": 1,
            "stored": true,
        }],
        "tip": 1,
    });
    // One ack for two pushed ops: the same application path `sync` uses
    // must refuse it.
    a.apply_push_ack(&lying, &[first, second]);
}

/// The ack contract's other half: a full-length batch whose acks claim
/// ops they are not for is refused too — a lying relay cannot mislabel
/// sequences onto the wrong ops.
#[tokio::test]
#[should_panic(expected = "an ack must echo the op it claims")]
async fn a_mislabeled_ack_is_loud_client_side() {
    let scope = budget_scope();
    let (_relay, mut a, _b, mut rng) = synced_pair(scope, 2).await;
    let first = a.mint(scope, &mut rng);
    let second = a.mint(scope, &mut rng);
    let swapped_echo = serde_json::json!({
        "v": 1,
        "results": [
            { "op_id": serde_json::to_value(second.op_id).unwrap(), "seq": 1, "stored": true },
            { "op_id": serde_json::to_value(first.op_id).unwrap(), "seq": 2, "stored": true },
        ],
        "tip": 2,
    });
    a.apply_push_ack(&swapped_echo, &[first, second]);
}

/// The running-clock expiry path: a code past its TTL is refused without
/// a restart to prune it first (ADR 0024).
#[tokio::test]
async fn an_expired_code_is_refused_by_the_running_clock() {
    let scope = budget_scope();
    let mut relay = TestRelay::new("expiry-running");
    let a = Device::enroll(&mut relay).await;
    let code = a.create_scope(&mut relay, scope).await;

    // A second database instance over the persisted file: the code is on
    // disk, and the redeem-time check sees the TTL directly.
    let mut db = pursecraft_api::auth::AuthDb::open(&relay.dir).unwrap();
    let joiner = pursecraft_core::ids::DeviceId::new(uuid::Uuid::nil()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let past_ttl = now + pursecraft_api::auth::PAIRING_TTL_SECS + 1;
    assert!(matches!(
        db.redeem_pairing_code_at(scope, &code, joiner, past_ttl),
        Err(pursecraft_api::auth::AuthError::PairingCodeExpired)
    ));
    // Within the TTL the same code still redeems — the boundary is the
    // TTL, not the check.
    let joiner = pursecraft_core::ids::DeviceId::new(uuid::Uuid::max()).unwrap();
    db.redeem_pairing_code_at(scope, &code, joiner, now)
        .unwrap();
}

#[tokio::test]
async fn replayed_deltas_are_idempotent_through_the_relay() {
    let scope = budget_scope();
    let (mut relay, a, _b, mut rng) = synced_pair(scope, 5).await;
    let tip = a.device.pull(&mut relay, scope, 0, 1).await.unwrap().tip;

    // Deliver the full delta three times over, shuffled: the state never
    // moves and the cursor never regresses (ADR 0017's at-least-once).
    let mut reference = None;
    for _ in 0..3 {
        let pull = a
            .device
            .pull(&mut relay, scope, 0, u64::MAX as usize)
            .await
            .unwrap();
        let mut batch: Vec<pursecraft_core::sync::SequencedOp> = pull
            .ops
            .iter()
            .map(|wire| {
                let payload = pursecraft_core::wire::decode_payload(&wire.payload).unwrap();
                pursecraft_core::sync::SequencedOp {
                    seq: wire.seq,
                    op: pursecraft_core::ops::Op::from_parts(wire.meta.clone(), payload),
                }
            })
            .collect();
        common::shuffle_slice(&mut rng, &mut batch);
        let mut fresh = pursecraft_core::sync::SyncSession::new();
        fresh.apply_delta(&batch).unwrap();
        assert_eq!(fresh.last_seen(), tip);
        match reference {
            None => reference = Some(fresh.state().clone()),
            Some(ref expected) => assert_eq!(fresh.state(), expected),
        }
    }
}

// ---------------------------------------------------------------------
// The auth boundary (ADR 0024): tokens gate every route, grants gate
// every scope, and the metadata honesty checks hold.
// ---------------------------------------------------------------------

#[tokio::test]
async fn the_auth_boundary_holds() {
    let scope = budget_scope();
    let mut relay = TestRelay::new("auth");
    let mut rng = Rng::new(19);

    // Enrollment needs the operator's secret.
    let (status, _) = relay
        .request(
            "POST",
            "/v1/devices",
            None,
            Some(r#"{"v":1,"enrollment_secret":"wrong"}"#.into()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let a = Device::enroll(&mut relay).await;
    let outsider = Device::enroll(&mut relay).await;
    let code = a.create_scope(&mut relay, scope).await;

    // Scope creation is single-shot: no squatting a taken id.
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/{}", common::scope_path(scope)),
            None,
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "creation still needs a token"
    );
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/{}", common::scope_path(scope)),
            Some(&outsider.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Pairing codes are single-use and scoped.
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/{}/devices", common::scope_path(scope)),
            Some(&outsider.token),
            Some(serde_json::json!({"v":1,"code":code}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/{}/devices", common::scope_path(scope)),
            Some(&a.token),
            Some(serde_json::json!({"v":1,"code":code}).to_string()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a code dies with its first use"
    );

    // An enrolled but unpaired device can neither push nor pull.
    let stranger = Device::enroll(&mut relay).await;
    let (status, body) = stranger
        .push(&mut relay, scope, &[a_mint(&stranger, scope, &mut rng)])
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = relay
        .request(
            "GET",
            &format!("/v1/{}/ops", common::scope_path(scope)),
            Some(&stranger.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unknown token, missing header.
    let (status, _) = relay
        .request(
            "GET",
            &format!("/v1/{}/ops", common::scope_path(scope)),
            Some("dev_not-a-token"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = relay
        .request(
            "GET",
            &format!("/v1/{}/ops", common::scope_path(scope)),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Metadata honesty: a device may append only its own ops (ADR 0024).
    let mut forged = a_mint(&a, scope, &mut rng);
    forged.device_id = stranger.id;
    let (status, body) = a.push(&mut relay, scope, &[forged]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Metadata honesty: the op's scope must match the route.
    let foreign = a_mint(&a, org_scope(), &mut rng); // meta.scope = the org
    let (meta, payload) = foreign.into_parts();
    let (status, body) = relay
        .request(
            "POST",
            &format!("/v1/{}/ops", common::scope_path(scope)),
            Some(&a.token),
            Some(
                serde_json::json!({
                    "v": 1,
                    "ops": [{
                        "meta": serde_json::to_value(&meta).unwrap(),
                        "payload": encode_payload(&payload).unwrap(),
                    }],
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Envelope versions are refused, never guessed.
    let (status, _) = relay
        .request(
            "POST",
            "/v1/devices",
            None,
            Some(
                serde_json::json!({
                    "v": 2,
                    "enrollment_secret": relay.enrollment_secret(),
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Even non-UTF-8 query bytes answer inside the error envelope —
    // axum's plain-text rejection is not part of this protocol's surface.
    let (status, body) = relay
        .request(
            "GET",
            &format!("/v1/{}/ops?since=%FF", common::scope_path(scope)),
            Some(&a.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].is_string(),
        "the rejection is enveloped, not plain text: {body}"
    );

    // A payload past the cap is refused without landing.
    let huge = a_mint(&a, scope, &mut rng);
    let (meta, _) = huge.clone().into_parts();
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/{}/ops", common::scope_path(scope)),
            Some(&a.token),
            Some(
                serde_json::json!({
                    "v": 1,
                    "ops": [{
                        "meta": serde_json::to_value(&meta).unwrap(),
                        "payload": "x".repeat(65 * 1024),
                    }],
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // The route kinds are typed: an unknown kind is a 400, a v4 id is a
    // 400 (scope ids are client-minted v7, ADR 0021).
    let (status, _) = relay
        .request(
            "POST",
            "/v1/households/018f0000-0000-7000-8000-000000000001",
            Some(&a.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = relay
        .request(
            "POST",
            &format!("/v1/budgets/{}", uuid::Uuid::new_v4()),
            Some(&a.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pairing_codes_expire() {
    let scope = budget_scope();
    let mut relay = TestRelay::new("expiry");
    let a = Device::enroll(&mut relay).await;
    let code = a.create_scope(&mut relay, scope).await;

    // Push the clock past the TTL by rewriting what the relay persists
    // (the operator's file powers): the code must die.
    let auth_path = relay.dir.join("auth.json");
    let mut auth: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&auth_path).unwrap()).unwrap();
    auth["pairing_codes"][0]["expires_at_unix"] = serde_json::json!(1);
    std::fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
    relay.restart();

    let joiner = Device::enroll(&mut relay).await;
    let (status, body) = relay
        .request(
            "POST",
            &format!("/v1/{}/devices", common::scope_path(scope)),
            Some(&joiner.token),
            Some(serde_json::json!({"v":1,"code":code}).to_string()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// Mint one pushable op for the auth tests (a device's own, well-formed).
fn a_mint(device: &Device, scope: ScopeId, rng: &mut Rng) -> pursecraft_core::ops::Op {
    let rand = rng.next_u64();
    pursecraft_core::ops::Op {
        op_id: pursecraft_core::ids::OpId::new(common::v7(1 << 40, rand & 0xffff)).unwrap(),
        scope,
        device_id: device.id,
        user_id: pursecraft_core::ids::UserId::new(common::v7(1 << 40, 777)).unwrap(),
        entity_kind: pursecraft_core::domain::EntityKind::Transaction,
        entity_id: pursecraft_core::ids::EntityId::new(common::v7(1 << 40, 50)).unwrap(),
        field: pursecraft_core::domain::Field::Transaction(
            pursecraft_core::domain::TransactionField::Memo,
        ),
        value: pursecraft_core::domain::Value::Text("auth probe".into()),
        hlc: pursecraft_core::hlc::Hlc {
            physical_ms: 1 << 50,
            logical: 0,
        },
    }
}
