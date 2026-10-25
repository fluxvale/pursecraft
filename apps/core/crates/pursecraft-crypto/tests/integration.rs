//! The E2EE integration suites (ADR 0022): the 0017 convergence and 0018
//! boot-from-store proofs re-run with every payload sealed through the
//! real cipher, plus the choke-point boundary tests — mode confusion,
//! splicing, at-rest opacity, keyless boot — that the envelope design
//! exists to guarantee. Uses `pursecraft-core`'s testkit (its
//! dev-only `testkit` feature) so the same deterministic generators prove
//! the same theorems with crypto in the path.

use pursecraft_core::ids::{OrgId, ScopeId};
use pursecraft_core::ops::Op;
use pursecraft_core::store::{LocalStore, StoreError};
use pursecraft_core::sync::{SequencedOp, SyncSession};
use pursecraft_core::testkit::conv;
use pursecraft_core::testkit::v7;
use pursecraft_core::testkit::{Rng, TempDir};
use pursecraft_core::wire::{self, PayloadCipher, PlainCipher};

use pursecraft_crypto::{DeviceKeypair, KeyChain, ScopeCipher, WrappedLogKey, WrappedOrgKey};

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// One device's key material for a one-log fixture, plus everything
/// needed to rebuild an equivalent cipher later: the same device secret
/// plus the wraps — precisely the new-device-restore path a reopened
/// store handle (or a real reinstall) takes.
struct SealedKeys {
    secret: [u8; 32],
    org: OrgId,
    org_wrap: WrappedOrgKey,
    log_wraps: Vec<WrappedLogKey>,
}

fn sealed_keys(scope: ScopeId, org: OrgId) -> (ScopeCipher, SealedKeys) {
    let device = DeviceKeypair::generate().unwrap();
    let secret = *device.to_secret_bytes();
    let mut chain = KeyChain::new(device);
    let org_wrap = chain.create_org(org).unwrap();
    let mut log_wraps = vec![chain.add_log(org, ScopeId::Org(org)).unwrap()];
    if scope != ScopeId::Org(org) {
        log_wraps.push(chain.add_log(org, scope).unwrap());
    }
    (
        ScopeCipher::new(chain),
        SealedKeys {
            secret,
            org,
            org_wrap,
            log_wraps,
        },
    )
}

fn restored_cipher(keys: &SealedKeys) -> ScopeCipher {
    let mut chain = KeyChain::new(DeviceKeypair::from_secret_bytes(keys.secret));
    chain.install_org_wrap(&keys.org_wrap).unwrap();
    for wrap in &keys.log_wraps {
        match wrap.scope {
            ScopeId::Org(_) => chain.install_log_wrap(wrap).unwrap(),
            ScopeId::Budget(_) => chain.install_log_wrap_for_org(wrap, &keys.org).unwrap(),
        }
    }
    ScopeCipher::new(chain)
}

/// A session booted from the store — the product operation (ADR 0018).
fn boot_session(store: &LocalStore<impl PayloadCipher>) -> SyncSession {
    let mut session = SyncSession::new();
    session
        .apply_delta(store.delta_since(0))
        .expect("stored ops are well-formed");
    session
}

/// An in-memory session fed the same ops in canonical order — the
/// replay every boot must equal (ADR 0018).
fn in_memory_session(ops: &[Op]) -> SyncSession {
    let sequenced: Vec<SequencedOp> = ops
        .iter()
        .enumerate()
        .map(|(i, op)| conv::sequenced(i as u64 + 1, op.clone()))
        .collect();
    let mut session = SyncSession::new();
    session
        .apply_delta(&sequenced)
        .expect("generated ops are well-formed");
    session
}

fn store_path(tmp: &TempDir, label: &str) -> std::path::PathBuf {
    tmp.path().join(format!("{label}.ops"))
}

// ---------------------------------------------------------------------
// The choke point under the cipher (ADR 0022)
// ---------------------------------------------------------------------

/// A cipher keyed for both scopes `every_variant` writes into (its org
/// ops carry the org id `v7(ID_MS, 1)` — not `conv::org()`, whose rand
/// differs).
fn cipher() -> ScopeCipher {
    let org = OrgId::new(v7(conv::ID_MS, 1)).unwrap();
    let org_scope = ScopeId::Org(org);
    let budget_scope = ScopeId::Budget(conv::budget());
    let mut chain = KeyChain::new(DeviceKeypair::generate().unwrap());
    chain.create_org(org).unwrap();
    chain.add_log(org, org_scope).unwrap();
    chain.add_log(org, budget_scope).unwrap();
    ScopeCipher::new(chain)
}

#[test]
fn every_variant_round_trips_sealed_through_the_cipher() {
    let cipher = cipher();
    for op in conv::every_variant() {
        let (meta, payload) = op.clone().into_parts();
        let plaintext = wire::encode_payload(&payload).unwrap();
        let sealed = cipher.seal(&meta, plaintext.clone()).unwrap();
        // The envelope is opaque: none of the payload's field names
        // appear. (Underscore and quote bytes are not in the base64
        // alphabet, so these assertions are deterministic, not
        // probabilistic.)
        for secret in ["entity_kind", "entity_id", "\"field\"", "\"value\""] {
            assert!(
                !sealed.contains(secret),
                "{secret} leaked into the envelope"
            );
        }
        assert_ne!(sealed, plaintext);
        // And it opens back to the exact op.
        let opened = cipher.open(&meta, &sealed).unwrap();
        assert_eq!(opened, plaintext);
        let back = wire::decode_payload(&opened).unwrap();
        assert_eq!(Op::from_parts(meta, back), op);
    }
}

#[test]
fn cipher_and_plaintext_modes_refuse_each_others_payloads() {
    // Strip/downgrade defense (ADR 0022): the envelope and plaintext
    // shapes are disjoint, so mode confusion is loud in both directions
    // — never a silent pass-through.
    let cipher = cipher();
    let (meta, payload) = conv::every_variant()[0].clone().into_parts();
    let plaintext = wire::encode_payload(&payload).unwrap();
    let sealed = cipher.seal(&meta, plaintext.clone()).unwrap();

    // A sealing cipher handed plaintext refuses it outright.
    assert!(
        cipher.open(&meta, &plaintext).is_err(),
        "plaintext must never pass as an envelope"
    );

    // The plain (self-host) cipher hands the envelope through unchanged
    // — and the payload decoder rejects it at the choke point: no
    // plaintext reading of sealed bytes exists.
    let passed = PlainCipher.open(&meta, &sealed).unwrap();
    assert_eq!(passed, sealed);
    assert!(
        wire::decode_payload(&passed).is_err(),
        "an envelope must never decode as a plaintext payload"
    );
}

#[test]
fn a_sealed_payload_cannot_be_spliced_onto_other_metadata() {
    // The AAD binding (ADR 0022): the same envelope bytes opened under
    // different op metadata fail — the transport cannot re-associate
    // ciphertexts with other ids, stamps, or scopes.
    let cipher = cipher();
    let (meta, payload) = conv::every_variant()[0].clone().into_parts();
    let sealed = cipher
        .seal(&meta, wire::encode_payload(&payload).unwrap())
        .unwrap();

    let mut other = meta.clone();
    other.op_id = pursecraft_core::ids::OpId::new(v7(conv::ID_MS + 99, 99)).unwrap();
    assert!(cipher.open(&other, &sealed).is_err(), "op id is bound");

    let mut other = meta.clone();
    other.hlc = pursecraft_core::hlc::Hlc {
        physical_ms: conv::HLC_BASE * 2,
        logical: 3,
    };
    assert!(cipher.open(&other, &sealed).is_err(), "the stamp is bound");

    let mut other = meta.clone();
    other.scope = match meta.scope {
        ScopeId::Org(_) => ScopeId::Budget(conv::budget()),
        ScopeId::Budget(_) => ScopeId::Org(conv::org()),
    };
    assert!(cipher.open(&other, &sealed).is_err(), "the scope is bound");

    // The correct metadata, of course, opens it.
    assert!(cipher.open(&meta, &sealed).is_ok());
}

// ---------------------------------------------------------------------
// Boot-from-store with wrapped payloads (ADRs 0018 + 0022)
// ---------------------------------------------------------------------

#[test]
fn a_ciphered_store_holds_no_plaintext_and_boots_to_the_replay_state() {
    for scope in conv::scopes() {
        let org = match scope {
            ScopeId::Org(org) => org,
            ScopeId::Budget(_) => conv::org(),
        };
        for seed in 1..=3u64 {
            let ops = conv::generate_ops(seed.wrapping_mul(0x0123_4567_89AB_CDEF), scope);
            let expected = in_memory_session(&ops);
            let tmp = TempDir::new("sealed-boot");
            let path = store_path(&tmp, "log");

            let (cipher, keys) = sealed_keys(scope, org);
            let mut store = LocalStore::open_with(&path, cipher).unwrap();
            for op in &ops {
                store.append(op.clone()).unwrap();
            }
            drop(store);

            // At-rest check (ADR 0022): the file carries envelopes — no
            // payload field names anywhere in the bytes.
            let bytes = std::fs::read(&path).unwrap();
            for marker in [
                &b"entity_kind"[..],
                &b"entity_id"[..],
                b"\"field\"",
                b"\"value\"",
            ] {
                assert!(
                    !bytes.windows(marker.len()).any(|w| w == marker),
                    "plaintext payload marker {marker:?} leaked into the store (seed {seed})"
                );
            }

            // Boot from DISK through the restored cipher.
            let store = LocalStore::open_with(&path, restored_cipher(&keys)).unwrap();
            let booted = boot_session(&store);
            assert_eq!(booted.state(), expected.state(), "seed {seed}");
            assert_eq!(booted.last_seen(), store.tip());
            assert_eq!(store.tip(), ops.len() as u64);
        }
    }
}

#[test]
fn booting_a_ciphered_store_without_keys_is_cipher_error_not_corruption() {
    let (scope, org) = (conv::scopes()[0], conv::org());
    let (field, value) = conv::amount(5);
    let ops: Vec<Op> = (1..=4)
        .map(|i| conv::op(i, 10 + i, 0, field, value.clone()))
        .collect();
    let tmp = TempDir::new("no-keys");
    let path = store_path(&tmp, "log");
    let (cipher, keys) = sealed_keys(scope, org);
    let mut store = LocalStore::open_with(&path, cipher).unwrap();
    for op in &ops {
        store.append(op.clone()).unwrap();
    }
    drop(store);
    let before = std::fs::read(&path).unwrap();

    // A fresh device holds no keys: the refusal is a Cipher error —
    // intact bytes the reader cannot open (ADR 0022) — never
    // corruption, and the repair paths never touch the file.
    let stranger = ScopeCipher::new(KeyChain::new(DeviceKeypair::generate().unwrap()));
    match LocalStore::open_with(&path, stranger) {
        Err(StoreError::Cipher(_)) => {}
        other => panic!("expected a cipher refusal, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "untouched");

    // A plaintext-mode reader on the same file also fails loudly — the
    // envelope does not decode as a payload (shape-disjoint, ADR 0022);
    // the label is corruption-class, the bytes still untouched.
    match LocalStore::open(&path) {
        Err(StoreError::Corrupt { .. }) => {}
        other => panic!("expected a loud refusal, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "untouched");

    // And the keyed reader still boots everything.
    let store = LocalStore::open_with(&path, restored_cipher(&keys)).unwrap();
    assert_eq!(store.tip(), 4);
}

#[test]
fn a_ciphered_stores_torn_tail_still_repairs_under_keys() {
    // Crash-tail repair is checksum-level (ADR 0018) — the cipher never
    // interferes: a torn last frame is cut, the rest boots.
    let (scope, org) = (conv::scopes()[0], conv::org());
    let (cipher, keys) = sealed_keys(scope, org);
    let tmp = TempDir::new("sealed-torn");
    let path = store_path(&tmp, "log");
    let (field, value) = conv::amount(5);
    let mut store = LocalStore::open_with(&path, cipher).unwrap();
    for i in 1..=6u64 {
        store
            .append(conv::op(i, 10 + i, 0, field, value.clone()))
            .unwrap();
    }
    drop(store);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 7);

    let cut = store_path(&tmp, "cut");
    std::fs::write(&cut, &bytes).unwrap();
    let mut store = LocalStore::open_with(&cut, restored_cipher(&keys)).unwrap();
    assert_eq!(store.tip(), 5, "the torn frame is the only loss");
    // The lost op's sequence was already acknowledged (its marker
    // committed), so the space resumes above it — a gap, never a reuse
    // (ADR 0018's external-damage rule).
    let (field, value) = conv::amount(6);
    assert_eq!(store.append(conv::op(50, 50, 0, field, value)).unwrap(), 7);
}

#[test]
fn a_re_encrypted_retry_collapses_by_op_id_across_stores() {
    // The E2EE-safe dedupe rule (ADRs 0017, 0018) under real crypto: the
    // SAME op sealed twice carries different envelope bytes — splicing
    // both records into one file still collapses to the first, and the
    // booted log is one op at one sequence.
    let (scope, org) = (conv::scopes()[0], conv::org());
    let (field, value) = conv::amount(7);
    let op = conv::op(1, 10, 0, field, value);
    let tmp = TempDir::new("sealed-dup");
    let one = store_path(&tmp, "one");
    let two = store_path(&tmp, "two");

    let (cipher, keys) = sealed_keys(scope, org);
    let mut store = LocalStore::open_with(&one, cipher).unwrap();
    store.append(op.clone()).unwrap();
    drop(store);

    // The second store is written through an independent handle holding
    // the same restored key material (the reinstall path) — the same op
    // is genuinely re-encrypted, not shared state.
    let mut store = LocalStore::open_with(&two, restored_cipher(&keys)).unwrap();
    store.append(op).unwrap();
    drop(store);

    // Both files carry the same op, differently encrypted.
    let a = std::fs::read(&one).unwrap();
    let b = std::fs::read(&two).unwrap();
    assert_ne!(
        &a[20..],
        &b[20..],
        "two seals of one op differ (fresh nonces)"
    );

    // Splice: record two after record one, resequenced to 2. The framing
    // arithmetic mirrors the store's (header 20, frame overhead 12,
    // FNV-1a-64 checksum) — store internals are not public API.
    let header_len = 20;
    let frame_overhead = 12;
    let fnv1a64 = |bytes: &[u8]| -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    let len = u32::from_le_bytes(b[header_len..header_len + 4].try_into().unwrap()) as usize;
    let mut body: serde_json::Value =
        serde_json::from_slice(&b[header_len + frame_overhead..header_len + frame_overhead + len])
            .unwrap();
    body["seq"] = serde_json::json!(2u64);
    let body = serde_json::to_vec(&body).unwrap();
    let mut reframed = Vec::with_capacity(frame_overhead + body.len());
    reframed.extend_from_slice(&(body.len() as u32).to_le_bytes());
    reframed.extend_from_slice(&fnv1a64(&body).to_le_bytes());
    reframed.extend_from_slice(&body);
    let mut spliced = a.clone();
    spliced.extend_from_slice(&reframed);
    let spliced_path = store_path(&tmp, "spliced");
    std::fs::write(&spliced_path, &spliced).unwrap();

    let store = LocalStore::open_with(&spliced_path, restored_cipher(&keys)).unwrap();
    assert_eq!(store.tip(), 1, "one op serves, at its own sequence");
    let seqs: Vec<u64> = store.delta_since(0).map(|s| s.seq).collect();
    assert_eq!(seqs, [1]);
}

// ---------------------------------------------------------------------
// Convergence through a ciphered, store-backed rendezvous (ADRs
// 0017 + 0018 + 0022)
// ---------------------------------------------------------------------

/// The 0017 convergence proof through a ciphered, store-backed
/// rendezvous: every append seals, every boot opens, and N devices still
/// converge on the canonical state — with mid-run crashes and reboots
/// through the restored-cipher path. Fewer seeds than the plaintext
/// loop: the same theorem, proved with the crypto in the path, at a
/// runtime the suite can afford.
#[test]
fn n_devices_converge_through_the_ciphered_store_backed_rendezvous_loop() {
    const SEALED_SEEDS: u64 = 4;
    const DEVICES: u64 = conv::DEVICES;
    const OPS_PER_DEVICE: usize = conv::OPS_PER_DEVICE;
    for scope in conv::scopes() {
        let org = match scope {
            ScopeId::Org(org) => org,
            ScopeId::Budget(_) => conv::org(),
        };
        for seed in 1..=SEALED_SEEDS {
            let ops = conv::generate_ops(seed.wrapping_mul(0x0F1E_2D3C_4B5A_6978), scope);
            let mut rng = Rng::new(seed.wrapping_mul(0x1611_5A5F_3C49_8C3D));
            let tmp = TempDir::new("sealed-rendezvous");
            let path = store_path(&tmp, "log");
            let (cipher, keys) = sealed_keys(scope, org);
            let mut store = LocalStore::open_with(&path, cipher).unwrap();
            let mut queues: Vec<std::collections::VecDeque<Op>> = (0..DEVICES)
                .map(|d| {
                    ops[d as usize * OPS_PER_DEVICE..(d as usize + 1) * OPS_PER_DEVICE]
                        .iter()
                        .cloned()
                        .collect()
                })
                .collect();
            let mut sessions: Vec<SyncSession> = (0..DEVICES).map(|_| SyncSession::new()).collect();
            let mut turns = 0u64;
            while queues.iter().any(|q| !q.is_empty()) {
                turns += 1;
                let d = rng.below(DEVICES) as usize;
                for _ in 0..1 + rng.below(4) {
                    if let Some(op) = queues[d].pop_front() {
                        store.append(op).expect("generated ops are well-formed");
                    }
                }
                for session in &mut sessions {
                    if rng.below(3) == 0 {
                        // Mostly pull only new ops; sometimes re-pull an
                        // overlap — at-least-once delivery.
                        let since = if rng.below(4) == 0 {
                            session.last_seen().saturating_sub(rng.below(5))
                        } else {
                            session.last_seen()
                        };
                        session
                            .apply_delta(store.delta_since(since))
                            .expect("generated ops are well-formed");
                    }
                }
                match turns {
                    // The rendezvous crashes and reboots from disk —
                    // through the restored-cipher path a reinstalled
                    // device takes.
                    30 | 70 => {
                        store = LocalStore::open_with(&path, restored_cipher(&keys)).unwrap()
                    }
                    // Device 0 reboots: a fresh session booted from the store.
                    50 => sessions[0] = boot_session(&store),
                    _ => {}
                }
            }
            for session in &mut sessions {
                let drained = session.apply_delta(store.delta_since(0)).unwrap();
                assert_eq!(drained.last_seen, store.tip());
            }

            let reference = sessions[0].state().clone();
            for (i, session) in sessions.iter().enumerate() {
                assert_eq!(
                    session.state(),
                    &reference,
                    "device {i} diverged (seed {seed})"
                );
            }
            let canonical = boot_session(&store);
            assert_eq!(canonical.state(), &reference, "seed {seed}");
            assert_eq!(canonical.last_seen(), store.tip());
            // The forced equal-HLC tie still breaks by op_id — observed
            // directly, as in the plaintext loop.
            let (tie_entity, tie_field, tie_value) = conv::expected_tie_value(&ops);
            assert_eq!(
                conv::materialized(canonical.state(), tie_entity, tie_field),
                Some(tie_value),
                "seed {seed}"
            );
        }
    }
}
