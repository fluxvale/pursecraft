//! Crypto tests (ADR 0022): the four named classes live here as
//! grep-able names — round-trip, tamper rejection, wrong-key rejection,
//! rotation-after-revocation — plus the wrap/binding attacks the
//! constructions exist to stop.

use pursecraft_core::hlc::Hlc;
use pursecraft_core::ids::{BudgetId, DeviceId, OpId, OrgId, ScopeId, UserId};
use pursecraft_core::wire::OpMeta;
use uuid::Uuid;

use pursecraft_crypto::{CryptoError, DeviceKeypair, Grant, KeyChain};

/// Deterministic UUIDv7, same construction as the core testkit (which is
/// crate-private): `ms` plus a disambiguator.
fn v7(ms: u64, rand: u64) -> Uuid {
    let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
    Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
}

const MS: u64 = 1 << 40;

fn org() -> OrgId {
    OrgId::new(v7(MS, 1)).unwrap()
}

fn budget() -> BudgetId {
    BudgetId::new(v7(MS, 2)).unwrap()
}

fn meta(i: u64, scope: ScopeId) -> OpMeta {
    OpMeta {
        op_id: OpId::new(v7(MS + i, 100 + i)).unwrap(),
        scope,
        device_id: DeviceId::new(Uuid::nil()).unwrap(),
        user_id: UserId::new(Uuid::max()).unwrap(),
        hlc: Hlc {
            physical_ms: MS + i,
            logical: 0,
        },
    }
}

/// The plaintext payload string, as the core choke point emits it.
fn payload_json(i: u64) -> String {
    format!(
        r#"{{"entity_kind":"Transaction","entity_id":"{}","field":{{"Transaction":"Memo"}},"value":{{"Text":"groceries {i}"}}}}"#,
        v7(MS, 7 + i)
    )
}

/// A keyed chain for `org` with data keys for the org log and one budget
/// log at epoch 0, plus the chain of a second member holding the same
/// grants (installed through the wraps, never shared raw).
struct Pair {
    a: KeyChain,
    b: KeyChain,
    org: OrgId,
    org_scope: ScopeId,
    budget_scope: ScopeId,
}

fn pair() -> Pair {
    let org = org();
    let org_scope = ScopeId::Org(org);
    let budget_scope = ScopeId::Budget(budget());

    let mut a = KeyChain::new(DeviceKeypair::generate().unwrap());
    let b_device = DeviceKeypair::generate().unwrap();
    let mut b = KeyChain::new(DeviceKeypair::from_secret_bytes(
        *b_device.to_secret_bytes(),
    ));
    let b_public = b.device_public();

    let _creator_wrap = a.create_org(org).unwrap();
    // B joins: A wraps the epoch-0 org key to B's device, B installs it,
    // A hands over the log-key wraps, B installs those.
    let invite = a
        .wrap_org_keys_to(&org, &b_public, Grant::CurrentEpoch)
        .unwrap();
    assert_eq!(invite.len(), 1);
    b.install_org_wrap(&invite[0]).unwrap();

    let org_log_wrap = a.add_log(org, org_scope).unwrap();
    let budget_log_wrap = a.add_log(org, budget_scope).unwrap();
    b.install_log_wrap(&org_log_wrap).unwrap();
    b.install_log_wrap_for_org(&budget_log_wrap, &org).unwrap();

    Pair {
        a,
        b,
        org,
        org_scope,
        budget_scope,
    }
}

#[test]
fn seal_open_round_trips_across_devices_and_scopes() {
    let p = pair();
    for (chain, label) in [(&p.a, "creator"), (&p.b, "invitee")] {
        for scope in [p.org_scope, p.budget_scope] {
            for i in 0..10u64 {
                let m = meta(i, scope);
                let plaintext = payload_json(i);
                let sealed = chain.seal_payload(&m, plaintext.as_bytes()).unwrap();
                assert_ne!(sealed, plaintext, "the envelope is not the plaintext");
                assert!(sealed.starts_with(r#"{"v":1,"e":"#), "{sealed}");
                let opened = chain.open_payload(&m, &sealed).unwrap();
                assert_eq!(
                    String::from_utf8(opened).unwrap(),
                    plaintext,
                    "{label} scope {scope:?} op {i}"
                );
            }
        }
    }
    // A seals, B opens — the whole point of wrapping keys to members.
    let m = meta(42, p.budget_scope);
    let sealed = p.a.seal_payload(&m, payload_json(42).as_bytes()).unwrap();
    assert_eq!(
        String::from_utf8(p.b.open_payload(&m, &sealed).unwrap()).unwrap(),
        payload_json(42)
    );
    // Sealing the same op twice yields different envelopes (fresh
    // nonces) and both open — the retry-dedupe premise of ADR 0017.
    let again = p.a.seal_payload(&m, payload_json(42).as_bytes()).unwrap();
    assert_ne!(sealed, again);
    assert!(p.b.open_payload(&m, &again).is_ok());
}

#[test]
fn tampered_envelopes_are_rejected() {
    let p = pair();
    let m = meta(1, p.budget_scope);
    let sealed = p.a.seal_payload(&m, payload_json(1).as_bytes()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&sealed).unwrap();

    // Flip one bit inside the ciphertext (decode→flip→re-encode, so the
    // envelope stays perfectly well-formed JSON).
    let mut bits = b64_decode(json["c"].as_str().unwrap());
    let mid = bits.len() / 2;
    bits[mid] ^= 0x01;
    let tampered_ct = render(json.clone(), "c", &bits);
    assert_eq!(
        p.b.open_payload(&m, &tampered_ct),
        Err(CryptoError::Auth),
        "flipped ciphertext bit"
    );

    // Flip a nonce byte.
    let mut nonce = b64_decode(json["n"].as_str().unwrap());
    nonce[0] ^= 0x80;
    let tampered_n = render(json.clone(), "n", &nonce);
    assert_eq!(
        p.b.open_payload(&m, &tampered_n),
        Err(CryptoError::Auth),
        "flipped nonce byte"
    );

    // Truncate the tag.
    let mut short = b64_decode(json["c"].as_str().unwrap());
    short.truncate(short.len() - 1);
    let tampered_short = render(json, "c", &short);
    assert_eq!(
        p.b.open_payload(&m, &tampered_short),
        Err(CryptoError::Auth),
        "truncated tag"
    );

    // Re-associate the ciphertext with a DIFFERENT op's metadata — the
    // AAD binding is the splicing defense (ADR 0022).
    let other_meta = meta(2, p.budget_scope);
    let untampered = p.a.seal_payload(&m, payload_json(1).as_bytes()).unwrap();
    assert_eq!(
        p.b.open_payload(&other_meta, &untampered),
        Err(CryptoError::Auth),
        "spliced onto another op id/stamp"
    );
    // Same op id and stamp but a different scope: still splicing.
    let mut foreign_scope = other_meta.clone();
    foreign_scope.scope = p.org_scope;
    assert_eq!(
        p.b.open_payload(&foreign_scope, &untampered),
        Err(CryptoError::Auth),
        "spliced onto another scope"
    );
}

#[test]
fn wrong_keys_are_rejected() {
    let mut p = pair();
    let m = meta(1, p.budget_scope);
    let sealed = p.a.seal_payload(&m, payload_json(1).as_bytes()).unwrap();

    // A complete outsider device: no key material at all.
    let outsider = KeyChain::new(DeviceKeypair::generate().unwrap());
    assert_eq!(
        outsider.open_payload(&m, &sealed),
        Err(CryptoError::MissingEpoch {
            scope: p.budget_scope,
            epoch: 0,
            held: None,
        }),
        "an outsider has no key material"
    );

    // A member of a DIFFERENT org holding its own key for the same scope
    // id: the wrong key must fail authentication, never decode.
    let other_org = OrgId::new(v7(MS, 55)).unwrap();
    let mut other = KeyChain::new(DeviceKeypair::generate().unwrap());
    other.create_org(other_org).unwrap();
    other.add_log(other_org, p.budget_scope).unwrap();
    assert_eq!(
        other.open_payload(&m, &sealed),
        Err(CryptoError::Auth),
        "a different org's key for the same scope id must fail"
    );

    // A wrap addressed to the wrong device does not open for B.
    let stranger = DeviceKeypair::generate().unwrap();
    let wraps =
        p.a.wrap_org_keys_to(&p.org, &stranger.public(), Grant::CurrentEpoch)
            .unwrap();
    assert_eq!(
        p.b.install_org_wrap(&wraps[0]),
        Err(CryptoError::Auth),
        "a wrap for another device's key must fail"
    );
}

#[test]
fn removed_member_cannot_read_the_new_epoch() {
    // The named rotation class (issue #20): B is removed — the org
    // rotates, only A survives — and B must not read anything sealed
    // under the new epoch, while keeping (honestly) what B already had.
    let mut p = pair();
    let m_old = meta(1, p.budget_scope);
    let old =
        p.a.seal_payload(&m_old, payload_json(1).as_bytes())
            .unwrap();

    // Removal: A rotates to epoch 1 wrapping only A's own device.
    let rotation = p.a.rotate(&p.org, &[p.a.device_public()]).unwrap();
    assert_eq!(rotation.epoch, 1);
    assert_eq!(rotation.org_wraps.len(), 1, "one surviving device");
    assert_eq!(rotation.log_wraps.len(), 2, "org log + budget log");
    // B receives nothing. (In production the channel carries wraps; the
    // removed member is simply not addressed — asserted below.)

    // New-epoch payload: A seals under epoch 1.
    let m_new = meta(2, p.budget_scope);
    let new =
        p.a.seal_payload(&m_new, payload_json(2).as_bytes())
            .unwrap();
    assert!(
        new.contains(r#""e":1"#),
        "the new envelope names the new epoch"
    );
    assert_eq!(
        String::from_utf8(p.a.open_payload(&m_new, &new).unwrap()).unwrap(),
        payload_json(2),
        "the survivor reads the new epoch"
    );

    // B's cached keys are stale: the loud, pre-decryption answer.
    assert_eq!(
        p.b.open_payload(&m_new, &new),
        Err(CryptoError::MissingEpoch {
            scope: p.budget_scope,
            epoch: 1,
            held: Some(0),
        }),
        "the removed member is told the keys are stale, before any decryption"
    );

    // Even forcing the old key onto the new envelope must fail: mark
    // the envelope as the old epoch and the AEAD still refuses — the
    // ciphertext was never under that key.
    let forced = {
        let mut json: serde_json::Value = serde_json::from_str(&new).unwrap();
        json["e"] = serde_json::json!(0u64);
        serde_json::to_string(&json).unwrap()
    };
    assert_eq!(
        p.b.open_payload(&m_new, &forced),
        Err(CryptoError::Auth),
        "a stale member cannot try the old key against the new epoch"
    );

    // Honesty clause (ADR 0009/0022): B keeps readable history.
    assert_eq!(
        String::from_utf8(p.b.open_payload(&m_old, &old).unwrap()).unwrap(),
        payload_json(1),
        "rotation protects future data only — history stays readable"
    );

    // And the wraps themselves: none of the rotation's wraps open for B.
    for wrap in &rotation.org_wraps {
        assert_eq!(
            p.b.install_org_wrap(wrap),
            Err(CryptoError::Auth),
            "a rotation wrap is addressed to survivors, not the removed member"
        );
    }
}

#[test]
fn plaintext_and_envelopes_are_shape_disjoint() {
    // The strip/downgrade defense (ADR 0022): no string both decodes as
    // a plaintext payload and parses as an envelope, in either direction.
    let p = pair();
    let plaintext = payload_json(1);
    assert_eq!(
        p.b.open_payload(&meta(1, p.budget_scope), &plaintext),
        Err(CryptoError::NotAnEnvelope),
        "a sealing cipher handed plaintext refuses it"
    );
    // The version gate: an unknown envelope version is refused, not
    // guessed. (The identity direction — a plaintext-mode core decoder
    // handed an envelope — is asserted in the core suite.)
    let m = meta(1, p.budget_scope);
    let sealed = p.a.seal_payload(&m, plaintext.as_bytes()).unwrap();
    let mut future = serde_json::from_str::<serde_json::Value>(&sealed).unwrap();
    future["v"] = serde_json::json!(2u16);
    let future = serde_json::to_string(&future).unwrap();
    assert_eq!(
        p.b.open_payload(&m, &future),
        Err(CryptoError::UnsupportedVersion(2)),
        "an unknown envelope version is refused, not guessed"
    );
}

#[test]
fn wraps_survive_their_wire_form_and_refuse_wrong_slots() {
    let mut p = pair();
    // The wire form round-trips (the channel relays opaque bytes).
    let invite =
        p.a.wrap_org_keys_to(&p.org, &p.b.device_public(), Grant::AllEpochs)
            .unwrap();
    assert_eq!(invite.len(), 1, "epoch 0 is the only epoch so far");
    let wire = invite[0].to_wire().unwrap();
    let back = pursecraft_crypto::WrappedOrgKey::from_wire(&wire).unwrap();
    assert_eq!(back, invite[0]);

    // A doctored wrap — relabeled onto another epoch or org — derives
    // the wrong wrap key and fails authentication: the identity is
    // welded into HKDF info and AEAD AAD alike (ADR 0022). Nothing
    // misrouted is stored.
    let mut doctored = invite[0].clone();
    doctored.epoch = 9;
    assert_eq!(
        p.b.install_org_wrap(&doctored),
        Err(CryptoError::Auth),
        "a wrap relabeled onto another epoch fails its binding"
    );
    let mut doctored = invite[0].clone();
    doctored.org = OrgId::new(v7(MS, 77)).unwrap();
    assert_eq!(
        p.b.install_org_wrap(&doctored),
        Err(CryptoError::Auth),
        "a wrap relabeled onto another org fails its binding"
    );
    // B already holds epoch 0; installing the same wrap again is a no-op.
    p.b.install_org_wrap(&invite[0]).unwrap();

    // Structural slots: a budget-scoped wrap needs its owning org named
    // (ADR 0021: the org of a budget log lives in the org log's data);
    // the org-scoped install path refuses it outright. A FRESH budget
    // scope, because re-adding a registered scope is itself refused
    // (asserted in add_log_and_create_org_refuse_re_registration).
    let second_budget = ScopeId::Budget(BudgetId::new(v7(MS, 79)).unwrap());
    let budget_wrap = p.a.add_log(p.org, second_budget).unwrap();
    assert_eq!(
        p.b.install_log_wrap(&budget_wrap),
        Err(CryptoError::WrongKeySlot),
        "a budget log wrap cannot install through the org-only path"
    );
    // And a scope registered under one org cannot gain keys through
    // another org's epoch key: B creates (and keys) the foreign org, so
    // the org-key lookup SUCCEEDS and the refusal is the structural
    // cross-org guard itself (chain.rs), not missing key material.
    let other_org = OrgId::new(v7(MS, 78)).unwrap();
    p.b.create_org(other_org).unwrap();
    // Register the second budget under the REAL org on B first — via
    // the org-scope-named install for its owning org.
    p.b.install_log_wrap_for_org(&budget_wrap, &p.org).unwrap();
    assert_eq!(
        p.b.install_log_wrap_for_org(&budget_wrap, &other_org),
        Err(CryptoError::WrongKeySlot),
        "a scope registered under one org cannot gain keys through another"
    );
}

#[test]
fn installs_refuse_to_swap_a_held_slot_but_redeliver_idempotently() {
    // The rotation-race posture (ADR 0022): a slot may be filled once.
    // DIFFERENT material for a held (org, epoch) slot is a loud
    // conflict — never a silent swap that leaves this device holding a
    // minority keyset; the SAME material (at-least-once redelivery, or
    // the same key re-wrapped) is a no-op.
    let mut p = pair();

    // Same wrap, delivered twice: no-op.
    let wraps =
        p.a.wrap_org_keys_to(&p.org, &p.b.device_public(), Grant::CurrentEpoch)
            .unwrap();
    p.b.install_org_wrap(&wraps[0]).unwrap();
    p.b.install_org_wrap(&wraps[0]).unwrap();

    // A DIFFERENT org-epoch-0 key for the same org (a competing
    // "creation", standing in for a competing rotation at one epoch):
    // refused.
    let mut rival = KeyChain::new(DeviceKeypair::generate().unwrap());
    rival.create_org(p.org).unwrap();
    let rival_wraps = rival
        .wrap_org_keys_to(&p.org, &p.b.device_public(), Grant::CurrentEpoch)
        .unwrap();
    assert_eq!(
        p.b.install_org_wrap(&rival_wraps[0]),
        Err(CryptoError::WrongKeySlot),
        "different material for a held org epoch slot is a loud conflict"
    );

    // The log-key side, in the realistic race shape: A rotates to
    // epoch 1 (B installs the new org key and the rotation's log key),
    // then a third chain C — holding the SAME epoch-1 org key — mints
    // its own log key for the same (scope, epoch). The channel may
    // deliver both; B must not silently adopt C's.
    let rotation =
        p.a.rotate(&p.org, &[p.a.device_public(), p.b.device_public()])
            .unwrap();
    let b_org_wraps =
        p.a.wrap_org_keys_to(&p.org, &p.b.device_public(), Grant::CurrentEpoch)
            .unwrap();
    let mut c = KeyChain::new(DeviceKeypair::generate().unwrap());
    // C receives A's invite wrap addressed to it — a distinct device.
    let c_wraps =
        p.a.wrap_org_keys_to(&p.org, &c.device_public(), Grant::CurrentEpoch)
            .unwrap();
    c.install_org_wrap(&c_wraps[0]).unwrap();
    // B's own epoch-1 wrap carries the same key the rotation minted.
    p.b.install_org_wrap(&b_org_wraps[0]).unwrap();
    for wrap in &rotation.log_wraps {
        match wrap.scope {
            ScopeId::Org(_) => p.b.install_log_wrap(wrap).unwrap(),
            ScopeId::Budget(_) => {
                p.b.install_log_wrap_for_org(wrap, &p.org).unwrap();
            }
        }
    }
    // C mints a competing log key for (budget_scope, epoch 1) — a fresh
    // registration on C's chain, sealed under the shared org key.
    let competing = c.add_log(p.org, p.budget_scope).unwrap();
    assert_eq!(
        p.b.install_log_wrap_for_org(&competing, &p.org),
        Err(CryptoError::WrongKeySlot),
        "different material for a held log epoch slot is a loud conflict"
    );
    // And re-delivering the rotation's own wrap for that slot stays a
    // no-op (B already installed it above).
    for wrap in &rotation.log_wraps {
        if wrap.scope == p.budget_scope {
            p.b.install_log_wrap_for_org(wrap, &p.org).unwrap();
        }
    }
}

#[test]
fn add_log_and_create_org_refuse_re_registration() {
    let mut p = pair();
    // One log, one registration: re-adding a registered scope (same org
    // or cross-org) is refused — a silent replace would destroy every
    // held epoch key for it (or re-bind it to another org, the hostile
    // two-orgs-one-budget input installs refuse).
    assert_eq!(
        p.a.add_log(p.org, p.budget_scope),
        Err(CryptoError::WrongKeySlot),
        "re-adding a registered scope under its own org is refused"
    );
    let other_org = OrgId::new(v7(MS, 80)).unwrap();
    assert_eq!(
        p.a.add_log(other_org, p.budget_scope),
        Err(CryptoError::WrongKeySlot),
        "re-registering a scope under a different org is refused"
    );
    // And an org is creatable exactly once — even by a chain that only
    // ever held later epochs (invited at epoch 3), so a down-mint
    // inside an org with history is impossible.
    let mut late_joiner = KeyChain::new(DeviceKeypair::generate().unwrap());
    let mut minter = KeyChain::new(DeviceKeypair::generate().unwrap());
    minter.create_org(p.org).unwrap();
    for _ in 0..3 {
        minter.rotate(&p.org, &[minter.device_public()]).unwrap();
    }
    let late = minter
        .wrap_org_keys_to(&p.org, &late_joiner.device_public(), Grant::CurrentEpoch)
        .unwrap();
    late_joiner.install_org_wrap(&late[0]).unwrap();
    assert_eq!(
        late_joiner.create_org(p.org),
        Err(CryptoError::WrongKeySlot),
        "a chain that knows the org at all cannot re-create it"
    );
}

#[test]
fn no_string_parses_as_both_envelope_and_payload() {
    // The strict-envelope half of the shape-disjointness (ADR 0022): a
    // doctored UNION of an envelope and a plaintext payload — the only
    // candidate for a string both decoders might accept — is refused by
    // the envelope parser (unknown fields denied), while a real envelope
    // round-trips.
    let p = pair();
    let m = meta(1, p.budget_scope);
    let plaintext = payload_json(1);
    let sealed = p.a.seal_payload(&m, plaintext.as_bytes()).unwrap();

    let mut union: serde_json::Value = serde_json::from_str(&sealed).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&plaintext).unwrap();
    for (key, value) in payload.as_object().unwrap() {
        union[key.as_str()] = value.clone();
    }
    let union = serde_json::to_string(&union).unwrap();
    assert_eq!(
        p.b.open_payload(&m, &union),
        Err(CryptoError::NotAnEnvelope),
        "an envelope carrying foreign payload fields is not an envelope"
    );
    // The untouched envelope still opens.
    assert!(p.b.open_payload(&m, &sealed).is_ok());
}

#[test]
fn invites_grant_exactly_what_was_wrapped() {
    let mut p = pair();
    // Seal something under epoch 0 BEFORE rotating — the history a
    // current-only invite must not read.
    let m_history = meta(9, p.budget_scope);
    let history = p.a.seal_payload(&m_history, b"history at epoch 0").unwrap();

    let rotation =
        p.a.rotate(&p.org, &[p.a.device_public(), p.b.device_public()])
            .unwrap();
    // Install B's wraps for the new epoch the way the channel would.
    let wraps =
        p.a.wrap_org_keys_to(&p.org, &p.b.device_public(), Grant::AllEpochs)
            .unwrap();
    assert_eq!(wraps.len(), 2, "both epochs are granted");
    for wrap in &wraps {
        p.b.install_org_wrap(wrap).unwrap();
    }
    // The rotation's log wraps ride along; B installs both.
    for wrap in &rotation.log_wraps {
        match wrap.scope {
            ScopeId::Org(_) => p.b.install_log_wrap(wrap).unwrap(),
            ScopeId::Budget(_) => {
                p.b.install_log_wrap_for_org(wrap, &p.org).unwrap();
            }
        }
    }
    // B now reads the current epoch on both logs.
    for scope in [p.org_scope, p.budget_scope] {
        let m = meta(3, scope);
        let sealed = p.a.seal_payload(&m, b"fresh").unwrap();
        assert!(p.b.open_payload(&m, &sealed).is_ok());
    }

    // A current-only invite to a fresh device grants no history: the
    // newcomer can read epoch 1 but not epoch 0.
    let newcomer_device = DeviceKeypair::generate().unwrap();
    let mut newcomer = KeyChain::new(DeviceKeypair::from_secret_bytes(
        *newcomer_device.to_secret_bytes(),
    ));
    let current_only =
        p.a.wrap_org_keys_to(&p.org, &newcomer_device.public(), Grant::CurrentEpoch)
            .unwrap();
    assert_eq!(current_only.len(), 1);
    newcomer.install_org_wrap(&current_only[0]).unwrap();
    for wrap in &rotation.log_wraps {
        match wrap.scope {
            ScopeId::Org(_) => newcomer.install_log_wrap(wrap).unwrap(),
            ScopeId::Budget(_) => {
                newcomer.install_log_wrap_for_org(wrap, &p.org).unwrap();
            }
        }
    }
    let m_new = meta(4, p.budget_scope);
    let new = p.a.seal_payload(&m_new, b"current").unwrap();
    assert!(newcomer.open_payload(&m_new, &new).is_ok());
    assert_eq!(
        newcomer.open_payload(&m_history, &history),
        Err(CryptoError::MissingEpoch {
            scope: p.budget_scope,
            epoch: 0,
            held: Some(1),
        }),
        "a current-only invite reads no history (the capture lane picks the grant)"
    );
}

fn b64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .unwrap()
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn render(mut json: serde_json::Value, field: &str, bytes: &[u8]) -> String {
    json[field] = serde_json::Value::String(b64_encode(bytes));
    serde_json::to_string(&json).unwrap()
}
