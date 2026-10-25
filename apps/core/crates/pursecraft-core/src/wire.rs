//! Op wire format: the metadata/payload split and the single serialization
//! choke point (ADRs 0009, 0017, 0020, 0022).
//!
//! The server may only ever see [`OpMeta`]; [`OpPayload`] is opaque data it
//! stores but never interprets, encrypted under the E2EE layer (ADR 0022).
//! All payload serialization routes through [`encode_payload`] /
//! [`decode_payload`] — the one pair the E2EE layer wraps — and that layer
//! plugs in through [`PayloadCipher`], implemented in `pursecraft-crypto`
//! (this crate stays crypto-free; the dependency points the other way).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::domain::{EntityKind, Field, Value};
use crate::hlc::Hlc;
use crate::ids::{DeviceId, EntityId, OpId, ScopeId, UserId};
use crate::ops::Op;

/// Server-visible op metadata (ADR 0009): everything the rendezvous may
/// read — including the typed log scope the future server routes
/// authorization on (ADR 0021).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OpMeta {
    pub op_id: OpId,
    pub scope: ScopeId,
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub hlc: Hlc,
}

/// The opaque op payload (ADR 0009): encrypted in transit in a later
/// layer; here it is data the core serializes through one choke point.
/// Deliberately NOT `Serialize`/`Deserialize` in public form —
/// [`encode_payload`] / [`decode_payload`] are the only serialization
/// surface, so the future E2EE layer cannot be bypassed around (ADR 0017).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpPayload {
    pub entity_kind: EntityKind,
    pub entity_id: EntityId,
    pub field: Field,
    pub value: Value,
}

/// The private wire shape of [`OpPayload`] — serde lives here, one step
/// inside the choke point.
#[derive(Serialize, Deserialize)]
struct PayloadWire {
    entity_kind: EntityKind,
    entity_id: EntityId,
    field: Field,
    value: Value,
}

impl From<&OpPayload> for PayloadWire {
    fn from(payload: &OpPayload) -> Self {
        Self {
            entity_kind: payload.entity_kind,
            entity_id: payload.entity_id,
            field: payload.field,
            value: payload.value.clone(),
        }
    }
}

impl From<PayloadWire> for OpPayload {
    fn from(wire: PayloadWire) -> Self {
        Self {
            entity_kind: wire.entity_kind,
            entity_id: wire.entity_id,
            field: wire.field,
            value: wire.value,
        }
    }
}

impl Op {
    /// Split into server-visible metadata and opaque payload (ADR 0017).
    pub fn into_parts(self) -> (OpMeta, OpPayload) {
        (
            OpMeta {
                op_id: self.op_id,
                scope: self.scope,
                device_id: self.device_id,
                user_id: self.user_id,
                hlc: self.hlc,
            },
            OpPayload {
                entity_kind: self.entity_kind,
                entity_id: self.entity_id,
                field: self.field,
                value: self.value,
            },
        )
    }

    /// Rejoin the parts; the inverse of [`Op::into_parts`].
    pub fn from_parts(meta: OpMeta, payload: OpPayload) -> Self {
        Self {
            op_id: meta.op_id,
            scope: meta.scope,
            device_id: meta.device_id,
            user_id: meta.user_id,
            hlc: meta.hlc,
            entity_kind: payload.entity_kind,
            entity_id: payload.entity_id,
            field: payload.field,
            value: payload.value,
        }
    }
}

/// The single payload serialization choke point (ADRs 0009, 0017): encode
/// ciphertext here when the E2EE layer lands; change format here if it ever
/// changes.
pub fn encode_payload(payload: &OpPayload) -> Result<String, serde_json::Error> {
    serde_json::to_string(&PayloadWire::from(payload))
}

/// The decode half of the choke point.
pub fn decode_payload(wire: &str) -> Result<OpPayload, serde_json::Error> {
    serde_json::from_str::<PayloadWire>(wire).map(OpPayload::from)
}

/// A cipher failure surfaced through a seam ([ADR 0022]). Boxed: the
/// crypto crate owns the causes (authentication, stale epochs, envelope
/// shape); core only carries it loudly — never repairs over it, never
/// mislabels it file corruption.
pub type CipherError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The E2EE seam (ADR 0022): wraps the payload choke point. `seal`
/// receives the plaintext payload string [`encode_payload`] produced plus
/// the op's metadata (binding material); `open` receives the sealed
/// envelope string plus the metadata it claims to belong to. Both are
/// fallible — a refusal is loud. [`PlainCipher`] is the identity
/// implementation for the no-E2EE self-host mode (ADR 0009); envelope
/// shapes are disjoint from plaintext by construction, so mode confusion
/// fails loudly in both directions.
pub trait PayloadCipher: fmt::Debug {
    /// Wrap the plaintext payload string into an envelope string.
    fn seal(&self, meta: &OpMeta, plaintext: String) -> Result<String, CipherError>;
    /// Unwrap an envelope string back to the plaintext payload string.
    fn open(&self, meta: &OpMeta, sealed: &str) -> Result<String, CipherError>;
}

/// The identity [`PayloadCipher`] — payloads travel as the plaintext
/// choke-point string (ADR 0009's optional-for-self-host mode). Not a
/// downgrade hole: handed an envelope string, `open` passes it through
/// unchanged and [`decode_payload`] rejects it (the shapes are disjoint,
/// ADR 0022).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlainCipher;

impl PayloadCipher for PlainCipher {
    fn seal(&self, _meta: &OpMeta, plaintext: String) -> Result<String, CipherError> {
        Ok(plaintext)
    }

    fn open(&self, _meta: &OpMeta, sealed: &str) -> Result<String, CipherError> {
        Ok(sealed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::{Date, Month};
    use crate::domain::{EntityKind, Field, MonthCategoryField, TransactionField, Value};
    use crate::hlc::Hlc;
    use crate::ids::{ScopeId, TransactionId};
    use crate::money::Milliunits;
    use crate::testkit::conv::every_variant;
    use crate::testkit::v7;
    use uuid::Uuid;

    const MS: u64 = 1 << 40;

    fn op(scope: ScopeId, kind: EntityKind, entity_rand: u64, field: Field, value: Value) -> Op {
        Op {
            op_id: crate::ids::OpId::new(v7(MS, entity_rand)).unwrap(),
            scope,
            device_id: DeviceId::new(Uuid::nil()).unwrap(),
            user_id: UserId::new(Uuid::max()).unwrap(),
            entity_kind: kind,
            entity_id: EntityId::new(v7(MS, entity_rand)).unwrap(),
            field,
            value,
            hlc: Hlc {
                physical_ms: MS + entity_rand,
                logical: 0,
            },
        }
    }

    fn budget_op(kind: EntityKind, entity_rand: u64, field: Field, value: Value) -> Op {
        op(
            ScopeId::Budget(crate::ids::BudgetId::new(v7(1, 1)).unwrap()),
            kind,
            entity_rand,
            field,
            value,
        )
    }

    #[test]
    fn ops_round_trip_through_the_wire_split() {
        for op in every_variant() {
            let (meta, payload) = op.clone().into_parts();
            let meta_wire = serde_json::to_string(&meta).unwrap();
            let payload_wire = encode_payload(&payload).unwrap();
            let meta_back: OpMeta = serde_json::from_str(&meta_wire).unwrap();
            let payload_back = decode_payload(&payload_wire).unwrap();
            assert_eq!(Op::from_parts(meta_back, payload_back), op);
        }
    }

    #[test]
    fn payload_encoding_is_what_the_wire_says_it_is() {
        // Money travels as bare integer milliunits (ADR 0006): no float, no
        // decimal string.
        let amount = budget_op(
            EntityKind::Transaction,
            6,
            Field::Transaction(TransactionField::Amount),
            Value::Milliunits(Milliunits::from_milli(-45_000)),
        );
        let wire = encode_payload(&amount.into_parts().1).unwrap();
        assert!(wire.contains(r#""value":{"Milliunits":-45000}}"#), "{wire}");
        // Dates and months are strict strings.
        let date = budget_op(
            EntityKind::Transaction,
            6,
            Field::Transaction(TransactionField::Date),
            Value::Date(Date::new(2026, 10, 23).unwrap()),
        );
        let wire = encode_payload(&date.into_parts().1).unwrap();
        assert!(wire.contains(r#""Date":"2026-10-23""#), "{wire}");
        let month = budget_op(
            EntityKind::MonthCategory,
            7,
            Field::MonthCategory(MonthCategoryField::Month),
            Value::Month(Month::new(2026, 10).unwrap()),
        );
        let wire = encode_payload(&month.into_parts().1).unwrap();
        assert!(wire.contains(r#""Month":"2026-10""#), "{wire}");
    }

    #[test]
    fn meta_hides_the_payload_and_payload_hides_the_metadata() {
        for op in every_variant() {
            let (meta, payload) = op.into_parts();
            let meta_wire = serde_json::to_string(&meta).unwrap();
            let payload_wire = encode_payload(&payload).unwrap();
            for secret in ["entity_kind", "entity_id", "\"field\"", "\"value\""] {
                assert!(!meta_wire.contains(secret), "{secret} leaked into meta");
            }
            for meta_key in ["op_id", "scope", "device_id", "user_id", "hlc"] {
                assert!(
                    !payload_wire.contains(meta_key),
                    "{meta_key} leaked into the payload"
                );
            }
        }
    }

    #[test]
    fn malformed_wire_is_rejected_at_the_boundary() {
        // Non-v7 entity id.
        let bad_id = r#"{"entity_kind":"Transaction","entity_id":"00000000-0000-0000-0000-000000000000","field":{"Transaction":"Memo"},"value":{"Text":"x"}}"#;
        assert!(decode_payload(bad_id).is_err());
        // Impossible calendar date and loose month.
        let bad_date = r#"{"entity_kind":"Transaction","entity_id":"018f0000-0000-7000-8000-000000000006","field":{"Transaction":"Date"},"value":{"Date":"2026-02-30"}}"#;
        assert!(decode_payload(bad_date).is_err());
        let bad_month = r#"{"entity_kind":"MonthCategory","entity_id":"018f0000-0000-7000-8000-000000000007","field":{"MonthCategory":"Month"},"value":{"Month":"2026-1"}}"#;
        assert!(decode_payload(bad_month).is_err());
        // Money as a float or string is not money on this wire.
        let float_money = r#"{"entity_kind":"Transaction","entity_id":"018f0000-0000-7000-8000-000000000006","field":{"Transaction":"Amount"},"value":{"Milliunits":-45.5}}"#;
        assert!(decode_payload(float_money).is_err());
        let string_money = r#"{"entity_kind":"Transaction","entity_id":"018f0000-0000-7000-8000-000000000006","field":{"Transaction":"Amount"},"value":{"Milliunits":"-45000"}}"#;
        assert!(decode_payload(string_money).is_err());
        // Garbage is garbage.
        assert!(decode_payload("not json").is_err());
    }

    #[test]
    fn hostile_hlc_stamps_are_rejected_before_they_can_exhaust_the_clock() {
        // One wire op with logical == u32::MAX would panic `Hlc::merge` in
        // the receive path; physical_ms past i64::MAX is not a wall clock
        // and lets later ticks run off the u64 cliff. Both are rejected at
        // decode (ADR 0017).
        let meta = budget_op(
            EntityKind::Transaction,
            6,
            Field::Deleted,
            Value::Bool(true),
        )
        .into_parts()
        .0;
        for bad in [
            r#"{"physical_ms":0,"logical":4294967295}"#,
            r#"{"physical_ms":18446744073709551615,"logical":0}"#,
            r#"{"physical_ms":9223372036854775808,"logical":0}"#,
        ] {
            let mut hostile = serde_json::to_value(&meta).unwrap();
            hostile["hlc"] = serde_json::from_str(bad).unwrap();
            assert!(
                serde_json::from_value::<OpMeta>(hostile).is_err(),
                "accepted hostile hlc {bad}"
            );
        }
        // The boundary values just inside the rule are fine — and
        // delivering such an op TWICE (at-least-once, the reviewer's
        // repro for receive-path exhaustion) plus ticks cannot panic and
        // never mints an undecodable stamp.
        let mut extreme = serde_json::to_value(&meta).unwrap();
        extreme["hlc"] =
            serde_json::from_str(r#"{"physical_ms":4611686018427387904,"logical":4294967294}"#)
                .unwrap();
        let meta: OpMeta = serde_json::from_value(extreme).unwrap();
        let payload = OpPayload {
            entity_kind: EntityKind::Transaction,
            entity_id: EntityId::new(v7(MS, 6)).unwrap(),
            field: Field::Deleted,
            value: Value::Bool(true),
        };
        let echo = crate::sync::SequencedOp {
            seq: 1,
            op: Op::from_parts(meta.clone(), payload),
        };
        let mut session = crate::sync::SyncSession::new();
        for _ in 0..2 {
            session.apply_delta([&echo]).unwrap();
        }
        let mut clock = session.clock();
        clock.tick();
        clock.tick();
        assert_ne!(clock.logical, u32::MAX);
        let wire_clock = serde_json::to_string(&clock).unwrap();
        assert!(
            serde_json::from_str::<crate::hlc::Hlc>(&wire_clock).is_ok(),
            "a sane-extreme receive must mint decodable stamps"
        );

        // A forged stamp at the top physical bound cannot panic — but its
        // single-millisecond borrow leaves the victim past the wire
        // bound, so its minted stamps are rejected LOUDLY by every
        // peer's decoder. Poison is contained and visible; forging it
        // requires a key-holding member (ADR 0017 posture — see the ADR
        // for the full ratchet reachability).
        let mut forged = serde_json::to_value(&meta).unwrap();
        forged["hlc"] =
            serde_json::from_str(r#"{"physical_ms":9223372036854775807,"logical":4294967294}"#)
                .unwrap();
        let forged: OpMeta = serde_json::from_value(forged).unwrap();
        let mut poisoned = crate::sync::SyncSession::new();
        poisoned
            .apply_delta(&[crate::sync::SequencedOp {
                seq: 1,
                op: Op::from_parts(
                    forged,
                    OpPayload {
                        entity_kind: EntityKind::Transaction,
                        entity_id: EntityId::new(v7(MS, 6)).unwrap(),
                        field: Field::Deleted,
                        value: Value::Bool(true),
                    },
                ),
            }])
            .unwrap();
        let mut clock = poisoned.clock();
        clock.tick();
        let wire_clock = serde_json::to_string(&clock).unwrap();
        assert!(
            serde_json::from_str::<crate::hlc::Hlc>(&wire_clock).is_err(),
            "a poisoned clock's stamps are rejected loudly, never silently accepted"
        );
    }

    #[test]
    fn dates_and_months_decode_from_any_serde_source() {
        // String-based deserialization must work for from_value and
        // from_reader too, not only from_str (ADR 0017: the choke point is
        // transport-ready).
        let payload = OpPayload {
            entity_kind: EntityKind::Transaction,
            entity_id: EntityId::new(v7(MS, 6)).unwrap(),
            field: Field::Transaction(TransactionField::Date),
            value: Value::Date(Date::new(2026, 10, 23).unwrap()),
        };
        let wire = serde_json::to_value(PayloadWire::from(&payload)).unwrap();
        let back: PayloadWire = serde_json::from_value(wire).unwrap();
        assert_eq!(OpPayload::from(back), payload);
    }

    #[test]
    fn parts_assign_every_op_field_to_exactly_one_side() {
        let op = every_variant().pop().unwrap();
        let (meta, payload) = op.clone().into_parts();
        // The five metadata fields live in OpMeta and only there.
        assert_eq!(meta.op_id, op.op_id);
        assert_eq!(meta.scope, op.scope);
        assert_eq!(meta.device_id, op.device_id);
        assert_eq!(meta.user_id, op.user_id);
        assert_eq!(meta.hlc, op.hlc);
        // The four payload fields live in OpPayload and only there.
        assert_eq!(payload.entity_kind, op.entity_kind);
        assert_eq!(payload.entity_id, op.entity_id);
        assert_eq!(payload.field, op.field);
        assert_eq!(payload.value, op.value);
        // Rejoining rebuilds the op bit for bit.
        assert_eq!(Op::from_parts(meta, payload), op);
        let _ = TransactionId::new(v7(MS, 6)).unwrap();
    }
}
