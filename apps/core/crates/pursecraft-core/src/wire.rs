//! Op wire format: the metadata/payload split and the single serialization
//! choke point (ADRs 0009, 0017).
//!
//! The server may only ever see [`OpMeta`]; [`OpPayload`] is opaque data it
//! stores but never interprets, encrypted in a later slice. All payload
//! serialization routes through [`encode_payload`] / [`decode_payload`] —
//! the one pair the E2EE layer will wrap.

use serde::{Deserialize, Serialize};

use crate::domain::{EntityKind, Field, Value};
use crate::hlc::Hlc;
use crate::ids::{BudgetId, DeviceId, EntityId, OpId, UserId};
use crate::ops::Op;

/// Server-visible op metadata (ADR 0009): everything the rendezvous may
/// read.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OpMeta {
    pub op_id: OpId,
    pub budget_id: BudgetId,
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub hlc: Hlc,
}

/// The opaque op payload (ADR 0009): encrypted in transit in a later slice;
/// here it is data the core serializes through one choke point.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OpPayload {
    pub entity_kind: EntityKind,
    pub entity_id: EntityId,
    pub field: Field,
    pub value: Value,
}

impl Op {
    /// Split into server-visible metadata and opaque payload (ADR 0017).
    pub fn into_parts(self) -> (OpMeta, OpPayload) {
        (
            OpMeta {
                op_id: self.op_id,
                budget_id: self.budget_id,
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
            budget_id: meta.budget_id,
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
    serde_json::to_string(payload)
}

/// The decode half of the choke point.
pub fn decode_payload(wire: &str) -> Result<OpPayload, serde_json::Error> {
    serde_json::from_str(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::{Date, Month};
    use crate::domain::{
        AccountField, AccountKind, BudgetField, CategoryField, CategoryGroupField, Cleared,
        EntityKind, MonthCategoryField, PayeeField, TransactionField,
    };
    use crate::hlc::Hlc;
    use crate::ids::TransactionId;
    use crate::money::Milliunits;
    use crate::testkit::v7;
    use uuid::Uuid;

    const MS: u64 = 1 << 40;

    fn op(kind: EntityKind, entity_rand: u64, field: Field, value: Value) -> Op {
        Op {
            op_id: crate::ids::OpId::new(v7(MS, entity_rand)).unwrap(),
            budget_id: crate::ids::BudgetId::new(v7(1, 1)).unwrap(),
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

    fn id(rand: u64) -> Value {
        Value::Id(EntityId::new(v7(MS, rand)).unwrap())
    }

    /// One op per (entity kind × field), covering every `Value` variant —
    /// including calendar edges, empty and non-ASCII text, and extreme
    /// milliunits.
    fn every_variant() -> Vec<Op> {
        vec![
            op(
                EntityKind::Budget,
                1,
                Field::Budget(BudgetField::Name),
                Value::Text("Home ₱".into()),
            ),
            op(
                EntityKind::Account,
                2,
                Field::Account(AccountField::Name),
                Value::Text(String::new()),
            ),
            op(
                EntityKind::Account,
                2,
                Field::Account(AccountField::Kind),
                Value::AccountKind(AccountKind::OtherLiability),
            ),
            op(
                EntityKind::CategoryGroup,
                3,
                Field::CategoryGroup(CategoryGroupField::Name),
                Value::Text("Bills".into()),
            ),
            op(
                EntityKind::Category,
                4,
                Field::Category(CategoryField::Name),
                Value::Text("Power".into()),
            ),
            op(
                EntityKind::Category,
                4,
                Field::Category(CategoryField::GroupId),
                id(3),
            ),
            op(
                EntityKind::Category,
                4,
                Field::Category(CategoryField::Note),
                Value::Text("note — em dash".into()),
            ),
            op(
                EntityKind::Payee,
                5,
                Field::Payee(PayeeField::Name),
                Value::Text("Meralco".into()),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::AccountId),
                id(2),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::Date),
                Value::Date(Date::new(2024, 2, 29).unwrap()),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(Milliunits::MIN),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::Amount),
                Value::Milliunits(Milliunits::MAX),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::PayeeId),
                id(5),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::CategoryId),
                id(4),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::Memo),
                Value::Text("groceries".into()),
            ),
            op(
                EntityKind::Transaction,
                6,
                Field::Transaction(TransactionField::Cleared),
                Value::Cleared(Cleared::Reconciled),
            ),
            op(
                EntityKind::MonthCategory,
                7,
                Field::MonthCategory(MonthCategoryField::Month),
                Value::Month(Month::new(2026, 1).unwrap()),
            ),
            op(
                EntityKind::MonthCategory,
                7,
                Field::MonthCategory(MonthCategoryField::CategoryId),
                id(4),
            ),
            op(
                EntityKind::MonthCategory,
                7,
                Field::MonthCategory(MonthCategoryField::Budgeted),
                Value::Milliunits(Milliunits::from_major(-45)),
            ),
            // The tombstone field rides the same wire.
            op(
                EntityKind::Transaction,
                6,
                Field::Deleted,
                Value::Bool(true),
            ),
        ]
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
        let amount = op(
            EntityKind::Transaction,
            6,
            Field::Transaction(TransactionField::Amount),
            Value::Milliunits(Milliunits::from_milli(-45_000)),
        );
        let wire = encode_payload(&amount.into_parts().1).unwrap();
        assert!(wire.contains(r#""value":{"Milliunits":-45000}}"#), "{wire}");
        // Dates and months are strict strings.
        let date = op(
            EntityKind::Transaction,
            6,
            Field::Transaction(TransactionField::Date),
            Value::Date(Date::new(2026, 10, 23).unwrap()),
        );
        let wire = encode_payload(&date.into_parts().1).unwrap();
        assert!(wire.contains(r#""Date":"2026-10-23""#), "{wire}");
        let month = op(
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
            for meta_key in ["op_id", "budget_id", "device_id", "user_id", "hlc"] {
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
    fn parts_split_covers_the_whole_op() {
        // from_parts ∘ into_parts is identity on a fully populated op; the
        // smoke check that every field of `Op` lives in exactly one part.
        let op = every_variant().pop().unwrap();
        let (meta, payload) = op.clone().into_parts();
        assert_eq!(Op::from_parts(meta, payload.clone()), op);
        let entity = TransactionId::new(v7(MS, 6)).unwrap();
        assert_eq!(payload.entity_id.as_uuid(), entity.as_uuid());
        assert_eq!(
            payload.value,
            Value::Bool(true),
            "the last variant op is the tombstone"
        );
    }
}
