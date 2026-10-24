//! UUID id newtypes (ADRs 0007, 0008, 0020) and the typed log scope.
//!
//! Entity and op ids are UUIDv7: time-ordered, so lexicographic order is
//! creation order within clock skew (relied on by referential resolution,
//! ADR 0016). Device and user ids are opaque UUIDs from auth — any version.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The id is not UUIDv7 where UUIDv7 is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdVersionError;

impl fmt::Display for IdVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("id is not UUIDv7")
    }
}

impl std::error::Error for IdVersionError {}

macro_rules! id_newtype {
    ($name:ident, v7) => {
        id_newtype!($name);

        impl $name {
            /// Accepts only UUIDv7 (ADR 0007).
            pub fn new(uuid: Uuid) -> Result<Self, IdVersionError> {
                if uuid.get_version_num() == 7 {
                    Ok(Self(uuid))
                } else {
                    Err(IdVersionError)
                }
            }
        }
    };
    ($name:ident, any_version) => {
        id_newtype!($name);

        impl $name {
            /// Accepts any UUID version (auth-issued identities).
            pub fn new(uuid: Uuid) -> Result<Self, IdVersionError> {
                Ok(Self(uuid))
            }
        }
    };
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Unvalidated rewrap of an id already checked at its boundary.
            /// Generated for every id type; not every type gets rewrapped.
            #[allow(dead_code)]
            pub(crate) const fn from_raw(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.0.hyphenated().to_string())
                    .finish()
            }
        }

        // Wire form: UUID string, deserialized through the validating
        // `new` so the id invariants hold on both sides of the boundary
        // (ADR 0017).
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let uuid = Uuid::deserialize(deserializer)?;
                Self::new(uuid).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_newtype!(EntityId, v7);
id_newtype!(OpId, v7);
id_newtype!(BudgetId, v7);
id_newtype!(OrgId, v7);
id_newtype!(AccountId, v7);
id_newtype!(CategoryGroupId, v7);
id_newtype!(CategoryId, v7);
id_newtype!(PayeeId, v7);
id_newtype!(TransactionId, v7);
id_newtype!(MonthCategoryId, v7);
id_newtype!(DeviceId, any_version);
id_newtype!(UserId, any_version);

/// Which log an op belongs to (ADR 0020): an organization's or a budget's.
/// Wire form is externally tagged (`{"Org": "…"} / {"Budget": "…"}`) — the
/// scope is metadata the server routes on, so its kind must be legible
/// without touching the encrypted payload.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum ScopeId {
    Org(OrgId),
    Budget(BudgetId),
}

impl ScopeId {
    /// The org this scope belongs to: the org itself for org scope, `None`
    /// for budget scope (a budget log does not name its org — ADR 0020).
    pub fn org(self) -> Option<OrgId> {
        match self {
            Self::Org(org) => Some(org),
            Self::Budget(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::v7;

    #[test]
    fn v7_ids_accepted() {
        assert!(EntityId::new(v7(0, 0)).is_ok());
        assert!(OpId::new(v7(1_700_000_000_000, 42)).is_ok());
        assert!(TransactionId::new(v7(u64::MAX, u64::MAX)).is_ok());
    }

    #[test]
    fn non_v7_entity_and_op_ids_rejected() {
        assert_eq!(EntityId::new(Uuid::nil()), Err(IdVersionError));
        assert_eq!(OpId::new(Uuid::max()), Err(IdVersionError));
        // UUIDv4 (random) has version nibble 4.
        let v4 = Uuid::from_u128(0x0123_4567_89ab_cdef_4123_4567_89ab_cdef);
        assert_eq!(EntityId::new(v4), Err(IdVersionError));
    }

    #[test]
    fn device_and_user_ids_accept_any_version() {
        assert!(DeviceId::new(Uuid::nil()).is_ok());
        assert!(UserId::new(Uuid::max()).is_ok());
        assert!(DeviceId::new(v7(5, 5)).is_ok());
    }

    #[test]
    fn org_ids_are_v7_and_the_scope_wire_form_is_tagged() {
        assert!(OrgId::new(v7(3, 4)).is_ok());
        assert_eq!(OrgId::new(Uuid::nil()), Err(IdVersionError));
        let org = ScopeId::Org(OrgId::new(v7(3, 4)).unwrap());
        let budget = ScopeId::Budget(BudgetId::new(v7(5, 6)).unwrap());
        for (scope, wire) in [(org, r#"{"Org":"0…"}"#), (budget, r#"{"Budget":"0…"}"#)] {
            let encoded = serde_json::to_string(&scope).unwrap();
            let decoded: ScopeId = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, scope, "round trip for {wire:?}");
        }
        assert!(
            serde_json::to_string(&org)
                .unwrap()
                .starts_with(r#"{"Org":"#)
        );
        assert!(
            serde_json::to_string(&budget)
                .unwrap()
                .starts_with(r#"{"Budget":"#)
        );
        assert_eq!(org.org(), Some(OrgId::new(v7(3, 4)).unwrap()));
        assert_eq!(budget.org(), None);
    }

    #[test]
    fn v7_ordering_is_chronological_by_timestamp() {
        let early = CategoryId::new(v7(1_000, 1)).unwrap();
        let late = CategoryId::new(v7(2_000, 0)).unwrap();
        let same_ms_low = CategoryId::new(v7(1_000, 1)).unwrap();
        assert!(early < late);
        assert_eq!(early, same_ms_low);
    }
}
