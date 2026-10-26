//! Key records (ADR 0028): the versioned, opaque envelope that carries key
//! material through the rendezvous channel. The relay stores and forwards
//! these strings exactly as it stores payloads — it never parses one.
//!
//! Three kinds, all strict: a device's public key (what a wrap is addressed
//! to), an org-epoch-key wrap addressed to one device, and a log-key wrap
//! openable by any epoch-holding member. Unknown kinds, unknown fields, and
//! versions other than [`FORMAT_VERSION`] are refused loudly — a device that
//! silently skipped its own rotation wrap would keep sealing under a dead
//! epoch with no signal (ADR 0022's loud-stale-reader contract).

use serde::{Deserialize, Serialize};

use pursecraft_core::ids::{DeviceId, OrgId, ScopeId};

use crate::error::CryptoError;
use crate::keys::{DevicePublicKey, FORMAT_VERSION, WrappedLogKey, WrappedOrgKey};

/// One record on the key channel (ADR 0028).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyRecord {
    /// A device's public key — the address a wrap is sealed to.
    Device {
        device: DeviceId,
        public: DevicePublicKey,
    },
    /// An org epoch key, wrapped to one device.
    Org { to: DeviceId, wrap: WrappedOrgKey },
    /// A per-log data key, wrapped under its org's same-epoch key.
    Log { wrap: WrappedLogKey },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceWire {
    v: u16,
    kind: KindTag,
    device: DeviceId,
    public: DevicePublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgWire {
    v: u16,
    kind: KindTag,
    to: DeviceId,
    wrap: WrappedOrgKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogWire {
    v: u16,
    kind: KindTag,
    wrap: WrappedLogKey,
}

/// The `kind` tag each shape carries; a record's kind and its fields must
/// agree, because each shape refuses the other's fields outright.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum KindTag {
    Device,
    Org,
    Log,
}

impl KeyRecord {
    /// The wire string — what the channel carries verbatim.
    pub fn to_wire(&self) -> String {
        // Every field is a number, an id newtype, a base64 string, or a
        // nested record; none of them can fail to serialize.
        match self {
            Self::Device { device, public } => serde_json::to_string(&DeviceWire {
                v: FORMAT_VERSION,
                kind: KindTag::Device,
                device: *device,
                public: public.clone(),
            }),
            Self::Org { to, wrap } => serde_json::to_string(&OrgWire {
                v: FORMAT_VERSION,
                kind: KindTag::Org,
                to: *to,
                wrap: wrap.clone(),
            }),
            Self::Log { wrap } => serde_json::to_string(&LogWire {
                v: FORMAT_VERSION,
                kind: KindTag::Log,
                wrap: wrap.clone(),
            }),
        }
        .expect("a key record's fields all serialize")
    }

    /// Parse one wire string. Anything that is not a v1 record of a known
    /// kind — including a payload envelope or a plaintext payload — is
    /// [`CryptoError::BadRecord`], never a guess.
    pub fn parse(wire: &str) -> Result<Self, CryptoError> {
        let value: serde_json::Value =
            serde_json::from_str(wire).map_err(|e| CryptoError::BadRecord(e.to_string()))?;
        let version = value
            .get("v")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| CryptoError::BadRecord("missing version".into()))?;
        let version = u16::try_from(version)
            .map_err(|_| CryptoError::BadRecord(format!("version {version} is not a u16")))?;
        if version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        match value.get("kind").and_then(serde_json::Value::as_str) {
            Some("device") => serde_json::from_value::<DeviceWire>(value)
                .map(|w| Self::Device {
                    device: w.device,
                    public: w.public,
                })
                .map_err(|e| CryptoError::BadRecord(e.to_string())),
            Some("org") => serde_json::from_value::<OrgWire>(value)
                .map(|w| Self::Org {
                    to: w.to,
                    wrap: w.wrap,
                })
                .map_err(|e| CryptoError::BadRecord(e.to_string())),
            Some("log") => serde_json::from_value::<LogWire>(value)
                .map(|w| Self::Log { wrap: w.wrap })
                .map_err(|e| CryptoError::BadRecord(e.to_string())),
            Some(other) => Err(CryptoError::BadRecord(format!("unknown kind {other:?}"))),
            None => Err(CryptoError::BadRecord("missing kind".into())),
        }
    }

    /// The org this record belongs to: the org itself for an org-key wrap,
    /// the owning org for an org-log key, and — deliberately — `None` for a
    /// budget log's wrap, because a budget log does not name its org
    /// ([ADR 0021]); the caller that holds the world knows it.
    pub fn org(&self) -> Option<OrgId> {
        match self {
            Self::Device { .. } => None,
            Self::Org { wrap, .. } => Some(wrap.org),
            Self::Log { wrap } => match wrap.scope {
                ScopeId::Org(org) => Some(org),
                ScopeId::Budget(_) => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pursecraft_core::ids::BudgetId;
    use uuid::Uuid;

    use crate::keys::{DataKey, DeviceKeypair, wrap_log_key, wrap_org_key};

    /// Deterministic UUIDv7, same construction as the core testkit.
    fn v7(ms: u64, rand: u64) -> Uuid {
        let rand = (rand & 0x3fff_ffff_ffff_ffff) as u128;
        Uuid::from_u128(((ms as u128) << 80) | (7u128 << 76) | (2u128 << 62) | rand)
    }

    fn device() -> DeviceId {
        DeviceId::new(v7(1 << 40, 1)).unwrap()
    }

    fn org() -> OrgId {
        OrgId::new(v7(1 << 40, 2)).unwrap()
    }

    /// Every kind round-trips through the wire string, and each carries the
    /// organisation it belongs to where one is derivable.
    #[test]
    fn every_record_kind_round_trips() {
        let keypair = DeviceKeypair::from_secret_bytes([7; 32]);
        let epoch_key = DataKey::new([3; 32]);

        let device_record = KeyRecord::Device {
            device: device(),
            public: keypair.public(),
        };
        let org_wrap = KeyRecord::Org {
            to: device(),
            wrap: wrap_org_key(&keypair.public(), &org(), 0, &epoch_key).unwrap(),
        };
        let log_wrap = KeyRecord::Log {
            wrap: wrap_log_key(
                &epoch_key,
                &ScopeId::Budget(BudgetId::new(v7(1 << 40, 3)).unwrap()),
                0,
                &DataKey::new([4; 32]),
            )
            .unwrap(),
        };

        for record in [device_record, org_wrap, log_wrap] {
            let wire = record.to_wire();
            assert_eq!(KeyRecord::parse(&wire).unwrap(), record, "{wire}");
        }
        assert_eq!(
            KeyRecord::parse(
                &KeyRecord::Org {
                    to: device(),
                    wrap: wrap_org_key(&keypair.public(), &org(), 0, &DataKey::new([3; 32]))
                        .unwrap(),
                }
                .to_wire()
            )
            .unwrap()
            .org(),
            Some(org())
        );
    }

    /// A device record names no org, an org-log record names its own, and a
    /// budget-log record names none (ADR 0021) — the caller supplies it.
    #[test]
    fn a_budget_log_record_has_no_derivable_org() {
        let keypair = DeviceKeypair::from_secret_bytes([7; 32]);
        assert_eq!(
            KeyRecord::Device {
                device: device(),
                public: keypair.public(),
            }
            .org(),
            None
        );
        assert_eq!(
            KeyRecord::Log {
                wrap: wrap_log_key(
                    &DataKey::new([3; 32]),
                    &ScopeId::Org(org()),
                    0,
                    &DataKey::new([4; 32]),
                )
                .unwrap(),
            }
            .org(),
            Some(org())
        );

        let record = KeyRecord::Log {
            wrap: wrap_log_key(
                &DataKey::new([3; 32]),
                &ScopeId::Budget(BudgetId::new(v7(1 << 40, 3)).unwrap()),
                0,
                &DataKey::new([4; 32]),
            )
            .unwrap(),
        };
        assert_eq!(record.org(), None);
    }

    /// Strictness: unknown kinds, unknown fields, wrong versions, and
    /// non-records are all refused — never skipped, never guessed (a device
    /// that ignored its own rotation wrap would seal under a dead epoch).
    #[test]
    fn malformed_and_foreign_records_are_refused() {
        assert!(matches!(
            KeyRecord::parse(r#"{"v":1,"kind":"epoch","wrap":{}}"#),
            Err(CryptoError::BadRecord(_))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"v":1,"kind":"device"}"#),
            Err(CryptoError::BadRecord(_))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"v":1,"kind":"log","wrap":{},"extra":1}"#),
            Err(CryptoError::BadRecord(_))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"v":2,"kind":"log","wrap":{}}"#),
            Err(CryptoError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"kind":"log"}"#),
            Err(CryptoError::BadRecord(_))
        ));
        // A payload envelope and a plaintext payload are neither records.
        assert!(matches!(
            KeyRecord::parse("not json"),
            Err(CryptoError::BadRecord(_))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"v":1,"e":0,"n":"","c":""}"#),
            Err(CryptoError::BadRecord(_))
        ));
        assert!(matches!(
            KeyRecord::parse(r#"{"entity_kind":"Payee"}"#),
            Err(CryptoError::BadRecord(_))
        ));
    }
}
