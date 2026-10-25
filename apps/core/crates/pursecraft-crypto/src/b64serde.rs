//! Serde glue: byte fields as base64 strings, so wraps and envelopes
//! stay self-describing JSON like the rest of the wire (ADR 0017's
//! stance, extended by ADR 0022).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Deserializer, Serializer};

fn ser<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&B64.encode(bytes))
}

/// `[u8; 32]` as base64.
pub mod b32 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        ser(bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let decoded = B64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let len = decoded.len();
        decoded
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"32 bytes base64-encoded"))
    }
}

/// `[u8; 24]` as base64.
pub mod b24 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8; 24], s: S) -> Result<S::Ok, S::Error> {
        ser(bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        let text = String::deserialize(d)?;
        let decoded = B64
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let len = decoded.len();
        decoded
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(len, &"24 bytes base64-encoded"))
    }
}

/// `Vec<u8>` as base64.
pub mod bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        ser(bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        B64.decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
