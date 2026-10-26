//! PurseCraft's rendezvous sync relay (ADR 0024): the store-and-forward
//! delta server devices sync through — axum over per-scope durable logs
//! (pursecraft-core's string-native `OpaqueStore`, ADR 0018's format),
//! never merging and never opening a payload.
//!
//! The library surface is [`AppState`] + [`router`]: the binary in
//! `main.rs` and the integration tests drive the same router in-process.

pub mod auth;
pub mod http;
pub mod state;

pub use http::router;
pub use state::{AppState, READINESS_PROBE_TTL};
