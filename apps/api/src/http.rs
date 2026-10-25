//! The relay's HTTP surface (ADR 0024): axum routes, versioned JSON
//! envelopes, and the push/pull delta protocol.
//!
//! The relay sees exactly [`OpMeta`] plus the payload as an opaque string
//! (ADRs 0009, 0017): it validates the metadata it must route on, stores
//! and forwards the payload verbatim, and never merges — deltas apply
//! client-side (ADR 0017).

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pursecraft_core::ids::{BudgetId, DeviceId, OpId, OrgId, ScopeId};
use pursecraft_core::store::StoreError;
use pursecraft_core::sync::LogError;
use pursecraft_core::wire::OpMeta;

use crate::auth::AuthError;
use crate::state::{AppState, StateError};

/// The envelope version every body carries (ADR 0024); unknown versions
/// are refused, never guessed.
pub const ENVELOPE_VERSION: u16 = 1;
/// Request body ceiling — the basic abuse bound (ADR 0024 defers real
/// rate limiting).
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Ops per push (ADR 0024: basic caps; a capture session is dozens).
pub const MAX_BATCH: usize = 1000;
/// Payload string ceiling — opaque bytes, but not unbounded ones.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Pull page size: default and ceiling.
pub const DEFAULT_PULL_LIMIT: usize = 1000;
pub const MAX_PULL_LIMIT: usize = 10_000;

/// The relay's error shape: `{"error": code, "message": …}` with the
/// status that matches. Internal failures never leak their details.
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", message)
    }

    fn internal(source: impl std::fmt::Display) -> Self {
        // Loud server-side, generic client-side: internals are not API.
        eprintln!("pursecraft-api: internal error: {source}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal storage failure",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.code,
            "message": self.message,
        }));
        (self.status, body).into_response()
    }
}

impl From<StateError> for ApiError {
    fn from(e: StateError) -> Self {
        Self::internal(e)
    }
}

/// The `{kind}/{id}` route pair as a typed scope — the scope is the one
/// thing the relay routes on (ADR 0021).
fn parse_scope(kind: &str, id: &str) -> Result<ScopeId, ApiError> {
    let uuid = Uuid::parse_str(id)
        .map_err(|e| ApiError::bad_request(format!("scope id is not a uuid: {e}")))?;
    match kind {
        "orgs" => {
            Ok(ScopeId::Org(OrgId::new(uuid).map_err(|e| {
                ApiError::bad_request(format!("org id: {e}"))
            })?))
        }
        "budgets" => {
            Ok(ScopeId::Budget(BudgetId::new(uuid).map_err(|e| {
                ApiError::bad_request(format!("budget id: {e}"))
            })?))
        }
        other => Err(ApiError::bad_request(format!(
            "unknown scope kind {other:?} (want \"orgs\" or \"budgets\")"
        ))),
    }
}

/// The bearer token from the `Authorization` header (ADR 0013: header
/// tokens, no cookies).
fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("Authorization must be \"Bearer <token>\""))?;
    Ok(token.to_owned())
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<DeviceId, ApiError> {
    let token = bearer(headers)?;
    state
        .auth
        .lock()
        .expect("auth lock")
        .authenticate(&token)
        .ok_or_else(|| ApiError::unauthorized("unknown device token"))
}

fn require_grant(state: &AppState, scope: ScopeId, device: DeviceId) -> Result<(), ApiError> {
    if state
        .auth
        .lock()
        .expect("auth lock")
        .is_granted(scope, device)
    {
        Ok(())
    } else {
        Err(ApiError::forbidden("device is not granted this scope"))
    }
}

fn check_version(v: u16) -> Result<(), ApiError> {
    if v == ENVELOPE_VERSION {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "unsupported envelope version {v} (server speaks {ENVELOPE_VERSION})"
        )))
    }
}

fn json_body<T: for<'de> Deserialize<'de>>(
    body: Result<Json<T>, JsonRejection>,
) -> Result<T, ApiError> {
    body.map(|Json(value)| value)
        .map_err(|e| ApiError::bad_request(format!("body does not decode: {e}")))
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::WrongEnrollmentSecret => ApiError::forbidden(e.to_string()),
            AuthError::NotGranted => ApiError::forbidden(e.to_string()),
            AuthError::ScopeExists => ApiError::conflict(e.to_string()),
            AuthError::InvalidPairingCode => ApiError::forbidden(e.to_string()),
            AuthError::PairingCodeExpired => ApiError::forbidden(e.to_string()),
            AuthError::Io(inner) => ApiError::internal(inner),
        }
    }
}

// ---------------------------------------------------------------------
// Envelopes (ADR 0024): every body carries v; the payload is a string
// the relay never opens.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct EnrollRequest {
    v: u16,
    enrollment_secret: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    v: u16,
    device_id: DeviceId,
    token: String,
}

#[derive(Serialize)]
struct CreateScopeResponse {
    v: u16,
    scope: ScopeId,
    pairing_code: String,
    expires_at_unix: u64,
}

#[derive(Deserialize)]
struct PairRequest {
    v: u16,
    code: String,
}

#[derive(Serialize)]
struct PairResponse {
    v: u16,
    scope: ScopeId,
    device_id: DeviceId,
}

#[derive(Deserialize)]
struct PushRequest {
    v: u16,
    ops: Vec<PushOp>,
}

#[derive(Deserialize)]
struct PushOp {
    meta: OpMeta,
    payload: String,
}

#[derive(Serialize)]
struct PushResponse {
    v: u16,
    results: Vec<PushResult>,
    tip: u64,
}

#[derive(Serialize)]
struct PushResult {
    op_id: OpId,
    seq: u64,
    stored: bool,
}

/// Parse an optional u64 query parameter inside the error envelope —
/// every relay error answers in the same shape (ADR 0024).
fn query_u64(
    params: &std::collections::HashMap<String, String>,
    key: &str,
) -> Result<Option<u64>, ApiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => raw
            .parse()
            .map(Some)
            .map_err(|e| ApiError::bad_request(format!("query parameter {key}: {e}"))),
    }
}

#[derive(Serialize)]
struct PullOp {
    seq: u64,
    meta: OpMeta,
    payload: String,
}

#[derive(Serialize)]
struct PullResponse {
    v: u16,
    ops: Vec<PullOp>,
    tip: u64,
    has_more: bool,
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

async fn create_device(
    State(state): State<Arc<AppState>>,
    body: Result<Json<EnrollRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let req = json_body(body)?;
    check_version(req.v)?;
    let (device_id, token) = state
        .auth
        .lock()
        .expect("auth lock")
        .enroll(&req.enrollment_secret)
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            v: ENVELOPE_VERSION,
            device_id,
            token,
        }),
    ))
}

async fn create_scope(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let device = authenticate(&state, &headers)?;
    let scope = parse_scope(&kind, &id)?;
    // A log file with no grants (operator-restored partial data) is just
    // as taken as a granted one.
    if state.log_exists(scope) {
        return Err(ApiError::conflict("scope already exists"));
    }
    let (pairing_code, expires_at_unix) = state
        .auth
        .lock()
        .expect("auth lock")
        .create_scope(scope, device)
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateScopeResponse {
            v: ENVELOPE_VERSION,
            scope,
            pairing_code,
            expires_at_unix,
        }),
    ))
}

async fn mint_pairing_code(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let device = authenticate(&state, &headers)?;
    let scope = parse_scope(&kind, &id)?;
    let (pairing_code, expires_at_unix) = state
        .auth
        .lock()
        .expect("auth lock")
        .mint_pairing_code(scope, device)
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateScopeResponse {
            v: ENVELOPE_VERSION,
            scope,
            pairing_code,
            expires_at_unix,
        }),
    ))
}

async fn pair_device(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Json<PairRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let device = authenticate(&state, &headers)?;
    let scope = parse_scope(&kind, &id)?;
    let req = json_body(body)?;
    check_version(req.v)?;
    state
        .auth
        .lock()
        .expect("auth lock")
        .redeem_pairing_code(scope, &req.code, device)
        .map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(PairResponse {
            v: ENVELOPE_VERSION,
            scope,
            device_id: device,
        }),
    ))
}

async fn push_ops(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Json<PushRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let device = authenticate(&state, &headers)?;
    let scope = parse_scope(&kind, &id)?;
    require_grant(&state, scope, device)?;
    let req = json_body(body)?;
    check_version(req.v)?;
    if req.ops.len() > MAX_BATCH {
        return Err(ApiError::too_large(format!(
            "push batch of {} exceeds {MAX_BATCH} ops",
            req.ops.len()
        )));
    }
    // Everything the relay may check, it checks before touching storage:
    // scope routing and device honesty are metadata (ADR 0024); the
    // payload is bounded bytes and nothing more.
    for op in &req.ops {
        if op.meta.scope != scope {
            return Err(ApiError::bad_request(
                "op meta scope does not match the route's scope",
            ));
        }
        if op.meta.device_id != device {
            return Err(ApiError::forbidden(
                "op meta device_id does not match the authenticated device",
            ));
        }
        if op.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(ApiError::too_large("op payload exceeds the byte cap"));
        }
    }
    let store = state
        .scope_log(scope, true)?
        .expect("create requested a store");
    let mut store = store.lock().expect("scope log lock");
    let mut results = Vec::with_capacity(req.ops.len());
    // Appends commit per-op: a mid-batch failure leaves earlier appends
    // durable and the client's retry re-append idempotently (dedupe by
    // op_id, ADR 0007).
    for op in req.ops {
        let known = store.seq_of(&op.meta.op_id);
        match store.append_parts(op.meta.clone(), &op.payload) {
            Ok(seq) => results.push(PushResult {
                op_id: op.meta.op_id,
                seq,
                stored: known.is_none(),
            }),
            Err(StoreError::Scope(LogError::ScopeMismatch { .. })) => {
                return Err(ApiError::bad_request(
                    "op meta scope does not match the log's scope",
                ));
            }
            Err(e) => return Err(ApiError::internal(e)),
        }
    }
    let tip = store.tip();
    Ok((
        StatusCode::OK,
        Json(PushResponse {
            v: ENVELOPE_VERSION,
            results,
            tip,
        }),
    ))
}

#[allow(clippy::type_complexity)]
async fn pull_ops(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    let device = authenticate(&state, &headers)?;
    let scope = parse_scope(&kind, &id)?;
    require_grant(&state, scope, device)?;
    let since = query_u64(&query, "since")?.unwrap_or(0);
    // At least one op per page, whatever the client asked: an empty page
    // that claims `has_more` is a shape this protocol never emits.
    let limit = query_u64(&query, "limit")?
        .unwrap_or(DEFAULT_PULL_LIMIT as u64)
        .clamp(1, MAX_PULL_LIMIT as u64) as usize;
    let Some(store) = state.scope_log(scope, false)? else {
        return Ok((
            StatusCode::OK,
            Json(PullResponse {
                v: ENVELOPE_VERSION,
                ops: Vec::new(),
                tip: 0,
                has_more: false,
            }),
        ));
    };
    let store = store.lock().expect("scope log lock");
    let ops: Vec<PullOp> = store
        .delta_parts_since(since)
        .take(limit)
        .map(|row| PullOp {
            seq: row.seq,
            meta: row.meta.clone(),
            payload: row.payload.to_owned(),
        })
        .collect();
    let tip = store.tip();
    let last_served = ops.last().map(|op| op.seq).unwrap_or(since);
    Ok((
        StatusCode::OK,
        Json(PullResponse {
            v: ENVELOPE_VERSION,
            ops,
            tip,
            has_more: tip > last_served,
        }),
    ))
}

/// The relay's router (ADR 0024). `GET /v1/{kind}/{id}/ops` pulls a delta
/// since the cursor; the routes and their auth are the crate's whole
/// HTTP surface.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/devices", post(create_device))
        .route("/v1/{kind}/{id}", post(create_scope))
        .route("/v1/{kind}/{id}/pairing-codes", post(mint_pairing_code))
        .route("/v1/{kind}/{id}/devices", post(pair_device))
        .route("/v1/{kind}/{id}/ops", post(push_ops).get(pull_ops))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
