//! The relay client (ADR 0025): plain HTTP/1.1 to the rendezvous relay's
//! v1 routes (ADR 0024) — enroll, scope create/pair, push, pull. The wire
//! is exactly the relay's envelopes; payloads stay the choke-point strings
//! ([ADR 0017] `encode_payload`/`decode_payload`), opaque to the transport.
//!
//! Errors are teaching-shaped (ADR 0025): a refused token says to re-enroll,
//! an unreachable relay says captures stay queued. The token appears only
//! in the `Authorization` header, never in an error or output.

use std::fmt;

use minreq::{Error as HttpError, Response};
use pursecraft_core::ids::{DeviceId, OpId, ScopeId};
use pursecraft_core::ops::Op;
use pursecraft_core::wire::OpMeta;

/// Request/response timeout, seconds (a household relay is fast; a hung
/// socket must not hang a one-shot command).
const TIMEOUT_SECS: u64 = 30;

/// A relay call failed — transport, refusal, or a malformed answer.
#[derive(Debug)]
pub enum RelayError {
    /// No HTTP conversation happened (connection refused, timeout, DNS).
    Unreachable { server: String, detail: String },
    /// The relay answered a non-OK status with its error envelope.
    Status {
        server: String,
        code: u16,
        error: String,
        message: String,
    },
    /// A success-shaped answer that is not (missing fields, short ack
    /// batch) — the hostile-answer contract: loud, never guessed
    /// (ADR 0024).
    BadAnswer(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { server, detail } => write!(
                f,
                "cannot reach the relay at {server} ({detail}); captures stay queued — retry: pursecraft sync"
            ),
            Self::Status {
                server,
                code,
                error,
                message,
            } => match *code {
                401 => write!(
                    f,
                    "the relay at {server} refused this device token — enroll again: pursecraft login {server}"
                ),
                403 if message.contains("enrollment") => write!(
                    f,
                    "the relay refused the enrollment secret — it lives in the relay's data directory (enrollment.secret)"
                ),
                403 if message.contains("granted") => write!(
                    f,
                    "the relay refused: {message} — to bring a fresh device into this world, \
                     run pursecraft pair on a granted device and pursecraft join here; \
                     to restore a backup, copy the whole data home (session.json included)"
                ),
                403 if message.contains("expired") => write!(
                    f,
                    "the relay refused the pairing code: {message} — mint a fresh one on a granted device: pursecraft pair"
                ),
                403 => write!(f, "the relay refused: {message}"),
                409 => write!(f, "the relay refused: {message}"),
                _ => write!(f, "relay error {code} ({error}): {message}"),
            },
            Self::BadAnswer(detail) => write!(f, "the relay answered strangely: {detail}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// One authenticated relay connection: base URL plus the bearer token
/// (ADR 0025's session).
pub struct Relay<'a> {
    server: &'a str,
    token: &'a str,
}

impl<'a> Relay<'a> {
    pub fn new(server: &'a str, token: &'a str) -> Self {
        Self { server, token }
    }

    /// `POST /v1/{kind}/{id}` — create the scope; the creator is granted
    /// and one single-use pairing code is minted (ADR 0024).
    pub fn create_scope(&self, scope: ScopeId) -> Result<ScopeCreated, RelayError> {
        let resp = self.send(minreq::post(self.scope_url(scope)), None)?;
        let pairing_code = resp
            .get("pairing_code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RelayError::BadAnswer("scope create missing code".into()))?
            .to_owned();
        Ok(ScopeCreated { pairing_code })
    }

    /// `POST /v1/{kind}/{id}/pairing-codes` — mint a fresh single-use code.
    pub fn mint_pairing_code(&self, scope: ScopeId) -> Result<String, RelayError> {
        self.send(minreq::post(self.pairing_url(scope)), None)
            .map(|resp| {
                resp.get("pairing_code")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| RelayError::BadAnswer("pairing answer missing code".into()))
            })?
    }

    /// `POST /v1/{kind}/{id}/devices` — redeem a pairing code into a grant.
    pub fn redeem(&self, scope: ScopeId, code: &str) -> Result<(), RelayError> {
        let body = serde_json::json!({ "v": 1, "code": code });
        self.send(minreq::post(self.devices_url(scope)), Some(&body))
            .map(|_| ())
    }

    /// `POST /v1/{kind}/{id}/ops` — push one batch (already chunked to the
    /// relay's cap by the caller). Every op must come back acked under its
    /// own id, in order — a short or lying ack batch is loud (ADR 0024).
    pub fn push(&self, scope: ScopeId, ops: &[Op]) -> Result<(), RelayError> {
        let mut wire_ops = Vec::with_capacity(ops.len());
        for op in ops {
            let (meta, payload) = op.clone().into_parts();
            let meta = serde_json::to_value(&meta)
                .map_err(|e| RelayError::BadAnswer(format!("an op does not encode: {e}")))?;
            let payload = pursecraft_core::wire::encode_payload(&payload).map_err(|e| {
                RelayError::BadAnswer(format!("an op payload does not encode: {e}"))
            })?;
            wire_ops.push(serde_json::json!({ "meta": meta, "payload": payload }));
        }
        let body = serde_json::json!({ "v": 1, "ops": wire_ops });
        let resp = self.send(minreq::post(self.ops_url(scope)), Some(&body))?;
        let results = resp
            .get("results")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RelayError::BadAnswer("push answer missing results".into()))?;
        if results.len() != ops.len() {
            return Err(RelayError::BadAnswer(format!(
                "a short ack batch is loud: {} acks for {} pushed ops",
                results.len(),
                ops.len()
            )));
        }
        for (result, op) in results.iter().zip(ops) {
            let acked: OpId = serde_json::from_value(result["op_id"].clone())
                .map_err(|e| RelayError::BadAnswer(format!("ack op_id: {e}")))?;
            if acked != op.op_id {
                return Err(RelayError::BadAnswer(format!(
                    "an ack must echo the op it claims ({acked} != {})",
                    op.op_id
                )));
            }
        }
        Ok(())
    }

    /// `GET /v1/{kind}/{id}/ops?since=N&limit=M` — one pull page
    /// (ADR 0024: exclusive cursor, ascending, `has_more` pages).
    pub fn pull(&self, scope: ScopeId, since: u64, limit: usize) -> Result<PullPage, RelayError> {
        let url = format!("{}?since={since}&limit={limit}", self.ops_url(scope));
        let resp = self.send(minreq::get(&url), None)?;
        let ops = resp
            .get("ops")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RelayError::BadAnswer("pull answer missing ops".into()))?;
        let mut wire = Vec::with_capacity(ops.len());
        for op in ops {
            wire.push(PullOpWire {
                seq: op["seq"]
                    .as_u64()
                    .ok_or_else(|| RelayError::BadAnswer("pull op missing seq".into()))?,
                meta: serde_json::from_value(op["meta"].clone())
                    .map_err(|e| RelayError::BadAnswer(format!("pull op meta: {e}")))?,
                payload: op["payload"]
                    .as_str()
                    .ok_or_else(|| RelayError::BadAnswer("pull op missing payload".into()))?
                    .to_owned(),
            });
        }
        Ok(PullPage {
            ops: wire,
            has_more: resp
                .get("has_more")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
    }

    /// One authorized JSON round trip; non-OK statuses become the relay's
    /// error envelope, transport failures become teaching unreachable.
    fn send(
        &self,
        request: minreq::Request,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, RelayError> {
        let mut request = request
            .with_header("Authorization", format!("Bearer {}", self.token))
            .with_timeout(TIMEOUT_SECS);
        if let Some(body) = body {
            let encoded = serde_json::to_string(body)
                .map_err(|e| RelayError::BadAnswer(format!("request does not encode: {e}")))?;
            request = request
                .with_header("Content-Type", "application/json")
                .with_body(encoded);
        }
        let response = map_transport(self.server, request.send())?;
        decode_body(self.server, response)
    }

    fn ops_url(&self, scope: ScopeId) -> String {
        format!("{}/v1/{}/ops", self.server, scope_path(scope))
    }

    fn pairing_url(&self, scope: ScopeId) -> String {
        format!("{}/v1/{}/pairing-codes", self.server, scope_path(scope))
    }

    fn devices_url(&self, scope: ScopeId) -> String {
        format!("{}/v1/{}/devices", self.server, scope_path(scope))
    }

    fn scope_url(&self, scope: ScopeId) -> String {
        format!("{}/v1/{}", self.server, scope_path(scope))
    }
}

/// `POST /v1/devices` — enroll with the operator's secret; the device id
/// and token are minted server-side and shown exactly once (ADR 0024).
pub fn enroll(server: &str, secret: &str) -> Result<(DeviceId, String), RelayError> {
    let body = serde_json::json!({ "v": 1, "enrollment_secret": secret });
    let encoded = serde_json::to_string(&body)
        .map_err(|e| RelayError::BadAnswer(format!("request does not encode: {e}")))?;
    let request = minreq::post(format!("{server}/v1/devices"))
        .with_header("Content-Type", "application/json")
        .with_body(encoded)
        .with_timeout(TIMEOUT_SECS);
    let response = map_transport(server, request.send())?;
    let value = decode_body(server, response)?;
    let device_id: DeviceId = serde_json::from_value(value["device_id"].clone())
        .map_err(|e| RelayError::BadAnswer(format!("enroll answer device_id: {e}")))?;
    let token = value["token"]
        .as_str()
        .ok_or_else(|| RelayError::BadAnswer("enroll answer missing token".into()))?
        .to_owned();
    Ok((device_id, token))
}

/// The `{kind}/{id}` route segments for a scope (ADR 0021's typed routes).
fn scope_path(scope: ScopeId) -> String {
    match scope {
        ScopeId::Org(id) => format!("orgs/{}", id.as_uuid()),
        ScopeId::Budget(id) => format!("budgets/{}", id.as_uuid()),
    }
}

/// Transport failures teach, including the TLS posture (ADR 0025: v1 is
/// plain http; https is the deployment slice's).
fn map_transport(
    server: &str,
    result: Result<Response, HttpError>,
) -> Result<Response, RelayError> {
    match result {
        Ok(response) => Ok(response),
        Err(HttpError::HttpsFeatureNotEnabled) => Err(RelayError::Unreachable {
            server: server.to_owned(),
            detail:
                "v1 speaks plain http to a local relay; TLS arrives with the hosted-relay slice"
                    .into(),
        }),
        Err(e) => Err(RelayError::Unreachable {
            server: server.to_owned(),
            detail: e.to_string(),
        }),
    }
}

/// Non-OK statuses become the relay's `{"error", "message"}` envelope.
fn decode_body(server: &str, response: Response) -> Result<serde_json::Value, RelayError> {
    let status = u16::try_from(response.status_code).unwrap_or(0);
    if !(200..300).contains(&status) {
        let body: serde_json::Value = response.json().map_err(|e| {
            RelayError::BadAnswer(format!("status {status} with no error body: {e}"))
        })?;
        return Err(RelayError::Status {
            server: server.to_owned(),
            code: status,
            error: body["error"].as_str().unwrap_or("unknown").to_owned(),
            message: body["message"].as_str().unwrap_or("no message").to_owned(),
        });
    }
    response
        .json()
        .map_err(|e| RelayError::BadAnswer(format!("a 2xx body does not decode: {e}")))
}

/// A scope's creation answer: the single-use pairing code for the next
/// device (the caller prints it; it is shown once, ADR 0024).
pub struct ScopeCreated {
    pub pairing_code: String,
}

/// One pulled op, wire-shaped: the relay's sequence, the server-visible
/// metadata, and the payload string — decoded client-side (ADR 0024).
#[derive(Clone, Debug)]
pub struct PullOpWire {
    pub seq: u64,
    pub meta: OpMeta,
    pub payload: String,
}

/// One pull page (ADR 0024): ops ascending since the cursor, and
/// whether more pages remain (`has_more` drives the loop).
#[derive(Clone, Debug)]
pub struct PullPage {
    pub ops: Vec<PullOpWire>,
    pub has_more: bool,
}
