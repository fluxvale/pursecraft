//! The relay client (ADR 0025): HTTP/1.1 to the rendezvous relay's v1
//! routes (ADR 0024) — enroll, scope create/pair, push, pull — over plain
//! `http` or TLS via ureq/rustls (ADR 0029: the deployed relay is
//! `https://pursecraft.com/api`). The wire is exactly the relay's
//! envelopes; payloads stay the choke-point strings ([ADR 0017]
//! `encode_payload`/`decode_payload`), opaque to the transport.
//!
//! Errors are teaching-shaped (ADR 0025): a refused token says to re-enroll,
//! an unreachable relay says captures stay queued. The token appears only
//! in the `Authorization` header, never in an error or output.

use std::fmt;
use std::time::Duration;

use pursecraft_core::ids::{DeviceId, OpId, OrgId, ScopeId};
use pursecraft_core::ops::Op;
use pursecraft_core::wire::{OpMeta, PayloadCipher};
use ureq::Agent;

/// Whole-call timeout, seconds (a household relay is fast; a hung socket
/// must not hang a one-shot command).
const TIMEOUT_SECS: u64 = 30;

/// The strictness settings of every agent this CLI builds (ADR 0029) —
/// ONE chain, so a test agent cannot drift from the shipped one
/// (hostile review round 2): `max_redirects(0)` — a 3xx (the fleet's
/// http→https 308 included) surfaces as a loud redirect error, never a
/// silently-followed ride; `http_status_as_error(false)` — statuses flow
/// to this module's teaching decoder; one bounded timeout per call;
/// `.proxy(None)` — no environment proxy lookup, ever: the environment
/// must not choose the peer a cleartext bearer token is sent to, and a
/// `HTTP_PROXY` var on a laptop must not silently break a loopback relay
/// (minreq never read these vars; this keeps that behavior exactly).
fn strict_builder() -> ureq::config::ConfigBuilder<ureq::typestate::AgentScope> {
    Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(TIMEOUT_SECS)))
        .proxy(None)
}

/// The shipped agent (ADR 0029): the strict chain with the default
/// Mozilla root bundle — no other setting differs, by construction.
pub fn default_agent() -> Agent {
    strict_builder().build().new_agent()
}

/// The test seam (ADR 0029's hermetic https round trip): the SAME strict
/// chain with test-only trust roots — the only difference from
/// [`default_agent`] is the roots, because the builder is shared.
pub fn agent_with_roots(roots: ureq::tls::RootCerts) -> Agent {
    strict_builder()
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build())
        .build()
        .new_agent()
}

/// A relay call failed — transport, refusal, or a malformed answer.
///
/// The relay's error shape is `{"error": code, "message": …}`; the code
/// is coarse ("forbidden" covers wrong-secret, ungranted, and expired),
/// so teaching branches below match on the MESSAGE prose — strings owned
/// by pursecraft-api's `AuthError` in this same repo, pinned end-to-end
/// by tests/sync.rs (the expired and invalid pairings and the refused
/// enrollment secret). A message drift there fails a test here.
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
                    "the relay at {server} refused this device token — enroll again: {}",
                    crate::argv::login_command(server)
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
/// (ADR 0025's session), carried by one strict agent (ADR 0029).
pub struct Relay<'a> {
    server: &'a str,
    token: &'a str,
    agent: Agent,
}

impl<'a> Relay<'a> {
    pub fn new(server: &'a str, token: &'a str) -> Self {
        Self::with_agent(server, token, default_agent())
    }

    /// The test seam (ADR 0029): a caller-built agent. The https
    /// round-trip test trusts exactly its self-signed test CA
    /// (`ureq::tls::RootCerts::Specific`); production keeps
    /// `default_agent`'s Mozilla roots.
    pub fn with_agent(server: &'a str, token: &'a str, agent: Agent) -> Self {
        Self {
            server,
            token,
            agent,
        }
    }

    /// `POST /v1/{kind}/{id}` — create the scope; the creator is granted
    /// and one single-use pairing code is minted (ADR 0024).
    pub fn create_scope(&self, scope: ScopeId) -> Result<String, RelayError> {
        let resp = self.send(Method::Post, &self.scope_url(scope), None)?;
        resp.get("pairing_code")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| RelayError::BadAnswer("scope create missing code".into()))
    }

    /// `POST /v1/{kind}/{id}/pairing-codes` — mint a fresh single-use code.
    pub fn mint_pairing_code(&self, scope: ScopeId) -> Result<String, RelayError> {
        self.send(Method::Post, &self.pairing_url(scope), None)
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
        self.send(Method::Post, &self.devices_url(scope), Some(&body))
            .map(|_| ())
    }

    /// `POST /v1/{kind}/{id}/ops` — push one batch (already chunked to the
    /// relay's cap by the caller). Every op must come back acked under its
    /// own id, in order — a short or lying ack batch is loud (ADR 0024).
    /// The payload is sealed through `cipher` here (ADR 0028): the relay
    /// never sees the plaintext in E2EE mode, and the self-host mode passes
    /// it through unchanged.
    pub fn push(
        &self,
        scope: ScopeId,
        ops: &[Op],
        cipher: &impl PayloadCipher,
    ) -> Result<(), RelayError> {
        let mut wire_ops = Vec::with_capacity(ops.len());
        for op in ops {
            let (meta, payload) = op.clone().into_parts();
            let meta_value = serde_json::to_value(&meta)
                .map_err(|e| RelayError::BadAnswer(format!("an op does not encode: {e}")))?;
            let plaintext = pursecraft_core::wire::encode_payload(&payload).map_err(|e| {
                RelayError::BadAnswer(format!("an op payload does not encode: {e}"))
            })?;
            let payload = cipher.seal(&meta, plaintext).map_err(|e| {
                // A local seal failure is not the relay's doing: missing or
                // stale keys (ADR 0028). Say that, not "answered strangely".
                RelayError::Unreachable {
                    server: self.server.to_owned(),
                    detail: format!("this device cannot seal the op: {e}"),
                }
            })?;
            wire_ops.push(serde_json::json!({ "meta": meta_value, "payload": payload }));
        }
        let body = serde_json::json!({ "v": 1, "ops": wire_ops });
        let resp = self.send(Method::Post, &self.ops_url(scope), Some(&body))?;
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
        let resp = self.send(Method::Get, &url, None)?;
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
                .ok_or_else(|| {
                    RelayError::BadAnswer("pull answer missing a boolean has_more".into())
                })?,
        })
    }

    /// One authorized JSON round trip; non-OK statuses become the relay's
    /// error envelope, transport failures become teaching unreachable.
    fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, RelayError> {
        let auth = format!("Bearer {}", self.token);
        let sent = match (method, body) {
            (Method::Post, Some(value)) => self
                .agent
                .post(url)
                .header("Authorization", auth.as_str())
                .send_json(value),
            (Method::Post, None) => self
                .agent
                .post(url)
                .header("Authorization", auth.as_str())
                .send_empty(),
            (Method::Get, _) => self
                .agent
                .get(url)
                .header("Authorization", auth.as_str())
                .call(),
        };
        decode_body(self.server, map_transport(self.server, sent)?)
    }

    /// `POST /v1/orgs/{id}/keys` — publish key records the relay stores and
    /// forwards verbatim (ADR 0028). The caller has already sealed them; the
    /// relay never parses one.
    pub fn publish_keys(&self, org: OrgId, records: &[String]) -> Result<(), RelayError> {
        let body = serde_json::json!({ "v": 1, "keys": records });
        let resp = self.send(Method::Post, &self.keys_url(org), Some(&body))?;
        let stored = resp
            .get("stored")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RelayError::BadAnswer("key push missing stored".into()))?;
        if stored != records.len() as u64 {
            // A short store is loud (ADR 0024's ack rule, applied here): the
            // client would otherwise believe a wrap it never delivered.
            return Err(RelayError::BadAnswer(format!(
                "the relay stored {stored} of {} key records",
                records.len()
            )));
        }
        Ok(())
    }

    /// `GET /v1/orgs/{id}/keys` — every key record the org holds, each with
    /// the authenticated device that pushed it (ADR 0028's provenance).
    pub fn pull_keys(&self, org: OrgId) -> Result<Vec<KeyRecordWire>, RelayError> {
        let resp = self.send(Method::Get, &self.keys_url(org), None)?;
        let keys = resp
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RelayError::BadAnswer("key pull missing keys".into()))?;
        keys.iter()
            .map(|entry| {
                Ok(KeyRecordWire {
                    record: entry["key"]
                        .as_str()
                        .ok_or_else(|| RelayError::BadAnswer("key pull entry missing key".into()))?
                        .to_owned(),
                    pushed_by: serde_json::from_value(entry["pushed_by"].clone())
                        .map_err(|e| RelayError::BadAnswer(format!("key pushed_by: {e}")))?,
                })
            })
            .collect()
    }

    fn keys_url(&self, org: OrgId) -> String {
        format!("{}/v1/orgs/{}/keys", self.server, org.as_uuid())
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
    enroll_with_agent(&default_agent(), server, secret)
}

/// A `/health` probe failure (ADR 0030, as amended): what went wrong
/// establishing that SOMETHING speaks HTTP at the URL before login asks
/// for anything secret. Teaching-shaped like [`RelayError`], but its own
/// type — the probe answers "is a relay reachable here", not "did this
/// call succeed", and its errors must not promise captures stay queued
/// (login has captured nothing yet).
#[derive(Debug)]
pub enum ProbeError {
    /// No HTTP conversation happened (connection refused, timeout, DNS,
    /// TLS handshake) — the fail-early case: dead URL, typo, wrong port.
    Unreachable { server: String, detail: String },
    /// Something answered, but it is not a relay: a 3xx is never followed
    /// (ADR 0029) and the destination is named; a non-2xx/404/405 at
    /// `/health` that is not a missing route means an edge answered where
    /// no healthy relay serves.
    NotThere { server: String, status: u16 },
    /// A 3xx — never followed (ADR 0029); the destination is named.
    Redirect {
        server: String,
        status: u16,
        location: String,
    },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { server, detail } => {
                write!(f, "cannot reach the relay at {server} ({detail})")
            }
            Self::NotThere { server, status } => write!(
                f,
                "the edge at {server} answered {status} at /health — something is \
                 listening there, but no healthy relay"
            ),
            Self::Redirect {
                server,
                status: _,
                location,
            } => write!(
                f,
                "the relay at {server} redirected to {location}; pursecraft does not \
                 follow redirects — check the relay url (the hosted relay is https://…/api)"
            ),
        }
    }
}

impl std::error::Error for ProbeError {}

/// The probe's own budget, seconds (ADR 0030, as amended): a pre-flight,
/// not a transfer — a typo'd URL must not cost the enrollment call's full
/// 30 s before it says so.
const PROBE_TIMEOUT_SECS: u64 = 5;

/// The login reachability probe (ADR 0030, as amended): `GET
/// <server>/health` — the relay's unauthenticated liveness route (ADR
/// 0026), which touches nothing — on the strict chain with the probe's
/// own short budget. The route is the fleet's, NOT the client's contract:
/// reachability is the question, so **2xx, 404, and 405 all pass** (a
/// `/v1`-only edge or a proxy that allow-lists `/v1` still enrolls,
/// exactly as before this probe existed); transport failures and 3xx
/// still fail enrollment immediately, naming the URL so a typo is
/// obvious. The probe runs exactly once per invocation and its result is
/// never reused — enrollment always makes its own round-trip.
pub fn probe_health(server: &str) -> Result<(), ProbeError> {
    let agent = strict_builder()
        .timeout_global(Some(Duration::from_secs(PROBE_TIMEOUT_SECS)))
        .build()
        .new_agent();
    let response =
        agent
            .get(format!("{server}/health"))
            .call()
            .map_err(|e| ProbeError::Unreachable {
                server: server.to_owned(),
                detail: e.to_string(),
            })?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) || status == 404 || status == 405 {
        Ok(())
    } else if (300..400).contains(&status) {
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("an unstated destination");
        Err(ProbeError::Redirect {
            server: server.to_owned(),
            status,
            location: location.to_owned(),
        })
    } else {
        Err(ProbeError::NotThere {
            server: server.to_owned(),
            status,
        })
    }
}

/// The agent seam for enrollment, as [`Relay::with_agent`] is for the
/// authenticated calls (ADR 0029's https test enrolls through its
/// test-CA agent before it ever syncs).
pub fn enroll_with_agent(
    agent: &Agent,
    server: &str,
    secret: &str,
) -> Result<(DeviceId, String), RelayError> {
    let body = serde_json::json!({ "v": 1, "enrollment_secret": secret });
    let response = map_transport(
        server,
        agent.post(format!("{server}/v1/devices")).send_json(&body),
    )?;
    let value = decode_body(server, response)?;
    let device_id: DeviceId = serde_json::from_value(value["device_id"].clone())
        .map_err(|e| RelayError::BadAnswer(format!("enroll answer device_id: {e}")))?;
    let token = value["token"]
        .as_str()
        .ok_or_else(|| RelayError::BadAnswer("enroll answer missing token".into()))?
        .to_owned();
    Ok((device_id, token))
}

/// The request verbs [`Relay::send`] speaks — the relay's v1 surface is
/// GET and POST, nothing else.
enum Method {
    Get,
    Post,
}

/// The `{kind}/{id}` route segments for a scope (ADR 0021's typed routes).
fn scope_path(scope: ScopeId) -> String {
    match scope {
        ScopeId::Org(id) => format!("orgs/{}", id.as_uuid()),
        ScopeId::Budget(id) => format!("budgets/{}", id.as_uuid()),
    }
}

/// Transport failures teach (ADR 0025): connection refused, DNS, TLS
/// handshake, timeout — every ureq error maps to unreachable, with the
/// library's own detail; the capture queue survives.
fn map_transport(
    server: &str,
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<ureq::http::Response<ureq::Body>, RelayError> {
    result.map_err(|e| RelayError::Unreachable {
        server: server.to_owned(),
        detail: e.to_string(),
    })
}

/// Non-OK statuses become the relay's `{"error", "message"}` envelope —
/// except a 3xx, which this client never follows (ADR 0029): it is its
/// own loud answer naming the destination, because the bodiless 308 a
/// plain-`http` probe of the fleet's edge earns is the deployed world's
/// most likely misconfiguration.
fn decode_body(
    server: &str,
    response: ureq::http::Response<ureq::Body>,
) -> Result<serde_json::Value, RelayError> {
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("an unstated destination");
        return Err(RelayError::Status {
            server: server.to_owned(),
            code: status,
            error: "redirect".into(),
            message: format!(
                "the relay redirected to {location}; pursecraft does not follow \
                 redirects — check the relay url (the hosted relay is https://…/api)"
            ),
        });
    }
    if !(200..300).contains(&status) {
        let mut body = response.into_body();
        let body: serde_json::Value = body.read_json().map_err(|e| {
            // Named (ADR 0030, as amended): a URL whose probe passed on a
            // 404 — the wrong-base-path shape — dies here, and the error
            // must still say WHERE.
            RelayError::BadAnswer(format!(
                "status {status} from {server} without a relay error body: {e}"
            ))
        })?;
        return Err(RelayError::Status {
            server: server.to_owned(),
            code: status,
            error: body["error"].as_str().unwrap_or("unknown").to_owned(),
            message: body["message"].as_str().unwrap_or("no message").to_owned(),
        });
    }
    let mut body = response.into_body();
    body.read_json()
        .map_err(|e| RelayError::BadAnswer(format!("a 2xx body does not decode: {e}")))
}

/// One pulled key record: the opaque string, and the authenticated device
/// that pushed it (ADR 0028). The relay never parses the record; the client
/// requires a device record's claimed id to equal this stamp.
#[derive(Clone, Debug)]
pub struct KeyRecordWire {
    pub record: String,
    pub pushed_by: DeviceId,
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
/// whether more pages remain (`has_more` drives the loop; a missing or
/// non-boolean `has_more` is a loud [`RelayError::BadAnswer`], never a
/// guess — a guessed `false` would strand the log's tail behind a cursor
/// that claims "synced").
#[derive(Clone, Debug)]
pub struct PullPage {
    pub ops: Vec<PullOpWire>,
    pub has_more: bool,
}
