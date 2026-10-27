# 0029 — HTTPS Relay Client: ureq/rustls and Base-Path Server URLs

- **Status:** Accepted
- **Date:** 2026-10-27
- **Builds on:** [ADR 0013](0013-deployment-topology.md),
  [ADR 0023](0023-capture-cli.md),
  [ADR 0024](0024-rendezvous-sync-relay.md),
  [ADR 0025](0025-authenticated-first-clients.md),
  [ADR 0026](0026-relay-containerization.md)
- **Amends (in part):** [ADR 0025](0025-authenticated-first-clients.md) — the
  transport choice (minreq → ureq) and the "v1 speaks plain http" clause; the
  enrollment gate, session shape, and sync contract are untouched.
- **Issue:** [#34](https://github.com/fluxvale/pursecraft/issues/34)

## Context

The relay is deployed at `https://pursecraft.com/api` — TLS terminates at the
fleet's Traefik edge ([ADR 0026]'s topology; the relay itself stays plain
HTTP behind it), and the public route carries a `/api` base path. The CLI
cannot speak that URL for two independent reasons: `minreq` is built with no
TLS feature (an https URL dies `HttpsFeatureNotEnabled`), and
`normalize_server` ([ADR 0025]) rejects the `https://` scheme and any URL
containing `/`. Until this lands, the deployed relay has no client.

[ADR 0025] deferred exactly this: "TLS arrives with the deployment/hosted
slice." This is that slice. Its two load-bearing rejections — "HTTPS now"
(deliberate, now expired) and "ureq drags the `url`/ICU tree" (a fact about
ureq 2's cookie-era feature set, re-examined below) — are re-decided here on
2026-10-27 facts, measured in this repo against this lockfile.

## Decision

### 1. TLS backend: replace minreq with ureq 3 (rustls, ring, webpki-roots)

**minreq (the pinned 2.14.x) is disqualifying for TLS, not merely
inconvenient.** Its TLS features pin `rustls 0.21` / `rustls-webpki 0.101`
/ `webpki-roots 0.25`, a
stack with live RustSec vulnerabilities whose fixes are unreachable through
those pins — `cargo deny check advisories` on the minimal `https` feature
reports RUSTSEC-2026-0346 and -0349 (rustls; fixed 0.23.46), -0098, -0099,
-0104, -0382 (rustls-webpki; fixed 0.103.16), -0381 (webpki-roots; fixed
1.0.10), plus unmaintained `rustls-pemfile` riding in via
`https-rustls-probe`. Several say "no safe upgrade is available"; deny.toml's
own rule (advisory ignores are documented, *temporary* exceptions) cannot
honestly cover an unfixable TLS vulnerability in a money app's transport.
And no minreq version — 2.14.x or 3.0.0 — exposes a way to inject trust
anchors (a static internal `ClientConfig` either way), so even a hermetic
self-signed https test would be impossible (see the alternatives below for
the 3.0.0 audit).

**ureq 3, minimal cut** — `ureq = { version = "3", default-features = false,
features = ["rustls", "json"] }`:

- **Fully patched rustls stack**: rustls 0.23.46, rustls-webpki 0.103.16,
  webpki-roots 1.0.11, ring 0.17 (the crypto provider — pure Rust built via
  `cc`; no aws-lc-rs, no cmake, no perl, keeping [ADR 0026]'s
  one-toolchain instinct).
- **Lean in the ways that are still free**: this feature cut pulls no `url`,
  no idna/ICU, no gzip in the **shipped tree** (those are ureq's optional
  cookies/url features, which stay off). Measured with
  `cargo tree -p pursecraft-cli -e normal --target x86_64-unknown-linux-gnu
  --prefix none | sed 's/ (\*)$//' | sort -u | wc -l`: **49 → 64 unique
  packages** on unix (+16 third-party added — ureq, ureq-proto, http,
  httparse, rustls, rustls-pki-types, rustls-webpki, webpki-roots, ring,
  and ring's small companions — minus minreq: **+15 net**). The Cargo.lock
  grows further (**82 entries added, one — minreq — removed: net 81**),
  and the split matters: the dev-only test scaffolding (`rcgen`,
  `tokio-rustls`, and their trees) is part of cargo-deny's resolved
  graph, while ureq's never-enabled optional edges (`url`, `idna`,
  `icu_*`, `cookie_store`) are merely *resolvable* — never resolved, so
  compiled into nothing and graded by no gate; they ride in Cargo.lock
  alone. None of it reaches the shipped binary; the cost is stated here
  rather than discovered.
- **Supply chain stays green, with one conscious license addition**:
  webpki-roots ships its certificate data under `CDLA-Permissive-2.0` (a
  permissive data license: use, distribute, modify; share-alike applies to
  the data itself only). deny.toml gains that one entry — same shape as its
  existing BSD-3-Clause/ISC additions. `cargo deny check advisories
  licenses` (the CI gate) passes; the wider `bans` check reports nine
  duplicate-version warnings where ring's RustCrypto deps split versions
  with pursecraft-crypto's (disclosed, warnings not errors, no advisory
  impact).
- **Testable TLS**: ureq's `TlsConfig` accepts `RootCerts::Specific(...)`,
  so an integration test can trust exactly a self-signed test CA — the
  hermetic https round-trip issue #34 asks for. Production keeps the
  default Mozilla root bundle (`RootCerts::WebPki`): deterministic,
  probe-free, independent of the host's store — right for a client whose
  public target is a Let's Encrypt-certified edge. Platform-verifier roots
  (private CAs) are a later, deliberate opt-in if a self-hoster needs them.

**Strictness posture, carried over exactly** — the agent is configured to
behave like minreq did, no more: `max_redirects(0)` (a 3xx — including the
bodiless http→https 308 the fleet's edge answers — is surfaced loudly as
its own redirect error naming the destination, never a silently-followed
ride; **no http fallback behind an https URL**), `http_status_as_error
(false)` (statuses flow into the existing teaching-shaped `decode_body`
arms), `timeout_global(30s)` (the old `TIMEOUT_SECS`), and
`.proxy(None)`: **no environment proxy lookup, ever**. ureq's inherited
default (`Proxy::try_from_env`) would route every request — loopback
`http://` relays included — through `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
when set, a behavior minreq never had: it silently breaks local relays on
proxy-configured machines and lets the environment choose the peer a
cleartext bearer token is sent to. The pin restores minreq's behavior
exactly; a deliberate, `NO_PROXY`-aware proxy opt-in is a future decision
if a self-hoster asks for it — proxy *configuration* remains out of scope
([issue #34]), and the no-proxy default is pinned by a regression test
that runs the real binary with every proxy variable aimed at a dead port.

### 2. `normalize_server`: the accepted grammar

Accepted canonical form, validated by an explicit parse:

```text
scheme://host[:port][/prefix]
```

- **Scheme: exactly `http://` or `https://`, lowercase.** Anything else —
  scheme-less `host:8080`, `HTTPS://`, `ftp://` — fails with a teaching
  error naming the two accepted forms. The typed scheme is the scheme used;
  nothing is guessed.
- **Host: non-empty**, ASCII letters/digits/`.`/`-`, or one bracketed IPv6
  literal `[…]` (a localhost relay must keep working). IDN/punycode is out
  of scope — the ASCII form fails loudly rather than dragging an ICU
  normalizer in.
- **Port: optional**, ASCII digits only, 1–65535. Absent port falls to the
  scheme's default (443/80) at connect time.
- **Prefix: at most one path segment** (`/api`), matching
  `[A-Za-z0-9_-]+` with interior, non-adjacent dots allowed. Not `.` or
  `..`, no `%`, no multi-segment paths (`/a/b`), no query strings (`?`),
  no fragments (`#`), no userinfo (`@`), no empty segments — each refused
  loudly, old strictness preserved.
- **Trailing slashes are trimmed before validation** (the pre-existing
  behavior: `http://host/` → `http://host`,
  `https://pursecraft.com/api/` → `https://pursecraft.com/api`), then no
  further `/` may appear. One inherited asymmetry, stated plainly: the
  trim eats *all* trailing slashes (`http://host//` → `http://host`,
  exactly as the pre-ADR-0025 trim already did), while a doubled slash
  before a segment (`http://host//api`) is refused — where the slash sits
  decides, because the trim runs first. Unchanged from the old behavior
  and covered by the table tests.

Old shapes behave byte-for-byte as today: `http://127.0.0.1:8099` and
`http://host` normalize unchanged; `https://…`, paths, queries, and garbage
still fail loudly — the https refusal's teaching text flips from "TLS
arrives later" to the accepted-form explanation.

### 3. Representation: the canonical string, not a URL type

`normalize_server` parses into `(scheme, host, port, prefix)` **for
validation only** and returns the canonical serialization. `session.json`'s
`server` field keeps its exact string shape; every existing session remains
valid (all are path-free by the old rule). `relay.rs` keeps composing URLs
by plain concatenation — `{server}/v1/…` is correct precisely because the
canonical form's no-trailing-slash invariant holds. No URL library, no new
public type, no join semantics; the parse stays private to
`normalize_server`, and the invariant is pinned by the accepted/rejected
table tests plus the nested-`/api` round-trip below.

## Tests

1. **Unit table** — `normalize_server` accepted and rejected shapes (old and
   new), extending the existing test in `lib.rs`.
2. **Base-path protocol round-trip** — the existing integration harness
   (real axum relay on a localhost socket) with the router nested under
   `/api`: enroll, capture, sync through `http://127.0.0.1:<port>/api`.
   Exercises prefix composition end-to-end over the real transport.
3. **Hermetic https round-trip** — the same relay behind `tokio-rustls`
   with an `rcgen`-minted self-signed certificate (both dev-dependencies),
   driven through a `Relay` built with `RootCerts::Specific` on the test
   CA. A real client-server TLS round trip in CI; the live relay is the
   final acceptance step, never a CI dependency. The test pins the
   shipped `default_agent` itself — its three strictness settings at the
   config level, and its refusal of the self-signed server asserted
   specifically as a certificate failure — so loosening the production
   agent (following redirects, statuses-as-errors, skipping certificate
   verification) turns it red.
4. **No-proxy regression** — the real `pursecraft` binary run against a
   live local relay with every proxy environment variable aimed at a
   dead port: login, capture, and sync must all succeed through the
   hostile environment (`.proxy(None)` is what makes this true).
5. **Redirect teaching** — a raw-socket bodiless-308 stand-in answers a
   login probe; the error names the destination and says the client does
   not follow redirects, never "answered strangely".
6. **Live acceptance** — `pursecraft login https://pursecraft.com/api`
   plus a capture + `sync` round-trip against production, transcript
   recorded with the enrollment secret redacted (requires the operator's
   secret at run time).

Out of scope, unchanged from [issue #34]: certificate pinning, proxy
configuration, retry-policy changes.

## Alternatives considered

- **minreq + any TLS feature** — rejected on two independent grounds.
  minreq **2.14.x** (what this repo pinned): its TLS features pin
  `rustls 0.21` / `rustls-webpki 0.101` / `webpki-roots 0.25` — a stack
  with seven live, unfixable-within-those-pins RustSec advisories
  (measured in-repo, Oct 2026). minreq **3.0.0** since resolves the
  patched rustls 0.23 / webpki-roots 1.x stack and grades green under
  `cargo deny check advisories` — but it still exposes **no way to inject
  trust anchors**: its TLS config is a module-static
  `LazyLock<Result<Arc<ClientConfig>, _>>` with no constructor hook
  (`src/connection/rustls_stream.rs`), so the hermetic self-signed https
  round-trip this slice's test story requires would be impossible with
  any minreq version. That, plus ureq's configurable agent (redirects,
  status handling, timeout, no-proxy — none of which minreq exposes),
  settles the choice on the merits, not only on advisories.
- **ureq 2** — rejected: advisories equally green, but the `url`/idna/ICU
  tree (+~20 compiled packages) is exactly what [ADR 0025] objected to;
  ureq 3's minimal cut avoids it entirely.
- **reqwest / tokio-based clients** — rejected, as in [ADR 0025]: a runtime
  in a sync one-shot CLI, plus the largest tree on offer.
- **minreq's OpenSSL-backed features (`https-bundled`, `https-native`)** —
  rejected: vendored OpenSSL makes every build a C/perl build with a huge
  blob; native-tls makes trust story host-dependent and drags
  schannel/security-framework. rustls/ring is the Rust-native, audited,
  buildable-anywhere path.
- **A URL-type representation (`ServerUrl`) with join semantics** —
  rejected: the accepted grammar is one prefix segment deep; a type would
  re-own parsing, encoding, and display rules the canonical string already
  carries. The invariant plus tests is the smaller honest machine.
- **Accepting multi-segment or percent-encoded prefixes** — rejected: no
  consumer exists; one segment covers the deployed `/api`, and strictness
  is cheap to relax later with a real case in hand.

## Consequences

- The CLI speaks the deployed relay URL; dogfooding through
  `https://pursecraft.com/api` is unblocked.
- One direct dependency swap (`minreq` → `ureq 3`): the shipped tree
  grows +15 net compiled packages (49 → 64, command in §1), the lockfile
  82 added / 1 removed (minreq) for net 81 (attribution in §1), one
  deny.toml license entry, two dev-dependencies for the TLS test
  (`rcgen`, `tokio-rustls`).
- `Relay` gains an injectable-agent constructor for the https test; the
  minreq `HttpsFeatureNotEnabled` teaching arm is deleted with its cause.
- Sessions are forward- and back-compatible by construction (string shape
  unchanged); re-login is the only way a base-path URL enters a session.
- Duplicate-version lockfile entries (ring vs pursecraft-crypto's RustCrypto
  pins) appear as cargo-deny `bans` *warnings* — a disclosed cost of the
  ring provider, with no advisory or license impact.
- [ADR 0025]'s "v1 speaks plain http" clause is superseded by this ADR's
  grammar; its enrollment-gate and sync mechanics are untouched.
