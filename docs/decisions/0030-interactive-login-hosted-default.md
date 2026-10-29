# 0030 — Interactive Login: Hosted Default and the Domain-Derivation Form

- **Status:** Accepted
- **Date:** 2026-10-29
- **Builds on:** [ADR 0014](0014-monorepo-and-fluxvale-cloud.md),
  [ADR 0015](0015-product-positioning.md),
  [ADR 0025](0025-authenticated-first-clients.md),
  [ADR 0026](0026-relay-containerization.md),
  [ADR 0029](0029-https-relay-client.md)
- **Amends (in part):** [ADR 0025](0025-authenticated-first-clients.md) — the
  `login <server-url>` command shape and the secret's read-from-stdin-only
  channel; the enrollment gate, session shape, and sync contract are
  untouched. [ADR 0029](0029-https-relay-client.md) — only its live-acceptance
  command line; the grammar, transport, and representation stand exactly.
- **Issue:** [#34](https://github.com/fluxvale/pursecraft/issues/34)

## Context

ADR 0029 made the CLI able to speak the deployed relay URL, but the UX still
asks the user to *know* it: `pursecraft login https://pursecraft.com/api`.
The owner's product steer (Oct 29, amended the same day) is that login takes
**no argument**: a small interactive form where the first screen is a choice —
the hosted relay by default (just Enter), or the user's own server, where they
type only a domain and the CLI derives the URL. The full URL on the command
line stops being the primary UX.

This is a new ADR rather than an amendment folded into [ADR 0029] because
0029's subject — transport, grammar, representation — is untouched here, and
its review arc is closed against its current text ("the implementation
matches it" is a Done-when of the lane); rewriting a closed, review-pinned
document to carry a UX layer would blur both. The precedent is 0029 itself,
which amended 0025 in part rather than restating it.

## Decision

### 1. Command shape

```text
pursecraft login                 # interactive form (tty) or hosted default (non-tty)
pursecraft login --server <url>  # non-interactive: the full relay URL, explicit
```

- **The positional URL argument is deleted** (pre-merge, nothing depends on
  it; a third accepted shape would only blur the teaching). `login <url>` is
  a usage error (exit 2) naming the two accepted shapes.
- **`--server` takes the full URL** — `https://pursecraft.com/api`,
  `http://127.0.0.1:8099` — validated by `normalize_server` exactly as
  today; the `--server=<url>` spelling is the same flag. No derivation
  applies to the flag: explicit configuration is an
  explicit URL, and scripts/tests (which know their URL) keep byte-identical
  behavior modulo the flag spelling.
- **Bare `login` with no terminal defaults to the hosted relay** — the same
  default the interactive form offers. `echo "$SECRET" | pursecraft login`
  is the minimal hosted enrollment; the success line names the server, so
  even unprompted output stays transparent about the endpoint. (An earlier
  draft considered erroring here; defaulting matches the interactive
  default, and the fixed-endpoint property below makes it safe.)

### 2. The hosted default is a named constant, not prompt text

```rust
pub const DEFAULT_SERVER: &str = "https://pursecraft.com/api";
```

- One first-class constant in the CLI; the choice screen renders it, the
  non-tty default uses it, and the success line echoes it. No copy of the
  endpoint participates in behavior (help prose may mention the domain
  descriptively).
- **The constant round-trips `normalize_server`** like every other server
  string — asserted by a unit test — so there is no bypass path around the
  single validator, not even for the compiled-in default.
- **Fixed-endpoint security property:** on the default path no user input
  influences the endpoint. The enrollment secret can only be sent to the
  URL compiled into the binary — a user cannot be typo-phished to a wrong
  server without deliberately choosing "own server" and typing a full
  URL themselves.
- Product fit: hosted-first with self-host as the alternative is exactly
  [ADR 0014]'s FluxVale-cloud-plus-self-host shape and [ADR 0015]'s
  positioning; the login form is that choice made visible.

### 3. The form

```text
$ pursecraft login
1) Log in to pursecraft.com — the hosted relay (https://pursecraft.com/api)
2) Use my own server
Choose [1]:
```

- **Enter or `1`** (the default): server = `DEFAULT_SERVER`; no typing, no
  derivation.
- **`2`**: the domain prompt — `Your relay domain (e.g. example.com or
  127.0.0.1:8099):` — then the derivation rule in §4.
- **Both screens show the final URL before anything secret is requested** —
  the choice line carries the constant, and the domain screen answers with
  `relay url: https://example.com/api` — so the endpoint is never a
  surprise. **The form lives on one descriptor**: the controlling terminal
  (`/dev/tty`, opened for reading and writing) — everything the form
  shows goes there, every answer (echoed lines and the hidden secret
  alike) is read from there, and the echo-off span (§6) rides the same
  tty. stdin's terminal-ness only decides whether the form runs at all, so
  a redirected stderr (`2>/dev/null`, a logging harness) can neither hide
  the questions nor split the conversation, and a stdin that happens to be
  a different terminal can neither capture the secret nor fragment it.
  Without a controlling terminal the lines fall back to stderr/stdin and
  the hidden read fails loudly. stdout keeps only the final
  `enrolled with <server> — capture is unlocked` line.
- **One shot, no loops.** Empty or unrecognized input is a teaching error
  (exit 1), not a re-prompt cycle: the same loud-on-ambiguity posture as
  every other parse in the CLI.

### 4. Derivation rule (deterministic; one candidate, never probed)

Applies only to the form's domain input — one line, trimmed:

1. **A typed scheme is the scheme used.** Input starting `http://` or
   `https://` is taken verbatim (validated, not interpreted). This is the
   deliberate escape hatch — 0029's rule, unchanged — and the *only* way a
   non-loopback plain-`http` relay is ever reached.
2. Otherwise the input is `host[:port]`, optionally with one typed prefix
   segment after a `/`. The host's class picks the scheme:
   - **Loopback** (`localhost` case-insensitive, `127.x.x.x`, `[::1]`/`::1`)
     → `http://…`, and **no prefix is added** (a local relay serves at the
     router root; `/api` is an edge-routing concern). A typed prefix is
     honored as typed (`127.0.0.1:8099/api`).
   - **Anything else** → `https://…` with prefix **`api`** unless one was
     typed (`example.com` → `https://example.com/api`;
     `example.com:8443` → `https://example.com:8443/api`;
     `example.com/relay` → `https://example.com/relay`).
3. The composed candidate is handed **unchanged** to `normalize_server`,
   which alone decides accept/reject with its existing grammar (charset,
   port range, one segment, no query/userinfo).

No silent downgrades: `http` is only ever *derived* for loopback, where no
TLS exists to downgrade from; every other host derives `https`. A
plain-http LAN relay (`192.168.1.10:8099`) therefore derives
`https://…/api`, whose probe fails as unreachable naming the URL, and the
form path's teaching says it plainly: `— derived from domain
"192.168.1.10:8099"; check the domain (the hosted relay is
pursecraft.com; plain-http relays are typed as their full url)`. Loud and
deliberate, never guessed.

**Classification is not validation.** The derivation inspects the input
only to pick scheme/prefix and to detect loopback; it validates nothing
(`127.0.0.1:zero` classifies as loopback and composes
`http://127.0.0.1:zero`, which `normalize_server` then rejects on the
port). The interactive layer never grows a second URL parser; a property
test pins `normalize_server(derive(x))` for every accepted row.

**"URLs" is one URL.** The derivation produces exactly one canonical server
string — the API base — and probes exactly it. No candidate list, no
fallback path, no web-app root: the (future) web app derives its own root
from the domain independently; inventing a discovery protocol here would be
scope the steer never asked for.

### 5. Fail-early: the fingerprint probe

After the server string is resolved — constant, flag, or form — and
normalized:

```text
GET <server>/v1/devices     (a route only a relay serves — the v1 wire contract, ADR 0024)
```

on the same strict chain as every other call ([ADR 0029]: no proxy lookup,
no followed redirects) but with **its own 5 s budget** — a pre-flight, not
a transfer: a typo'd or black-holed URL must not cost the enrollment
call's 30 s before it says so. The route is the discriminator: every real
relay — old image, new image, `/v1`-only proxy — answers **405 Method Not
Allowed** for a GET on a POST-only route, while every plain web host
answers 404; the fleet itself answers 405 at `/api/v1/devices`.

- **405 and any 2xx pass** — a relay is proven present BEFORE any secret
  is collected (tty) or consumed (pipe). A `/v1`-only edge enrolls exactly
  as it did before this probe existed.
- **404 fails early** — `the host at <server> answered 404 at /v1/devices
  — no relay serves this url` — every web server on the internet answers
  404, so this is exactly the mistyped-but-resolving domain the probe
  exists to stop: the secret never reaches a host that is not a relay.
- **Transport failure** (refused, DNS, TLS, timeout) fails early —
  `cannot reach the relay at http://127.0.0.1:9999 (io: Connection
  refused (os error 111)) — derived from domain "127.0.0.1:9999"; check
  the domain (the hosted relay is pursecraft.com; plain-http relays are
  typed as their full url)` on the form path; the URL-only prefix on the
  flag path.
- **A 3xx** fails early with [ADR 0029]'s redirect arm (destination named,
  never followed).
- **Another answered status** (5xx, odd 4xx) fails early — `the edge at
  <server> answered 503 at /v1/devices — something is listening there,
  but no healthy relay`.

The probe runs **exactly once per invocation and its result is never
cached** — not within the invocation, not across invocations; enrollment
always makes its own round-trip. A URL that passes the fingerprint and
still fails enrollment names the URL in every enrollment error shape —
bodiless (`status 404 from <server> without a relay error body`), JSON
envelope (`the relay at <server> answered 404 (not_found): no such
route`), and the teaching arms of [ADR 0025].

**Ordering, one rule on every path**: fingerprint first, then the secret —
nothing secret is collected or consumed until a relay answered, and the
tty path keeps echo off across the whole gap (§6). On failure the piped
secret's source is never called (the writer's pipe is left unread; a
producer may see EPIPE — POSIX pipe semantics, and the reason scripts
should feed the secret from a small producer or a file redirect).

### 6. The enrollment secret: no echo window, probe first, hidden read after

- **tty (form or `--server`)**: after the form's last echoed answer, echo
  goes OFF and stays off across the fingerprint probe — there is NO
  echo-on window from the start of the domain read to the end of the
  secret read. The probe runs inside the span (a dead or wrong relay says
  so BEFORE the secret is asked for, restoring echo on the way out); when
  it passes, the hidden read **drains everything that arrived meanwhile**
  (`tcflush`) — those bytes were never echoed and are discarded, never
  the secret — then reads one line hidden (`rpassword`, echo off, the
  same `/dev/tty`) and restores the terminal exactly as it was. The
  property is total: characters typed anywhere between the domain answer
  and the end of the hidden read are either echoed-when-harmless (before
  the span) or not echoed at all (inside it). An interrupted login can
  leave the terminal echo-off (`stty sane` restores) — the same exposure
  rpassword's own read has always had; the span merely lengthens it by
  the probe's ≤5 s.
- **non-tty**: the lazy piped source is first called after the
  fingerprint passes (§5) — first line, [ADR 0025]'s contract, byte for
  byte. Empty piped stdin keeps the teaching error.
- **Supply chain**: `rpassword` 7.5 (Apache-2.0, already allowed) does
  the hidden read; the echo-off span and drain are `nix`'s safe termios
  API (`tcgetattr`/`tcsetattr`/`tcflush` — this workspace forbids unsafe
  code, so the termios calls are not hand-rolled over libc). Off-unix the
  span is a no-op and rpassword's own hidden read is the whole guarantee
  (disclosed; the workspace ships Linux).

### 7. Injectability

The library never touches the process environment. `Context` grows one
seam — a terminal handle present only when stdin is a tty (`main.rs`:
`IsTerminal`), carrying `read_line(prompt)` and `read_secret(prompt)`.
`main.rs` wires the real handle (stdin lines; `rpassword`); tests script a
fake and assert the prompt *order*, not just the outcomes. Bare `login`
with no handle is the hosted default (§1); the form exists only behind a
handle.

## Tests

1. **Derivation unit table** (lib.rs): every row of §4 — bare domains,
   ports, typed prefixes, typed schemes verbatim, the loopback set
   (`localhost`/`Localhost`/`127.0.0.1`/`127.5.6.7`/`[::1]`), the LAN-https
   row — asserting the composed candidate *and* that `normalize_server`
   accepts it; refused-input rows assert the existing teaching messages.
2. **The constant pins**: `DEFAULT_SERVER` equals the deployed URL and
   `normalize_server(DEFAULT_SERVER)` round-trips.
3. **tty/non-tty behavior** (scripted terminal): bare `login` + handle →
   choice screen (Enter → hosted; `2` → domain prompt → derived line);
   bare `login` without a handle → hosted enrollment from piped stdin;
   `--server` + piped stdin → byte-identical today-behavior; `--server` +
   handle → hidden prompt; positional `login <url>` → exit 2 teaching.
4. **Fingerprint probe paths and budget**: dead port (error names URL +
   domain); the ADR's own typo case — a 404-answering stand-in host never
   sees a POST, never receives the secret, and the error names the typed
   domain (both form and piped paths); a `/v1`-only edge (405 at the
   fingerprint) still enrolls; the wrong-base-path URL fails EARLY at the
   fingerprint, URL named; a JSON-bodied 404 at enrollment names the URL
   (the status arm); a 5xx at the fingerprint teaches verbatim; a
   black-holed port fails on the probe's own short budget
   (elapsed « 30 s); the existing bodiless-308 raw-socket test — which
   now exercises the probe, message unchanged.
5. **Ordering, per path**: the piped source is provably never called on
   probe failure or invalid-`--server` (a recording closure and a
   panicking one); a timestamped scripted terminal plus a slow
   `/v1/devices` socket proves the probe's answer PRECEDES the hidden
   read and the probe runs exactly once; a dead relay never demands the
   secret and always restores echo (the transcript pins off→failure→on).
6. **The real binary under a real pty** (`script(1)`, the suite's
   `CARGO_BIN_EXE` harness): bare `login` shows the form (the tty branch
   is wired, not silently the hosted default) and the typed secret never
   appears in the capture (the hidden read is not an echoing one); a
   second pty test types a marker DURING a slow probe and asserts it is
   neither echoed in the capture nor delivered to the relay — the drain
   discarded it — while the real typed secret enrolls.
7. **Taught commands parse** (the P1 class): the gate's line, the 401
   re-enroll line, and the pairing bundle's login line are extracted from
   real output and fed to `argv::parse` — a teaching that exits 2 can
   never ship again.
8. **Live acceptance** (merge gate): the interactive form against
   `https://pursecraft.com/api` — domain path exercised per the issue,
   transcript with the enrollment secret redacted.

## Alternatives considered

- **Amending ADR 0029 in place** — rejected: its subject (transport,
  grammar, representation) is untouched and its review arc is closed; a UX
  layer would make a pinned document a moving target.
- **Domain-first form (the steer's first shape, same day)** — superseded by
  the owner's choice-first amendment: the hosted default deserves to be a
  visible, zero-typing option, not one correct typing of a domain field.
- **Keeping `login <url>` as a positional (compat)** — rejected: nothing has
  shipped; three accepted shapes teach worse than two.
- **`--server` accepting a bare domain (derivation for scripts)** —
  rejected: explicit configuration should be an explicit URL; derivation
  lives in exactly one place, and it is trivially reproducible in any shell.
- **Probing candidate paths/ports to "find" the relay** — rejected: one
  deterministic URL, one probe; discovery protocols are unrequested scope
  and a side-channel.
- **Re-prompt loops on bad input** — rejected: one shot, loud, rerun — the
  CLI's uniform parse posture.
- **stdin-only secret (no `rpassword`)** — rejected as the recommendation
  (echoed secrets in the primary UX) but kept as the documented fallback if
  a supply-chain gate fails.

## Consequences

- `pursecraft login` alone enrolls against the hosted relay — the product's
  front door — with the endpoint fixed by the binary on the default path.
- Self-host enrollment is `--server <full-url>` (scripts, LAN, plain-http)
  or the form's own-server path (domain-only, https-derived).
- Two new direct dependencies (`rpassword` + `rtoolbox`, Apache-2.0; and
  `nix` for the safe termios span, MIT — libc was already in the tree),
  for 66 → 68 compiled unix packages; deny/advisories gates re-run green
  as part of the lane.
- `session.json`'s shape is untouched — the server string is the same
  canonical form `normalize_server` already produces.
- The login surface gains terminal interactivity: tty detection, prompt
  ordering, echo-off spans, and secret echo become hostile-review surface
  for the delta (flagged for the reviewer), alongside the
  derivation/validation split.

## Implementation plan (lane)

- **Files**: `apps/cli/src/argv.rs` (`Login { server: Option<String> }` via
  `--server`; USAGE/HELP), `apps/cli/src/lib.rs` (`DEFAULT_SERVER`,
  `derive_server`, login rework, probe ordering, `LoginError` arms),
  `apps/cli/src/relay.rs` (`probe_health` on the strict agent),
  `apps/cli/src/main.rs` (`IsTerminal`, the terminal seam, `rpassword`),
  `apps/cli/Cargo.toml` (+rpassword), `apps/cli/tests/{sync,https}.rs`
  (mechanical `--server` migration + the new tests above). Docs: this ADR,
  back-links in 0025/0029, README index; terminal captures under
  `docs/screenshots/34/` at PR time.
- **Solo implementation post-go: declared.** Same class and size as the
  original solo slice this lane already ran; no worker slice wanted.
- **Gates**: every `scripts/ci/*` re-run green before diff-ready is claimed;
  delta hostile review launches on the opposite host (Synthetic) with the
  new surface named above; live transcript (then PR → CI green incl.
  `Wait for CI` + codecov → self-merge) after review closes.

## Done when (amended scope; mirrors issue #34)

1. `pursecraft login` (no argument) opens the form; **Enter enrolls against
   the hosted relay**, and the own-server path (`2` → typing just
   `pursecraft.com`) derives `https://pursecraft.com/api` and completes
   enrollment against the **live** relay; a capture + `sync` round-trips
   through it (transcript pasted, enrollment secret redacted).
2. Old shapes still behave via `--server`: `http://127.0.0.1:8099` (no
   path) works; query strings / garbage suffixes fail loudly; bare non-tty
   `login` enrolls hosted; positional `login <url>` teaches the two shapes
   (exit 2).
3. `scripts/ci/*` for every touched crate exit 0 (raw tails pasted) and PR
   CI is green including `Wait for CI` and the codecov checks.
4. This ADR exists (Status: Accepted) and the implementation matches it.
5. PR open against `main`: conventional title, `Closes #34`, no reviewers,
   no assignees, terminal captures of the form (choice screen, derived-URL
   line, a fail-early error) embedded in the body.
