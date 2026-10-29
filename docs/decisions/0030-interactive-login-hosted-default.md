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
  today. No derivation applies to the flag: explicit configuration is an
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
  surprise. Prompts go to stderr; stdout keeps only the final
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
`https://…/api`, whose probe fails with a teaching error that says a
plain-http self-hosted relay must be typed with its full URL — loud and
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

### 5. Fail-early: probe before any secret

After the server string is resolved — constant, flag, or form — and
normalized, and **before any secret is requested or read**:

```text
GET <server>/health     (the relay's unauthenticated liveness route, ADR 0026)
```

through the same strict agent as every other call ([ADR 0029]: no proxy
lookup, no followed redirects, 30 s cap). **Any 2xx passes**; anything else
fails enrollment immediately with an error that **names the final URL** (and,
on the form path, the domain it came from), so a typo is obvious:

- unreachable — `cannot reach https://pursecraf.com/api (…); derived from
  domain "pursecraf.com" — check the domain (the hosted relay is
  pursecraft.com)`;
- a non-2xx status — `the relay at https://host/api answered 404 at
  /health — wrong domain or base path?` (a wrong prefix looks exactly like
  this);
- a 3xx — [ADR 0029]'s redirect arm, which names the destination and says
  redirects are never followed (a plain-`http` probe of the fleet's edge
  earns the bodiless 308 this catches).

The probe runs on **every** path, `--server` included: `login` is already
inherently online (enrollment is a network call), so the probe adds no new
failure mode — it moves the typo diagnosis ahead of the secret and costs
one GET on a path that already round-trips.

### 6. The enrollment secret: hidden prompt on a tty, first line of stdin otherwise

- **tty (either path — form or `--server`): a hidden-input prompt**
  (`enrollment secret:`) via `rpassword` 7.5 — typed characters are not
  echoed to the terminal or scrollback. Recommended over stdin-only: the
  form exists for humans, and the current to-EOF stdin read echoes a typed
  secret in cleartext — the exact leak an interactive login should close.
  Supply chain: `rpassword` is Apache-2.0 (already in deny.toml's allow
  list) and adds exactly two compiled packages on unix (`rpassword`,
  `rtoolbox`; `libc` already ships via ring) — `cargo deny` gates must stay
  green, and if one surprises, the documented fallback is stdin-only, not a
  hand-rolled termios.
- **non-tty: unchanged** — the secret is the first line of piped stdin,
  exactly ADR 0025's behavior; `--server` scripts and the whole existing
  test suite keep their contract. Empty piped stdin keeps today's teaching
  error (after the probe, per §5's ordering).

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
4. **Health-probe paths**: dead port (error names URL + domain), a relay
   serving at root probed under `/api` (404 teaching), and the existing
   bodiless-308 raw-socket test — which now exercises the probe, message
   unchanged.
5. **Ordering**: an unreachable server plus a scripted terminal asserts the
   secret prompt is never reached (probe fails first) — the fail-early
   contract as a behavioral test, not a code-reading claim.
6. **Live acceptance** (merge gate): the interactive form against
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
- One new direct dependency (`rpassword`, Apache-2.0, +2 compiled packages
  on unix); deny/advisories gates re-run green as part of the lane.
- `session.json`'s shape is untouched — the server string is the same
  canonical form `normalize_server` already produces.
- The login surface gains terminal interactivity: tty detection, prompt
  ordering, and secret echo become hostile-review surface for the delta
  (flagged for the reviewer), alongside the derivation/validation split.

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
