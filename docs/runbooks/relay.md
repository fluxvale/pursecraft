# Relay Runbook: Image, Deploy, Health, Shutdown

Operational reference for the rendezvous relay's container image
([ADR 0024] for the service, [ADR 0026] for this deployment shape).
Product-side only — cluster manifests live in the fleet repo
(`fluxvale/infrastructure`, Flux + Traefik + cert-manager).

## Image

- `ghcr.io/fluxvale/pursecraft` — one image, the `pursecraft-api` binary.
- Multi-stage: `rust:<mise-pin>-bookworm` builder (digest-pinned in the
  [Dockerfile](../../Dockerfile); CI asserts the pin matches
  [mise.toml](../../mise.toml)), `distroless/cc-debian12:nonroot` runtime
  (non-root UID 65532, no shell).
- Platform `linux/amd64`. Exec-form entrypoint: the relay is PID 1 and
  receives SIGTERM directly.
- Public package (FSL source, [ADR 0019]); **nothing secret is baked in** —
  secrets the relay itself needs are none; cluster-side secrets (TLS, etc.)
  come from the fleet's secret store.

### Tags

| Tag | Written by | Meaning |
| --- | --- | --- |
| `sha-<commit>` | every publish | Immutable per-commit image; pin these for rollouts and rollbacks |
| `latest` | main merges only | The head of `main`; what Flux image-automation follows, digest-pinned |

### Pipeline (CI `release-image` job)

- **Main merges** with image inputs changed (`Dockerfile`, `apps/api`,
  `apps/core`, workspace manifests, `mise.toml`, the workflow) — after the
  API CI suite is green: builds, pushes `sha-<sha>` + `latest`, provenance
  attestation `mode=min`.
- **Manual dispatch** with the `push-image` input — pushes `sha-<sha>`
  *only*, from any branch whose image inputs differ from `main`. This is
  the bootstrap/candidate path (e.g. the fleet lane deploying a
  pre-merge candidate). `latest` never moves on a dispatch. Footgun:
  dispatching *from main itself* compares main's last commit against its
  parent — if that commit didn't touch the image inputs, the job
  silently skips; dispatch from the branch whose changes you want built.

### One-time setup (owner)

1. The first push creates the package linked to this repo (a
   `GITHUB_TOKEN` push links it automatically).
2. Flip the package to **public**: package → settings → danger zone →
   change visibility. CI cannot do this; it is a one-click manual step.

## Environment contract

| Variable | Default (dev) | In the image | Meaning |
| --- | --- | --- | --- |
| `PURSECRAFT_DATA_DIR` | `data` (cwd-relative) | `/var/lib/pursecraft` | The relay's whole state ([ADR 0024]): `auth.json`, `enrollment.secret`, `logs/*.pcoplog`. Mount the fleet's PVC (or docker `-v`) here |
| `PURSECRAFT_BIND` | `127.0.0.1:8080` | `0.0.0.0:8080` | Listen address; container port `8080` |

One process per data directory ([ADR 0024]) — single-replica Deployment
with a ReadWriteOnce PVC is the shape; do not scale replicas against one
volume.

Volume ownership: the runtime user is 65532 — give the mount write access
(e.g. `securityContext.fsGroup: 65532`) or the readiness probe will
(rightly) report 503.

First boot writes `enrollment.secret` (mode 0600) into the data dir —
read it once, keep it off the network ([ADR 0024]).

## Health contract (the fleet's two-route shape)

| Route | Role | Behavior |
| --- | --- | --- |
| `GET /health` | Liveness | `200 {"status":"ok"}` unconditionally; touches nothing |
| `GET /health/ready` | Readiness | `200 {"status":"ready"}` when a write+fsync probe into both on-disk homes (data dir, `logs/`) succeeds; `503 {"status":"unavailable"}` otherwise (detail only in server logs) |

Probe results are cached for one second (an honest durable write must not
be an fsync firehose on a public listener); a failing store is still
reported well inside the fleet's 5s probe cadence.

Suggested probes (mirroring the fleet's other apps): startup
`/health` 5s × 30; readiness `/health/ready` 5s period, 3s timeout,
failureThreshold 2; liveness `/health` 10s.

Semantics when the data dir is unwritable (read-only volume, full disk,
wrong directory ownership): readiness fails, liveness stays green — the
pod leaves the Service endpoints but is **not** restarted, because a
restart cannot fix a volume ([ADR 0026]). The canary is directory-level:
per-file damage inside a writable directory (a root-owned log file, a
partial restore) still fails loudly as a 500 at request time, per
[ADR 0024]'s contract. One deliberate asymmetry, exactly stated: with
`logs/` deleted at runtime, already-open stores keep serving from their
open file handles — appends even *ghost-ack* onto the unlinked inode
(the 200 describes data that dies with the process; the next boot
recreates the log from sequence 1) — while readiness reports 503 and
pulls the pod, bounding that ghost window. Readiness errs unavailable,
never available. The probe writes `health.probe` files in both
directories; their mtimes are the last successful probe (a stray entry
shaped like `health.probe` fails the probe too — the safe direction).

## Shutdown contract

SIGTERM (or SIGINT): the listener closes immediately; in-flight requests
drain up to **25 s** — inside the fleet's default 30 s termination grace,
so the process exits on its own terms and is never SIGKILLed mid-fsync.
An overrun exits 0 and logs; the next boot repairs any torn tail
([ADR 0018]). Nothing is buffered: appends commit per-op under the
request and the auth db commits before acknowledging ([ADR 0024]), so a
drained request leaves nothing half-written. Keep the deployment's
`terminationGracePeriodSeconds` ≥ 30.

## Self-host quick start

```sh
docker run -d --name pursecraft \
  -p 8080:8080 \
  -v pursecraft-data:/var/lib/pursecraft \
  ghcr.io/fluxvale/pursecraft:latest
# the secret is written at boot — wait for liveness before reading it
# (the runtime image has no shell, so copy the secret out to read it once)
until curl -sf http://localhost:8080/health >/dev/null; do sleep 1; done
docker cp pursecraft:/var/lib/pursecraft/enrollment.secret ./enrollment.secret
```

Building locally (no Docker required for development — `cargo run -p
pursecraft-api` from the repo root is the dev loop):

```sh
docker build -t pursecraft-relay .
```

[ADR 0018]: ../decisions/0018-local-oplog-store.md
[ADR 0019]: ../decisions/0019-license-fsl.md
[ADR 0024]: ../decisions/0024-rendezvous-sync-relay.md
[ADR 0026]: ../decisions/0026-relay-containerization.md
