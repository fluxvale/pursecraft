# 0026 — Relay Containerization: One Image, Two-Route Health, Bounded Drain

- **Status:** Accepted
- **Date:** 2026-10-26
- **Builds on:** [ADR 0013](0013-deployment-topology.md),
  [ADR 0018](0018-local-oplog-store.md),
  [ADR 0024](0024-rendezvous-sync-relay.md)
- **Issue:** [#27](https://github.com/fluxvale/pursecraft/issues/27)

## Context

The relay ([ADR 0024]) runs today as a bare `cargo run` process. The owner's
fleet is the `fluxvale/infrastructure` GitOps repo (Flux + Traefik +
cert-manager), whose deployments follow the Thalmyra pattern: app-repo CI
pushes `sha-<sha>` + `latest` to GHCR; Flux image-automation follows
`latest` digest-pinned. Issue #27 lands the product-side half — the image,
its publish pipeline, the fleet's two-route health contract, and SIGTERM
drain — with the fleet-side manifests a separate lane. Settled by the owner
(Oct 26): one public package, `ghcr.io/fluxvale/pursecraft`, running the
relay binary; nothing secret ships in the image (this repo is source
available, [ADR 0019]; runtime secrets come from the cluster's store).

## Decision

### Image: multi-stage glibc, distroless runtime, non-root

Builder `rust:<version>-bookworm`, digest-pinned, where `<version>` is
exactly [mise.toml](../../mise.toml)'s Rust pin — a CI step asserts the
match, same as Thalmyra's BEAM-pin assertion, so the pin rule
([ADR 0014]'s one version source) holds. Runtime
`distroless/cc-debian12:nonroot`: same Debian release as the builder (glibc
parity — a binary linked against a newer glibc must not meet an older one
in production), no shell or package manager to attack, non-root by default
(UID 65532). `cargo build --locked --release`, the binary stripped, exec-form
`ENTRYPOINT` so the process is PID 1 and receives SIGTERM directly. One
platform (`linux/amd64`) — the fleet's nodes; multi-arch waits for a
non-amd64 consumer.

### Publish: a job in the one CI workflow, `latest` moves only on main

A `release-image` job in the monorepo CI workflow ([ADR 0014]'s one
workflow), gated `push to main && image inputs changed` and `needs: api`
(the suite that vets the baked code — the docker paths filter is a subset
of the api filter, so the need can never be skipped under the gate).
Tags `sha-<sha>` + `latest` on main merges; `GITHUB_TOKEN` with
`packages: write`; provenance `mode=min` (free with buildx, attests the
build without extra machinery). A `workflow_dispatch` input pushes
`sha-<sha>` **only** — the bootstrap path that lets the fleet lane deploy a
candidate image before the product lane merges, and the pre-merge
verification that the image actually builds and pushes; `latest` never
moves off a merge, preserving the Thalmyra contract. The first push creates
the package and links it to this repo automatically (a `GITHUB_TOKEN`
creation does); flipping the package to **public** is a one-time manual
step for the owner — no token available to CI may set visibility.

### Health: two routes, liveness dependency-free, readiness is a write probe

Mirroring the fleet's platform shape (the same two routes its deployments
probe): `GET /health` is liveness and touches nothing — a store blip must
pull the pod from rotation, never restart-storm it. `GET /health/ready` is
readiness and reflects the store's *actual* health: a write-then-fsync
probe into each on-disk home (the data directory for `auth.json`, `logs/`
for the scope logs — [ADR 0024]'s whole durable state). It is a
**directory-level canary**: it fails exactly when no write to those
directories could succeed — an unwritable data dir (read-only volume, full
disk, lost directory ownership) answers 503 and keeps answering 503 until
the filesystem recovers. Per-file damage inside a still-writable
directory (a root-owned or mode-0444 log file, an operator's partial
restore) does not fail the canary — it stays loud at request time as a
500, the [ADR 0024] contract; probing a real log file would mean writing
into it, which no probe may do. One deliberate asymmetry: with `logs/`
deleted at runtime, already-open stores keep serving until their next
write while readiness reports 503 — readiness errs unavailable, never
available. Because the probe is an honest durable write, its result is
cached for one second: the route cannot be used as an fsync firehose,
while a failing store is still reported well inside the fleet's 5 s probe
cadence. The pod leaves the Service endpoints but is not restarted — a
restart cannot fix a volume.

### Graceful shutdown: drain bounded inside the fleet's termination grace

SIGTERM/SIGINT stops the listener and drains in-flight requests for at
most **25 s**, sized inside the fleet's 30 s termination grace so the
process always exits on its own terms — never by SIGKILL mid-fsync. The
drain needs no flush hook by construction: appends commit per-op under the
request ([ADR 0024]), and the auth database commits before it acknowledges
([ADR 0024]) — nothing is buffered anywhere. The two-phase commit marker
([ADR 0018]) is safe at *any* interruption point (a pending marker grants
nothing; boot repairs the torn tail), so draining narrows only the
client-visible unacked window; a drain overrunning its window exits 0 and
lets the crash-repair path do exactly what it was designed for.

### Data directory: env-configured as before, absolute in the image

`PURSECRAFT_DATA_DIR` keeps its `data` default for dev; the image sets it
to `/var/lib/pursecraft` (a `VOLUME`, the mount point for the fleet's PVC —
[ADR 0024]: the data directory is the relay's whole state). `PURSECRAFT_BIND`
keeps its `127.0.0.1:8080` dev default; the image overrides `0.0.0.0:8080`.
The env contract and operational details live in
[the relay runbook](../runbooks/relay.md).

## Alternatives considered

- **Alpine/musl static binary on scratch** — rejected: a second target
  toolchain in every build for zero household-scale gain; glibc bookworm +
  distroless is the same minimal surface with the primary toolchain.
- **`debian:bookworm-slim` runtime** — rejected: a shell and apt in the
  production image buy debugging convenience the fleet already has via
  ephemeral debug containers.
- **A second workflow file for publishing** — rejected: [ADR 0014] keeps
  one workflow; the paths-filter + umbrella pattern extends to the image
  job (the workflow's own four-edit checklist).
- **`latest` on dispatch too** — rejected: breaks the Thalmyra contract
  (`latest` = main's head, what Flux follows); candidate images are exactly
  what the immutable `sha-<sha>` tags exist for.
- **Readiness as an internal health flag** — rejected: a flag reports what
  the process believes, not what the filesystem does; only a write probe
  exercises the failure mode readiness exists to catch.
- **Per-file probing of the real store paths** — rejected: proving a log
  file is appendable requires writing to it, which no probe may do; the
  directory canary plus request-time loud failure is the honest pair.
- **Liveness reflecting the store** — rejected: a read-only volume would
  crash-loop the pod out of rotation *and* out of sight; 503 readiness on a
  live process keeps the failure observable.
- **Unbounded drain (trust the 30 s SIGKILL)** — rejected: a self-bounded
  window exits cleanly inside the grace period and logs the overrun instead
  of dying mid-fsync at an arbitrary point.

## Consequences

- `ghcr.io/fluxvale/pursecraft` builds only in CI — local iteration needs
  no Docker; the dispatch path exercises the real pipeline pre-merge.
- The fleet lane can point manifests at a `sha-<sha>` image the moment
  this branch's dispatch pushes one, before the PR merges.
- The owner flips the package public once, after first push (runbook step).
- Image rebuilds happen only in CI: any source change busts the (single)
  expensive build layer, so most publishes are a full release build
  (minutes, accepted on main merges); dependency pre-build layering was
  rejected as complexity the publish cadence does not need yet.
- Health probes write two tiny files per probe — fsync-bound and
  deliberate: the probe must cost what a real append costs or it lies.
  The one-second result cache bounds that cost against hostile clients.
