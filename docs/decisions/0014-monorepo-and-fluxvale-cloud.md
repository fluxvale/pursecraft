# 0014 — Monorepo and FluxVale GitOps Cloud

- **Status:** Accepted
- **Date:** 2026-10-15
- **Extends:** [ADR 0013](0013-deployment-topology.md) (domains and
  single-image deployment unchanged; this ADR decides repo structure, CI shape,
  and who operates the cloud)

## Context

Pursecraft produces many deliverables from one shared core: API, web SPA,
desktop shell, iOS and Android apps, and the marketing site. Cross-cutting
changes — a sync-protocol tweak touching core, bindings, and two UIs — must
land atomically to avoid version skew.

The hosted cloud tier is operated by FluxVale alongside its other products
(e.g. Thalmyra), whose fleet runs GitOps: Flux watches a private fleet repo
([fluxvale/infrastructure](https://github.com/fluxvale/infrastructure)); app
repos hold zero cluster credentials. Fleet conventions (from that repo's README
and [fluxvale/thalmyra](https://github.com/fluxvale/thalmyra)): per-app
Kustomize overlays (`apps/<app>/{base,staging,production}`), app CI pushes
`sha-<sha>` images to GHCR, Flux image automation commits overlay tag bumps,
rollback = revert the PR (never `kubectl rollout undo`), secrets are BWS
(Bitwarden Secrets) references — never values, Postgres via the shared CNPG
cluster, Traefik IngressRoutes + cert-manager on Cloudflare DNS. The **why**
lives in the app repo's `docs/`, the **how-to-operate** in the fleet repo —
cross-link, never mirror.

## Decision

**Monorepo.** All apps live under `apps/`:

```text
apps/
  api/         Axum backend
  web/         React SPA (serves browser + Tauri desktop)
  desktop/     Tauri shell wrapping apps/web
  ios/         SwiftUI app
  android/     Jetpack Compose app
  marketing/   Astro site (pursecraft.com)
  cli/         `pursecraft` binary: CLI, `mcp`, `serve` (ADR 0012)
  core/        Rust workspace: budget engine, sync, persistence, bindings
docs/          ADRs + DEPLOYMENT.md runbook
scripts/ci/    per-app check scripts, one per CI job
Dockerfile     release image: builds api + WASM core + SPA, serves both on one port
compose.yaml   self-host quickstart: image + Postgres
```

All first-party code lives under `apps/`. `apps/core` is the library the other
apps consume — it ships inside them, never alone, and its only externally
visible surface is binding generation. CI implication, deliberate: a change to
`apps/core` is a **shared** path in the changes filter that triggers every
consuming app's job — never treated as a single-app change. The Rust apps
(`apps/api`, `apps/cli`) join `apps/core/crates/*` in one root Cargo workspace:
single lockfile, shared lints, one `cargo test` entry point.

Supporting conventions adopted from Thalmyra's monorepo (see its
`docs/decisions/00013-ci-pattern.md`):

- **One CI workflow** with a `dorny/paths-filter` changes job; per-app jobs
  gated on its outputs; an umbrella **"Wait for CI"** job that always runs and
  is the only required check — path-skipped apps can never leave a required
  check pending.
- **`mise.toml`** is the single source of truth for tool versions; CI parses
  it rather than duplicating pins.
- **Toolchain pins apply to Docker builds too** — the release image base must
  match `mise.toml`.

**Cloud under FluxVale GitOps.** The fleet repo gains
`apps/pursecraft/{base,staging,production}`:

- This repo's CI builds the release image on `main` and pushes
  `ghcr.io/fluxvale/pursecraft:sha-<sha>` (+ tags). The package is **public** —
  self-hosters pull the same image the cloud runs (per ADR 0013's dogfooding
  rule; the one divergence from Thalmyra, whose package is private).
- Flux image automation rewrites the overlay tags; staging
  (`staging.pursecraft.com`) and production (`app.pursecraft.com` /
  `api.pursecraft.com`) roll from one commit. Rollback = revert the PR in the
  fleet repo (manifests) or here (app code).
- DNS on Cloudflare; Traefik + cert-manager as per fleet conventions; Postgres
  from the shared CNPG cluster.
- Secrets: BWS references hold *infrastructure* credentials only (DB passwords,
  tokens). Budget keys never exist server-side — E2EE (ADR 0009) means the
  server stores ciphertext regardless.
- Pursecraft's own operate runbook lives at `docs/DEPLOYMENT.md`; DR specifics
  cross-link into the fleet repo's cold-start sequence.

## Alternatives considered

- **Polyrepo (one repo per app)** — rejected: cross-cutting changes would need
  synchronized PRs across repos; version skew between core and UIs becomes
  routine.
- **Separate infrastructure repo for Pursecraft's cloud** — rejected: the cloud
  is one more FluxVale-hosted product; duplicating fleet patterns per-product
  defeats them.
- **App repo deploys directly (CI with cluster credentials)** — rejected: the
  fleet holds all cluster access; Flux reasserts git state, so out-of-band
  deploys and `kubectl rollout undo` are forbidden by design.

## Consequences

- One PR can touch core, bindings, API, and UIs together — atomic by default.
- CI is a matrix gated by path filters; each app's checks live in one script
  (`scripts/ci/<app>.sh`) — which also satisfies local runs per AGENTS.md Rule 4
  (CI tools = local tools, same scripts).
- Xcode and Gradle projects live in-tree; UniFFI binding generation is wired
  into their build steps.
- Pursecraft's cloud ops are FluxVale's responsibility; the self-host path must
  never depend on FluxVale-internal tooling — only on the public image and this
  repo's docs.
