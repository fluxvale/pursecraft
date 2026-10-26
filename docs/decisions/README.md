# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for Pursecraft.

## Format

Each ADR uses a lightweight Nygard-style format:

- **Status** — Accepted / Superseded / Deprecated
- **Date** — when the decision was made
- **Context** — the forces at play and the problem being solved
- **Decision** — what we chose
- **Alternatives considered** — what we rejected and why
- **Consequences** — what this decision implies, including trade-offs

## Numbering

Files are prefixed with a 4-digit padded, zero-based sequence number (`0001-...`).
Numbers are never reused. Superseded ADRs keep their number and gain a link to
their replacement.

## Index

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](0001-shared-rust-core.md) | Shared Rust core across all platforms | Accepted |
| [0002](0002-rust-backend-over-elixir.md) | Rust (Axum) backend over Elixir | Accepted |
| [0003](0003-native-mobile-over-flutter.md) | Native mobile (SwiftUI + Jetpack Compose) over Flutter | Accepted |
| [0004](0004-tauri-for-desktop.md) | Tauri for desktop | Accepted |
| [0005](0005-react-spa-for-web.md) | React SPA for web, no SSR | Accepted |
| [0006](0006-integer-money.md) | Money as integers (milliunits) | Accepted |
| [0007](0007-oplog-sync-protocol.md) | YNAB-style op-log sync protocol | Accepted |
| [0008](0008-multiuser-day-one.md) | Multi-user budgets from day one | Accepted |
| [0009](0009-e2ee-opaque-payloads.md) | E2EE with opaque server payloads | Accepted |
| [0010](0010-no-bank-import.md) | No bank import — manual-first | Accepted |
| [0011](0011-capture-first-mobile.md) | Capture-first mobile scope | Accepted |
| [0012](0012-api-ecosystem.md) | CLI, MCP, webhooks, and direct API access | Accepted |
| [0013](0013-deployment-topology.md) | Domains, hosting, and single-image deployment | Accepted |
| [0014](0014-monorepo-and-fluxvale-cloud.md) | Monorepo layout and FluxVale-hosted cloud | Accepted |
| [0015](0015-product-positioning.md) | Product positioning: local-first and E2EE | Accepted |
| [0016](0016-core-domain-model.md) | Core domain model: entities, fields, and op mapping | Accepted |
| [0017](0017-core-sync-engine.md) | Core sync engine: canonical log, sync sessions, and the op wire format | Accepted |
| [0018](0018-local-oplog-store.md) | Durable local oplog store | Accepted |
| [0019](0019-license-fsl.md) | License: FSL-1.1-ALv2 (source-available, SaaS + self-host) | Accepted |
| [0020](0020-codecov-coverage.md) | Codecov coverage reporting and per-flag gates | Accepted |
| [0021](0021-organizations-own-budgets.md) | Organizations own budgets: personal-org-per-user, memberships with roles | Accepted |
| [0022](0022-client-side-e2ee.md) | Client-side E2EE: envelope encryption over the payload choke point | Accepted |
| [0023](0023-capture-cli.md) | Capture CLI: fast local transaction capture | Accepted |
| [0024](0024-rendezvous-sync-relay.md) | Rendezvous sync relay: HTTP delta relay on apps/api | Accepted |
| [0025](0025-authenticated-first-clients.md) | Authenticated-first clients: enrollment gate and first sync | Accepted |
| [0026](0026-relay-containerization.md) | Relay containerization: one image, two-route health, bounded drain | Accepted |
