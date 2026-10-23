# 0019 — License: FSL-1.1-ALv2

- **Status:** Accepted
- **Date:** 2026-10-23
- **Ties together:** [ADR 0013](0013-deployment-topology.md),
  [ADR 0015](0015-product-positioning.md)

## Context

PurseCraft is built as a commercial product: a hosted SaaS offering, with
self-hosting available as a first-class path
([ADR 0013](0013-deployment-topology.md)). The license is a business decision
as much as a legal one: it must protect the hosted revenue, keep self-hosting
genuinely free, and stay consistent with the trust posture an end-to-end
encrypted money app needs — inspectable code, no ambiguity about what
self-hosters may do.

Portfolio convention (set with this decision): **products get FSL, tools get
MIT.** DashFloat, the internal harness succeeding an MIT-licensed tool, is
MIT; PurseCraft and FluxVale are products.

## Decision

License the repository under the **Functional Source License 1.1 with an
Apache-2.0 future grant** (FSL-1.1-ALv2), as added in PR #11. Concretely:

- Anyone may use, study, modify, self-host, and build on the software,
  including internal commercial use.
- The only restriction is offering a **competing service** — and it is
  temporary: each version becomes available under Apache-2.0 on the second
  anniversary of its release.

That is exactly the SaaS shape: the competing-use clause is the moat around
the hosted offering, while self-hosters get a perpetual free path (each
version's restriction expires) and the codebase stays inspectable.

## Alternatives considered

- **MIT** — no protection for a hosted revenue model; right for tools
  (DashFloat), wrong for products.
- **AGPL** (the broad "open-source YNAB alternative" slot's choice) — its
  network-copyleft mechanics scare exactly the enterprise self-hosters the
  wedge wants, and source-disclosure pressure is a different instrument from
  the explicit competing-use restriction a SaaS needs.
- **Closed source** — kills the self-host wedge and the inspectable-code
  trust story an E2EE money app depends on.

## Consequences

- The project is **source-available**, never described as open source
  (wording aligned across AGENTS.md and ADRs 0002/0013/0015, PR #13).
- The NOTICE carries the same OPC copyright holder as the rest of the
  portfolio.
- Future portfolio products default to FSL; tools default to MIT.
