# 0020 — Codecov coverage reporting and per-flag gates

- **Status:** Accepted
- **Date:** 2026-10-24
- **Extends:** [ADR 0014](0014-monorepo-and-fluxvale-cloud.md) (mise.toml as
  the single version source; CI runs the same scripts as local)

## Context

Three core slices are in and CI is comprehensive (#12), but nothing measures
or reports test coverage. Issue #17 adds coverage through Codecov.io. The
pattern is proven in the sibling [fluxvale/fluxvale](https://github.com/fluxvale/fluxvale)
repo (upload riding the platform CI job, per-flag statuses, a root
`codecov.yml`); this ADR records the Rust-side transfer. The
`CODECOV_TOKEN` repository secret is already set.

## Decision

- **`cargo-llvm-cov`** (taiki-e) generates an lcov report for the core
  crates. It is maintained, runs on the pinned stable toolchain, and emits
  the lcov format Codecov ingests. Pinned in `mise.toml` together with the
  `llvm-tools-preview` rustup component it needs (`llvm-profdata`); the CI
  job installs the same versions parsed from the same file (ADR 0014).
- **Generation lives at the end of `scripts/ci/core.sh`**, after the
  unchanged checks: the suite runs a second time under instrumentation to
  produce `target/coverage/core.lcov`. The check itself stays literally
  `cargo test` — coverage is reporting, not a check, and stays strictly
  additive: an llvm-cov defect fails its own command after the checks have
  run, never the test result itself.
- **The upload rides the existing Core CI job** (FluxVale's shape) as a
  SHA-pinned `codecov/codecov-action` step with `flags: core` and the
  `CODECOV_TOKEN` secret (referenced, never stored in-repo). A separate
  Coverage job would need the four-edit checklist from the workflow's
  extension comment plus its own toolchain setup and instrumented build,
  for the same report.
- **`fail_ci_if_error` is the silent-upload watchdog**, armed wherever the
  token is (same-repo PRs and main pushes): a swallowed upload failure must
  not look like passing CI with fresh coverage, and a codecov.io outage
  reds the step. Fork PRs get no secret access and upload tokenless, so the
  watchdog is disarmed for them — an external contributor is never blocked
  by an upload they cannot authorize.
- **Root `codecov.yml`:** one flag per app (`core` today; api/cli get flags
  when they get code), a per-flag project status with a 1% threshold and a
  per-flag patch status with `target: auto`, and `carryforward: false` so a
  flag reports only when its path-gated job ran — the same shape as the
  workflow itself. Reliability hierarchy, deliberate: the patch status is
  the always-armed gate; the project status is best-effort (it needs
  base-commit data for the flag — see Consequences).

## Alternatives considered

- **A separate Coverage CI job** — rejected: four checklist edits and a
  second toolchain setup + instrumented build, for a report the Core job
  already produces in-place.
- **Making the instrumented run THE test step** (one `cargo llvm-cov`
  instead of `cargo test`) — rejected: couples the #12 test check to report
  generation. The double run costs minutes on a free public-repo runner.
- **tarpaulin / kcov** — rejected: narrower platform support and weaker
  maintenance records than cargo-llvm-cov.

## Consequences

- Core CI (and a local `scripts/ci/core.sh`) runs the suite twice: plain,
  then instrumented. `mise install` must have fetched the tool and the
  component before the script works (ADR 0014 parity; the component list is
  mirrored in the workflow's toolchain step — keep the two in sync).
- Codecov statuses post as check runs but are not required checks — branch
  protection still requires only "Wait for CI". A red coverage status
  signals; it does not block. Tightening that is a repo-settings change,
  not a code change.
- A per-flag project status only posts when the flag has base-commit data:
  with `carryforward: false` and path-gated uploads, a base commit that
  skipped the job leaves nothing to compare against (observed on
  fluxvale/fluxvale, whose identical shape posts only
  `codecov/patch/<flag>`). The patch status is the always-armed gate — a
  coverage drop reds there.
- Until base data exists on main (and on any later main stretch that skipped
  the core job), pure deletions — removing tests or code, adding no new
  lines — pass the patch gate vacuously and gate nothing; the project
  status covers exactly those, and only where its base data exists.
- Doctests are not instrumented (stable-toolchain limitation) — the report
  measures the binaries cargo-llvm-cov runs.
