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
  additive: an llvm-cov defect must red the coverage step, never blur into
  the test result.
- **The upload rides the existing Core CI job** (FluxVale's shape) as a
  SHA-pinned `codecov/codecov-action` step with `flags: core` and
  `token: CODECOV_TOKEN`. A separate Coverage job would need the four-edit
  checklist from the workflow's extension comment plus its own toolchain
  setup and instrumented build, for the same report.
- **`fail_ci_if_error: true`** — the silent-upload watchdog. Without it a
  swallowed upload failure looks like passing CI with fresh coverage; with
  it, a codecov.io outage reds the step. Same deliberate tradeoff as
  FluxVale's upload step.
- **Root `codecov.yml`:** one flag per app (`core` today; api/cli get flags
  when they get code), per-flag project status with a 1% threshold, patch
  status `target: auto`, and `carryforward: false` so a flag reports only
  when its path-gated job ran — the same shape as the workflow itself.

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
  component before the script works (ADR 0014 parity).
- Codecov statuses post as check runs but are not required checks — branch
  protection still requires only "Wait for CI". A red coverage status
  signals; it does not block. Tightening that is a repo-settings change,
  not a code change.
- Doctests are not instrumented (stable-toolchain limitation) — the report
  measures the binaries cargo-llvm-cov runs.
