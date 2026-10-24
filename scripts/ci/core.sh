#!/usr/bin/env bash
# Core CI (ADR 0014): lint and test the shared Rust core — every crate under
# apps/core/crates/*, enumerated from the workspace so a new member can never
# land unchecked (its name is not hardcoded here). After the checks, the same
# suite runs once more under cargo-llvm-cov (pinned in mise.toml) to emit the
# lcov report the CI's Codecov step uploads (ADR 0020).
set -euo pipefail
cd "$(dirname "$0")/../.."
# pwd -P: cargo metadata reports canonical paths — a symlinked checkout's
# logical $PWD would match nothing and die below.
mapfile -t pkgs < <(cargo metadata --format-version 1 --no-deps \
  | jq -r --arg root "$(pwd -P)/apps/core/crates" \
      '.packages[] | select(.manifest_path | startswith($root + "/")) | .name')
if [[ ${#pkgs[@]} -eq 0 ]]; then
  echo "scripts/ci/core.sh: no workspace members matched under apps/core/crates (is jq installed? pwd -P: $(pwd -P))" >&2
  exit 1
fi
scripts/ci/rust.sh "${pkgs[@]}"
# Coverage (ADR 0020): reporting only — the checks above stay literally
# `cargo test`. The -p set mirrors rust.sh's so api/cli workspace members
# can never leak into the `core` flag's report.
cov_pkgs=(); for pkg in "${pkgs[@]}"; do cov_pkgs+=(-p "$pkg"); done
mkdir -p target/coverage
cargo llvm-cov --lcov --output-path target/coverage/core.lcov "${cov_pkgs[@]}"
