#!/usr/bin/env bash
# Core CI (ADR 0014): lint and test the shared Rust core — every crate under
# apps/core/crates/*, enumerated from the workspace so a new member can never
# land unchecked (its name is not hardcoded here).
set -euo pipefail
cd "$(dirname "$0")/../.."
mapfile -t pkgs < <(cargo metadata --format-version 1 --no-deps \
  | jq -r --arg root "$PWD/apps/core/crates" \
      '.packages[] | select(.manifest_path | startswith($root + "/")) | .name')
test "${#pkgs[@]}" -gt 0
exec scripts/ci/rust.sh "${pkgs[@]}"
