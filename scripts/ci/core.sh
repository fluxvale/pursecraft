#!/usr/bin/env bash
# Core CI (ADR 0014): lint and test the shared Rust core — every crate under
# apps/core/crates/*, enumerated from the workspace so a new member can never
# land unchecked (its name is not hardcoded here).
set -euo pipefail
cd "$(dirname "$0")/../.."
# pwd -P: cargo metadata reports canonical paths — a symlinked checkout's
# logical $PWD would match nothing and die below.
mapfile -t pkgs < <(cargo metadata --format-version 1 --no-deps \
  | jq -r --arg root "$(pwd -P)/apps/core/crates" \
      '.packages[] | select(.manifest_path | startswith($root + "/")) | .name')
if [[ ${#pkgs[@]} -eq 0 ]]; then
  echo "scripts/ci/core.sh: no workspace members matched under apps/core/crates (pwd -P: $(pwd -P))" >&2
  exit 1
fi
exec scripts/ci/rust.sh "${pkgs[@]}"
