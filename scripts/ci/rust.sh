#!/usr/bin/env bash
# Shared per-package Rust checks (ADR 0014: CI runs the same scripts as local).
# Takes one or more package names; every check runs for all of them at once,
# so a workspace member can never be silently skipped.
set -euo pipefail

pkgs=()
for pkg in "$@"; do pkgs+=(-p "$pkg"); done

cargo fmt "${pkgs[@]}" --check
cargo clippy "${pkgs[@]}" --all-targets -- -D warnings
# --no-deps: lint our docs only; third-party doc warnings aren't ours to fix.
# --document-private-items: internal docs break too (free — tree is clean).
RUSTDOCFLAGS="-D warnings" cargo doc "${pkgs[@]}" --no-deps --document-private-items
cargo test "${pkgs[@]}"
