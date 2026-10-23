#!/usr/bin/env bash
# Shared per-package Rust checks (ADR 0014: CI runs the same scripts as local).
set -euo pipefail

pkg="$1"

cargo fmt -p "$pkg" --check
cargo clippy -p "$pkg" --all-targets -- -D warnings
# --no-deps: lint our docs only; third-party doc warnings aren't ours to fix.
RUSTDOCFLAGS="-D warnings" cargo doc -p "$pkg" --no-deps
cargo test -p "$pkg"
