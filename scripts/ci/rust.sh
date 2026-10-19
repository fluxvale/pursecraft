#!/usr/bin/env bash
# Shared per-package Rust checks (ADR 0014: CI runs the same scripts as local).
set -euo pipefail

pkg="$1"

cargo fmt -p "$pkg" --check
cargo clippy -p "$pkg" --all-targets -- -D warnings
cargo test -p "$pkg"
