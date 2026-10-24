#!/usr/bin/env bash
# Dependency hygiene (issue #12): no unused dependencies in the workspace.
# --with-metadata: also resolve target-specific and build dependencies —
# plain mode false-greens on those (needs cargo on PATH).
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo-machete --with-metadata
# deny.sh has --locked; machete has no such flag, and --with-metadata would
# silently rewrite (and grade) a stale Cargo.lock instead. Fail on rewrite
# (HEAD: staged rewrites count too).
git diff --exit-code HEAD -- Cargo.lock
