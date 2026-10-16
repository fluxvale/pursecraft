#!/usr/bin/env bash
# Core CI (ADR 0014): lint and test the shared Rust core.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/ci/rust.sh pursecraft-core
