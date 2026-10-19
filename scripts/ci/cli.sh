#!/usr/bin/env bash
# CLI CI (ADR 0014): lint and test the `pursecraft` CLI crate.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/ci/rust.sh pursecraft-cli
