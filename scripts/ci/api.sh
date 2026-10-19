#!/usr/bin/env bash
# API CI (ADR 0014): lint and test the Axum backend crate.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec scripts/ci/rust.sh pursecraft-api
