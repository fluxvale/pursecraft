#!/usr/bin/env bash
# Dependency hygiene (issue #12): no unused dependencies in the workspace.
# --with-metadata: also resolve target-specific and build dependencies —
# plain mode false-greens on those (needs cargo on PATH).
set -euo pipefail
cd "$(dirname "$0")/../.."
exec cargo-machete --with-metadata
