#!/usr/bin/env bash
# Dependency hygiene (issue #12): no unused dependencies in the workspace.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec cargo-machete
