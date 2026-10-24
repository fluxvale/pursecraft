#!/usr/bin/env bash
# Supply-chain CI (issue #12): RustSec advisories + license allow-list
# (deny.toml) over the workspace dependency tree. --locked: grade the
# committed Cargo.lock, never a fresh resolution the PR didn't ship.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec cargo-deny --locked check advisories licenses
