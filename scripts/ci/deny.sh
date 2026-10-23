#!/usr/bin/env bash
# Supply-chain CI (issue #12): RustSec advisories + license allow-list
# (deny.toml) over the workspace dependency tree.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec cargo-deny check advisories licenses
