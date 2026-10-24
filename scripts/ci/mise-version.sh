#!/usr/bin/env bash
# Parse a tool version out of mise.toml — the single source of truth CI reads
# (ADR 0014). One parser shared by every CI job (AGENTS.md rule 7), so the
# extraction can never drift between them. The rust line accepts both forms:
# plain ("x") and a single-line table with components (a reformat to a
# multi-line table yields nothing and the caller's test -n fails loudly).
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $# -eq 1 ]] || { echo "usage: scripts/ci/mise-version.sh <tool-key>" >&2; exit 2; }
key="$1"
if [[ $key == rust ]]; then
  sed -n 's/^rust *= *\({ *version *= *\)\?"\([^"]*\)".*/\2/p' mise.toml | head -n1
else
  sed -n "s|^\"$key\" *= *\"\([^\"]*\)\".*|\1|p" mise.toml | head -n1
fi
