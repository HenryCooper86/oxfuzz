#!/usr/bin/env bash
# oxfuzz -- production sandbox health check
# Delegates readiness derivation to hf-service through the CLI.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "${OXFUZZ_FUZZ_BIN:-}" ]]; then
    CLI="$OXFUZZ_FUZZ_BIN"
elif command -v oxfuzz >/dev/null 2>&1; then
    CLI="$(command -v oxfuzz)"
elif [[ -x "$ROOT_DIR/target/release/oxfuzz" ]]; then
    CLI="$ROOT_DIR/target/release/oxfuzz"
elif [[ -x "$ROOT_DIR/target/debug/oxfuzz" ]]; then
    CLI="$ROOT_DIR/target/debug/oxfuzz"
else
    echo "MISSING  oxfuzz CLI (run: ./scripts/build-release.sh)" >&2
    exit 1
fi

exec "$CLI" doctor "$@"
