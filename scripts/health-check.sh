#!/usr/bin/env bash
# hobot_fuzz -- production sandbox health check
# Delegates readiness derivation to hf-service through the CLI.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "${HOBOT_FUZZ_BIN:-}" ]]; then
    CLI="$HOBOT_FUZZ_BIN"
elif command -v hobot-fuzz >/dev/null 2>&1; then
    CLI="$(command -v hobot-fuzz)"
elif [[ -x "$ROOT_DIR/target/release/hobot-fuzz" ]]; then
    CLI="$ROOT_DIR/target/release/hobot-fuzz"
elif [[ -x "$ROOT_DIR/target/debug/hobot-fuzz" ]]; then
    CLI="$ROOT_DIR/target/debug/hobot-fuzz"
else
    echo "MISSING  hobot-fuzz CLI (run: ./scripts/build-release.sh)" >&2
    exit 1
fi

exec "$CLI" doctor "$@"
