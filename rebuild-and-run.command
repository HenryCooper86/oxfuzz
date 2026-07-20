#!/usr/bin/env bash
# Rebuild the oxfuzz desktop app (picks up the Tauri arg-passing fix)
# and relaunch it. Double-click to run.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Rebuilding oxfuzz desktop app ==="
./scripts/build-app.sh

echo ""
echo "=== Relaunching app ==="
open "target/release/bundle/macos/oxfuzz.app"

echo ""
echo "Done. You can close this window."
