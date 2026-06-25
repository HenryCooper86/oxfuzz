#!/usr/bin/env bash
# Rebuild the hobot_fuzz desktop app (picks up the Tauri arg-passing fix)
# and relaunch it. Double-click to run.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Rebuilding hobot_fuzz desktop app ==="
./scripts/build-app.sh

echo ""
echo "=== Relaunching app ==="
open "target/release/bundle/macos/hobot_fuzz.app"

echo ""
echo "Done. You can close this window."
