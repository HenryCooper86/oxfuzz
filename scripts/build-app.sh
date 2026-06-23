#!/usr/bin/env bash
# Build the hobot_fuzz macOS desktop app (Tauri v2).
# Produces .app bundle and .dmg installer.
# Usage: ./scripts/build-app.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Building frontend ==="
cd crates/hf-gui
npm install --silent
npm run build

echo ""
echo "=== Building Tauri app ==="
node_modules/.bin/tauri build

cd ../..

APP="target/release/bundle/macos/hobot_fuzz.app"
DMG="target/release/bundle/dmg/hobot_fuzz_0.1.0_aarch64.dmg"

echo ""
echo "=== Fixing code signing (ad-hoc) ==="
codesign --force --deep -s - "$APP"
xattr -cr "$APP"

echo ""
echo "=== Build complete ==="
echo "App:  $APP"
echo "DMG:  $DMG"
echo ""
echo "To install: open $DMG"
echo "To run:    open $APP"