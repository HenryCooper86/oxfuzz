#!/usr/bin/env bash
# Build the hobot_fuzz desktop app (Tauri v2).
#   macOS -> .app + .dmg (ad-hoc signed)
#   Linux -> .deb / .AppImage / .rpm
# Works on arm64 macOS, x86_64/arm64 Linux. Usage: ./scripts/build-app.sh
set -euo pipefail

cd "$(dirname "$0")/.."

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "=== Building frontend ==="
cd crates/hf-gui
npm install --silent
npm run build

echo ""
echo "=== Building Tauri app ($OS $ARCH) ==="
node_modules/.bin/tauri build

cd ../..

BUNDLE="target/release/bundle"

# The bundle filenames embed the arch (e.g. _aarch64 vs _x64) and the OS decides
# which bundle types Tauri emits, so discover the artifacts instead of
# hardcoding paths. Only macOS produces a .app that needs ad-hoc signing.
APP=""
if [[ "$OS" == "Darwin" ]]; then
  APP="$(find "$BUNDLE/macos" -maxdepth 1 -name '*.app' -print -quit 2>/dev/null || true)"
  if [[ -n "$APP" ]]; then
    echo ""
    echo "=== Fixing code signing (ad-hoc) ==="
    codesign --force --deep -s - "$APP"
    xattr -cr "$APP"
  fi
fi

echo ""
echo "=== Build complete ==="
echo "Artifacts:"
find "$BUNDLE" -maxdepth 2 -type f \
  \( -name '*.dmg' -o -name '*.deb' -o -name '*.AppImage' -o -name '*.rpm' \) \
  -print 2>/dev/null | sed 's/^/  /'
if [[ -n "$APP" ]]; then echo "  $APP"; fi

echo ""
if [[ "$OS" == "Darwin" && -n "$APP" ]]; then
  echo "To run:    open \"$APP\""
else
  echo "To install a bundle above, e.g.: sudo dpkg -i <deb>  |  chmod +x <AppImage> && ./<AppImage>"
fi
