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
npm ci --silent
npm run build

echo ""
echo "=== Building Tauri app ($OS $ARCH) ==="
node_modules/.bin/tauri build --ci --features automotive-scapy -- --locked

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
    SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:--}"
    codesign --force --deep --sign "$SIGNING_IDENTITY" "$APP"
    xattr -cr "$APP"
    codesign --verify --deep --strict --verbose=2 "$APP"
  fi
fi

ARTIFACTS="$(find "$BUNDLE" -maxdepth 2 -type f \
  \( -name '*.dmg' -o -name '*.deb' -o -name '*.AppImage' -o -name '*.rpm' \) \
  -print 2>/dev/null || true)"
if [[ -z "$APP" && -z "$ARTIFACTS" ]]; then
  echo "Tauri completed without producing an application bundle" >&2
  exit 1
fi

if [[ "$OS" == "Darwin" ]]; then
  while IFS= read -r dmg; do
    [[ -n "$dmg" ]] && hdiutil verify "$dmg"
  done <<< "$(find "$BUNDLE/dmg" -maxdepth 1 -name '*.dmg' -type f -print 2>/dev/null || true)"
fi

# Optional companion service: bring up the local DefectDojo the app integrates
# with, as part of preparing the tool's environment. Best-effort and idempotent
# (a fast no-op once it is running); never fails the build. Skip with
# HF_SKIP_DEFECTDOJO=1.
if [[ "${HF_SKIP_DEFECTDOJO:-0}" != "1" ]]; then
  echo ""
  echo "=== Setting up local DefectDojo (best-effort; set HF_SKIP_DEFECTDOJO=1 to skip) ==="
  ./scripts/setup-defectdojo.sh \
    || echo "DefectDojo setup did not complete (non-fatal); run ./scripts/setup-defectdojo.sh later."
fi

echo ""
echo "=== Build complete ==="
echo "Artifacts:"
if [[ -n "$ARTIFACTS" ]]; then
  echo "$ARTIFACTS" | sed 's/^/  /'
fi
if [[ -n "$APP" ]]; then echo "  $APP"; fi

echo ""
if [[ "$OS" == "Darwin" && -n "$APP" ]]; then
  echo "To run:    open \"$APP\""
else
  echo "To install a bundle above, e.g.: sudo dpkg -i <deb>  |  chmod +x <AppImage> && ./<AppImage>"
fi
