#!/usr/bin/env bash
# hobot_fuzz -- build and smoke-check the release CLI binary.
set -euo pipefail

cd "$(dirname "$0")/.."

FEATURES="${HOBOT_RELEASE_FEATURES:-automotive-scapy}"
build_args=(--locked --release -p hf-cli)
if [[ -n "$FEATURES" ]]; then
  build_args+=(--features "$FEATURES")
fi

echo "Building release CLI..."
cargo build "${build_args[@]}"

binary="${CARGO_TARGET_DIR:-target}/release/hobot-fuzz"
if [[ ! -x "$binary" ]]; then
  echo "Release binary is missing or not executable: $binary" >&2
  exit 1
fi

"$binary" --version
"$binary" --help >/dev/null
echo "Verified release CLI: $binary"
