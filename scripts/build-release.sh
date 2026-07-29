#!/usr/bin/env bash
# oxfuzz -- build and smoke-check the release CLI binary.
set -euo pipefail

cd "$(dirname "$0")/.."

build_args=(--locked --release -p hf-cli)
release_features_overridden=false
if [[ "${OXFUZZ_RELEASE_FEATURES+x}" == "x" ]]; then
  release_features_overridden=true
  build_args+=(--no-default-features)
  if [[ -n "$OXFUZZ_RELEASE_FEATURES" ]]; then
    build_args+=(--features "$OXFUZZ_RELEASE_FEATURES")
  fi
fi

echo "Building release CLI..."
cargo build "${build_args[@]}"

binary="${CARGO_TARGET_DIR:-target}/release/oxfuzz"
if [[ ! -x "$binary" ]]; then
  echo "Release binary is missing or not executable: $binary" >&2
  exit 1
fi

"$binary" --version
"$binary" --help >/dev/null
if [[ "$release_features_overridden" == false ]]; then
  if ! "$binary" discover --help | grep -F -- "--semgrep" >/dev/null; then
    echo "Default release CLI is missing semgrep-enrichment" >&2
    exit 1
  fi
  echo "Verified default release feature: semgrep-enrichment"
fi

if [[ "${OXFUZZ_VERIFY_SEMGREP_SANDBOX:-0}" == "1" ]]; then
  ./scripts/test-semgrep-sandbox.sh
fi

echo "Verified release CLI: $binary"
