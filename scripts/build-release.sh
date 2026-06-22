#!/usr/bin/env bash
# hobot_fuzz -- build a release binary
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building release..."
cargo build --release
echo "Binary: target/release/hobot-fuzz"