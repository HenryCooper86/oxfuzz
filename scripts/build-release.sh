#!/usr/bin/env bash
# hobot_fuzz -- build a release binary
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building release..."
cargo build --release -p hf-cli --features automotive-scapy
echo "Binary: target/release/hobot-fuzz"
