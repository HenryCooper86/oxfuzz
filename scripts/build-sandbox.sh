#!/usr/bin/env bash
# Build the hobot_fuzz sandbox Docker image.
# Usage: ./scripts/build-sandbox.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building hobot/fuzz-sandbox:latest ..."
docker build -t hobot/fuzz-sandbox:latest -f docker/sandbox/Dockerfile .
echo "Done."