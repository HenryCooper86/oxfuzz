#!/usr/bin/env bash
# Build the optional, separately distributed Scapy automotive sidecar image.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${OXFUZZ_SCAPY_IMAGE:-oxfuzz/scapy-automotive:2.7.0}"
case "$IMAGE" in
  *:latest|latest|*[$'\n\r\t ']*|'')
    echo "OXFUZZ_SCAPY_IMAGE must be a non-latest pinned image reference" >&2
    exit 1
    ;;
esac

docker build --pull --tag "$IMAGE" sidecars/scapy_automotive
echo "Built optional sidecar image: $IMAGE"
