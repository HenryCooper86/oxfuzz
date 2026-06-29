#!/usr/bin/env bash
# Build the hobot_fuzz Docker sandbox image (hobot/fuzz-sandbox:latest) for the
# host arch, including the syzkaller toolchain (Go 1.26 + qemu + syz-manager).
# Double-click to run; watch the output for build success/failure.
set -uo pipefail
cd "$(dirname "$0")"

# Finder-launched scripts may not inherit the OrbStack/Docker PATH.
export PATH="$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm64/arm64/')"
IMAGE="hobot/fuzz-sandbox:latest"

echo "=== Building ${IMAGE} for ${PLATFORM} (this is a long build) ==="
docker build --platform="${PLATFORM}" -t "${IMAGE}" -f docker/sandbox/Dockerfile . ; BUILD_RC=$?

echo ""
if [ "${BUILD_RC}" -eq 0 ]; then
  echo "=== Build OK. Verifying syz-manager ==="
  docker run --rm --platform="${PLATFORM}" "${IMAGE}" bash -lc 'which syz-manager && syz-manager --help 2>&1 | head -3'
  echo ""
  echo "=== Image architecture ==="
  docker image inspect --format '{{.Architecture}}' "${IMAGE}"
else
  echo "=== Build FAILED (exit ${BUILD_RC}). See errors above. ==="
fi

echo ""
echo "Done (exit ${BUILD_RC}). You can close this window."
