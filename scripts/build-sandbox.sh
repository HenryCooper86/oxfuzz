#!/usr/bin/env bash
# Build the hobot_fuzz sandbox Docker image.
# Usage: ./scripts/build-sandbox.sh
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${HOBOT_SANDBOX_IMAGE:-hobot/fuzz-sandbox:0.1.0}"
if [[ "$IMAGE" == "latest" || "$IMAGE" == *":latest" ]]; then
    echo "HOBOT_SANDBOX_IMAGE must use an explicit version tag" >&2
    exit 1
fi

echo "Building ${IMAGE} ..."
build_args=(--pull -t "$IMAGE" -f docker/sandbox/Dockerfile)
run_args=(--rm --network none --read-only)
if [[ -n "${HOBOT_SANDBOX_PLATFORM:-}" ]]; then
    build_args+=(--platform "$HOBOT_SANDBOX_PLATFORM")
    run_args+=(--platform "$HOBOT_SANDBOX_PLATFORM")
fi
docker build "${build_args[@]}" .

echo "Verifying the pinned sandbox toolchain ..."
docker run "${run_args[@]}" \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    "$IMAGE" bash -lc '
        set -euo pipefail
        for binary in clang afl-fuzz honggfuzz python3 syz-manager casr-san casr-cluster cargo; do
            command -v "$binary" >/dev/null
        done
        cargo fuzz --version >/dev/null
    '

docker image inspect --format 'Verified {{.Id}} ({{.Architecture}})' "$IMAGE"
