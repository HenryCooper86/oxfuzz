#!/usr/bin/env bash
# Build the oxfuzz Docker sandbox image (oxfuzz/fuzz-sandbox:0.1.0) for the
# host arch, including the syzkaller toolchain (Go 1.26 + qemu + syz-manager).
# Double-click to run; watch the output for build success/failure.
set -uo pipefail
cd "$(dirname "$0")"

# Finder-launched scripts may not inherit the OrbStack/Docker PATH.
export PATH="$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm64/arm64/')"
IMAGE="oxfuzz/fuzz-sandbox:0.1.0"

echo "=== Building ${IMAGE} for ${PLATFORM} (this is a long build) ==="
OXFUZZ_SANDBOX_PLATFORM="${PLATFORM}" OXFUZZ_SANDBOX_IMAGE="${IMAGE}" \
  ./scripts/build-sandbox.sh ; BUILD_RC=$?

echo ""
if [ "${BUILD_RC}" -ne 0 ]; then
  echo "=== Build FAILED (exit ${BUILD_RC}). See errors above. ==="
fi

# Bring up the local DefectDojo the app integrates with, as part of preparing
# the environment. Best-effort and idempotent (a fast no-op once running); does
# not affect the sandbox build result. Skip with HF_SKIP_DEFECTDOJO=1.
if [ "${HF_SKIP_DEFECTDOJO:-0}" != "1" ]; then
  echo ""
  echo "=== Setting up local DefectDojo (best-effort; set HF_SKIP_DEFECTDOJO=1 to skip) ==="
  ./scripts/setup-defectdojo.sh \
    || echo "DefectDojo setup did not complete (non-fatal); run ./setup-defectdojo.command later."
fi

echo ""
echo "Done (exit ${BUILD_RC}). You can close this window."
