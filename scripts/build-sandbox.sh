#!/usr/bin/env bash
# Build the oxfuzz sandbox Docker image.
# Usage: ./scripts/build-sandbox.sh
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${OXFUZZ_SANDBOX_IMAGE:-oxfuzz/fuzz-sandbox:0.1.0}"
if [[ "$IMAGE" == "latest" || "$IMAGE" == *":latest" ]]; then
    echo "OXFUZZ_SANDBOX_IMAGE must use an explicit version tag" >&2
    exit 1
fi

echo "Building ${IMAGE} ..."
build_args=(--pull -t "$IMAGE" -f docker/sandbox/Dockerfile)
run_args=(
    --rm
    --network none
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
)
if [[ -n "${OXFUZZ_SANDBOX_PLATFORM:-}" ]]; then
    build_args+=(--platform "$OXFUZZ_SANDBOX_PLATFORM")
    run_args+=(--platform "$OXFUZZ_SANDBOX_PLATFORM")
fi
docker build "${build_args[@]}" .

temp_base="${TMPDIR:-/tmp}"
temp_base="$(cd "$temp_base" && pwd -P)"
verification_output="$(mktemp -d "${temp_base%/}/oxfuzz-semgrep-verify.XXXXXXXX")"
if [[ ! -d "$verification_output" || -L "$verification_output" ||
      "$verification_output" != "${temp_base%/}/oxfuzz-semgrep-verify."* ]]; then
    echo "refusing unvalidated verification directory: ${verification_output}" >&2
    exit 1
fi
cleanup() {
    rm -rf -- "$verification_output"
}
trap cleanup EXIT

echo "Verifying the pinned sandbox toolchain ..."
docker run "${run_args[@]}" \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=${PWD}/docker/sandbox/semgrep/fixtures,dst=/work/source,readonly" \
    --mount "type=bind,src=${verification_output},dst=/work/output" \
    "$IMAGE" bash -lc '
        set -euo pipefail
        for binary in clang afl-fuzz honggfuzz python3 syz-manager casr-san casr-cluster cargo semgrep; do
            command -v "$binary" >/dev/null
        done
        cargo fuzz --version >/dev/null
        test "$(semgrep --version --disable-version-check)" = "1.169.0"
        rules_digest="$(
            python3 /opt/oxfuzz/semgrep-tree-digest.py \
                /opt/oxfuzz/semgrep-rules/rules/c
        )"
        test "$rules_digest" = "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)"

        set +e
        oxfuzz-semgrep-scan unexpected >/tmp/semgrep-arguments.stdout \
            2>/tmp/semgrep-arguments.stderr
        argument_status="$?"
        set -e
        test "$argument_status" -eq 64
        grep -Fx "oxfuzz-semgrep-scan accepts no arguments" \
            /tmp/semgrep-arguments.stderr >/dev/null

        # Do not use `semgrep scan --validate`: Semgrep CE 1.169.0 fetches
        # p/semgrep-rule-lints. This network-disabled fixed-wrapper scan loads
        # and executes the complete bundled local configuration instead.
        oxfuzz-semgrep-scan
        python3 - <<'"'"'PY'"'"'
import json
import pathlib

report = json.loads(pathlib.Path("/work/output/semgrep.json").read_text())
findings = [
    (finding.get("check_id"), finding.get("path"))
    for finding in report["results"]
    if finding.get("check_id") == "raptor-insecure-api-gets"
]
expected = [("raptor-insecure-api-gets", "vulnerable.c")]
if findings != expected:
    raise SystemExit(f"unexpected raptor-insecure-api-gets findings: {findings!r}")
print("Semgrep version verified: 1.169.0")
print("Rules digest verified:", pathlib.Path(
    "/opt/oxfuzz/semgrep-rules/RULES_SHA256"
).read_text().strip())
print("Complete local rules configuration loaded and executed")
print("Fixture finding verified: raptor-insecure-api-gets vulnerable.c")
print("Clean fixture verified: no findings")
PY
    '

echo "Verified offline read-only scan with read-only source and writable output"
docker image inspect --format 'Verified {{.Id}} ({{.Architecture}})' "$IMAGE"
