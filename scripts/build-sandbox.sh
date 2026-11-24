#!/usr/bin/env bash
# Build the oxfuzz sandbox Docker image.
# Usage: ./scripts/build-sandbox.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Git Bash on Windows rewrites arguments that look like POSIX paths, which
# corrupts paths meant for the container, and reports host paths as /d/...,
# which no container engine accepts as a bind source. Switch the rewriting
# off and convert host paths here. On other hosts both are no-ops.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
host_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s\n' "$1"
    fi
}
python_command=python3
if ! command -v python3 >/dev/null 2>&1; then
    python_command=python
fi

IMAGE="${OXFUZZ_SANDBOX_IMAGE:-oxfuzz/fuzz-sandbox:0.2.4}"
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
./scripts/verify-sandbox-compilers.sh "$IMAGE"

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
# The container's root user has every capability dropped, so on a native Linux
# host it cannot write to a directory the invoking user owns (Docker Desktop
# and OrbStack map ownership and hide this). Keep the private 0700 mktemp root
# and give the container a world-writable directory inside it; other host
# users still cannot reach it.
verification_mount="${verification_output}/output"
mkdir -m 0777 "$verification_mount"

echo "Verifying the pinned sandbox toolchain ..."
docker run "${run_args[@]}" \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=$(host_path "${PWD}/docker/sandbox/semgrep/fixtures"),dst=/work/source,readonly" \
    --mount "type=bind,src=$(host_path "$verification_mount"),dst=/work/output" \
    "$IMAGE" bash -lc '
        set -euo pipefail
        for binary in clang afl-fuzz afl-qemu-trace honggfuzz python3 java javac jazzer jazzer-js bazel oxfuzz-bazel-compdb syz-manager ssh scp qemu-system-aarch64 qemu-system-x86_64 casr-san casr-cluster cargo semgrep; do
            command -v "$binary" >/dev/null
        done
        python3 -I -c "import atheris"
        test -f /opt/oxfuzz/msan-libcxx/lib/libc++.so.1
        test -f /opt/oxfuzz/msan-libcxx/lib/libFuzzer-msan.a
        notices=/usr/share/doc/oxfuzz-sandbox
        test -s "$notices/NOTICES.md"
        test -s "$notices/packages.tsv"
        grep -Eqx "[0-9]{8}T[0-9]{6}Z" "$notices/ubuntu-snapshot.txt"
        test -s "$notices/licenses/LGPL-3"
        cargo fuzz --version >/dev/null
        test "$(semgrep --version --disable-version-check)" = "1.169.0"
        test -z "$(
            find /opt/oxfuzz/semgrep-rules/rules/c -type l -print -quit
        )"
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
    '

"$python_command" scripts/validate-semgrep-smoke.py \
    "$(host_path "$verification_mount/semgrep.json")" 67108864

echo "Verified offline read-only scan with read-only source and writable output"
docker image inspect --format 'Verified {{.Id}} ({{.Architecture}})' "$IMAGE"
