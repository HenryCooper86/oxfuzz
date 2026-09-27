#!/usr/bin/env bash
# Link a harmless toolchain probe with the flags used by instrumented harnesses.
set -euo pipefail

image="${1:?usage: verify-sandbox-compilers.sh IMAGE}"
if [[ "$image" == "latest" || "$image" == *":latest" ]]; then
    echo "sandbox compiler verification requires a pinned image" >&2
    exit 1
fi

docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    "$image" sh -ec '
        printf "int main(void) { return 0; }\n" >/tmp/toolchain-probe.c
        for compiler in clang afl-clang-fast hfuzz-cc; do
            "$compiler" -fsanitize=address -fprofile-instr-generate \
                -fcoverage-mapping /tmp/toolchain-probe.c \
                -o "/tmp/toolchain-probe-$compiler"
        done
    '
