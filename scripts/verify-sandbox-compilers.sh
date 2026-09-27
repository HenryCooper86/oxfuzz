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
    --tmpfs /tmp:rw,exec,nosuid,nodev,size=64m \
    "$image" sh -ec '
        printf "int main(void) { return 0; }\n" >/tmp/toolchain-probe.c
        for compiler in clang afl-clang-fast hfuzz-cc; do
            "$compiler" -fsanitize=address -fprofile-instr-generate \
                -fcoverage-mapping /tmp/toolchain-probe.c \
                -o "/tmp/toolchain-probe-$compiler"
            LLVM_PROFILE_FILE="/tmp/toolchain-probe-$compiler.profraw" \
                "/tmp/toolchain-probe-$compiler"
            if [ "$compiler" = afl-clang-fast ]; then
                version=17
            else
                version=18
            fi
            "llvm-profdata-$version" merge -sparse \
                "/tmp/toolchain-probe-$compiler.profraw" \
                -o "/tmp/toolchain-probe-$compiler.profdata"
            "llvm-cov-$version" export "/tmp/toolchain-probe-$compiler" \
                -instr-profile="/tmp/toolchain-probe-$compiler.profdata" \
                >"/tmp/toolchain-probe-$compiler.json"
        done
    '
