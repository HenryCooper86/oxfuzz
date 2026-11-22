#!/usr/bin/env bash
# oxfuzz -- type-check the workspace for Windows from a Linux or macOS host.
#
#   scripts/check-windows-target.sh
#
# The Windows CI job is the only place the workspace is compiled for Windows,
# so a platform-specific mistake costs one CI cycle to find. This runs
# `cargo check` for x86_64-pc-windows-msvc with every target (library, tests,
# binaries) so the same mistake is found before a push.
#
# It checks types only. Nothing is linked and nothing runs, so a clean result
# says the code compiles for Windows, not that its tests pass there. Build
# scripts that compile C are given a stand-in compiler that creates the
# requested output file and compiles nothing; that is sound only because no
# object file is ever linked. The desktop shell (hf-gui) is left out: its
# build script needs the Windows resource compiler.
#
# Needs the Rust target: rustup target add x86_64-pc-windows-msvc
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=x86_64-pc-windows-msvc

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "the Rust target $TARGET is not installed; run: rustup target add $TARGET" >&2
    exit 2
fi

temp_base="${TMPDIR:-/tmp}"
tools="$(mktemp -d "${temp_base%/}/oxfuzz-windows-check.XXXXXXXX")"
cleanup() {
    rm -f -- "$tools/clang-cl" "$tools/llvm-lib"
    rmdir -- "$tools" 2>/dev/null || true
}
trap cleanup EXIT

# Compiler stand-in: create the object or executable named by -Fo, -Fe or -o.
cat > "$tools/clang-cl" <<'TOOL'
#!/bin/sh
previous=""
for argument in "$@"; do
    case "$argument" in
        -Fo*|/Fo*|-Fe*|/Fe*)
            output="${argument#???}"
            [ -n "$output" ] && : > "$output"
            ;;
    esac
    [ "$previous" = "-o" ] && : > "$argument"
    previous="$argument"
done
exit 0
TOOL

# Archiver stand-in: create the library named by -out: or /OUT:.
cat > "$tools/llvm-lib" <<'TOOL'
#!/bin/sh
for argument in "$@"; do
    case "$argument" in
        -out:*|/out:*|-OUT:*|/OUT:*) : > "${argument#?????}" ;;
    esac
done
exit 0
TOOL
chmod +x "$tools/clang-cl" "$tools/llvm-lib"

CC_x86_64_pc_windows_msvc="$tools/clang-cl" \
CXX_x86_64_pc_windows_msvc="$tools/clang-cl" \
AR_x86_64_pc_windows_msvc="$tools/llvm-lib" \
    cargo check --target "$TARGET" --workspace --exclude hf-gui --all-targets --keep-going
