#!/usr/bin/env bash
# Fetch the library sources the vendored honggfuzz reference harnesses target,
# each pinned to an exact upstream commit, into a git-ignored directory.
#
# Usage: examples/honggfuzz_upstream/fetch-libs.sh [library ...]
#   library: libxml2, libpng, libjpeg-turbo, file (default: all four)
#   OXFUZZ_LIBS_DIR overrides the destination
#   (default: examples/honggfuzz_upstream/third_party).
#
# The script only downloads source. It builds nothing and runs nothing, so it
# needs git and network access only. Each checkout is verified against its
# pinned commit; a mismatch removes the checkout and fails the script.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${OXFUZZ_LIBS_DIR:-$HERE/third_party}"

# name | repository | release tag | pinned commit
LIBRARIES=(
    "libxml2|https://github.com/GNOME/libxml2.git|v2.13.5|de918d45e1b2276a28a4cd32bcf556bef65284e4"
    "libpng|https://github.com/pnggroup/libpng.git|v1.6.44|f5e92d76973a7a53f517579bc95d61483bf108c0"
    "libjpeg-turbo|https://github.com/libjpeg-turbo/libjpeg-turbo.git|3.0.4|f29eda648547b36aa594c4116c7764a6c8a079b9"
    "file|https://github.com/file/file.git|FILE5_45|4cbd5c8f0851201d203755b76cb66ba991ffd8be"
)

usage() {
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

fetch() {
    local name="$1" repo="$2" tag="$3" commit="$4"
    local target="$DEST/$name"
    if [[ -d "$target/.git" ]] && [[ "$(git -C "$target" rev-parse HEAD)" == "$commit" ]]; then
        echo "ok       $name $tag (already at $commit)"
        return
    fi
    rm -rf "$target"
    mkdir -p "$target"
    git -C "$target" init --quiet
    git -C "$target" remote add origin "$repo"
    git -C "$target" fetch --quiet --depth 1 origin "$commit"
    git -C "$target" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
    local actual
    actual="$(git -C "$target" rev-parse HEAD)"
    if [[ "$actual" != "$commit" ]]; then
        rm -rf "$target"
        echo "MISMATCH $name: expected $commit, got $actual" >&2
        exit 1
    fi
    echo "fetched  $name $tag ($commit)"
}

main() {
    local wanted=("$@")
    if [[ ${#wanted[@]} -eq 1 && ( "${wanted[0]}" == "-h" || "${wanted[0]}" == "--help" ) ]]; then
        usage
        return
    fi
    mkdir -p "$DEST"
    local entry name repo tag commit matched selected
    for wanted_name in "${wanted[@]}"; do
        matched=0
        for entry in "${LIBRARIES[@]}"; do
            [[ "${entry%%|*}" == "$wanted_name" ]] && matched=1
        done
        if [[ $matched -eq 0 ]]; then
            echo "unknown library: $wanted_name" >&2
            usage >&2
            exit 2
        fi
    done
    for entry in "${LIBRARIES[@]}"; do
        IFS='|' read -r name repo tag commit <<<"$entry"
        selected=1
        if [[ ${#wanted[@]} -gt 0 ]]; then
            selected=0
            for wanted_name in "${wanted[@]}"; do
                [[ "$wanted_name" == "$name" ]] && selected=1
            done
        fi
        if [[ $selected -eq 1 ]]; then
            fetch "$name" "$repo" "$tag" "$commit"
        fi
    done
}

main "$@"
