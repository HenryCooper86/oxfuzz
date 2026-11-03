#!/usr/bin/env bash
# Pull a prebuilt oxfuzz sandbox image instead of building it locally.
# Usage: ./scripts/pull-sandbox.sh
#
# The image is pulled from GitHub Container Registry, tagged with the local
# name the runtime expects, and checked with the same compiler verification a
# local build runs. Falls back to telling you to build when no image has been
# published for this version.
set -euo pipefail

cd "$(dirname "$0")/.."

version="$(grep -oE 'oxfuzz/fuzz-sandbox:[0-9][0-9A-Za-z._-]*' scripts/build-sandbox.sh | head -n 1 | cut -d: -f2)"
if [[ -z "$version" ]]; then
    echo "could not read the sandbox version from scripts/build-sandbox.sh" >&2
    exit 1
fi

local_image="oxfuzz/fuzz-sandbox:${version}"
remote_image="${OXFUZZ_SANDBOX_REGISTRY_IMAGE:-ghcr.io/henrycooper86/oxfuzz-fuzz-sandbox:${version}}"
if [[ "$remote_image" == *":latest" ]]; then
    echo "OXFUZZ_SANDBOX_REGISTRY_IMAGE must use an explicit version tag" >&2
    exit 1
fi

echo "Pulling ${remote_image} ..."
if ! docker pull "$remote_image"; then
    echo "No prebuilt image is available at ${remote_image}." >&2
    echo "Build it locally instead: ./scripts/build-sandbox.sh" >&2
    exit 1
fi

docker tag "$remote_image" "$local_image"
./scripts/verify-sandbox-compilers.sh "$local_image"

digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$remote_image" 2>/dev/null || true)"
echo "Ready: ${local_image}${digest:+ (from ${digest})}"
