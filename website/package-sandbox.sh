#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="$(node --input-type=module -e "import {version} from './website/release.mjs'; console.log(version)")"
output="${1:-$PWD/target/release-$version/artifacts}"
mkdir -p "$output"
output="$(cd "$output" && pwd -P)"
staging="$(mktemp -d "${TMPDIR:-/tmp}/oxfuzz-public-kit.XXXXXXXX")"
trap 'rm -rf -- "$staging"' EXIT
prefix="oxfuzz-sandbox-kit-$version"
mkdir "$staging/$prefix"
# Archive tracked inputs from the release tag; never copy runtime files or Git history.
git archive "v$version" LICENSE docker/sandbox tools/clang-analysis \
  third_party/semgrep third_party/semgrep-rules scripts/build-sandbox.sh \
  scripts/verify-sandbox-compilers.sh scripts/semgrep-tree-digest.py \
  scripts/validate-semgrep-smoke.py | tar -x -C "$staging/$prefix"
cp website/sandbox-kit-README.md "$staging/$prefix/README.md"
COPYFILE_DISABLE=1 tar -czf "$output/$prefix.tar.gz" -C "$staging" "$prefix"
printf '%s\n' "$output/$prefix.tar.gz"
