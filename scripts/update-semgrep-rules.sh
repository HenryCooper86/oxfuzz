#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

readonly RULES_REPOSITORY="https://github.com/0xdea/semgrep-rules.git"
readonly RULES_COMMIT="4d66ecf30bfb1809a984085f2c86a8c3915bfc71"
readonly SEMGREP_REPOSITORY="https://github.com/semgrep/semgrep.git"
readonly SEMGREP_TAG="v1.169.0"

temp_base="${TMPDIR:-/tmp}"
temp_base="$(cd "$temp_base" && pwd -P)"

make_temp_repository() {
    local name="$1"
    local directory
    directory="$(mktemp -d "${temp_base%/}/oxfuzz-${name}.XXXXXXXX")"
    if [[ ! -d "$directory" || -L "$directory" ||
          "$directory" != "${temp_base%/}/oxfuzz-${name}."* ]]; then
        echo "refusing unvalidated temporary directory: ${directory}" >&2
        exit 1
    fi
    printf '%s\n' "$directory"
}

rules_repository="$(make_temp_repository semgrep-rules)"
semgrep_repository="$(make_temp_repository semgrep-cli)"
cleanup() {
    rm -rf -- "$rules_repository" "$semgrep_repository"
}
trap cleanup EXIT

git init -q "$rules_repository"
git -C "$rules_repository" remote add origin "$RULES_REPOSITORY"
git -C "$rules_repository" fetch --depth=1 origin "$RULES_COMMIT"
git -C "$rules_repository" checkout -q --detach FETCH_HEAD
resolved_rules_commit="$(git -C "$rules_repository" rev-parse HEAD)"
if [[ "$resolved_rules_commit" != "$RULES_COMMIT" ]]; then
    echo "rules commit mismatch: expected ${RULES_COMMIT}, got ${resolved_rules_commit}" >&2
    exit 1
fi
test -d "$rules_repository/rules/c"
test -f "$rules_repository/LICENSE"

rules_parent="third_party/semgrep-rules/rules"
rules_target="${rules_parent}/c"
rules_staging="${rules_parent}/.c.new"
mkdir -p "$rules_parent"
rm -rf -- "$rules_staging"
cp -R "$rules_repository/rules/c" "$rules_staging"
rm -rf -- "$rules_target"
mv "$rules_staging" "$rules_target"

mkdir -p third_party/semgrep-rules
cp "$rules_repository/LICENSE" third_party/semgrep-rules/LICENSE
printf '%s\n' "$RULES_COMMIT" > third_party/semgrep-rules/COMMIT
scripts/semgrep-tree-digest.py "$rules_target" > third_party/semgrep-rules/RULES_SHA256
{
    printf '# 0xdea Semgrep rules provenance\n\n'
    printf -- '- Repository: %s\n' "$RULES_REPOSITORY"
    printf -- '- Commit: `%s`\n' "$RULES_COMMIT"
    printf -- '- Vendored scope: `rules/c`\n'
} > third_party/semgrep-rules/UPSTREAM.md

git init -q "$semgrep_repository"
git -C "$semgrep_repository" remote add origin "$SEMGREP_REPOSITORY"
git -C "$semgrep_repository" fetch --depth=1 origin \
    "refs/tags/${SEMGREP_TAG}:refs/tags/${SEMGREP_TAG}"
resolved_semgrep_commit="$(git -C "$semgrep_repository" rev-parse "${SEMGREP_TAG}^{commit}")"
fetched_semgrep_commit="$(git -C "$semgrep_repository" rev-parse "FETCH_HEAD^{commit}")"
if [[ "$resolved_semgrep_commit" != "$fetched_semgrep_commit" ]]; then
    echo "Semgrep tag does not resolve to the fetched commit" >&2
    exit 1
fi
git -C "$semgrep_repository" checkout -q --detach "$resolved_semgrep_commit"
if [[ "$(git -C "$semgrep_repository" rev-parse HEAD)" != "$resolved_semgrep_commit" ]]; then
    echo "Semgrep checkout does not match the resolved tag commit" >&2
    exit 1
fi
test -f "$semgrep_repository/LICENSE"

mkdir -p third_party/semgrep
cp "$semgrep_repository/LICENSE" third_party/semgrep/LICENSE
{
    printf '# Semgrep CE provenance\n\n'
    printf -- '- Repository: %s\n' "$SEMGREP_REPOSITORY"
    printf -- '- Tag: `%s`\n' "$SEMGREP_TAG"
    printf -- '- Commit: `%s`\n' "$resolved_semgrep_commit"
} > third_party/semgrep/UPSTREAM.md

printf 'Vendored rules commit %s with digest %s\n' \
    "$RULES_COMMIT" "$(cat third_party/semgrep-rules/RULES_SHA256)"
printf 'Vendored Semgrep %s license from commit %s\n' \
    "$SEMGREP_TAG" "$resolved_semgrep_commit"
