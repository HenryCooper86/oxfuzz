#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
git_repository_root="$(git -C "$repository_root" rev-parse --show-toplevel)"
git_repository_root="$(cd "$git_repository_root" && pwd -P)"
if [[ "$repository_root" != "$git_repository_root" ]]; then
    echo "repository root mismatch: ${repository_root}" >&2
    exit 1
fi
cd "$repository_root"

readonly REPOSITORY_ROOT="$repository_root"
readonly RULES_REPOSITORY="https://github.com/0xdea/semgrep-rules.git"
readonly RULES_COMMIT="4d66ecf30bfb1809a984085f2c86a8c3915bfc71"
readonly SEMGREP_REPOSITORY="https://github.com/semgrep/semgrep.git"
readonly SEMGREP_TAG="v1.169.0"
readonly RULES_METADATA_ROOT="${REPOSITORY_ROOT}/third_party/semgrep-rules"
readonly RULES_PARENT="${RULES_METADATA_ROOT}/rules"
readonly RULES_TARGET="${RULES_PARENT}/c"
readonly RULES_STAGING="${RULES_PARENT}/.c.new"
readonly SEMGREP_METADATA_ROOT="${REPOSITORY_ROOT}/third_party/semgrep"

temp_base="${TMPDIR:-/tmp}"
temp_base="$(cd "$temp_base" && pwd -P)"

validate_temp_repository() {
    local directory="$1"
    local name="$2"
    if [[ ! -d "$directory" || -L "$directory" ||
          "$directory" != "${temp_base%/}/oxfuzz-${name}."* ]]; then
        echo "refusing unvalidated temporary directory: ${directory}" >&2
        exit 1
    fi
}

validate_destination_path() {
    local destination="$1"
    if [[ "$destination" != "$REPOSITORY_ROOT" &&
          "$destination" != "$REPOSITORY_ROOT/"* ]]; then
        echo "destination escapes repository root: ${destination}" >&2
        exit 1
    fi
    if [[ "$destination" == "$REPOSITORY_ROOT" ]]; then
        return
    fi

    local relative="${destination#"$REPOSITORY_ROOT"/}"
    local current="$REPOSITORY_ROOT"
    local component
    while [[ -n "$relative" ]]; do
        if [[ "$relative" == */* ]]; then
            component="${relative%%/*}"
            relative="${relative#*/}"
        else
            component="$relative"
            relative=""
        fi
        if [[ -z "$component" || "$component" == "." || "$component" == ".." ]]; then
            echo "invalid destination component in ${destination}" >&2
            exit 1
        fi
        current="${current}/${component}"
        if [[ -L "$current" ]]; then
            echo "refusing symlinked destination component: ${current}" >&2
            exit 1
        fi
        if [[ -n "$relative" && -e "$current" && ! -d "$current" ]]; then
            echo "destination parent is not a directory: ${current}" >&2
            exit 1
        fi
    done
}

validate_destination_paths() {
    if [[ "$RULES_PARENT" != "${REPOSITORY_ROOT}/third_party/semgrep-rules/rules" ||
          "$RULES_TARGET" != "$RULES_PARENT/c" ||
          "$RULES_STAGING" != "$RULES_PARENT/.c.new" ]]; then
        echo "rules replacement path mismatch" >&2
        exit 1
    fi

    local destination
    for destination in \
        "$RULES_METADATA_ROOT" \
        "$RULES_PARENT" \
        "$RULES_TARGET" \
        "$RULES_STAGING" \
        "$RULES_METADATA_ROOT/LICENSE" \
        "$RULES_METADATA_ROOT/COMMIT" \
        "$RULES_METADATA_ROOT/RULES_SHA256" \
        "$RULES_METADATA_ROOT/UPSTREAM.md" \
        "$SEMGREP_METADATA_ROOT" \
        "$SEMGREP_METADATA_ROOT/LICENSE" \
        "$SEMGREP_METADATA_ROOT/UPSTREAM.md"; do
        validate_destination_path "$destination"
    done
}

rules_repository=""
semgrep_repository=""
rules_repository_validated=false
semgrep_repository_validated=false
cleanup() {
    if [[ "$rules_repository_validated" == true ]]; then
        rm -rf -- "$rules_repository"
    fi
    if [[ "$semgrep_repository_validated" == true ]]; then
        rm -rf -- "$semgrep_repository"
    fi
}
trap cleanup EXIT

rules_repository="$(mktemp -d "${temp_base%/}/oxfuzz-semgrep-rules.XXXXXXXX")"
validate_temp_repository "$rules_repository" semgrep-rules
rules_repository_validated=true

semgrep_repository="$(mktemp -d "${temp_base%/}/oxfuzz-semgrep-cli.XXXXXXXX")"
validate_temp_repository "$semgrep_repository" semgrep-cli
semgrep_repository_validated=true

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
upstream_rules_symlink="$(find "$rules_repository/rules/c" -type l -print -quit)"
if [[ -n "$upstream_rules_symlink" ]]; then
    echo "refusing symlink in upstream rules/c: ${upstream_rules_symlink}" >&2
    exit 1
fi

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

validate_destination_paths
mkdir -p "$RULES_PARENT" "$SEMGREP_METADATA_ROOT"
if [[ "$(cd "$RULES_PARENT" && pwd -P)" != "$RULES_PARENT" ||
      "$(cd "$SEMGREP_METADATA_ROOT" && pwd -P)" != "$SEMGREP_METADATA_ROOT" ]]; then
    echo "resolved destination path mismatch" >&2
    exit 1
fi

rm -rf -- "$RULES_STAGING"
cp -R "$rules_repository/rules/c" "$RULES_STAGING"
rm -rf -- "$RULES_TARGET"
mv "$RULES_STAGING" "$RULES_TARGET"

cp "$rules_repository/LICENSE" "$RULES_METADATA_ROOT/LICENSE"
printf '%s\n' "$RULES_COMMIT" > "$RULES_METADATA_ROOT/COMMIT"
"$REPOSITORY_ROOT/scripts/semgrep-tree-digest.py" "$RULES_TARGET" \
    > "$RULES_METADATA_ROOT/RULES_SHA256"
{
    printf '# 0xdea Semgrep rules provenance\n\n'
    printf -- '- Repository: %s\n' "$RULES_REPOSITORY"
    printf -- '- Commit: `%s`\n' "$RULES_COMMIT"
    printf -- '- Vendored scope: `rules/c`\n'
} > "$RULES_METADATA_ROOT/UPSTREAM.md"

cp "$semgrep_repository/LICENSE" "$SEMGREP_METADATA_ROOT/LICENSE"
{
    printf '# Semgrep CE provenance\n\n'
    printf -- '- Repository: %s\n' "$SEMGREP_REPOSITORY"
    printf -- '- Tag: `%s`\n' "$SEMGREP_TAG"
    printf -- '- Commit: `%s`\n' "$resolved_semgrep_commit"
} > "$SEMGREP_METADATA_ROOT/UPSTREAM.md"

printf 'Vendored rules commit %s with digest %s\n' \
    "$RULES_COMMIT" "$(cat "$RULES_METADATA_ROOT/RULES_SHA256")"
printf 'Vendored Semgrep %s license from commit %s\n' \
    "$SEMGREP_TAG" "$resolved_semgrep_commit"
