#!/usr/bin/env bash
# oxfuzz -- bump the release version across every file that declares it.
# Usage: ./scripts/bump-version.sh 0.2.0
#
# The version lives in four places that must agree: the Cargo workspace, the
# GUI package manifest and its lockfile, and the Tauri bundle config. Bumping
# only Cargo.toml is what left the shipped 0.1.1 and 0.1.2 desktop apps
# reporting "v0.1.0" in their own UI, so this script bumps all four and then
# verifies they match before returning.
set -euo pipefail

VERSION="${1:?usage: bump-version.sh <new-version>}"
cd "$(dirname "$0")/.."

if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Version must be plain semver (e.g. 0.2.0), got: $VERSION" >&2
  exit 1
fi

GUI=crates/hf-gui

# Cargo workspace: the sole line-anchored `version = ` key is workspace.package.
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml

# package.json and tauri.conf.json each hold exactly one `"version":` key, at
# two-space top-level indentation. Dependency versions are values, not keys.
sed -i.bak "s/^  \"version\": \".*\"/  \"version\": \"$VERSION\"/" \
  "$GUI/package.json" "$GUI/src-tauri/tauri.conf.json"

# The lockfile repeats `"version":` for every dependency. Only the two in the
# header -- the root entry and packages[""] -- describe this package, so the
# edit is bounded to the header rather than matched by indentation alone.
sed -i.bak "1,12s/^\( *\)\"version\": \".*\"/\1\"version\": \"$VERSION\"/" \
  "$GUI/package-lock.json"

rm -f Cargo.toml.bak "$GUI/package.json.bak" \
  "$GUI/src-tauri/tauri.conf.json.bak" "$GUI/package-lock.json.bak"

# Propagate the new member versions into Cargo.lock without touching deps.
cargo update --workspace --quiet

# Fail loudly rather than leave a half-applied bump: a silent miss here is the
# exact defect this script exists to prevent.
check() {
  local file="$1" found
  # sort -u collapses the lockfile's two header entries to one value when they
  # agree, and leaves two lines -- failing the compare -- when they do not.
  found=$(sed -n "$2" "$file" | sort -u)
  if [ "$found" != "$VERSION" ]; then
    echo "Bump did not apply to $file (found '${found:-nothing}', want '$VERSION')" >&2
    exit 1
  fi
}

# Each pattern consumes the whole line: `s///p` prints the transformed line, so
# anything left unmatched -- the trailing comma in JSON -- would leak into the
# compared value and fail a bump that actually applied correctly.
check Cargo.toml            's/^version = "\([^"]*\)".*$/\1/p;'
check "$GUI/package.json"   's/^  "version": "\([^"]*\)".*$/\1/p;'
check "$GUI/src-tauri/tauri.conf.json" 's/^  "version": "\([^"]*\)".*$/\1/p;'
check "$GUI/package-lock.json" '1,12{s/^ *"version": "\([^"]*\)".*$/\1/p;}'

echo "Bumped to $VERSION: Cargo.toml, Cargo.lock, package.json, package-lock.json, tauri.conf.json"
