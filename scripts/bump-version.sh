#!/usr/bin/env bash
# hobot_fuzz -- bump workspace version
# Usage: ./scripts/bump-version.sh 0.2.0
set -euo pipefail

VERSION="${1:?usage: bump-version.sh <new-version>}"
cd "$(dirname "$0")/.."

sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak

echo "Bumped workspace to $VERSION"