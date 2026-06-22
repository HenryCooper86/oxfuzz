#!/usr/bin/env bash
# hobot_fuzz -- run quality gates in order
set -euo pipefail

cd "$(dirname "$0")/.."

echo "1/4 cargo fmt --all --check"
cargo fmt --all -- --check

echo "2/4 cargo clippy --workspace -- -D warnings"
cargo clippy --workspace -- -D warnings

echo "3/4 cargo check --workspace"
cargo check --workspace

echo "4/4 cargo test --workspace"
cargo test --workspace

echo "All gates passed."