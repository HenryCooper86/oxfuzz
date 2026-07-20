#!/usr/bin/env bash
# oxfuzz -- run quality gates in order
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "1/8 cargo fmt --all --check"
cargo fmt --all -- --check

echo "2/8 cargo clippy --workspace -- -D warnings"
cargo clippy --workspace -- -D warnings

echo "3/8 cargo check --workspace"
cargo check --workspace

echo "4/8 cargo test --workspace"
cargo test --workspace 2>&1 | grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' | head -200

echo "5/8 cargo doc --workspace --no-deps"
cargo doc --workspace --no-deps

echo "6/8 cargo deny check"
if command -v cargo-deny >/dev/null; then
  CARGO_DENY_BIN="$(command -v cargo-deny)"
elif [ -x "${HOME}/.cargo/bin/cargo-deny" ]; then
  CARGO_DENY_BIN="${HOME}/.cargo/bin/cargo-deny"
else
  echo "cargo-deny is required; install it with: cargo install cargo-deny --locked" >&2
  exit 1
fi
"${CARGO_DENY_BIN}" check

echo "7/8 frontend tests and build"
npm --prefix crates/hf-gui ci
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run build

echo "8/8 frontend lint"
npm --prefix crates/hf-gui run lint

echo "All gates passed."
