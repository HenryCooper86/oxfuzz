#!/usr/bin/env bash
# oxfuzz -- quality gates.
#
#   scripts/tests/gates.sh                 # every gate, in AGENTS.md 4.5 order
#   scripts/tests/gates.sh clippy test     # only the named gates
#
# This file is the single definition of what each gate means. Continuous
# integration (.github/workflows/ci.yml and .gitlab-ci.yml) invokes named gates
# rather than restating the commands, so the three cannot drift. Named gates
# also let developers rerun only the relevant checks without duplicating commands.
set -euo pipefail

cd "$(dirname "$0")/../.."

ALL_GATES=(fmt clippy check check-no-default-features test doc deny script-tests frontend-test frontend-lint)

# Output noise that hides real results in a workspace this size.
TEST_NOISE='^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$'

gate_fmt() {
  cargo fmt --all -- --check
}

gate_clippy() {
  # `--fix` is deliberately absent: it mutates the working tree, which is
  # correct locally and wrong as a gate. AGENTS.md 4.5 keeps the fixing pass as
  # a developer step; this is the verifying pass.
  cargo clippy --workspace -- -D warnings
}

gate_check() {
  cargo check --workspace
}

gate_check_no_default_features() {
  # Two defects on this branch were visible only here: an import left behind
  # whose sole remaining user was feature-gated, and an import moved without the
  # gate its use site needed. Both compiled cleanly with default features on.
  cargo check --workspace --no-default-features
}

gate_test() {
  # The filter is display-only and must never decide the gate's status.
  # Wrapping grep in a group that always succeeds covers its exit-1-on-no-match
  # behavior, and there is no `head`, so no SIGPIPE. Under pipefail a failing
  # `cargo test` still fails the pipeline.
  cargo test --workspace 2>&1 | { grep -v "${TEST_NOISE}" || true; }
}

gate_doc() {
  # -D warnings because rustdoc warnings are not errors by default, so a broken
  # intra-doc link otherwise ships green. --document-private-items because
  # rustdoc does not link-check non-public items at all, and this crate has many
  # pub(super) ones.
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
}

gate_deny() {
  local binary
  if command -v cargo-deny >/dev/null; then
    binary="$(command -v cargo-deny)"
  elif [ -x "${HOME}/.cargo/bin/cargo-deny" ]; then
    binary="${HOME}/.cargo/bin/cargo-deny"
  else
    echo "cargo-deny is required; install it with: cargo install cargo-deny --locked" >&2
    return 1
  fi
  "${binary}" check
}

gate_script_tests() {
  # scripts/tests/test_*.py had no runner before this gate existed.
  python3 -m unittest discover \
    --start-directory scripts/tests \
    --top-level-directory scripts/tests \
    --pattern 'test_*.py'
}

gate_frontend_test() {
  npm --prefix crates/hf-gui ci
  npm --prefix crates/hf-gui test
  npm --prefix crates/hf-gui run build
}

gate_frontend_lint() {
  npm --prefix crates/hf-gui run lint
}

run_gate() {
  local name="$1"
  local function_name="gate_${name//-/_}"
  if ! declare -F "${function_name}" >/dev/null; then
    echo "unknown gate '${name}'; valid gates: ${ALL_GATES[*]}" >&2
    exit 2
  fi
  echo "== ${name}"
  "${function_name}"
}

if [ "$#" -eq 0 ]; then
  set -- "${ALL_GATES[@]}"
fi

for gate in "$@"; do
  run_gate "${gate}"
done

echo "All gates passed."
