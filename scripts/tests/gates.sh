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

ALL_GATES=(fmt clippy check check-no-default-features check-feature-matrix test doc deny coverage script-tests translation-pairing frontend-test frontend-lint)

# The crates TEST_STRATEGY.md section 4 names for its >= 80% unit-test line
# coverage target. Measuring exactly what the standard names keeps the
# instrumented rebuild small enough for every run.
COVERAGE_CRATES=(hf-discovery hf-harness hf-engine hf-crash)

# Each product subsystem is independently selectable in hf-cli and forwards to
# hf-web and hf-service. Checking them one at a time catches undeclared feature
# coupling that default and all-feature builds both hide.
PRODUCT_FEATURES=(
  automotive-lab
  automotive-scapy
  campaign-health
  build-context
  concolic-enrichment
  build-doctor
  campaign-trust
  change-aware
  coverage-blockers
  harness-tournament
  harness-work-order
  native-analysis
  oracle-studio
  patch-to-proof
  proof-carrying
  run-closeout
  semgrep-enrichment
  triage-disposition
  unreached-surface
)

# Output noise that hides real results in a workspace this size.
TEST_NOISE='^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$'

gate_fmt() {
  cargo fmt --all -- --check
}

gate_clippy() {
  # `--fix` is deliberately absent: it mutates the working tree, which is
  # correct locally and wrong as a gate. AGENTS.md 4.5 keeps the fixing pass as
  # a developer step; this is the verifying pass.
  # --all-targets extends linting to test/example/bench code, which a plain
  # `cargo clippy --workspace` never compiles and therefore never lints.
  cargo clippy --workspace --all-targets -- -D warnings
}

gate_check() {
  cargo check --workspace
}

gate_check_no_default_features() {
  # Feature-absent code and tests must meet the same warning policy as the
  # default build. A plain check missed dead helpers and feature-specific test
  # compile failures because it neither denied warnings nor compiled all targets.
  cargo clippy --workspace --all-targets --no-default-features -- -D warnings
}

gate_check_feature_matrix() {
  local feature
  for feature in "${PRODUCT_FEATURES[@]}"; do
    cargo clippy --workspace --all-targets --no-default-features \
      --features "hf-cli/${feature}" -- -D warnings
  done
}

gate_test() {
  # The filter is display-only and must never decide the gate's status.
  # Wrapping grep in a group that always succeeds covers its exit-1-on-no-match
  # behavior, and there is no `head`, so no SIGPIPE. Under pipefail a failing
  # `cargo test` still fails the pipeline.
  # --no-fail-fast so one failing test binary cannot hide what the rest of the
  # suite would have found: the Windows job burned one full CI cycle per hidden
  # failure until the gate reported them all at once.
  cargo test --workspace --no-fail-fast 2>&1 | { grep -v "${TEST_NOISE}" || true; }
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
  # Dependency-policy warnings are actionable findings. Promoting them here
  # prevents advisory, duplicate-version, and stale-policy notices from being
  # reported while the gate still exits successfully.
  "${binary}" check -D warnings
}

gate_coverage() {
  # TEST_STRATEGY.md section 4 sets line-coverage targets that no gate measured,
  # so the numbers were asserted but never observed. This gate REPORTS per-crate
  # line coverage for the domain crates; thresholds are not enforced yet: the
  # measurement must exist and be trusted before a threshold can gate on it.
  # Enforcement is a separate decision once a baseline is recorded.
  local binary
  if command -v cargo-llvm-cov >/dev/null; then
    binary="$(command -v cargo-llvm-cov)"
  elif [ -x "${HOME}/.cargo/bin/cargo-llvm-cov" ]; then
    binary="${HOME}/.cargo/bin/cargo-llvm-cov"
  else
    echo "cargo-llvm-cov is required; install it with: cargo install cargo-llvm-cov --locked" >&2
    echo "the llvm-tools-preview rustup component is also required" >&2
    return 1
  fi
  local crate_args=()
  local crate
  for crate in "${COVERAGE_CRATES[@]}"; do
    crate_args+=(-p "${crate}")
  done
  "${binary}" --summary-only "${crate_args[@]}"
}

gate_script_tests() {
  # scripts/tests/test_*.py had no runner before this gate existed.
  python3 -m unittest discover \
    --start-directory scripts/tests \
    --top-level-directory scripts/tests \
    --pattern 'test_*.py'
}

gate_translation_pairing() {
  # Needs no toolchain and finishes instantly, so it runs beside script-tests
  # rather than behind the Rust gates: a documentation-only change should not
  # wait on a workspace build to learn that its counterpart is stale.
  python3 scripts/verify_translation_pairing.py
}

gate_frontend_test() {
  npm --prefix crates/hf-gui ci
  npm --prefix crates/hf-gui audit --audit-level=moderate
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
