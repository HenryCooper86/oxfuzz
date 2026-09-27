#!/usr/bin/env bash
# oxfuzz -- quality gates.
#
#   scripts/tests/gates.sh                 # every gate, in Engineering Protocol 4.5 order
#   scripts/tests/gates.sh clippy test     # only the named gates
#
# This file is the single definition of what each gate means. Continuous
# integration (.github/workflows/ci.yml and .gitlab-ci.yml) invokes named gates
# rather than restating the commands, so the three cannot drift. Named gates
# also let developers rerun only the relevant checks without duplicating commands.
set -euo pipefail

cd "$(dirname "$0")/../.."

ALL_GATES=(fmt clippy check check-no-default-features check-feature-matrix test feature-behavior doc deny coverage script-tests translation-pairing frontend-test frontend-lint)

# Keep the two package groups separate so each instrumented test run has an
# explicit package set and its own report.
COVERAGE_DOMAIN_CRATES=(hf-discovery hf-harness hf-engine hf-crash)
COVERAGE_INFRASTRUCTURE_CRATES=(
  hf-provider hf-session hf-context hf-storage hf-knowledge hf-diagnostics
  hf-spill hf-guardrails hf-prompt hf-tools hf-skills hf-runtime hf-scheduler
  hf-service
)

# Each product subsystem is independently selectable in hf-cli and forwards to
# hf-web and hf-service. Checking them one at a time catches undeclared feature
# coupling that default and all-feature builds both hide.
PRODUCT_FEATURES=(
  ai-target-ranking
  campaign-allocation
  automotive-lab
  automotive-scapy
  campaign-health
  build-context
  concolic-enrichment
  build-doctor
  campaign-trust
  change-aware
  coverage-blockers
  coverage-experiments
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
  # correct locally and wrong as a gate. Engineering Protocol 4.5 keeps the fixing pass as
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

gate_feature_behavior() {
  # Compile-only feature checks cannot establish the behavior of a disabled
  # route or an enabled standalone service operation.
  ./scripts/cargo-test-filtered.sh -p hf-web --no-default-features --test build_doctor_disabled_api
  ./scripts/cargo-test-filtered.sh -p hf-web --no-default-features --test coverage_experiments_api
  ./scripts/cargo-test-filtered.sh -p hf-service --no-default-features --test coverage_experiments
  ./scripts/cargo-test-filtered.sh -p hf-service --no-default-features \
    --features proof-carrying --test run_replay
  ./scripts/cargo-test-filtered.sh -p hf-service --no-default-features \
    --features patch-to-proof --test finding_review
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
  # Measure all named packages before setting the Linux no-regression baseline.
  # The parser rejects missing data even during this measurement phase.
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
  local coverage_target="${CARGO_TARGET_DIR:-target}/llvm-cov-target"
  local coverage_reports="${CARGO_TARGET_DIR:-target}/coverage"
  mkdir -p "${coverage_reports}"
  coverage_group() {
    local report="$1"
    shift
    local crate_args=()
    local crate
    for crate in "$@"; do
      crate_args+=(-p "${crate}")
    done
    "${binary}" llvm-cov --no-report "${crate_args[@]}"
    # The restrictive-umask child tests intentionally create mode-000 profile
    # files. Restore owner read access only on this run's generated profiles so
    # llvm-profdata can merge them; test artifacts remain in the coverage dir.
    if [ -d "${coverage_target}" ]; then
      find "${coverage_target}" -maxdepth 1 -type f -name 'oxfuzz-*.profraw' \
        -exec chmod u+r {} +
    fi
    "${binary}" llvm-cov report --json --summary-only "${crate_args[@]}" \
      --output-path "${report}"
  }
  coverage_group "${coverage_reports}/domain.json" "${COVERAGE_DOMAIN_CRATES[@]}"
  coverage_group "${coverage_reports}/infrastructure.json" "${COVERAGE_INFRASTRUCTURE_CRATES[@]}"
  python3 scripts/check_coverage.py \
    --domain "${coverage_reports}/domain.json" \
    --infrastructure "${coverage_reports}/infrastructure.json" \
    --domain-packages "${COVERAGE_DOMAIN_CRATES[@]}" \
    --infrastructure-packages "${COVERAGE_INFRASTRUCTURE_CRATES[@]}" --measure
}

gate_script_tests() {
  # scripts/tests/test_*.py had no runner before this gate existed.
  python3 -m unittest discover \
    --start-directory scripts/tests \
    --top-level-directory scripts/tests \
    --pattern 'test_*.py'
  node --test scripts/tests/release_candidate.test.cjs
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
