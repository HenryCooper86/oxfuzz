# Code Health and Continuous Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate every change with an automated Linux workflow running the repository's nine quality gates, and decompose the 12438-line `hf-service` orchestration file into a module tree with real boundaries.

**Architecture:** `scripts/tests/gates.sh` becomes a function-per-gate dispatcher accepting gate names, so `.github/workflows/ci.yml` invokes named gates rather than duplicating command lines. `crates/hf-service/src/container.rs` becomes `crates/hf-service/src/container/`, with eight modules genuinely extracted (each owning one boundary and its tests) and eleven method groups relocated into per-concern `impl ServiceContainer` blocks. Rust resolves privacy by module ancestry, so child modules reach the parent's private fields and no public API changes.

**Tech Stack:** Rust 1.94.0 (pinned in `rust-toolchain.toml`), GitHub Actions, Bash, Python 3 `unittest`, React 19 with Vitest and `react-dom/server`, Tauri v2.

**Design spec:** `docs/superpowers/specs/2026-07-31-code-health-and-ci-design.md`

**Task map:** Phase A is Tasks 1 and 2 (gate dispatcher, CI workflow). Phase B is Tasks 3 through 13 (one directory conversion, eight module extractions, eleven method-group relocations). Phase C is Tasks 14 through 16 (desktop policy surface, documentation corrections, final verification). Phase A must land before Phase B so the decomposition is gated as it lands. Phases B and C are independent of each other.

## Global Constraints

- Rust toolchain is pinned to `1.94.0` by `rust-toolchain.toml`. Never add a GitHub Action that installs a Rust channel; it silently overrides the pin. Use `rustup show active-toolchain` to provision it.
- Clippy runs `pedantic` workspace-wide with `-D warnings`. **Never add inline lint suppressions** (`#[allow(clippy::...)]`). Fix the code or move the rule to the owning config with a justifying comment. The only sanctioned exception is `#[allow(dead_code)]` on fields or variants kept for API completeness.
- **No emoji anywhere** in code, comments, commit messages, or docs.
- Post-change gate order is fixed by `AGENTS.md` section 4.5: `cargo fmt --all`, `cargo clippy --fix --allow-dirty --workspace -- -D warnings`, `cargo clippy --workspace -- -D warnings`, `cargo check --workspace`, `cargo doc --workspace --no-deps`.
- All domain logic lives in `hf-service`. `hf-cli`, `hf-web`, and `hf-gui` are thin presentation layers doing only input, output, and rendering. This plan adds no logic to a presentation crate.
- Rust casing: `snake_case` files and functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants.
- A move commit contains only moves. Never combine a relocation with a behavior change in one commit.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Baseline verified 2026-07-31 on this checkout: `cargo test --workspace` passes in 69 seconds, `cargo check --workspace --all-targets` is clean, `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`, and `python3 -m unittest discover -s scripts/tests -t scripts/tests -p 'test_*.py'` passes. Any red gate you encounter was introduced by this work.

---

## File Structure

**Created:**

| Path | Responsibility |
| --- | --- |
| `.github/workflows/ci.yml` | Three parallel Linux jobs invoking named gates (public repo) |
| `.gitlab-ci.yml` | Four parallel jobs invoking named gates (current origin, merge gate) |
| `scripts/tests/test_gates.py` | Regression tests for the gate dispatcher |
| `crates/hf-service/src/container/mod.rs` | `ServiceContainer` struct, shared constants, private helpers, submodule declarations, re-exports |
| `crates/hf-service/src/container/workspace.rs` | Managed workspace boundary: root resolution, ownership manifest, lock file, symlink-refusing directory resolution |
| `crates/hf-service/src/container/staging.rs` | Approval-to-execution integrity: run artifacts, digests, staging, verification |
| `crates/hf-service/src/container/output_budget.rs` | Run output accounting and the overflow-versus-race distinction |
| `crates/hf-service/src/container/crash_inputs.rs` | Crash artifact and CASR report collection |
| `crates/hf-service/src/container/harness_workspace.rs` | On-disk harness source, id, binary, dictionary, and seed staging |
| `crates/hf-service/src/container/project_identity.rs` | Project canonicalization, slugs, target candidate selection |
| `crates/hf-service/src/container/coverage_cache.rs` | Coverage export caching, signatures, covered-function parsing |
| `crates/hf-service/src/container/guards.rs` | RAII guards and run-journal durability helpers |
| `crates/hf-service/src/container/lifecycle.rs` | Construction, bootstrap, accessors, teardown methods |
| `crates/hf-service/src/container/chat.rs` | Chat session, transcript, checkpoint, branch methods |
| `crates/hf-service/src/container/discovery.rs` | Discovery and ranking methods |
| `crates/hf-service/src/container/harness.rs` | Harness authoring, qualification, promotion methods |
| `crates/hf-service/src/container/run.rs` | Campaign execution and cancellation methods |
| `crates/hf-service/src/container/triage.rs` | Triage, verification, coverage query methods |
| `crates/hf-service/src/container/corpus.rs` | Corpus operation methods |
| `crates/hf-service/src/container/history.rs` | Run history, artifact listing, deletion, export methods |
| `crates/hf-service/src/container/policy.rs` | Guardrail decision and auto-revert policy methods |
| `crates/hf-service/src/container/export.rs` | Report, SARIF, repro bundle, issue tracker, DefectDojo methods |
| `crates/hf-service/src/container/system.rs` | System snapshot, provider status, cost, workbench, ingest methods |
| `crates/hf-gui/src/components/PolicyDecisionList.tsx` | Presentational guardrail decision rows |
| `crates/hf-gui/src/__tests__/policyDecisionList.test.tsx` | Vitest coverage for that component |

**Modified:**

| Path | Change |
| --- | --- |
| `scripts/tests/gates.sh` | Rewritten as a gate dispatcher; `head -200` truncation removed |
| `crates/hf-gui/src-tauri/src/commands.rs` | Adds the `policy_decisions` command |
| `crates/hf-gui/src-tauri/src/lib.rs` | Registers that command |
| `crates/hf-gui/src/lib/httpTransport.ts` | Adds the `/policy/decisions` route |
| `crates/hf-gui/src/views/AuditView.tsx` | Loads and renders guardrail decisions |
| `crates/hf-gui/src/i18n.extra.ts` | Adds `audit.decisions.*` keys |
| `TODO.md` | Removes two contradicted entries |
| `CONTRIBUTING.md` | Replaces the GitLab CI claim |
| `README.md` | Replaces the GitLab CI claim |

**Deleted:** none.

---

## Phase A: Continuous Integration

### Task 1: Gate dispatcher with the SIGPIPE fix

`scripts/tests/gates.sh` currently runs eight gates as a fixed sequence. Gate 4
pipes `cargo test` through `grep | head -200` under `set -euo pipefail`. When
output exceeds 200 lines, `head` closes the pipe, `grep` dies on SIGPIPE with
status 141, and the pipeline fails even though the tests passed. A second latent
failure exists in the same line: `grep -v` exits 1 when it filters every line.

This task converts the script to one shell function per gate with a name
dispatcher, fixes both failure modes, and adds a ninth gate for the Python
script tests that nothing currently runs.

**Files:**
- Create: `scripts/tests/test_gates.py`
- Modify: `scripts/tests/gates.sh` (full rewrite)

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/tests/gates.sh [gate ...]` where a gate name is one of `fmt`, `clippy`, `check`, `test`, `doc`, `deny`, `script-tests`, `frontend-test`, `frontend-lint`. No arguments runs all nine in that order. An unknown name exits 2. Task 2 depends on these exact names.

- [ ] **Step 1: Write the failing tests**

Create `scripts/tests/test_gates.py`:

```python
#!/usr/bin/env python3
"""Regression tests for the quality gate dispatcher."""

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
GATES = REPOSITORY_ROOT / "scripts" / "tests" / "gates.sh"


class GateDispatcherTests(unittest.TestCase):
    def make_stub(self, directory: pathlib.Path, name: str, body: str) -> None:
        """Place an executable stub named `name` in `directory`."""
        path = directory / name
        path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_gates(
        self, arguments: list[str], stub_dir: pathlib.Path, timeout: float = 30.0
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PATH"] = f"{stub_dir}{os.pathsep}{environment['PATH']}"
        return subprocess.run(
            [str(GATES), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
            cwd=REPOSITORY_ROOT,
        )

    def test_passing_tests_with_long_output_exit_zero(self) -> None:
        """A passing run must not fail the gate because its output was long.

        The previous `| head -200` truncation raised SIGPIPE in grep, and
        pipefail reported status 141 for a run that actually succeeded.
        """
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            self.make_stub(
                stub_dir,
                "cargo",
                'for i in $(seq 1 500); do echo "warning: line $i"; done\nexit 0',
            )
            result = self.run_gates(["test"], stub_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fully_filtered_output_exits_zero(self) -> None:
        """`grep -v` exits 1 when it removes every line. That is not a failure."""
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            self.make_stub(stub_dir, "cargo", 'echo "running 3 tests"\nexit 0')
            result = self.run_gates(["test"], stub_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failing_tests_still_fail_the_gate(self) -> None:
        """The gate's status must be cargo's status, not the filter's."""
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            self.make_stub(stub_dir, "cargo", 'echo "test result: FAILED"\nexit 101')
            result = self.run_gates(["test"], stub_dir)
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_gate_name_is_rejected_with_the_valid_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            result = self.run_gates(["not-a-gate"], stub_dir)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not-a-gate", result.stderr)
        self.assertIn("frontend-lint", result.stderr)

    def test_no_arguments_runs_every_gate_in_the_mandated_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "invocations.log"
            self.make_stub(
                stub_dir, "cargo", f'echo "cargo $1" >> "{log}"\nexit 0'
            )
            self.make_stub(stub_dir, "npm", f'echo "npm $*" >> "{log}"\nexit 0')
            self.make_stub(
                stub_dir, "cargo-deny", f'echo "cargo-deny" >> "{log}"\nexit 0'
            )
            self.make_stub(
                stub_dir, "python3", f'echo "python3" >> "{log}"\nexit 0'
            )
            result = self.run_gates([], stub_dir, timeout=60.0)
            recorded = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded[0], "cargo fmt")
        self.assertEqual(recorded[1], "cargo clippy")
        self.assertEqual(recorded[2], "cargo check")
        self.assertEqual(recorded[3], "cargo test")
        self.assertEqual(recorded[4], "cargo doc")

    def test_named_subset_runs_only_those_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "invocations.log"
            self.make_stub(
                stub_dir, "cargo", f'echo "cargo $1" >> "{log}"\nexit 0'
            )
            result = self.run_gates(["fmt", "check"], stub_dir)
            recorded = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, ["cargo fmt", "cargo check"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest discover -s scripts/tests -t scripts/tests -p 'test_gates.py' -v`

Expected: FAIL. `test_passing_tests_with_long_output_exit_zero` returns 141 from
the SIGPIPE. `test_unknown_gate_name_is_rejected_with_the_valid_list` returns 0
because the current script ignores arguments entirely.

- [ ] **Step 3: Rewrite the gate script**

Replace the entire contents of `scripts/tests/gates.sh`:

```bash
#!/usr/bin/env bash
# oxfuzz -- quality gates.
#
#   scripts/tests/gates.sh                 # every gate, in AGENTS.md 4.5 order
#   scripts/tests/gates.sh clippy test     # only the named gates
#
# This file is the single definition of what each gate means. Continuous
# integration invokes named gates one at a time so GitHub annotates each
# separately; it never restates the commands, so the two cannot drift.
set -euo pipefail

cd "$(dirname "$0")/../.."

ALL_GATES=(fmt clippy check test doc deny script-tests frontend-test frontend-lint)

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

gate_test() {
  # The filter is display-only and must never decide the gate's status.
  # Wrapping grep in a group that always succeeds covers its exit-1-on-no-match
  # behavior, and there is no `head`, so no SIGPIPE. Under pipefail a failing
  # `cargo test` still fails the pipeline.
  cargo test --workspace 2>&1 | { grep -v "${TEST_NOISE}" || true; }
}

gate_doc() {
  cargo doc --workspace --no-deps
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest discover -s scripts/tests -t scripts/tests -p 'test_gates.py' -v`

Expected: PASS, 6 tests.

- [ ] **Step 5: Verify the real gates still work end to end**

Run: `scripts/tests/gates.sh fmt check script-tests`

Expected: three `== <name>` headers followed by `All gates passed.`, exit 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/tests/gates.sh scripts/tests/test_gates.py
git commit -m "$(cat <<'EOF'
fix: make the test gate report cargo status, not its output filter

gates.sh piped cargo test through grep | head -200 under pipefail. Output over
200 lines closed the pipe, killed grep with SIGPIPE, and failed the gate on a
passing run. grep -v exiting 1 when it filtered every line could do the same.
The filter is now display-only and the truncation is gone.

Gates become one shell function each behind a name dispatcher so continuous
integration can invoke them individually without restating the commands. Adds a
script-tests gate: scripts/tests/test_validate_semgrep_smoke.py had no runner.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: The CI workflow

`.github/workflows/` contains only `release.yml` and `fuzz.yml.example`. Nothing
runs tests, lints, or dependency checks on push. This adds three parallel Linux
jobs invoking the gates from Task 1.

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.gitlab-ci.yml`

**Interfaces:**
- Consumes: `scripts/tests/gates.sh <name>` from Task 1, with the nine gate names defined there.
- Produces: GitHub job names `rust`, `frontend`, `supply-chain`; GitLab job names `rust`, `frontend`, `script-tests`, `supply-chain`. Task 15 describes these in `CONTRIBUTING.md`.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

# Runs the gate set defined by scripts/tests/gates.sh on every push and pull
# request. That script stays the single definition of what a gate means; this
# workflow only decides which gates run where, so the two cannot drift.
#
# Linux only. Cross-platform coverage belongs to release.yml, which builds all
# four platform bundles on tag -- that is the property that actually ships, and
# the workspace itself is platform-agnostic.

on:
  push:
  pull_request:

# A rapid push sequence should not queue redundant runs.
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

# Read-only: nothing here publishes, and no secret is needed. cargo deny reaches
# the network only for advisory data.
permissions:
  contents: read

jobs:
  rust:
    name: Rust gates
    runs-on: ubuntu-latest
    steps:
      - name: Check out the repository
        uses: actions/checkout@v5

      # The Python script tests need no toolchain and finish in under a second.
      # Running them first fails fast, and a fourth job would not earn a runner.
      - name: Script tests
        run: scripts/tests/gates.sh script-tests

      # No toolchain action on purpose: rust-toolchain.toml pins 1.94.0, and an
      # action that installs a channel would silently override the pin. rustup
      # is preinstalled on the runner and provisions the pinned toolchain here.
      - name: Provision the pinned toolchain
        run: rustup show active-toolchain

      - name: Cache Rust build artifacts
        uses: Swatinem/rust-cache@v2

      - name: Format
        run: scripts/tests/gates.sh fmt

      - name: Clippy
        run: scripts/tests/gates.sh clippy

      - name: Check
        run: scripts/tests/gates.sh check

      - name: Test
        run: scripts/tests/gates.sh test

      - name: Docs
        run: scripts/tests/gates.sh doc

  frontend:
    name: Frontend gates
    runs-on: ubuntu-latest
    steps:
      - name: Check out the repository
        uses: actions/checkout@v5

      - name: Set up Node
        uses: actions/setup-node@v5
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: crates/hf-gui/package-lock.json

      - name: Test and build
        run: scripts/tests/gates.sh frontend-test

      - name: Lint
        run: scripts/tests/gates.sh frontend-lint

  supply-chain:
    name: Dependency policy
    runs-on: ubuntu-latest
    steps:
      - name: Check out the repository
        uses: actions/checkout@v5

      - name: Install cargo-deny
        uses: taiki-e/install-action@v2
        with:
          tool: cargo-deny

      - name: Deny
        run: scripts/tests/gates.sh deny
```

- [ ] **Step 2: Write the GitLab pipeline**

`origin` is `git@gitlab-ce.orb.local:hobot/oxfuzz.git`. GitHub Actions gates the
public repository the project is being open-sourced to; GitLab gates the merges
that happen today. Both call the same named gates, so neither restates a
command.

Create `.gitlab-ci.yml`:

```yaml
# oxfuzz CI.
#
# This pipeline and .github/workflows/ci.yml both invoke named gates from
# scripts/tests/gates.sh, which stays the single definition of what a gate
# means. GitLab gates merges on the current origin; the GitHub workflow gates
# the public repository.
#
# Jobs are split so a red pipeline identifies which category broke without
# opening a log.

stages:
  - gate

default:
  interruptible: true

rust:
  stage: gate
  # rustup in this image honors rust-toolchain.toml, which pins 1.94.0. Pinning
  # the image tag as well keeps the base layer stable without overriding it.
  image: rust:1.94
  variables:
    # Keep the cargo registry inside the project so it can be cached; GitLab only
    # caches paths under the build directory.
    CARGO_HOME: $CI_PROJECT_DIR/.cargo
  cache:
    key:
      files:
        - Cargo.lock
    paths:
      - .cargo/registry
      - target/
  script:
    - scripts/tests/gates.sh fmt
    - scripts/tests/gates.sh clippy
    - scripts/tests/gates.sh check
    - scripts/tests/gates.sh test
    - scripts/tests/gates.sh doc

frontend:
  stage: gate
  image: node:22
  variables:
    # npm ci wipes node_modules every run, so caching it saves nothing. The
    # download cache is the part that survives and speeds up reinstall.
    npm_config_cache: $CI_PROJECT_DIR/.npm
  cache:
    key:
      files:
        - crates/hf-gui/package-lock.json
    paths:
      - .npm
  script:
    - scripts/tests/gates.sh frontend-test
    - scripts/tests/gates.sh frontend-lint

script-tests:
  stage: gate
  # Its own job rather than riding along with rust: the Rust image has no
  # python3, and installing one there would cost more than this job does.
  image: python:3.12-slim
  script:
    - scripts/tests/gates.sh script-tests

supply-chain:
  stage: gate
  image: rust:1.94
  variables:
    CARGO_HOME: $CI_PROJECT_DIR/.cargo
  cache:
    key: cargo-deny
    paths:
      - .cargo/bin
  before_script:
    # cargo install honors CARGO_HOME, but the rust image bakes PATH at build
    # time, so the installed binary is invisible without this.
    - export PATH="$CARGO_HOME/bin:$PATH"
  script:
    - command -v cargo-deny || cargo install cargo-deny --locked
    - scripts/tests/gates.sh deny
```

Three things in that file are load-bearing and easy to get wrong:

- `script-tests` is its own job because GitLab jobs pick their own images and
  `rust:1.94` has no `python3`, whereas the GitHub runner has both preinstalled.
- `CARGO_HOME` is job-scoped, never global. It exists so the cargo registry sits
  inside the build directory, which is the only place GitLab can cache. A global
  setting would leak into `supply-chain`.
- `supply-chain` must export `$CARGO_HOME/bin` onto `PATH` before running the
  gate. `cargo install` honors `CARGO_HOME`, but the `rust` image bakes
  `PATH=/usr/local/cargo/bin:$PATH` at image build time, so the freshly
  installed `cargo-deny` is otherwise invisible — and `gate_deny`'s fallback
  looks in `${HOME}/.cargo/bin`, which is `/root/.cargo/bin` in that image, not
  the project directory. Without the export the job fails on every run.

- [ ] **Step 3: Validate both files parse**

Run:

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); yaml.safe_load(open('.gitlab-ci.yml')); print('ok')"
```

Expected: `ok`. If PyYAML is unavailable, run
`npx --yes yaml-lint .github/workflows/ci.yml .gitlab-ci.yml` instead.

- [ ] **Step 4: Verify the gate sequence runs locally**

Run: `scripts/tests/gates.sh script-tests fmt check`

Expected: exit 0. This is the cheap subset of the `rust` job; the full sequence
is verified by the pipeline itself in Step 6.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml .gitlab-ci.yml
git commit -m "$(cat <<'EOF'
ci: gate every push and merge request

Nothing ran tests, lints, or dependency checks on push. scripts/tests/gates.sh
defined the gate set but only ran when someone remembered to invoke it.

Adds two pipelines that both call named gates from that script, so neither
restates a command and the two cannot drift: .gitlab-ci.yml gates merges on the
current origin, and .github/workflows/ci.yml gates the public repository. Jobs
are split so a red pipeline identifies which category broke without opening a
log.

Linux only. release.yml already proves the four platform bundles build on tag,
and the workspace is platform-agnostic.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Report what can and cannot be verified here**

Do not push in this task. Two things make live pipeline verification the
controller's call, not the implementer's:

- The GitLab instance runs in OrbStack and may have no runner registered, in
  which case a pushed pipeline sits pending rather than failing — a state that
  looks like breakage but is not.
- GitHub Actions cannot run at all until the repository is pushed to GitHub,
  which has not happened.

Instead, report in your task report:

1. that both files parse (Step 3 output);
2. that the local gate subset passes (Step 4 output);
3. the exact commands a human should run to verify live, namely
   `git push -u origin code-health-and-ci-20260731` followed by checking the
   pipeline on the GitLab instance.

The controller records live verification as a deferred item and resolves it
outside this task.

---

## Phase B: Container Decomposition

Every task in this phase is a move. Do not rename anything, do not reorder
statements inside a moved item, and do not fix anything you notice along the
way. If you find a genuine bug, note it and finish the move first.

**Verification command used by every task in this phase:**

```bash
cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20
```

### Task 3: Convert the file to a directory module

**Files:**
- Modify: `crates/hf-service/src/container.rs` becomes `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `crates/hf-service/src/container/mod.rs`, the parent module every later task in this phase adds submodules to.

- [ ] **Step 1: Move the file**

```bash
mkdir -p crates/hf-service/src/container
git mv crates/hf-service/src/container.rs crates/hf-service/src/container/mod.rs
```

- [ ] **Step 2: Verify nothing else changes**

Run: `cargo check -p hf-service --all-targets`

Expected: success with no warnings. `pub mod container;` in
`crates/hf-service/src/lib.rs:23` resolves to `container/mod.rs` unchanged.

- [ ] **Step 3: Run the crate's tests**

Run: `cargo test -p hf-service 2>&1 | tail -20`

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src
git commit -m "$(cat <<'EOF'
refactor: make hf-service container a directory module

Pure file move ahead of decomposition. No content change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Extract the workspace boundary module

This is the `AGENTS.md` section 2.12 guarantee that untrusted target and project
names never reach the host filesystem outside the managed workspace. It is
currently a run of free functions above the struct, reachable only through
whichever `ServiceContainer` method happens to exercise it.

**Files:**
- Create: `crates/hf-service/src/container/workspace.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container/mod.rs` from Task 3.
- Produces: `crate::container::workspace` exporting `workspace_root() -> PathBuf`, `initialize_workspace_root() -> Result<PathBuf, ClassifiedError>`, `workspace_dir(project: &Path, target: &str) -> PathBuf`, `project_workspace_dir(project: &Path) -> PathBuf`, `document_staging_dir(project: &Path, import_id: Uuid) -> PathBuf`, `run_output_relative(run_id: Uuid) -> PathBuf`, `resolve_workspace_directory(...)`, `prepare_managed_workspace_root`, `prepare_configured_workspace_root`, `clear_managed_workspace_root`, `validate_workspace_cleanup_root`, and `workspace_operation_gate`. Tasks 5 through 21 rely on these names.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/workspace.rs` with this header, then
move the following items into it **verbatim** from `mod.rs`:

```rust
//! The managed workspace boundary.
//!
//! Every path that a project name, target name, or run id contributes to is
//! resolved here. The module exists so that boundary has one name and one test
//! surface: `AGENTS.md` 2.12 requires untrusted inputs never to touch the host
//! filesystem outside the workspace, and that guarantee is only as good as the
//! resolution functions below.
```

Items to move, in their current order:

- constants `WORKSPACE_MANIFEST_FILE`, `WORKSPACE_MANIFEST_VERSION`
- `struct WorkspaceOwnershipManifest`
- `workspace_root`, `initialize_workspace_root`, `workspace_root_from`,
  `workspace_root_selection`, `configured_workspace_root`
- `workspace_operation_gate`, `workspace_lock_file`, `workspace_lock_error`
- `protected_workspace_paths`, `comparable_path`, both `same_filesystem_entry`
  definitions with their `#[cfg]` attributes intact
- `validate_workspace_cleanup_root`, `workspace_manifest`,
  `validate_workspace_manifest`, `write_workspace_manifest`
- `prepare_managed_workspace_root_with_adoption`, `prepare_managed_workspace_root`,
  `prepare_configured_workspace_root`, `clear_managed_workspace_root`
- `workspace_dir`, `project_workspace_dir`, `document_staging_dir`,
  `run_output_relative`
- `resolve_workspace_directory` and the private resolver beneath it
- the `#[cfg(test)]` module currently at roughly line 511, which tests these
  functions

Add the `use` statements the moved code needs at the top of the new file. Copy
them from `mod.rs`; do not guess.

- [ ] **Step 2: Wire the module into the parent**

In `crates/hf-service/src/container/mod.rs`, delete the moved items and add near
the other module declarations:

```rust
mod workspace;

pub use workspace::{initialize_workspace_root, project_workspace_dir, workspace_dir, workspace_root};
```

Then add an internal import so the remaining code in `mod.rs` still resolves:

```rust
use workspace::{
    clear_managed_workspace_root, document_staging_dir, prepare_configured_workspace_root,
    prepare_managed_workspace_root, resolve_workspace_directory, run_output_relative,
    validate_workspace_cleanup_root, workspace_operation_gate,
};
```

The `pub use` list must match exactly the four names `lib.rs` re-exports today.
Confirm with `grep -n 'workspace_root\|workspace_dir' crates/hf-service/src/lib.rs`
before committing.

- [ ] **Step 3: Verify**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass. If a private item is now unreachable, add it
to the internal `use` list rather than widening its visibility.

- [ ] **Step 4: Verify the whole workspace still builds**

Run: `cargo check --workspace`

Expected: success. This catches any path `hf-cli`, `hf-web`, or `hf-gui` imports
directly.

- [ ] **Step 5: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract the managed workspace boundary

Moves workspace root resolution, the ownership manifest, the advisory lock,
cleanup validation, and the symlink-refusing directory resolver out of the
container file into container/workspace.rs. Move only; no behavior change.

The AGENTS.md 2.12 boundary now has one name and one test surface instead of
being a run of free functions above a 131-method type.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Add the missing manifest adoption test**

The adoption rule is asymmetric and load-bearing: the implicit per-user default
root may adopt pre-manifest artifacts, but an explicit `HF_WORKSPACE_DIR`
override without a manifest never may. Add to the `#[cfg(test)]` module in
`crates/hf-service/src/container/workspace.rs`:

```rust
    #[test]
    fn explicit_override_without_a_manifest_is_never_adopted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("explicit");
        std::fs::create_dir_all(root.join("legacy-project")).expect("legacy artifact");

        let adopted = prepare_managed_workspace_root_with_adoption(&root, false);

        assert!(
            adopted.is_err(),
            "an explicit override must not adopt unmanaged artifacts"
        );
    }

    #[test]
    fn implicit_default_adopts_pre_manifest_artifacts() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("implicit");
        std::fs::create_dir_all(root.join("legacy-project")).expect("legacy artifact");

        let adopted =
            prepare_managed_workspace_root_with_adoption(&root, true).expect("adoption allowed");

        assert_eq!(adopted, root);
        assert!(workspace_manifest(&root).is_file(), "manifest written on adoption");
    }
```

Check `prepare_managed_workspace_root_with_adoption`'s real signature before
running: if its second parameter is not a bare `bool`, adapt the call and keep
the assertions. Run
`cargo test -p hf-service container::workspace 2>&1 | tail -20` and expect both
to pass. If either fails, the extraction changed behavior; revert Step 6, fix
the extraction, and repeat.

- [ ] **Step 7: Commit the tests**

```bash
git add crates/hf-service/src/container/workspace.rs
git commit -m "$(cat <<'EOF'
test: cover workspace manifest adoption asymmetry

The implicit per-user default may adopt pre-manifest artifacts; an explicit
HF_WORKSPACE_DIR override may not. Only the second half was covered.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Extract the staging and integrity module

This module owns one invariant: the source and binary a human approved are
byte-identical to what executes in the sandbox.

**Files:**
- Create: `crates/hf-service/src/container/staging.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container::workspace` from Task 4.
- Produces: `crate::container::staging` exporting `struct RunArtifacts`, `struct ReplayProvenance`, `struct RunContextDigests`, `sha256_file(path: &Path) -> Result<String, ClassifiedError>`, `stage_run_artifacts(...)`, `verify_run_artifacts(artifacts: &RunArtifacts) -> Result<(), ClassifiedError>`, `run_context_digests(...)`, `retain_run_context(...)`, `resolve_run_sandbox_image(...)`, `qualification_evidence(harness: &Harness) -> Result<(Uuid, &str, &str), ClassifiedError>`, `verify_staged_qualification(...)`, `run_output_dir(...)`, `run_binary_path(...)`, `run_source_path(...)`, `run_sandbox_options(...)`, `minimization_sandbox_options(...)`, `minimization_failure_with_rollback(...)`, and `quarantine_corpus_entry(...)`. Tasks 11 through 15 rely on these.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/staging.rs` with this header:

```rust
//! Approval-to-execution integrity.
//!
//! A human approves a specific harness revision. This module stages that exact
//! source and binary into a run-owned input directory, records their digests,
//! and re-verifies them immediately before launch. If anything changed between
//! approval and execution, the run fails closed rather than fuzzing something
//! the operator never saw.
```

Move these items verbatim from `mod.rs`, in their current order:

- `struct RunArtifacts`, `struct ReplayProvenance`
- `sha256_file`, `quarantine_corpus_entry`
- `struct RunContextDigests`, `retain_run_context`, `run_context_digests`
- `resolve_run_sandbox_image`, `stage_run_artifacts`, `verify_run_artifacts`
- `qualification_evidence`, `verify_staged_qualification`
- `run_sandbox_options`, `minimization_sandbox_options`,
  `minimization_failure_with_rollback`
- `run_output_dir`, `run_binary_path`, `run_source_path`

Add the `use` statements the moved code needs, including
`use super::workspace::resolve_workspace_directory;` if the moved code calls it.

- [ ] **Step 2: Wire the module into the parent**

In `mod.rs`, delete the moved items and add:

```rust
mod staging;

use staging::{
    minimization_failure_with_rollback, minimization_sandbox_options, qualification_evidence,
    quarantine_corpus_entry, resolve_run_sandbox_image, retain_run_context, run_binary_path,
    run_context_digests, run_output_dir, run_sandbox_options, run_source_path, sha256_file,
    stage_run_artifacts, verify_run_artifacts, verify_staged_qualification, ReplayProvenance,
    RunArtifacts, RunContextDigests,
};
```

- [ ] **Step 3: Verify**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract run staging and integrity verification

Moves RunArtifacts, digest computation, sandbox image resolution, staging, and
pre-launch verification into container/staging.rs. Move only; no behavior
change.

The invariant this code enforces -- what was approved is what executes -- now
has a module boundary instead of being spread across free functions.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Extract the output budget module

A live fuzzer creates, renames, and deletes files continuously, so a directory
entry enumerated by `read_dir` can vanish before its `symlink_metadata` call.
Conflating that race with a real budget overflow previously killed valid
campaigns. This module owns that three-state distinction.

**Files:**
- Create: `crates/hf-service/src/container/output_budget.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container::staging::RunArtifacts` from Task 5.
- Produces: `crate::container::output_budget` exporting `enum OutputBudget` with variants `Within`, `Exceeded`, and the indeterminate variant (use the existing name), `output_budget_status(...) -> OutputBudget`, `monitor_run_output(...)`, `run_artifacts_within_budget(artifacts: &RunArtifacts, max_output_file_bytes: u64) -> bool`, and the constants `MAX_RUN_OUTPUT_BYTES` and `MAX_RUN_OUTPUT_ENTRIES`.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/output_budget.rs` with this header:

```rust
//! Run output accounting.
//!
//! A running fuzzer mutates its output tree constantly, so an entry seen by
//! `read_dir` can be gone by the time it is stat-ed. That transient race must
//! not be reported as a budget violation: doing so killed valid campaigns and
//! discarded their results. The scan therefore has three outcomes, not two.
```

Move verbatim from `mod.rs`: constants `MAX_RUN_OUTPUT_BYTES` and
`MAX_RUN_OUTPUT_ENTRIES`, `enum OutputBudget` with its doc comments intact,
`output_budget_status`, `monitor_run_output`, and
`run_artifacts_within_budget`.

- [ ] **Step 2: Wire the module into the parent**

```rust
mod output_budget;

use output_budget::{monitor_run_output, run_artifacts_within_budget};
```

Add `output_budget_status` and the constants to that list only if `mod.rs` still
references them after the move.

- [ ] **Step 3: Verify**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract run output budget accounting

Moves OutputBudget and its scan into container/output_budget.rs. Move only; no
behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Add the missing race classification test**

Add to `crates/hf-service/src/container/output_budget.rs` a `#[cfg(test)]`
module (or extend one if the move brought it along):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vanishing_entry_is_indeterminate_not_a_violation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("gone");

        // A path enumerated by read_dir and deleted before stat: exactly what a
        // live fuzzer does between iterations.
        let status = output_budget_status(&missing, MAX_RUN_OUTPUT_BYTES);

        // Assert the specific variant, not merely "not Exceeded". The enum has
        // three states, so a not-Exceeded assertion would also pass if a bug
        // classified the vanished entry as Within -- an equally wrong answer,
        // and the one this module exists to prevent.
        assert_eq!(
            status,
            OutputBudget::Indeterminate,
            "a transient read race must classify as indeterminate, not as within budget or as a violation"
        );
    }

    #[test]
    fn an_empty_tree_is_within_budget() {
        let dir = tempfile::tempdir().expect("temp dir");

        let status = output_budget_status(dir.path(), MAX_RUN_OUTPUT_BYTES);

        assert!(matches!(status, OutputBudget::Within));
    }
}
```

Check `output_budget_status`'s real signature and `OutputBudget`'s real variant
names before running; adapt the call and the patterns, keep the assertions. Run
`cargo test -p hf-service container::output_budget 2>&1 | tail -20` and expect
both to pass.

- [ ] **Step 6: Commit the tests**

```bash
git add crates/hf-service/src/container/output_budget.rs
git commit -m "$(cat <<'EOF'
test: cover the output budget race classification

A vanishing directory entry must classify as indeterminate, not as a budget
violation. That distinction was only covered indirectly.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Extract the crash input collection module

**Files:**
- Create: `crates/hf-service/src/container/crash_inputs.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container/mod.rs`.
- Produces: `crate::container::crash_inputs` exporting `stage_crash_inputs(engine: EngineKind, out_dir: &Path, staging: &Path) -> usize`, `collect_crash_inputs(engine: EngineKind, out_dir: &Path) -> Vec<PathBuf>`, `collect_legacy_crash_inputs(out_dir: &Path) -> Vec<PathBuf>`, `collect_workspace_crash_inputs(workspace: &Path) -> Vec<PathBuf>`, `collect_casreps(dir: &Path) -> Vec<(PathBuf, CasrReport)>`, `collect_casreps_into(dir: &Path, out: &mut Vec<(PathBuf, CasrReport)>)`, `casrep_input_path(out_dir: &Path, casrep: &Path, crash_inputs: &[PathBuf]) -> PathBuf`, `deterministic_crash_id(run_id: Uuid, signature: &str, input: &Path) -> Uuid`, and `bucket_by_cluster(crashes: Vec<Crash>) -> Vec<Crash>`.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/crash_inputs.rs` with this header:

```rust
//! Crash artifact and CASR report collection.
//!
//! Engines lay out their findings differently, and older runs used a flat
//! layout. This module normalizes both into the input paths and CASR reports
//! triage consumes, and derives the stable crash identity used for dedup.
```

Move verbatim: `is_regular_file`, `is_regular_directory`, `stage_crash_inputs`,
`collect_crash_inputs`, `collect_legacy_crash_inputs`,
`collect_workspace_crash_inputs`, the `#[cfg(test)]` module currently at roughly
line 2235, `bucket_by_cluster`, `collect_casreps`, `collect_casreps_into`,
`casrep_input_path`, and `deterministic_crash_id`.

- [ ] **Step 2: Wire the module into the parent**

```rust
mod crash_inputs;

use crash_inputs::{
    bucket_by_cluster, casrep_input_path, collect_casreps, collect_crash_inputs,
    collect_workspace_crash_inputs, deterministic_crash_id, is_regular_directory, is_regular_file,
    stage_crash_inputs,
};
```

Include `collect_casreps_into` and `collect_legacy_crash_inputs` in that list
only if `mod.rs` calls them directly rather than through their siblings.

- [ ] **Step 3: Verify**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract crash input and CASR report collection

Moves per-engine crash layout normalization, CASR report walking, and
deterministic crash identity into container/crash_inputs.rs, with the test
module that already covered them. Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Extract the harness workspace module

**Files:**
- Create: `crates/hf-service/src/container/harness_workspace.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container::workspace`.
- Produces: `crate::container::harness_workspace` exporting `read_current_harness_source(workspace: &Path) -> Option<String>`, `read_current_harness_id(workspace: &Path) -> Option<Uuid>`, `write_current_harness_source(workspace: &Path, source: &str) -> Result<(), ClassifiedError>`, `write_current_harness_id(workspace: &Path, id: Uuid) -> Result<(), ClassifiedError>`, `write_current_harness_binary(...)`, `harness_binary_name(target: &str) -> String`, `target_artifact_stem(target: &str) -> String`, `sanitize_target(target: &str) -> PathBuf`, `container_input_path(workspace: &Path, host_path: &Path) -> String`, `build_workspace_dictionary(workspace: &Path, dict_name: &str) -> Option<PathBuf>`, `read_dictionary_source_excerpt(workspace: &Path, max_bytes: usize) -> String`, `dict_llm_cache()`, `generate_target_seeds(target: &str) -> Vec<(Vec<u8>, String)>`, `copy_project_sources(project: &Path, workspace: &Path)`, `stage_rust_crate(project: &Path, workspace: &Path)`, and `copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()>`.

Note: `generate_target_seeds`, `copy_project_sources`, and `build_sandbox_image`
are currently `pub`. Check `grep -rn 'generate_target_seeds\|copy_project_sources' crates --include='*.rs' | grep -v hf-service`
before moving; whatever is used outside the crate must stay `pub use`-exported
from `mod.rs`.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/harness_workspace.rs` with this header:

```rust
//! On-disk harness state inside a target workspace.
//!
//! The workspace holds the harness revision currently staged for a target: its
//! source, its id marker, its compiled binary, and the dictionary and seeds
//! derived from it. Reading and writing that state is separated here so the
//! marker-versus-source resolution rules live in one place.
```

Move verbatim: `sanitize_target`, `target_artifact_stem`, `harness_binary_name`,
`generate_target_seeds`, `build_workspace_dictionary`,
`read_dictionary_source_excerpt`, `dict_llm_cache`, `read_current_harness_source`,
`read_current_harness_id`, `write_current_harness_source`,
`write_current_harness_id`, `write_current_harness_binary`,
`container_input_path`, `copy_project_sources`, `stage_rust_crate`, and
`copy_dir_recursive`.

- [ ] **Step 2: Wire the module into the parent**

```rust
mod harness_workspace;

pub use harness_workspace::{copy_project_sources, generate_target_seeds};

use harness_workspace::{
    build_workspace_dictionary, container_input_path, harness_binary_name,
    read_current_harness_id, read_current_harness_source, read_dictionary_source_excerpt,
    sanitize_target, stage_rust_crate, target_artifact_stem, write_current_harness_binary,
    write_current_harness_id, write_current_harness_source,
};
```

Adjust the `pub use` list to exactly the names the grep in the task preamble
showed are used outside `hf-service`.

- [ ] **Step 3: Verify**

Run: `cargo check --workspace --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass. The workspace-wide check matters here because
two moved functions are part of the crate's public surface.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract on-disk harness workspace state

Moves harness source/id/binary read and write, target name sanitization,
dictionary building, seed generation, and project source staging into
container/harness_workspace.rs. Move only; no behavior change. The two
crate-public functions keep their paths through a re-export.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Extract project identity and coverage cache modules

Two small modules in one task: neither is large enough to justify its own
review gate, and they have no interaction.

**Files:**
- Create: `crates/hf-service/src/container/project_identity.rs`
- Create: `crates/hf-service/src/container/coverage_cache.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container/mod.rs`.
- Produces: `crate::container::project_identity` exporting `canonical_project_root(project: &Path) -> Result<PathBuf, ClassifiedError>`, `stored_project_matches(stored: &Path, canonical: &Path) -> bool`, `project_lookup_identity(project: &Path) -> PathBuf`, `select_target_candidate<'c>(...) -> Result<Option<&'c TargetCandidate>, ClassifiedError>`, `project_slug(project: &Path) -> String`, `defectdojo_project_name(project: &Path) -> String`. And `crate::container::coverage_cache` exporting `export_cache()`, `frontier_refine_lines(...)`, `coverage_signature(workspace: &Path) -> u64`, `parse_covered_functions(json: &str) -> Vec<String>`.

- [ ] **Step 1: Create the project identity module**

Create `crates/hf-service/src/container/project_identity.rs` with this header:

```rust
//! Project and target identity resolution.
//!
//! A project is addressed by path from three presentation layers and stored
//! canonically. A target is addressed by bare symbol or by the file-scoped
//! `file::symbol` qualifier introduced in migration 0019. Both resolutions live
//! here so callers cannot invent their own matching rules.
```

Move verbatim: `defectdojo_project_name`, `canonical_project_root`,
`stored_project_matches`, `project_lookup_identity`, `select_target_candidate`,
and `project_slug`.

- [ ] **Step 2: Create the coverage cache module**

Create `crates/hf-service/src/container/coverage_cache.rs` with this header:

```rust
//! Coverage export caching and parsing.
//!
//! Recomputing a coverage export is expensive, so results are cached against a
//! signature of the workspace state that produced them. The parsing helpers
//! turn `llvm-cov export` JSON into the function lists the refine loop uses.
```

Move verbatim: `export_cache`, `frontier_refine_lines`, `coverage_signature`,
and `parse_covered_functions`.

- [ ] **Step 3: Wire both modules into the parent**

```rust
mod coverage_cache;
mod project_identity;

use coverage_cache::{
    coverage_signature, export_cache, frontier_refine_lines, parse_covered_functions,
};
use project_identity::{
    canonical_project_root, defectdojo_project_name, project_lookup_identity, project_slug,
    select_target_candidate, stored_project_matches,
};
```

- [ ] **Step 4: Verify**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract project identity and coverage caching

Moves project canonicalization, slug derivation, and target candidate selection
into container/project_identity.rs; moves coverage export caching, signatures,
and covered-function parsing into container/coverage_cache.rs. Move only; no
behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Extract the RAII guards module

**Files:**
- Create: `crates/hf-service/src/container/guards.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: `container/mod.rs`.
- Produces: `crate::container::guards` exporting `pub struct AgentTurnGuard`, `struct ActiveRunGuard`, `struct PersistedRunGuard`, `struct ProviderHealthTask`, `struct StagingDirectoryGuard`, `ensure_run_journal_durable(...)`, and `close_run_journal(...)`, each with its `Drop` implementation.

Note: `AgentTurnGuard` is `pub` and re-exported from `lib.rs`. Verify with
`grep -n 'AgentTurnGuard' crates/hf-service/src/lib.rs` and keep its public path.

- [ ] **Step 1: Create the module and move the items**

Create `crates/hf-service/src/container/guards.rs` with this header:

```rust
//! Scope guards for container-owned state.
//!
//! Each guard exists because the state it manages must be released even on an
//! error path: an in-flight run's cancellation token, a tracked agent turn, a
//! staging directory, a provider health task, and the run journal entry whose
//! durability gates further execution.
```

Move verbatim: `struct StagingDirectoryGuard` and its `Drop`,
`pub struct AgentTurnGuard` and its `Drop`, `struct ActiveRunGuard` and its
`Drop`, `struct ProviderHealthTask` and its `Drop`, `struct PersistedRunGuard`
with its `impl` and `Drop`, `spawn_provider_health_checks`,
`ensure_run_journal_durable`, and `close_run_journal`.

- [ ] **Step 2: Wire the module into the parent**

```rust
mod guards;

pub use guards::AgentTurnGuard;

use guards::{
    close_run_journal, ensure_run_journal_durable, spawn_provider_health_checks, ActiveRunGuard,
    PersistedRunGuard, ProviderHealthTask, StagingDirectoryGuard,
};
```

- [ ] **Step 3: Verify**

Run: `cargo check --workspace --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: extract container scope guards

Moves the agent turn, active run, persisted run, staging directory, and provider
health guards with their Drop implementations into container/guards.rs, along
with the run journal durability helpers. Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Relocate lifecycle, system, and chat methods

The remaining tasks in this phase move `impl ServiceContainer` methods into
per-concern blocks. The struct definition, its fields, and the private helpers
`build_cost_map`, `build_session_managers`, `bounded_guardrail_detail`,
`chat_storage_error`, `fuzzing_policy_error`, `require_fuzzing_harness_engine`,
`resolve_fuzzing_run`, `resolve_internal_run`, and `run_has_crash_evidence` stay
in `mod.rs`.

Each new file follows this shape:

```rust
//! <one-line description of the concern>

use super::ServiceContainer;
// plus whatever the moved bodies need

impl ServiceContainer {
    // moved methods, verbatim
}
```

Child modules see the parent's private fields, so no field visibility changes.

**Files:**
- Create: `crates/hf-service/src/container/lifecycle.rs`
- Create: `crates/hf-service/src/container/system.rs`
- Create: `crates/hf-service/src/container/chat.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: every module from Tasks 4 through 10.
- Produces: no new names. `ServiceContainer`'s method set is unchanged; only its definition site moves.

- [ ] **Step 1: Move the lifecycle methods**

Create `crates/hf-service/src/container/lifecycle.rs` with the doc comment
`//! Container construction, bootstrap, accessors, and teardown.` and move these
methods verbatim out of the `impl ServiceContainer` block in `mod.rs`:

`new`, `stubbed`, `with_store`, `with_store_path`, `with_guardrails`,
`with_provider_pool`, `bootstrap`, `provider_pool`, `store`, `guardrails`,
`diagnostics`, `checkpoint_manager`, `session_manager`, `session_turn_lock`,
`reload_providers`, `track_agent`, `clear_workspace`, `delete_project`,
`clear_knowledge`.

Add `mod lifecycle;` to `mod.rs`.

- [ ] **Step 2: Verify and commit the lifecycle move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container lifecycle methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 3: Move the system methods**

Create `crates/hf-service/src/container/system.rs` with the doc comment
`//! Readiness, provider status, cost, and workbench queries.` and move
verbatim: `system_snapshot`, `provider_statuses`, `thaw_provider`,
`cost_summary`, `workbench_dashboard`, `ingest_document`.

Add `mod system;` to `mod.rs`.

Note: `crates/hf-service/src/system.rs` and `workbench.rs` already exist as
sibling modules of `container`. This new file is `container/system.rs`, a
different path. Do not merge them.

- [ ] **Step 4: Verify and commit the system move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container system and readiness methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Move the chat methods**

Create `crates/hf-service/src/container/chat.rs` with the doc comment
`//! Chat sessions, transcripts, checkpoints, and branches.` and move verbatim:
`chat_send`, `chat_history`, `create_chat_session`, `delete_chat_session`,
`chat_branch`, `chat_branches`, `chat_checkpoints`, `chat_create_checkpoint`,
`chat_rollback_last`, `chat_rollback_to`.

Add `mod chat;` to `mod.rs`.

- [ ] **Step 6: Verify and commit the chat move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass. `chat_send` is the largest single method in
the file; if the move breaks compilation, the cause is a missing `use`, not a
visibility problem.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container chat methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Relocate discovery, harness, and run methods

**Files:**
- Create: `crates/hf-service/src/container/discovery.rs`
- Create: `crates/hf-service/src/container/harness.rs`
- Create: `crates/hf-service/src/container/run.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: Tasks 4 through 11.
- Produces: no new names.

- [ ] **Step 1: Move the discovery methods**

Create `crates/hf-service/src/container/discovery.rs` with the doc comment
`//! Target discovery and ranking.` and move verbatim: `discover`, `rank`,
`schedulable_targets`. Add `mod discovery;` to `mod.rs`.

- [ ] **Step 2: Verify and commit the discovery move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container discovery methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 3: Move the harness methods**

Create `crates/hf-service/src/container/harness.rs` with the doc comment
`//! Harness authoring, sandbox qualification, and promotion.` and move
verbatim: `harness_draft`, `harness_compile`, `harness_generate`,
`harness_refine`, `harness_smoke`, `harness_promote`,
`harness_promote_with_findings`, `harness_review_queue`, `generate_seeds`,
`generate_seeds_llm`. Add `mod harness;` to `mod.rs`.

- [ ] **Step 4: Verify and commit the harness move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container harness methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Move the run methods**

Create `crates/hf-service/src/container/run.rs` with the doc comment
`//! Campaign execution, replay, and cooperative cancellation.` and move
verbatim: `run_campaign`, `start_fuzzer`, `run_fuzzer`, `replay_run`,
`run_syzkaller`, `run_control_status`, `request_run_cancel`, `cancel_run`,
`cancel_all_runs`, `active_run_ids`. Add `mod run;` to `mod.rs`.

- [ ] **Step 6: Verify and commit the run move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container run execution methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: Relocate triage, corpus, history, policy, and export methods

**Files:**
- Create: `crates/hf-service/src/container/triage.rs`
- Create: `crates/hf-service/src/container/corpus.rs`
- Create: `crates/hf-service/src/container/history.rs`
- Create: `crates/hf-service/src/container/policy.rs`
- Create: `crates/hf-service/src/container/export.rs`
- Modify: `crates/hf-service/src/container/mod.rs`

**Interfaces:**
- Consumes: Tasks 4 through 12.
- Produces: no new names. After this task `mod.rs` contains only the struct, its constants, its private helpers, and its module declarations and re-exports.

- [ ] **Step 1: Move the triage methods**

Create `crates/hf-service/src/container/triage.rs` with the doc comment
`//! Crash triage, verification, and coverage queries.` and move verbatim:
`triage`, `triage_run`, `verify_crash`, `verify_crashes`,
`verify_harness_source`, `verify_regressions`, `coverage_functions`,
`coverage_uncovered`, `coverage_summary`. Add `mod triage;` to `mod.rs`.

- [ ] **Step 2: Verify and commit the triage move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container triage and coverage methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 3: Move the corpus methods**

Create `crates/hf-service/src/container/corpus.rs` with the doc comment
`//! Corpus seeding, growth, pruning, minimization, and crash absorption.` and
move verbatim: `corpus_list`, `corpus_seed`, `corpus_grow`, `corpus_prune`,
`corpus_prune_coverage`, `corpus_absorb_crashes`,
`corpus_absorb_crashes_for_run`, `corpus_minimize`. Add `mod corpus;` to
`mod.rs`.

- [ ] **Step 4: Verify and commit the corpus move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container corpus methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Move the history methods**

Create `crates/hf-service/src/container/history.rs` with the doc comment
`//! Retained evidence: run history, artifacts, deletion, and export.` and move
verbatim: `run_history`, `run_coverage_series`, `run_harness_source`,
`delete_run`, `clear_all_runs`, `interrupted_runs`, `dismiss_interrupted_run`,
`artifact_summary`, `all_crashes`, `delete_crash`, `all_corpus_entries`,
`delete_corpus_entry`, `clear_all_artifacts`, `export_project_data`. Add
`mod history;` to `mod.rs`.

- [ ] **Step 6: Verify and commit the history move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container history and artifact methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Move the policy methods**

Create `crates/hf-service/src/container/policy.rs` with the doc comment
`//! Guardrail decision history and auto-revert policy.` and move verbatim:
`policy_decisions`, `auto_revert_events`, `project_auto_revert_override`,
`project_auto_revert_overrides`, `effective_auto_revert_view`,
`set_project_auto_revert_override`, `clear_project_auto_revert_override`,
`revert_harness_from_run`, `approve_agent_tool`. Add `mod policy;` to `mod.rs`.

Move any `#[cfg(test)]` module covering `policy_decisions` into this file with
them.

**Leave `GUARDRAIL_DECISION_RETENTION` in `mod.rs`.** An earlier revision of this
plan said to move it, which was wrong. The rule is that a constant moves with its
sole consumer; this constant's sole consumer is the private method
`record_guardrail_decision`, which stays in `mod.rs` because it is called from
`authorize_recorded` — a chokepoint every sibling module reaches through
`self.authorize_recorded(...)`. Moving the constant therefore inverts the
dependency: the child module would own a value whose only user is the parent, and
the constant would need `pub(super)` purely to be imported back up. Leave it a
plain private `const` where it is.

- [ ] **Step 8: Verify and commit the policy move**

Run: `cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20`

Expected: success, all tests pass, including
`policy_decisions_are_newest_first_and_bounded`.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container policy methods

Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Move the export methods**

Create `crates/hf-service/src/container/export.rs` with the doc comment
`//! Reports, SARIF, repro bundles, and external tracker handoff.` and move
verbatim: `export_repro_bundle`, `export_repro_bundle_for_latest`,
`export_sarif`, `generate_report`, `report_formats`, `export_report`,
`export_markdown`, `list_report_drafts`, `save_report_draft`,
`delete_report_draft`, `issue_export`, `issue_tracker_configured`,
`issue_tracker_test_connection`, `file_issue`, `defectdojo_configured`,
`defectdojo_url`, `defectdojo_test_connection`, `push_to_defectdojo`. Add
`mod export;` to `mod.rs`.

- [ ] **Step 10: Verify and commit the export move**

Run: `cargo check --workspace --all-targets && cargo test --workspace 2>&1 | tail -20`

Expected: success, all tests pass. Run the full workspace here: this is the last
move, and `hf-cli`, `hf-web`, and `hf-gui/src-tauri` must compile untouched.

```bash
git add -A crates/hf-service/src/container
git commit -m "$(cat <<'EOF'
refactor: relocate container export and integration methods

Completes the container decomposition. mod.rs now holds the struct, its
constants, its private helpers, and its module declarations; every method group
lives in a named sibling. Move only; no behavior change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 11: Confirm the size target**

Run:

```bash
wc -l crates/hf-service/src/container/*.rs | sort -rn
```

Expected: no file over roughly 1500 lines. If one is, split it along the same
concern lines and commit the split separately. `mod.rs` should be well under
that.

- [ ] **Step 12: Run the full gate set**

Run: `scripts/tests/gates.sh`

Expected: `All gates passed.`

---

---

### Task 13b: Distribute the private container methods

Tasks 11 through 13 relocated all 131 **public** `ServiceContainer` methods.
They did not touch the **73 private** methods in the same `impl` block, because
this plan's method lists were built by matching `pub fn` and `pub async fn` only.
Those 73 span roughly 2374 lines and are the reason `mod.rs` sits at 4216 rather
than near the 1500-line target in Success Criterion 6.

The planning gap is the plan's, not any implementer's. This task closes it.

**Files:**
- Modify: `crates/hf-service/src/container/mod.rs`
- Modify: the existing per-concern files under `crates/hf-service/src/container/`

**Interfaces:**
- Consumes: the eleven method-group files created by Tasks 11 through 13.
- Produces: no new names and no new files. Only definition sites move.

- [ ] **Step 1: Enumerate and assign**

List every private method in the `impl ServiceContainer` block in `mod.rs`:

```bash
awk '/^impl ServiceContainer/{f=1} f' crates/hf-service/src/container/mod.rs \
  | grep -oE '^    (async )?fn [a-z_0-9]+' | sed 's/^ *//'
```

Assign each to the file holding the public methods that call it. Most pair
unambiguously: `chat_session_manager` and `validate_chat_session` with
`chat.rs`; `maybe_auto_revert` and `persist_auto_revert_event` with `policy.rs`;
`run_evidence_root` and `run_target_id` with `run.rs`.

A helper called from **more than one** sibling module stays in `mod.rs`. Do not
widen a method to `pub(super)` to make a move possible — if a method would need
widening, that is proof it belongs in `mod.rs`. `authorize_recorded` and
`record_guardrail_decision` are known members of this staying set.

Write the assignment table into your report before moving anything.

- [ ] **Step 2: Move one group per commit**

For each destination file, move its assigned private methods into the existing
`impl ServiceContainer` block in that file. Same rules as Tasks 11 through 13:
zero content change, every `#[cfg]` travels, nothing deleted beyond the moved
methods, orphaned comments left in place, and no method changes visibility.

After each commit:

```bash
cargo check -p hf-service --all-targets && cargo test -p hf-service 2>&1 | tail -20
cargo check -p hf-service --no-default-features
```

Expect 609 passing, 0 failing and zero warnings, every time.

- [ ] **Step 3: Report the final size**

```bash
wc -l crates/hf-service/src/container/*.rs | sort -rn
```

Report the figures plainly. If `mod.rs` still exceeds roughly 1500 lines, say so
and state what remains rather than splitting further — that is the controller's
call, not yours.

- [ ] **Step 4: Full gate run**

```bash
scripts/tests/gates.sh
```

Expect `All gates passed.`


## Phase C: Desktop Surface and Documentation

### Task 14: Show persisted guardrail decisions in the desktop app

Migration `0018_guardrail_decisions.sql` persists every guardrail authorization
decision, and `ServiceContainer::policy_decisions` reads them. The CLI
(`policy decisions`) and REST (`/policy/decisions`) expose them. The desktop app
does not: `AuditView.tsx:43` calls `auto_revert_events` only, and there is no
Tauri command for decisions. An operator on the desktop cannot see who approved
what.

The Vitest environment is `node`, so hook- and context-bound views cannot be
rendered in a test. The established pattern is a presentational component taking
props, tested with `renderToStaticMarkup`. See
`crates/hf-gui/src/__tests__/scheduleRecoveryPanel.test.tsx`.

**Files:**
- Create: `crates/hf-gui/src/components/PolicyDecisionList.tsx`
- Create: `crates/hf-gui/src/__tests__/policyDecisionList.test.tsx`
- Modify: `crates/hf-gui/src-tauri/src/commands.rs`
- Modify: `crates/hf-gui/src-tauri/src/lib.rs`
- Modify: `crates/hf-gui/src/lib/httpTransport.ts`
- Modify: `crates/hf-gui/src/views/AuditView.tsx`
- Modify: `crates/hf-gui/src/i18n.extra.ts`

**Interfaces:**
- Consumes: `ServiceContainer::policy_decisions(limit: usize) -> Result<Vec<GuardrailDecisionRecord>, ClassifiedError>`, re-exported as `hf_service::GuardrailDecisionRecord` (`lib.rs:88`). Fields: `id: String`, `decided_at: DateTime<Utc>`, `action: String`, `risk_tier: String`, `decision: String`, `origin: String`, `project: Option<String>`, `detail: Option<String>`.
- Produces: the Tauri command `policy_decisions(limit: Option<usize>)` and the React component `PolicyDecisionList`.

- [ ] **Step 1: Write the failing component test**

Create `crates/hf-gui/src/__tests__/policyDecisionList.test.tsx`:

```tsx
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PolicyDecisionList } from "../components/PolicyDecisionList";

describe("PolicyDecisionList", () => {
  it("renders every recorded field of a guardrail decision", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList
        decisions={[
          {
            id: "decision-1",
            decided_at: "2026-07-30T09:15:00Z",
            action: "run_fuzzer",
            risk_tier: "high",
            decision: "approved",
            origin: "run_fuzzer",
            project: "/projects/libjson",
            detail: "operator approved a 60m campaign",
          },
        ]}
        emptyLabel="No decisions recorded"
      />,
    );

    expect(html).toContain("run_fuzzer");
    expect(html).toContain("high");
    expect(html).toContain("approved");
    expect(html).toContain("libjson");
    expect(html).toContain("operator approved a 60m campaign");
  });

  it("renders a distinct empty state rather than an empty list", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList decisions={[]} emptyLabel="No decisions recorded" />,
    );

    expect(html).toContain("No decisions recorded");
  });

  it("omits the optional fields when the record has none", () => {
    const html = renderToStaticMarkup(
      <PolicyDecisionList
        decisions={[
          {
            id: "decision-2",
            decided_at: "2026-07-30T09:16:00Z",
            action: "discover",
            risk_tier: "low",
            decision: "allowed",
            origin: "discover",
            project: null,
            detail: null,
          },
        ]}
        emptyLabel="No decisions recorded"
      />,
    );

    expect(html).toContain("discover");
    // Assert on the markup the guards control, not on the strings "null" /
    // "undefined". renderToStaticMarkup never emits those for a null child, so
    // a component with no conditional at all would pass that check identically.
    // These two strings appear ONLY inside their guards: the " -- " separator
    // precedes a present detail, and the three-class span wraps a present
    // project (the sibling risk_tier span omits `truncate`, so it cannot match).
    expect(html).not.toContain(" -- ");
    expect(html).not.toContain('class="text-xs text-text-muted truncate"');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm --prefix crates/hf-gui test -- policyDecisionList`

Expected: FAIL with a module resolution error — `../components/PolicyDecisionList`
does not exist.

- [ ] **Step 3: Write the component**

Create `crates/hf-gui/src/components/PolicyDecisionList.tsx`:

```tsx
import { ShieldCheck, ShieldX } from "lucide-react";

// One persisted guardrail authorization decision, as recorded by the service in
// migration 0018. Field names match GuardrailDecisionRecord exactly so the
// transport needs no mapping layer.
export interface PolicyDecision {
  id: string;
  decided_at: string;
  action: string;
  risk_tier: string;
  decision: string;
  origin: string;
  project: string | null;
  detail: string | null;
}

interface PolicyDecisionListProps {
  decisions: PolicyDecision[];
  emptyLabel: string;
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// A denial is the outcome an operator scans for, so it carries the warning
// treatment; everything else reads as routine.
function isDenial(decision: string): boolean {
  return decision.startsWith("denied");
}

export function PolicyDecisionList({ decisions, emptyLabel }: PolicyDecisionListProps) {
  if (decisions.length === 0) {
    return <div className="text-xs text-text-muted">{emptyLabel}</div>;
  }

  return (
    <div className="flex flex-col gap-1.5">
      {decisions.map((d) => {
        const denied = isDenial(d.decision);
        const color = denied ? "var(--warning, var(--accent))" : "var(--accent)";
        const projectName = d.project
          ? d.project.split("/").filter(Boolean).pop() || d.project
          : null;
        return (
          <div
            key={d.id}
            className="surface-card flex items-start gap-3"
            style={{ padding: "var(--space-sm) var(--space-md)", borderLeft: `3px solid ${color}` }}
          >
            {denied ? (
              <ShieldX size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
            ) : (
              <ShieldCheck size={16} style={{ color, flexShrink: 0, marginTop: 2 }} />
            )}
            <div className="flex flex-col min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium truncate" style={{ fontFamily: "var(--font-mono)" }}>
                  {d.action}
                </span>
                <span
                  className="text-xs rounded-full"
                  style={{ padding: "0 8px", border: `1px solid ${color}`, color }}
                >
                  {d.decision}
                </span>
                <span className="text-xs text-text-muted">{d.risk_tier}</span>
                {projectName && (
                  <span className="text-xs text-text-muted truncate">{projectName}</span>
                )}
              </div>
              <span className="text-xs text-text-secondary" style={{ lineHeight: 1.5 }}>
                <code>{d.origin}</code>
                {d.detail ? ` -- ${d.detail}` : ""}
              </span>
            </div>
            <span className="text-xs text-text-muted whitespace-nowrap" style={{ marginTop: 2 }}>
              {fmtTime(d.decided_at)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm --prefix crates/hf-gui test -- policyDecisionList`

Expected: PASS, 3 tests.

- [ ] **Step 5: Add the Tauri command**

In `crates/hf-gui/src-tauri/src/commands.rs`, immediately after the
`auto_revert_events` command, add:

```rust
/// The persisted guardrail authorization trail (newest first). `limit` caps the
/// rows; the service prunes older decisions on write. Mirrors the REST
/// `/policy/decisions` route so both transports show the same records.
#[tauri::command]
pub async fn policy_decisions(
    state: tauri::State<'_, crate::state::AppState>,
    limit: Option<usize>,
) -> Result<Vec<hf_service::GuardrailDecisionRecord>, String> {
    state
        .container
        .policy_decisions(limit.unwrap_or(200))
        .await
        .map_err(|error| error.to_string())
}
```

In `crates/hf-gui/src-tauri/src/lib.rs`, add `policy_decisions` to the `use`
list near `auto_revert_events` (line 15) and to the
`generate_handler!` list near line 146. Both lists are alphabetical; insert
accordingly.

- [ ] **Step 6: Verify the command compiles**

Run: `cargo check -p hf-gui --all-targets`

Expected: success.

- [ ] **Step 7: Add the browser transport route**

In `crates/hf-gui/src/lib/httpTransport.ts`, beside the existing
`auto_revert_events` entry, add:

```typescript
  policy_decisions: { method: "GET", path: "/policy/decisions" },
```

The REST handler takes `limit` as a query parameter (`PolicyDecisionsQuery`),
which is why this is `GET` while `auto_revert_events` is `POST`. The transport
already handles this: after path placeholders are substituted, leftover argument
keys become the query string on a `GET` (`httpTransport.ts`, the
`URLSearchParams` block at roughly line 216). Passing `{ limit: 200 }` therefore
produces `GET /policy/decisions?limit=200`. No transport change is needed beyond
the route entry.

- [ ] **Step 8: Add the translation keys**

`crates/hf-gui/src/i18n.extra.ts` defines exactly two dictionaries: `enExtra`
(line 5) and `zhExtra` (line 1343). Its header says "AUTO-GENERATED ... do not
edit by hand", but no generator script exists in the repository and the two most
recent plans both edit it directly. Edit it directly; keys stay alphabetical
within each block.

Add to `enExtra`, beside the existing `audit.*` entries:

```typescript
  "audit.decisionsEmpty": "No guardrail decisions recorded yet.",
  "audit.decisionsTitle": "Authorization decisions",
  "audit.revertsTitle": "Auto-revert firings",
```

Add to `zhExtra`, in the same alphabetical position:

```typescript
  "audit.decisionsEmpty": "尚未记录任何护栏决策。",
  "audit.decisionsTitle": "授权决策",
  "audit.revertsTitle": "自动还原触发记录",
```

The Chinese wording follows the existing block's vocabulary: `audit.description`
already renders auto-revert as 自动还原策略, so 自动还原 is the established term
rather than 自动回滚.

- [ ] **Step 9: Wire the view**

In `crates/hf-gui/src/views/AuditView.tsx`, import the component and its type,
add a `decisions` state, load both sources in the existing `load` callback, and
render `PolicyDecisionList` above the auto-revert list under its own heading.
The load callback becomes:

```tsx
  const load = useCallback(async () => {
    setError(null);
    try {
      const project = scope === "project" ? activeProject || undefined : undefined;
      // allSettled, not all: the two sources are independent. Under Promise.all
      // a rejection from the newly added decisions call would clear the
      // auto-revert events too, breaking functionality that worked before this
      // feature existed. Populate whichever succeeded and name the one that did
      // not in the error banner.
      const [eventsResult, decisionsResult] = await Promise.allSettled([
        getTransport().invoke<AutoRevertEvent[]>("auto_revert_events", {
          project,
          limit: 200,
        }),
        // Decisions are not project-scoped in the service: the guardrail trail
        // records actions that have no project, so scoping would silently drop
        // them.
        getTransport().invoke<PolicyDecision[]>("policy_decisions", { limit: 200 }),
      ]);
      setEvents(events ?? []);
      setDecisions(records ?? []);
    } catch (e) {
      setError(String(e));
      setEvents([]);
      setDecisions([]);
    } finally {
      setLoading(false);
    }
  }, [scope, activeProject]);
```

Add `const [decisions, setDecisions] = useState<PolicyDecision[]>([]);` beside
the existing `events` state, and render above the existing events block:

```tsx
      <div className="flex flex-col gap-2">
        <h3 className="text-sm font-medium">{t("audit.decisionsTitle")}</h3>
        {/* Gate on `loading` exactly as the events section below does. Rendering
            straight from `decisions` (which starts []) shows "No guardrail
            decisions recorded yet" during the initial fetch, which an operator
            reads as "there are none" rather than "still loading". */}
        {loading ? (
          <div className="text-xs text-text-muted">{t("audit.loading")}</div>
        ) : (
          <PolicyDecisionList decisions={decisions} emptyLabel={t("audit.decisionsEmpty")} />
        )}
      </div>

      <h3 className="text-sm font-medium">{t("audit.revertsTitle")}</h3>
```

- [ ] **Step 10: Verify the frontend gates pass**

Run: `npm --prefix crates/hf-gui test && npm --prefix crates/hf-gui run build && npm --prefix crates/hf-gui run lint`

Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add crates/hf-gui
git commit -m "$(cat <<'EOF'
feat: show persisted guardrail decisions in the desktop Policy Audit

Migration 0018 persists every authorization decision and the CLI and REST API
expose them, but the desktop app showed only auto-revert firings. An operator
could not see who approved what from the app they actually use.

Adds the policy_decisions Tauri command mirroring the existing REST route, the
browser transport entry, and a PolicyDecisionList component rendering the full
GuardrailDecisionRecord. Decisions are deliberately not project-scoped: the
trail records actions that have no project.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Correct the contradicted documentation

**Files:**
- Modify: `TODO.md`
- Modify: `CONTRIBUTING.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the CI workflow from Task 2 and the desktop surface from Task 14.
- Produces: nothing.

- [ ] **Step 1: Verify each claim is still false before removing it**

Run:

```bash
ls crates | grep -E 'hf-mcp|hf-hooks' ; echo "crates found above (expect none)"
ls .gitlab-ci.yml .github/workflows/ci.yml
ls crates/hf-storage/migrations/0018_guardrail_decisions.sql
grep -rn 'policy_decisions' crates/hf-web/src/router.rs | head -2
```

Expected: no `hf-mcp` or `hf-hooks` crate; both CI files present (Task 2 created
them, which is why the documentation claim can now be made true rather than
merely deleted); the migration present; and the REST route registered.

- [ ] **Step 2: Fix the TODO entries**

In `TODO.md`, delete this entry (currently line 99):

```
- [ ] Review and either complete or remove the remaining thin extension
  surfaces: hf-mcp, hf-skills, hf-hooks, and hf-test-utils.
```

Replace it with:

```
- [ ] Review and either complete or remove `hf-skills`. `hf-mcp` and `hf-hooks`
  were removed; `hf-test-utils` is consumed by `hf-harness`, `hf-service`, and
  `hf-session` and is doing its job.
```

Then replace the open item currently at lines 176 and 177:

```
- [ ] Guardrail authorization decisions are only traced, never persisted; the
  GUI "Policy Audit" view shows auto-revert events instead. Persisting
  decisions (who/what/when/outcome) would close the audit-trail gap.
```

with:

```
- [x] Guardrail authorization decisions persist to storage (migration 0018) and
  surface through the CLI `policy decisions`, REST `/policy/decisions`, and the
  desktop Policy Audit view.
```

- [ ] **Step 3: Fix the CI claims**

The old text described GitLab CI jobs that did not exist. Task 2 created a real
`.gitlab-ci.yml`, so the fix is to describe what it actually runs, not to swap
in a different unproven claim.

In `CONTRIBUTING.md`, replace lines 65 through 67:

```
Use `./scripts/tests/gates.sh` for the wider local gate set. GitLab CI remains
the merge gate and adds locked all-feature checks, release-readiness tests, the
automotive sidecar, and release CLI verification.
```

with:

```
Use `./scripts/tests/gates.sh` for the full local gate set, or
`./scripts/tests/gates.sh <gate>` for one of `fmt`, `clippy`, `check`, `test`,
`doc`, `deny`, `script-tests`, `frontend-test`, `frontend-lint`.

The same gates run in CI, so a green local run predicts a green pipeline.
`.gitlab-ci.yml` is the merge gate on this remote; `.github/workflows/ci.yml`
runs the same gates on the public GitHub repository. Both invoke
`scripts/tests/gates.sh` by gate name rather than restating commands, so the
three cannot drift apart.
```

Then find every remaining CI claim in the README:

```bash
grep -n 'GitLab CI' README.md
```

Four occurrences exist, two of them in the Chinese half of the document
(around lines 167, 250, 713, and 774). Rewrite each to describe the real
pipeline:

- The Node version notes ("GitLab CI uses Node 22") stay true as written --
  `.gitlab-ci.yml` uses `node:22`. Leave them.
- The Release Readiness sentence claims "GitLab CI jobs for locked all-feature
  coverage". Replace the claim with what the pipeline does run: the nine gates
  on every push, split across rust, frontend, script-tests, and supply-chain
  jobs. Do not claim all-feature coverage; no job passes `--all-features`.
- Keep the Chinese text in step with the English. Match the existing
  translation's register rather than translating literally.

Leave references to the GitLab remote itself alone: that is where the
repository is hosted today.

- [ ] **Step 4: Verify no contradicted claim remains**

Run:

```bash
grep -rn 'GitLab CI' README.md CONTRIBUTING.md docs/ ; echo "matches above (expect none describing a live gate)"
grep -n 'hf-mcp\|hf-hooks' TODO.md ; echo "matches above (expect only the removal note)"
```

- [ ] **Step 5: Commit**

```bash
git add TODO.md CONTRIBUTING.md README.md
git commit -m "$(cat <<'EOF'
docs: correct claims the codebase contradicts

TODO.md asked to complete or remove hf-mcp and hf-hooks, which no longer exist,
and listed guardrail decision persistence as open although migration 0018 and
its CLI, REST, and desktop surfaces all ship. CONTRIBUTING.md and the README
told contributors GitLab CI was the merge gate; no .gitlab-ci.yml exists, and
the gate is now GitHub Actions.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: Final verification

**Files:** none.

**Interfaces:**
- Consumes: every prior task.
- Produces: the evidence for the merge request.

- [ ] **Step 1: Run the complete gate set**

Run: `scripts/tests/gates.sh`

Expected: nine `== <name>` headers followed by `All gates passed.`

- [ ] **Step 2: Confirm the size target held**

Run: `wc -l crates/hf-service/src/container/*.rs | sort -rn | head -5`

Expected: largest file under roughly 1500 lines, versus 12438 before.

- [ ] **Step 3: Confirm no public API moved**

Run:

```bash
git diff --stat main -- crates/hf-cli crates/hf-web
```

Expected: no changes to either crate. The decomposition is internal to
`hf-service`; the only presentation change in this plan is the desktop Policy
Audit surface in `hf-gui`.

- [ ] **Step 4: Confirm CI is green on the branch**

Check the Actions tab for the branch head. All three jobs green.

- [ ] **Step 5: Record the evidence**

Note in the merge request description: the gate run output, the before and after
line counts for `container.rs`, the CI run URL, and the URL of the deliberate
break from Task 2 Step 5 proving the gate rejects a failure.
