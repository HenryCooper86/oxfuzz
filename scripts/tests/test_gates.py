#!/usr/bin/env python3
"""Regression tests for the quality gate dispatcher."""

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from typing import Optional


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
GATES = REPOSITORY_ROOT / "scripts" / "tests" / "gates.sh"


class GateDispatcherTests(unittest.TestCase):
    def test_ci_invokes_the_independent_feature_matrix(self) -> None:
        for path in (REPOSITORY_ROOT / ".github/workflows/ci.yml", REPOSITORY_ROOT / ".gitlab-ci.yml"):
            with self.subTest(pipeline=path):
                self.assertIn("scripts/tests/gates.sh check-feature-matrix", path.read_text())
                self.assertIn("scripts/tests/gates.sh performance", path.read_text())

    def test_ci_runs_feature_behavior_and_retains_coverage_reports(self) -> None:
        for path in (REPOSITORY_ROOT / ".github/workflows/ci.yml", REPOSITORY_ROOT / ".gitlab-ci.yml"):
            with self.subTest(pipeline=path):
                source = path.read_text()
                self.assertIn("scripts/tests/gates.sh feature-behavior", source)
                self.assertIn("scripts/tests/gates.sh coverage", source)
                self.assertIn("target/coverage/*.json", source)
        github = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text()
        gitlab = (REPOSITORY_ROOT / ".gitlab-ci.yml").read_text()
        self.assertIn("needs: [rust, cross-platform, frontend, supply-chain, coverage, clang-analysis]", github)
        self.assertIn("needs.coverage.result == 'success'", github)
        self.assertNotIn("allow_failure: true", gitlab)

    def make_stub(self, directory: pathlib.Path, name: str, body: str) -> None:
        """Place an executable stub named `name` in `directory`."""
        path = directory / name
        path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_gates(
        self, arguments: list[str], stub_dir: pathlib.Path, timeout: float = 30.0,
        extra_env: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PATH"] = f"{stub_dir}{os.pathsep}{environment['PATH']}"
        environment.update(extra_env or {})
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

    def test_feature_behavior_gate_runs_disabled_and_standalone_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "feature-tests"
            self.make_stub(stub_dir, "cargo", f'echo "$*" >> "{log}"\nexit 0')
            result = self.run_gates(["feature-behavior"], stub_dir)
            recorded = log.read_text().splitlines() if log.exists() else []
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(recorded, [
            "test -p hf-harness --no-default-features --test managed_mutator_feature_off",
            "test -p hf-engine --no-default-features --test managed_mutators feature_disabled_dispatch_rejects_native_plugin_requests",
            "test -p hf-service --no-default-features --features managed-mutators --test managed_mutators",
            "test -p hf-service --no-default-features --features model-budgets --test model_budgets",
            "test -p hf-service --no-default-features --lib model_budget::tests",
            "test -p hf-service --no-default-features --features harness-behavior --test harness_qualification stable_sequence_is_measured_and_promotable",
            "test -p hf-web --no-default-features --test build_doctor_disabled_api",
            "test -p hf-web --no-default-features --test coverage_experiments_api",
            "test -p hf-service --no-default-features --test coverage_experiments",
            "test -p hf-service --no-default-features --features proof-carrying --test run_replay",
            "test -p hf-service --no-default-features --features patch-to-proof --test finding_review",
            "test -p hf-service --no-default-features --features clang-analysis --test clang_analysis",
            "test -p hf-service --no-default-features --features clang-analysis --lib clang_analysis",
            "test -p hf-discovery --features clang-analysis --test clang_analysis",
            "test -p hf-cli --no-default-features --features clang-analysis --bin oxfuzz clang_cli_tests",
        ])

    def test_feature_behavior_gate_keeps_test_failure_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            self.make_stub(stub_dir, "cargo", 'echo "feature test failed"\nexit 101')
            result = self.run_gates(["feature-behavior"], stub_dir)
        self.assertNotEqual(result.returncode, 0)

    def test_performance_gate_compiles_benchmark_and_checks_report_parsers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            cargo_log = stub_dir / "cargo-commands"
            python_log = stub_dir / "python-commands"
            self.make_stub(stub_dir, "cargo", f'echo "$*" >> "{cargo_log}"\nexit 0')
            self.make_stub(stub_dir, "python3", f'echo "$*" >> "{python_log}"\nexit 0')
            result = self.run_gates(["performance"], stub_dir)
            cargo = cargo_log.read_text() if cargo_log.exists() else ""
            python = python_log.read_text() if python_log.exists() else ""
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bench -p hf-tools --bench dispatch --no-run", cargo)
        self.assertIn("test_dispatch_samples", python)
        self.assertIn("test_history_samples", python)

    def test_dependency_policy_gate_denies_warning_level_findings(self) -> None:
        """Dependency advisories must not pass merely because they are warnings."""
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            self.make_stub(
                stub_dir,
                "cargo-deny",
                'if [ "$*" = "check -D warnings" ]; then exit 0; fi\n'
                'echo "cargo-deny warnings were not denied" >&2\nexit 64',
            )
            result = self.run_gates(["deny"], stub_dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_coverage_gate_reopens_owned_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            target = stub_dir / "target"
            self.make_stub(
                stub_dir,
                "cargo-llvm-cov",
                'if [ "$2" = "--no-report" ]; then\n'
                '  mkdir -p "$CARGO_TARGET_DIR/llvm-cov-target"\n'
                '  touch "$CARGO_TARGET_DIR/llvm-cov-target/oxfuzz-owned.profraw"\n'
                '  chmod 000 "$CARGO_TARGET_DIR/llvm-cov-target/oxfuzz-owned.profraw"\n'
                'fi\nexit 0',
            )
            self.make_stub(stub_dir, "python3", "exit 0")
            result = self.run_gates(
                ["coverage"], stub_dir, extra_env={"CARGO_TARGET_DIR": str(target)}
            )
            owned = target / "llvm-cov-target" / "oxfuzz-owned.profraw"
            owner_can_read = owned.exists() and bool(owned.stat().st_mode & stat.S_IRUSR)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(owner_can_read)

    def test_unknown_gate_name_is_rejected_with_the_valid_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            result = self.run_gates(["not-a-gate"], stub_dir)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not-a-gate", result.stderr)
        self.assertIn("frontend-lint", result.stderr)

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

    def test_no_default_feature_gate_lints_every_target_with_warnings_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "invocations.log"
            self.make_stub(
                stub_dir, "cargo", f'echo "$*" >> "{log}"\nexit 0'
            )
            result = self.run_gates(["check-no-default-features"], stub_dir)
            recorded = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            recorded,
            ["clippy --workspace --all-targets --no-default-features -- -D warnings"],
        )

    def test_feature_matrix_gate_lints_every_product_feature_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "invocations.log"
            self.make_stub(
                stub_dir, "cargo", f'echo "$*" >> "{log}"\nexit 0'
            )
            result = self.run_gates(["check-feature-matrix"], stub_dir)
            recorded = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        features = [
            "managed-mutators",
            "model-budgets",
            "harness-behavior",
            "clang-analysis",
            "ai-target-ranking",
            "campaign-allocation",
            "automotive-lab",
            "automotive-scapy",
            "campaign-health",
            "build-context",
            "concolic-enrichment",
            "build-doctor",
            "campaign-trust",
            "change-aware",
            "coverage-blockers",
            "coverage-experiments",
            "harness-tournament",
            "harness-work-order",
            "native-analysis",
            "oracle-studio",
            "patch-to-proof",
            "proof-carrying",
            "run-closeout",
            "semgrep-enrichment",
            "triage-disposition",
            "unreached-surface",
        ]
        self.assertEqual(
            recorded,
            [
                "clippy --workspace --all-targets --no-default-features "
                f"--features hf-cli/{feature} -- -D warnings"
                for feature in features
            ],
        )

    def test_frontend_gate_rejects_advisories_before_running_tests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = pathlib.Path(directory)
            log = stub_dir / "invocations.log"
            self.make_stub(
                stub_dir, "npm", f'echo "$*" >> "{log}"\nexit 0'
            )
            result = self.run_gates(["frontend-test"], stub_dir)
            recorded = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            recorded,
            [
                "--prefix crates/hf-gui ci",
                "--prefix crates/hf-gui audit --audit-level=moderate",
                "--prefix crates/hf-gui test",
                "--prefix crates/hf-gui run build",
            ],
        )


if __name__ == "__main__":
    unittest.main()
