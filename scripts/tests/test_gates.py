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
        # One assertion per gate in ALL_GATES, in order. check-no-default-features
        # invokes Clippy for the feature-absent build, so it shows up as a second
        # Clippy entry. The feature-matrix gate then invokes Clippy once per
        # product feature. script-tests and
        # translation-pairing both invoke python3, so they show up as two
        # consecutive "python3" entries. frontend-test runs npm four times
        # (ci, test, run build); only the first call is asserted here since it
        # alone identifies that the gate ran in the right position, and
        # frontend-lint's single call follows it.
        self.assertEqual(recorded[0], "cargo fmt")
        self.assertEqual(recorded[1], "cargo clippy")
        self.assertEqual(recorded[2], "cargo check")
        self.assertEqual(recorded[3], "cargo clippy")
        self.assertEqual(recorded[4], "cargo clippy")
        self.assertEqual(recorded[22], "cargo clippy")
        self.assertEqual(recorded[23], "cargo test")
        self.assertEqual(recorded[24], "cargo doc")
        self.assertEqual(recorded[25], "cargo-deny")
        self.assertEqual(recorded[26], "python3")
        self.assertEqual(recorded[27], "python3")
        self.assertEqual(recorded[28], "npm --prefix crates/hf-gui ci")
        self.assertEqual(recorded[32], "npm --prefix crates/hf-gui run lint")

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
            "automotive-lab",
            "automotive-scapy",
            "campaign-health",
            "build-context",
            "concolic-enrichment",
            "build-doctor",
            "campaign-trust",
            "change-aware",
            "coverage-blockers",
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
