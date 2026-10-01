"""The diagnostic runner selects only its two inert measurements."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "performance_measurements.sh"


class PerformanceCommandTests(unittest.TestCase):
    def run_phase(self, phase, fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$CALL_LOG"\n'
                             + ("exit 17\n" if fail else "exit 0\n"))
            cargo.chmod(0o755)
            calls = root / "calls"
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                           "CALL_LOG": str(calls)}
            result = subprocess.run(["bash", str(SCRIPT), phase], cwd=ROOT, env=environment,
                                    text=True, capture_output=True, check=False)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_prepare_compiles_both_measurements_without_executing_tests(self):
        result, calls = self.run_phase("prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["bench -p hf-tools --bench dispatch --no-run",
                                 "test -p hf-service --release --test finding_review --no-run"])

    def test_measure_runs_only_the_exact_ignored_history_fixture(self):
        result, calls = self.run_phase("measure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["bench -p hf-tools --bench dispatch -- --test",
                                 "test -p hf-service --release --test finding_review profile_retained_multi_target_finding_queue -- --ignored --exact"])

    def test_unknown_phase_and_first_command_failure_stop_further_execution(self):
        result, calls = self.run_phase("all")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        result, calls = self.run_phase("measure", fail=True)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
