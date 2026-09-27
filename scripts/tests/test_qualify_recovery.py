"""Fault runner supervision uses fake workers and private temporary evidence."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qualify_recovery


class RecoveryRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.identity = {"commit": "candidate", "files": {}}

    def run_cases(self, executor, scenarios=None):
        with mock.patch.object(qualify_recovery, "revision_identity", return_value=self.identity):
            return qualify_recovery.run_faults(
                self.repo, self.root / "evidence", 10,
                executor=executor, scenarios=scenarios or qualify_recovery.SCENARIOS[:2]
            )

    def test_each_fixed_case_requires_one_successful_test_and_keeps_evidence(self):
        def execute(command, repo, env, log, timeout):
            self.assertEqual(repo, self.repo.resolve())
            self.assertIn("--exact", command)
            self.assertEqual(timeout, 10)
            state = json.loads((self.root / "evidence/manifest.json").read_text())
            self.assertEqual(state["cases"][-1]["status"], "running")
            log.write_text("running 1 test\ntest result: ok. 1 passed; 0 failed\n")
            return 0

        result = self.run_cases(execute)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["cases"]), 2)
        self.assertEqual([case["status"] for case in result["cases"]], ["passed", "passed"])
        self.assertEqual(json.loads((self.root / "evidence/manifest.json").read_text()), result)

    def test_zero_exit_without_one_test_is_not_accepted(self):
        def execute(command, repo, env, log, timeout):
            log.write_text("running 0 tests\ntest result: ok. 0 passed\n")
            return 0

        result = self.run_cases(execute)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["cases"]), 1)
        self.assertEqual(result["cases"][0]["cleanup"], "unverified")

    def test_timeout_stops_future_cases_without_claiming_cleanup(self):
        executor = mock.Mock(side_effect=subprocess.TimeoutExpired("fake", 10))
        result = self.run_cases(executor)
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(result["cases"][0]["cleanup"], "unverified")

    def test_revision_change_stops_before_second_worker(self):
        def execute(command, repo, env, log, timeout):
            log.write_text("running 1 test\ntest result: ok. 1 passed; 0 failed\n")
            return 0

        identities = [self.identity, self.identity, self.identity, {"commit": "changed"}]
        with mock.patch.object(qualify_recovery, "revision_identity", side_effect=identities):
            result = qualify_recovery.run_faults(self.repo, self.root / "evidence", 10,
                                                  executor=mock.Mock(side_effect=execute),
                                                  scenarios=qualify_recovery.SCENARIOS[:2])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["cases"]), 2)

    def test_output_inside_repository_is_refused_before_launch(self):
        executor = mock.Mock()
        with self.assertRaisesRegex(ValueError, "outside"):
            qualify_recovery.run_faults(self.repo, self.repo / "evidence", 10, executor=executor)
        executor.assert_not_called()

    def test_owned_worker_timeout_retains_partial_log(self):
        log = self.root / "worker.log"
        with self.assertRaises(subprocess.TimeoutExpired):
            qualify_recovery.run_owned_process(
                [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
                self.repo, {}, log, 0.2
            )
        self.assertIn("started", log.read_text())

    def test_worker_output_limit_stops_only_the_owned_child(self):
        log = self.root / "bounded.log"
        with mock.patch.object(qualify_recovery, "MAX_LOG_BYTES", 128):
            with self.assertRaisesRegex(ValueError, "output limit"):
                qualify_recovery.run_owned_process(
                    [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000)"],
                    self.repo, {}, log, 10
                )
        self.assertLessEqual(log.stat().st_size, 128)

    def test_unwritable_log_refuses_before_worker_launch(self):
        with mock.patch.object(qualify_recovery.subprocess, "Popen") as launch:
            with self.assertRaises(OSError):
                qualify_recovery.run_owned_process(
                    [sys.executable, "-c", "pass"], self.repo, {},
                    self.root / "missing/log", 1
                )
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
