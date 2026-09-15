"""Qualification supervision uses disposable fake processes, never fuzzers."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qualify_engines as qualification


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        sources = self.repo / "examples/qualification"
        sources.mkdir(parents=True)
        (sources / "parser.c").write_text("target")
        (sources / "harness.c").write_text("harness")
        self.digest = qualification.source_digest(self.repo)

    def reports(self, root, stop=20):
        for engine in qualification.ENGINES:
            path = root / "qualification-test" / engine / "qualification.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"engine": engine, "harness_id": str(uuid.uuid4()),
                "campaign_run_id": str(uuid.uuid4()), "replay_run_id": str(uuid.uuid4()),
                "stop_ms": stop, "smoke": {"verdict": {"level": "pass"}}}))

    def run_campaign(self, executor, cycles=2, approval=None):
        with mock.patch.object(qualification, "revision_identity", return_value={"commit": "test"}):
            return qualification.run_qualification(self.repo, self.root / "output", cycles,
                30, self.digest if approval is None else approval, executor=executor)

    def test_wrong_source_approval_never_launches_or_creates_evidence(self):
        executor = mock.Mock()
        with self.assertRaisesRegex(ValueError, "approval"):
            self.run_campaign(executor, approval="yes")
        executor.assert_not_called()
        self.assertFalse((self.root / "output").exists())

    def test_success_requires_each_engine_and_preserves_cycle_evidence(self):
        def execute(command, repo, env, log, timeout):
            self.assertIn("--exact", command)
            self.assertIn("--ignored", command)
            self.assertEqual(env["OXFUZZ_LIVE_APPROVAL_SHA256"], self.digest)
            parent = pathlib.Path(env["OXFUZZ_LIVE_EVIDENCE_ROOT"])
            manifest = json.loads((self.root / "output/manifest.json").read_text())
            self.assertEqual(manifest["cycles"][-1]["status"], "running")
            self.reports(parent, len(manifest["cycles"]) * 20)
            return 0
        result = self.run_campaign(execute)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["stop_latency_ms"]["afl++"],
                         {"samples": 2, "median": 30.0, "p95": 40})
        self.assertEqual(len(result["cycles"]), 2)
        self.assertEqual(json.loads((self.root / "output/manifest.json").read_text()), result)

    def test_nonzero_timeout_and_interruption_stop_without_retry(self):
        for outcome, status in [(1, "failed"), (subprocess.TimeoutExpired("fake", 1), "timed_out"),
                                (KeyboardInterrupt(), "interrupted")]:
            with self.subTest(status=status):
                executor = mock.Mock(side_effect=outcome if isinstance(outcome, BaseException) else None,
                                     return_value=outcome)
                output = self.root / "output"
                if output.exists():
                    output.rename(self.root / ("previous-" + status))
                result = self.run_campaign(executor)
                self.assertEqual(result["status"], status)
                self.assertEqual(executor.call_count, 1)
                self.assertNotIn("stop_latency_ms", result)
                self.assertEqual(result["cycles"][0]["cleanup"], "unverified")

    def test_zero_exit_without_reports_is_not_success(self):
        result = self.run_campaign(mock.Mock(return_value=0))
        self.assertEqual(result["status"], "failed")
        self.assertIn("evidence", result["cycles"][0]["error"])

    def test_report_rejects_duplicate_ids_and_invalid_stop_counter(self):
        self.reports(self.root)
        path = self.root / "qualification-test/libfuzzer/qualification.json"
        original = json.loads(path.read_text())
        for changes in [{"replay_run_id": original["campaign_run_id"]}, {"stop_ms": True},
                        {"stop_ms": -1}, {"stop_ms": 15001}, {"smoke": {"verdict": {"level": "Fail"}}}]:
            path.write_text(json.dumps({**original, **changes}))
            with self.assertRaises(ValueError):
                qualification.read_reports(self.root)

    def test_source_change_during_execution_is_not_certified(self):
        def execute(command, repo, env, log, timeout):
            self.reports(pathlib.Path(env["OXFUZZ_LIVE_EVIDENCE_ROOT"]))
            (self.repo / "examples/qualification/parser.c").write_text("changed")
            return 0
        result = self.run_campaign(execute)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["cycles"]), 1)

    def test_malformed_report_records_failure_instead_of_leaving_running(self):
        def execute(command, repo, env, log, timeout):
            root = pathlib.Path(env["OXFUZZ_LIVE_EVIDENCE_ROOT"])
            self.reports(root)
            (root / "qualification-test/libfuzzer/qualification.json").write_text("[]")
            return 0
        result = self.run_campaign(execute)
        self.assertEqual(result["status"], "failed")
        self.assertIn("evidence", result["cycles"][0]["error"])

    def test_reused_run_from_previous_cycle_is_rejected(self):
        previous = []
        def execute(command, repo, env, log, timeout):
            root = pathlib.Path(env["OXFUZZ_LIVE_EVIDENCE_ROOT"])
            self.reports(root)
            path = root / "qualification-test/libfuzzer/qualification.json"
            report = json.loads(path.read_text())
            if previous:
                report["campaign_run_id"] = previous[0].upper()
                path.write_text(json.dumps(report))
            previous.append(report["campaign_run_id"])
            return 0
        result = self.run_campaign(execute)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["cycles"][0]["status"], "passed")

    def test_evidence_cannot_change_the_repository_being_measured(self):
        executor = mock.Mock()
        with mock.patch.object(qualification, "revision_identity", return_value={"commit": "test"}):
            with self.assertRaisesRegex(ValueError, "outside"):
                qualification.run_qualification(self.repo, self.repo / "evidence", 1, 30,
                                                self.digest, executor=executor)
        executor.assert_not_called()

    def test_invalid_limits_never_create_evidence(self):
        for cycles, timeout in [(0, 30), (True, 30), (10001, 30), (1, 0), (1, float("nan")),
                                (1, float("inf")), (1, 86401)]:
            with self.subTest(cycles=cycles, timeout=timeout):
                with self.assertRaises(ValueError):
                    qualification.run_qualification(self.repo, self.root / "output", cycles,
                                                    timeout, self.digest)
                self.assertFalse((self.root / "output").exists())

    def test_existing_output_is_never_overwritten(self):
        (self.root / "output").mkdir()
        executor = mock.Mock()
        with self.assertRaises(FileExistsError):
            self.run_campaign(executor)
        executor.assert_not_called()

    def test_revision_identity_tracks_uncommitted_inputs_without_storing_contents(self):
        def git(*args):
            subprocess.run(["git", *args], cwd=self.repo, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        git("init")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-m", "Fixture")
        before = qualification.revision_identity(self.repo)
        (self.repo / "examples/qualification/parser.c").write_text("changed")
        (self.repo / "untracked.txt").write_text("private fixture contents")
        after = qualification.revision_identity(self.repo)
        self.assertEqual(before["commit"], after["commit"])
        self.assertNotEqual(before["patch_sha256"], after["patch_sha256"])
        self.assertIn("untracked.txt", after["files"])
        self.assertNotIn("private fixture contents", json.dumps(after))

    def test_owned_process_times_out_and_retains_log(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            qualification.run_process([sys.executable, "-c",
                "import time; print('started', flush=True); time.sleep(30)"],
                self.root, {}, self.root / "process.log", 0.2)
        self.assertIn("started", (self.root / "process.log").read_text())
