"""Bind diagnostic samples to their admitted source and runner before reporting."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import check_performance_bundle as bundle
from scripts.tests.test_dispatch_samples import document as dispatch_document
from scripts.tests.test_history_samples import document as history_document


SHA = "a" * 40
RUNNER = "gha-linux-ubuntu24-x64-diagnostic"
ROOT = Path(__file__).resolve().parents[2]


def documents():
    dispatch, history = dispatch_document(), history_document()
    for report in (dispatch, history):
        report["environment"].update(runner=RUNNER, rustc="rustc 1.94.0")
    receipt = {"schema_version": 1, "candidate_commit": SHA, "ci_run_id": 7,
               "ci_run_attempt": 1, "ci_url": "https://github.com/example/oxfuzz/actions/runs/7"}
    runner = {"schema_version": 1, "candidate_commit": SHA, "runner": RUNNER,
              "workflow_run_id": 8, "workflow_run_attempt": 1,
              "runner_os": "Linux", "runner_arch": "X64", "runner_name": "Hosted Agent",
              "image_os": "ubuntu24", "image_version": "20261001.1"}
    return dispatch, history, receipt, runner


class PerformanceBundleTests(unittest.TestCase):
    def test_shared_runner_high_timings_are_diagnostic_and_recomputed(self):
        reports = documents()
        reports[0]["cases"][0]["dispatch_us"] = [200_000] * 1000
        reports[0]["cases"][0]["total_us"] = [200_000] * 1000
        result = bundle.summarize(*reports, revision=SHA, runner=RUNNER)
        self.assertEqual(result["scope"], "shared-runner-diagnostic")
        self.assertEqual(result["dispatch"][0]["dispatch_p95_us"], 200_000)
        self.assertEqual(result["history"][0]["first_query_p95_us"], 50)
        self.assertEqual(result["source_ci"], reports[2])

    def test_reports_must_match_admitted_revision_runner_release_and_each_other(self):
        for index, field, value in [(0, "revision", "b" * 40), (1, "runner", "other"),
                                    (0, "profile", "debug"), (1, "profile", "debug"),
                                    (1, "rustc", "rustc 1.95.0"), (1, "arch", "aarch64"),
                                    (0, "fixture", "unknown")]:
            reports = documents()
            reports[index]["environment"][field] = value
            with self.subTest(index=index, field=field):
                with self.assertRaises(ValueError):
                    bundle.summarize(*reports, revision=SHA, runner=RUNNER)
        reports = documents()
        reports[0]["cases"].pop()
        with self.assertRaises(ValueError):
            bundle.summarize(*reports, revision=SHA, runner=RUNNER)
        reports = documents()
        reports[1]["cases"][0]["repeat_query_us"][0] = float("nan")
        with self.assertRaises(ValueError):
            bundle.summarize(*reports, revision=SHA, runner=RUNNER)

    def test_ci_receipt_and_actual_runner_identity_are_required(self):
        for index, field, value in [(2, "candidate_commit", "b" * 40),
                                    (2, "ci_run_id", True), (2, "ci_run_attempt", 0),
                                    (2, "ci_url", "https://secret@github.com/run"),
                                    (3, "image_version", ""), (3, "runner_arch", "ARM64"),
                                    (3, "candidate_commit", "b" * 40), (3, "runner", "other")]:
            reports = copy.deepcopy(documents())
            reports[index][field] = value
            with self.subTest(index=index, field=field):
                with self.assertRaises(ValueError):
                    bundle.summarize(*reports, revision=SHA, runner=RUNNER)

    def test_bundle_denies_boolean_or_float_sample_identities(self):
        for index, field, value in ((0, "concurrency", True), (0, "concurrency", 1.0),
                                    (1, "targets", 161.0), (1, "runs", 3200.0)):
            reports = documents()
            reports[index]["cases"][0][field] = value
            with self.subTest(index=index, field=field):
                with self.assertRaises(ValueError):
                    bundle.summarize(*reports, revision=SHA, runner=RUNNER)

    def test_loading_is_bounded_before_json_decoding_and_hashes_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            raw = b'{"message":"ok"}\n'
            path.write_bytes(raw)
            document, digest = bundle.load_report(path, len(raw))
            self.assertEqual(document, {"message": "ok"})
            self.assertEqual(digest, "sha256:" + hashlib.sha256(raw).hexdigest())
            with self.assertRaisesRegex(ValueError, "byte allowance"):
                bundle.load_report(path, len(raw) - 1)
            path.write_bytes(b"{broken}")
            with self.assertRaises(ValueError):
                bundle.load_report(path, 100)

    def test_cli_rejects_invalid_allowance_without_reading_missing_reports(self):
        command = [sys.executable, "-m", "scripts.check_performance_bundle",
                   "--directory", "missing", "--revision", SHA, "--runner", RUNNER]
        result = subprocess.run(command + ["--max-report-bytes", "0"], cwd=ROOT,
                                text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive", result.stderr)
        self.assertNotIn("No such file", result.stderr)

    def test_cli_writes_complete_summary_only_after_all_four_inputs_validate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, document in zip(("dispatch", "history", "source-ci", "runner"), documents()):
                (root / f"{name}.json").write_text(json.dumps(document), encoding="utf-8")
            command = [sys.executable, "-m", "scripts.check_performance_bundle",
                       "--directory", directory, "--revision", SHA, "--runner", RUNNER]
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(set(summary["digests"]), {"dispatch", "history", "source-ci", "runner"})
            (root / "history.json").unlink()
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
