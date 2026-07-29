#!/usr/bin/env python3
"""Regression tests for the host-side Semgrep smoke report validator."""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate-semgrep-smoke.py"
OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024


class SemgrepSmokeReportTests(unittest.TestCase):
    def run_validator(
        self, report_path: pathlib.Path, timeout: float = 1.0
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), str(report_path), str(OUTPUT_LIMIT_BYTES)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_fifo_is_rejected_promptly_without_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = pathlib.Path(directory) / "semgrep.json"
            os.mkfifo(report_path)

            result = self.run_validator(report_path)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Semgrep report is not a regular file", result.stderr)

    def test_regular_complete_report_is_accepted(self) -> None:
        report = {
            "version": "1.169.0",
            "results": [
                {
                    "check_id": "raptor-insecure-api-gets",
                    "path": "vulnerable.c",
                }
            ],
            "errors": [],
            "paths": {"scanned": ["clean.c", "vulnerable.c"]},
        }
        with tempfile.TemporaryDirectory() as directory:
            report_path = pathlib.Path(directory) / "semgrep.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = self.run_validator(report_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified regular, symlink-safe, bounded Semgrep JSON", result.stdout)


if __name__ == "__main__":
    unittest.main()
