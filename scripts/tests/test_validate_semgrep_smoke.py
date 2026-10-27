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
    def run_sandbox_build_with_report(self, report: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            docker = root / "docker"
            docker.write_text("""#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
for argument in sys.argv:
    if argument.startswith('type=bind,src=') and argument.endswith(',dst=/work/output'):
        output = pathlib.Path(argument.removeprefix('type=bind,src=').removesuffix(',dst=/work/output'))
        (output / 'semgrep.json').write_text(os.environ['OXFUZZ_FIXTURE_REPORT'])
        payload = sys.argv[-1]
        marker = "python3 - <<'PY'\\n"
        if marker in payload:
            script = payload.split(marker, 1)[1].split('\\nPY', 1)[0]
            script = script.replace('/work/output/semgrep.json', str(output / 'semgrep.json'))
            digest = output / 'digest'
            digest.write_text('fixture-digest')
            script = script.replace('/opt/oxfuzz/semgrep-rules/RULES_SHA256', str(digest))
            sys.exit(subprocess.run([sys.executable, '-c', script], check=False).returncode)
""", encoding="utf-8")
            docker.chmod(0o700)
            environment = dict(os.environ)
            environment.update({"PATH": f"{root}{os.pathsep}{environment['PATH']}",
                                "OXFUZZ_FIXTURE_REPORT": json.dumps(report)})
            return subprocess.run(["bash", str(REPOSITORY_ROOT / "scripts/build-sandbox.sh")],
                                  env=environment, capture_output=True, text=True, timeout=10, check=False)

    def test_sandbox_build_rejects_any_finding_in_the_clean_fixture(self) -> None:
        report = {"errors": [], "paths": {"scanned": ["clean.c", "vulnerable.c"]},
                  "results": [{"check_id": "raptor-insecure-api-gets", "path": "vulnerable.c"},
                              {"check_id": "another-rule", "path": "clean.c"}]}
        result = self.run_sandbox_build_with_report(report)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("clean.c unexpectedly produced result", result.stderr)

    def test_sandbox_build_reports_semgrep_errors_without_shell_quote_corruption(self) -> None:
        result = self.run_sandbox_build_with_report({"errors": ["fixture failure"]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Semgrep errors", result.stderr)
        self.assertNotIn("NameError", result.stderr)

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
