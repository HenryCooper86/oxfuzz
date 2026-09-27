"""Behavior tests for exact per-package coverage measurement."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_coverage", ROOT / "scripts" / "check_coverage.py"
)
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def file_entry(package: str, name: str, lines: int, covered: int) -> dict:
    return {
        "filename": str(ROOT / "crates" / package / "src" / name),
        "summary": {"lines": {"count": lines, "covered": covered}},
    }


def report(*files: dict) -> dict:
    return {"data": [{"files": list(files)}], "type": "llvm.coverage.json.export"}


class CoverageReportTests(unittest.TestCase):
    def test_aggregates_source_lines_for_each_required_package(self) -> None:
        extra_test = {
            "filename": str(ROOT / "crates" / "hf-engine" / "tests" / "fixture.rs"),
            "summary": {"lines": {"count": 100, "covered": 0}},
        }
        measured = coverage.parse_report(
            report(
                file_entry("hf-engine", "a.rs", 10, 8),
                file_entry("hf-engine", "b.rs", 20, 12),
                file_entry("hf-crash", "lib.rs", 5, 5),
                extra_test,
            ),
            ROOT,
            ("hf-engine", "hf-crash"),
        )
        self.assertEqual(measured, {
            "hf-engine": {"lines": 30, "covered": 20},
            "hf-crash": {"lines": 5, "covered": 5},
        })

    def test_missing_package_malformed_counts_and_duplicate_file_fail(self) -> None:
        cases = [
            (report(file_entry("hf-engine", "lib.rs", 10, 8)), ("hf-engine", "hf-crash")),
            (report(file_entry("hf-engine", "lib.rs", 0, 0)), ("hf-engine",)),
            (report(file_entry("hf-engine", "lib.rs", 10, 11)), ("hf-engine",)),
            (report(file_entry("hf-engine", "lib.rs", True, 1)), ("hf-engine",)),
            (
                report(
                    file_entry("hf-engine", "lib.rs", 10, 8),
                    file_entry("hf-engine", "lib.rs", 10, 8),
                ),
                ("hf-engine",),
            ),
        ]
        for source, packages in cases:
            with self.subTest(source=source, packages=packages):
                with self.assertRaises(ValueError):
                    coverage.parse_report(source, ROOT, packages)

    def test_baseline_rejects_regression_and_missing_or_invalid_entries(self) -> None:
        measured = {"hf-engine": {"lines": 20, "covered": 15}}
        passing = {"schema_version": 1, "platform": "linux", "packages": {
            "hf-engine": {"lines": 10, "covered": 7},
        }}
        coverage.verify_baseline(measured, passing, "linux")
        for baseline in [
            {**passing, "packages": {}},
            {**passing, "packages": {"hf-engine": {"lines": 0, "covered": 0}}},
            {**passing, "platform": "darwin"},
            {**passing, "schema_version": 2},
            {**passing, "packages": {"hf-engine": {"lines": 10, "covered": 8}}},
        ]:
            with self.subTest(baseline=baseline):
                with self.assertRaises(ValueError):
                    coverage.verify_baseline(measured, baseline, "linux")

    def test_report_rejects_invalid_envelope_and_outside_source_path(self) -> None:
        for source in [
            {},
            {"data": []},
            {"data": [{"files": [file_entry("hf-engine", "lib.rs", 10, 8)]}],
             "type": "another.report"},
            report({"filename": "/tmp/elsewhere/src/lib.rs",
                    "summary": {"lines": {"count": 10, "covered": 8}}}),
            report({"filename": str(ROOT / "crates/hf-engine/src/../../../../outside.rs"),
                    "summary": {"lines": {"count": 10, "covered": 8}}}),
        ]:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    coverage.parse_report(source, ROOT, ("hf-engine",))

    def test_cli_uses_the_gate_supplied_package_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            domain = Path(directory) / "domain.json"
            infrastructure = Path(directory) / "infrastructure.json"
            domain.write_text(json.dumps(report(file_entry("hf-engine", "lib.rs", 10, 8))))
            infrastructure.write_text(json.dumps(report(file_entry("hf-runtime", "lib.rs", 10, 7))))
            result = subprocess.run([
                sys.executable, str(ROOT / "scripts/check_coverage.py"),
                "--domain", str(domain), "--infrastructure", str(infrastructure),
                "--domain-packages", "hf-engine", "--infrastructure-packages", "hf-runtime",
                "--measure",
            ], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hf-engine: 8/10", result.stdout)
        self.assertIn("hf-runtime: 7/10", result.stdout)

    def test_cli_enforces_a_complete_linux_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            domain = root / "domain.json"
            infrastructure = root / "infrastructure.json"
            baseline = root / "baseline.json"
            domain.write_text(json.dumps(report(file_entry("hf-engine", "lib.rs", 10, 8))))
            infrastructure.write_text(json.dumps(report(file_entry("hf-runtime", "lib.rs", 10, 7))))
            baseline.write_text(json.dumps({
                "schema_version": 1, "platform": sys.platform,
                "packages": {
                    "hf-engine": {"lines": 10, "covered": 8},
                    "hf-runtime": {"lines": 10, "covered": 7},
                },
            }))
            command = [
                sys.executable, str(ROOT / "scripts/check_coverage.py"),
                "--domain", str(domain), "--infrastructure", str(infrastructure),
                "--domain-packages", "hf-engine", "--infrastructure-packages", "hf-runtime",
                "--baseline", str(baseline),
            ]
            passing = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(passing.returncode, 0, passing.stderr)
            domain.write_text(json.dumps(report(file_entry("hf-engine", "lib.rs", 10, 7))))
            failing = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(failing.returncode, 0)
            self.assertIn("hf-engine line coverage regressed", failing.stderr)


if __name__ == "__main__":
    unittest.main()
