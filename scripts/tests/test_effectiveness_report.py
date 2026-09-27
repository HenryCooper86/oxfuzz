"""Tests for report assembly from retained service evidence exports."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.effectiveness_report import assemble_report
from scripts.tests.test_effectiveness_benchmark import DIGEST, cohort


RUN_ID = "11111111-1111-4111-8111-111111111111"


def campaign_manifest(edges=0):
    return {
        "body": {
            "schema_version": 2,
            "run_id": RUN_ID,
            "target": "parse_record",
            "status": "done",
            "engine": "libfuzzer",
            "source_revision": DIGEST,
            "sandbox_image_sha256": DIGEST,
            "binary_sha256": DIGEST,
            "run_config": {
                "duration_secs": 60,
                "max_mem_mb": 1024,
                "max_cpus": 2,
                "sanitizer": "address",
                "seed": 123,
            },
            "coverage": {"edges": edges, "delta_edges": 0},
            "cost": {"compute_cost_usd": 0.0, "model_cost_usd": 0.0},
            "findings": [],
        },
        "manifest_sha256": DIGEST,
    }


def function_coverage(count="0"):
    return {
        "status": "available",
        "run_id": RUN_ID,
        "binary_sha256": DIGEST,
        "export_sha256": DIGEST,
        "functions": [{"name": "parse_record", "count": count, "files": ["parser.c"]}],
        "observed_functions": 1 if int(count) > 0 else 0,
        "limitation": "zero does not prove non-entry",
    }


class ReportTests(unittest.TestCase):
    def test_documented_cli_starts_from_repository_root(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, "-m", "scripts.effectiveness_report", "--help"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observations", result.stdout)

    def test_cli_reads_relative_hashed_artifacts(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        (self.root / "cohort.json").write_text(json.dumps(cohort()), encoding="utf-8")
        (self.root / "observations.json").write_text(
            json.dumps(self.observations(manifest)), encoding="utf-8")
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run([
            sys.executable, "-m", "scripts.effectiveness_report",
            str(self.root / "cohort.json"), str(self.root / "observations.json"),
        ], cwd=root, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["trials"][0]["peak_edges"]["value"], 0)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def artifact(self, name, value):
        content = json.dumps(value, sort_keys=True).encode("utf-8")
        (self.root / name).write_bytes(content)
        return {"path": name, "sha256": hashlib.sha256(content).hexdigest()}

    def observations(self, manifest=None, functions=None, outcome="completed", reason=None):
        return {
            "schema_version": 1,
            "cohort_id": "held-out-c-1",
            "trials": [{
                "id": "parser-ranked-1",
                "outcome": outcome,
                "reason": reason,
                "campaign_manifest": manifest,
                "function_coverage": functions,
            }],
        }

    def test_zero_progress_and_cost_are_measured_zero_not_unavailable(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        self.assertEqual(trial["peak_edges"], {"status": "available", "value": 0})
        self.assertEqual(trial["total_cost_usd"], {"status": "available", "value": 0.0})
        self.assertEqual(trial["selected_function_entry"]["status"], "unavailable")
        self.assertEqual(report["conditions"]["ranked-libfuzzer"]["peak_edges_median"], 0)

    def test_positive_function_counter_is_observed_entry(self):
        manifest = self.artifact("manifest.json", campaign_manifest(7))
        functions = self.artifact("functions.json", function_coverage("3"))
        report = assemble_report(cohort(), self.observations(manifest, functions), self.root)
        self.assertEqual(report["trials"][0]["selected_function_entry"]["status"], "observed")

    def test_zero_function_counter_does_not_claim_non_entry(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        functions = self.artifact("functions.json", function_coverage())
        report = assemble_report(cohort(), self.observations(manifest, functions), self.root)
        self.assertEqual(report["trials"][0]["selected_function_entry"]["status"], "not_observed")

    def test_failed_and_unavailable_trials_remain_in_report(self):
        for outcome in ("failed", "unavailable"):
            with self.subTest(outcome=outcome):
                report = assemble_report(cohort(), self.observations(
                    outcome=outcome, reason="qualification stopped"), self.root)
                self.assertEqual(report["outcomes"][outcome], 1)
                self.assertEqual(report["trials"][0]["peak_edges"]["status"], "unavailable")
                self.assertIsNone(report["conditions"]["ranked-libfuzzer"]["peak_edges_median"])

    def test_failed_campaign_keeps_measured_zero_progress(self):
        value = campaign_manifest()
        value["body"]["status"] = "failed"
        manifest = self.artifact("failed.json", value)
        report = assemble_report(cohort(), self.observations(
            manifest=manifest, outcome="failed", reason="engine exited"), self.root)
        self.assertEqual(report["outcomes"]["failed"], 1)
        self.assertEqual(report["trials"][0]["peak_edges"], {"status": "available", "value": 0})

    def test_cancelled_campaign_keeps_terminal_measurements(self):
        value = campaign_manifest(4)
        value["body"]["status"] = "cancelled"
        manifest = self.artifact("cancelled.json", value)
        report = assemble_report(cohort(), self.observations(
            manifest=manifest, outcome="cancelled", reason="operator stopped trial"), self.root)
        self.assertEqual(report["outcomes"]["cancelled"], 1)
        self.assertEqual(report["trials"][0]["peak_edges"], {"status": "available", "value": 4})

    def test_cancelled_manifest_cannot_be_reported_as_failed(self):
        value = campaign_manifest()
        value["body"]["status"] = "cancelled"
        manifest = self.artifact("cancelled.json", value)
        with self.assertRaisesRegex(ValueError, "status"):
            assemble_report(cohort(), self.observations(
                manifest=manifest, outcome="failed", reason="operator stopped trial"), self.root)

    def test_manifest_must_match_frozen_source_image_target_and_budget(self):
        for field, replacement in [
            ("source_revision", "c" * 64),
            ("sandbox_image_sha256", "c" * 64),
            ("target", "another_target"),
        ]:
            value = campaign_manifest()
            value["body"][field] = replacement
            manifest = self.artifact("manifest.json", value)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                assemble_report(cohort(), self.observations(manifest), self.root)
        value = campaign_manifest()
        value["body"]["run_config"]["duration_secs"] = 120
        manifest = self.artifact("manifest.json", value)
        with self.assertRaisesRegex(ValueError, "duration_secs"):
            assemble_report(cohort(), self.observations(manifest), self.root)

    def test_artifact_hash_and_function_run_identity_are_checked(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        changed = copy.deepcopy(manifest)
        changed["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "sha256"):
            assemble_report(cohort(), self.observations(changed), self.root)
        functions = function_coverage("1")
        functions["run_id"] = "22222222-2222-4222-8222-222222222222"
        reference = self.artifact("functions.json", functions)
        with self.assertRaisesRegex(ValueError, "run_id"):
            assemble_report(cohort(), self.observations(manifest, reference), self.root)

    def test_every_declared_trial_needs_one_outcome(self):
        with self.assertRaisesRegex(ValueError, "trial"):
            assemble_report(cohort(), self.observations() | {"trials": []}, self.root)
        duplicate = self.observations(outcome="failed", reason="stopped")
        duplicate["trials"].append(copy.deepcopy(duplicate["trials"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate trial"):
            assemble_report(cohort(), duplicate, self.root)

    def test_rejects_malformed_outcome_and_artifact_path_escape(self):
        value = self.observations(outcome=[], reason="invalid")
        with self.assertRaisesRegex(ValueError, "outcome"):
            assemble_report(cohort(), value, self.root)
        outside = self.root.parent / (self.root.name + "-outside-evidence.json")
        outside.write_text(json.dumps(campaign_manifest()), encoding="utf-8")
        self.addCleanup(outside.unlink)
        (self.root / "linked").symlink_to(self.root.parent, target_is_directory=True)
        reference = {"path": "linked/" + outside.name,
                     "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()}
        with self.assertRaisesRegex(ValueError, "artifact path"):
            assemble_report(cohort(), self.observations(reference), self.root)

    def test_rejects_function_counter_outside_u64(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        functions = self.artifact("functions.json", function_coverage("9" * 25))
        with self.assertRaisesRegex(ValueError, "counter"):
            assemble_report(cohort(), self.observations(manifest, functions), self.root)

    def test_rejects_cost_total_that_overflows_json_numbers(self):
        value = campaign_manifest()
        value["body"]["cost"] = {
            "compute_cost_usd": 1e308,
            "model_cost_usd": 1e308,
        }
        manifest = self.artifact("manifest.json", value)
        plan = cohort()
        plan["conditions"][0]["model_cost_budget_usd"] = 1e308
        with self.assertRaisesRegex(ValueError, "total_cost"):
            assemble_report(plan, self.observations(manifest), self.root)


if __name__ == "__main__":
    unittest.main()
