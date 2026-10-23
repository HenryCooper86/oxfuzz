"""Tests for report assembly from retained service evidence exports."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.effectiveness_report import (
    MAX_ARTIFACT_BYTES, assemble_report, read_artifact, read_json,
)
from scripts.tests.test_effectiveness_benchmark import DIGEST, cohort


RUN_ID = "11111111-1111-4111-8111-111111111111"
TARGET_SIGNATURE = "1" * 64
HARNESS_SIGNATURE = "2" * 64
RUNTIME_SIGNATURE = "3" * 64
UNKNOWN_SIGNATURE = "4" * 64


def numbered_crash_id(index):
    return "00000000-0000-4000-8000-{:012d}".format(index)


def finding(signature=TARGET_SIGNATURE, origin="target", identifier=1, minimized=True,
            crash_id=None):
    return {
        "crash_id": crash_id if crash_id is not None else numbered_crash_id(identifier),
        "stack_signature": signature,
        "reproducer_sha256": "5" * 64,
        "minimized": minimized,
        "origin": origin,
    }


def campaign_manifest(edges=0, findings=None):
    return {
        "body": {
            "schema_version": 3,
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
            "findings": [] if findings is None else findings,
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
    def test_schema_two_report_binds_the_exact_prepared_trial_source(self):
        plan = cohort()
        plan["schema_version"] = 2
        plan["trials"][0]["prepared_harness"] = {
            "path": "harnesses/reference.c", "sha256": "c" * 64,
            "source_sha256": "d" * 64, "origin": "reference",
        }
        value = campaign_manifest()
        value["body"]["source_revision"] = "d" * 64
        manifest = self.artifact("prepared.json", value)
        assemble_report(plan, self.observations(manifest), self.root)
        value["body"]["source_revision"] = DIGEST
        stale = self.artifact("stale.json", value)
        with self.assertRaisesRegex(ValueError, "source_revision"):
            assemble_report(plan, self.observations(stale), self.root)

    def test_evidence_reads_do_not_load_unbounded_file_bytes(self):
        small = self.root / "small.json"
        small.write_text('{"ok": true}', encoding="utf-8")
        reference = self.artifact("artifact.json", {"ok": True})
        large = self.root / "large.json"
        with large.open("wb") as output:
            output.seek(MAX_ARTIFACT_BYTES)
            output.write(b"x")
        original_open = Path.open
        assert_size = self.assertEqual

        class CheckedReader:
            def __init__(self, source):
                self.source = source

            def __enter__(self):
                self.source.__enter__()
                return self

            def __exit__(self, *args):
                return self.source.__exit__(*args)

            def read(self, size=-1):
                assert_size(size, MAX_ARTIFACT_BYTES + 1)
                return self.source.read(size)

        def checked_open(path, *args, **kwargs):
            return CheckedReader(original_open(path, *args, **kwargs))

        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")), \
                mock.patch.object(Path, "open", checked_open):
            self.assertEqual(read_json(small), {"ok": True})
            self.assertEqual(read_artifact(self.root, reference), {"ok": True})
            with self.assertRaisesRegex(ValueError, "16 MiB"):
                read_json(large)
            with self.assertRaisesRegex(ValueError, "16 MiB"):
                read_artifact(self.root, {"path": "large.json", "sha256": DIGEST})

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

    def test_campaign_without_crashes_measures_zero_signature_counts(self):
        manifest = self.artifact("manifest.json", campaign_manifest())
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        self.assertEqual(trial["unique_crash_signatures"],
                         {"status": "available", "value": 0})
        origins = trial["crash_signature_origins"]
        self.assertEqual(origins["status"], "available")
        self.assertEqual(
            {name: origins["value"][name]
             for name in ("target", "harness", "runtime", "unknown", "ambiguous")},
            {"target": 0, "harness": 0, "runtime": 0, "unknown": 0, "ambiguous": 0},
        )

    def test_duplicate_signatures_deduplicate_to_one_unique_observation(self):
        findings = [finding(), finding(identifier=2)]
        manifest = self.artifact(
            "manifest.json", campaign_manifest(findings=findings))
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        self.assertEqual(trial["unique_crash_signatures"],
                         {"status": "available", "value": 1})
        self.assertEqual(trial["crash_signature_origins"]["value"]["target"], 1)
        self.assertEqual(trial["crash_signature_origins"]["value"]["ambiguous"], 0)

    def test_mixed_origin_signature_counts_ambiguous_and_never_target(self):
        findings = [
            finding(origin="target"),
            finding(origin="harness", identifier=2),
        ]
        manifest = self.artifact(
            "manifest.json", campaign_manifest(findings=findings))
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        self.assertEqual(trial["unique_crash_signatures"]["value"], 1)
        origins = trial["crash_signature_origins"]["value"]
        self.assertEqual(origins["ambiguous"], 1)
        self.assertEqual(origins["target"], 0)
        self.assertEqual(origins["harness"], 0)

    def test_retained_origins_are_counted_per_layer(self):
        findings = [
            finding(signature=TARGET_SIGNATURE, origin="target"),
            finding(signature=HARNESS_SIGNATURE, origin="harness", identifier=2),
            finding(signature=RUNTIME_SIGNATURE, origin="runtime", identifier=3),
            finding(signature=UNKNOWN_SIGNATURE, origin="unknown", identifier=4),
        ]
        manifest = self.artifact(
            "manifest.json", campaign_manifest(findings=findings))
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        self.assertEqual(trial["unique_crash_signatures"]["value"], 4)
        origins = trial["crash_signature_origins"]["value"]
        self.assertEqual(origins["target"], 1)
        self.assertEqual(origins["harness"], 1)
        self.assertEqual(origins["runtime"], 1)
        self.assertEqual(origins["unknown"], 1)
        self.assertEqual(origins["ambiguous"], 0)

    def test_signature_counts_carry_a_nonempty_limitation_note(self):
        manifest = self.artifact(
            "manifest.json", campaign_manifest(findings=[finding()]))
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        limitation = report["trials"][0]["crash_signature_origins"]["value"]["limitation"]
        self.assertIsInstance(limitation, str)
        self.assertTrue(limitation.strip())

    def test_timing_and_replay_stay_unavailable_even_with_crash_evidence(self):
        manifest = self.artifact(
            "manifest.json", campaign_manifest(findings=[finding()]))
        report = assemble_report(cohort(), self.observations(manifest), self.root)
        trial = report["trials"][0]
        for field in ("time_to_first_crash_secs", "crash_reproducibility"):
            measurement = trial[field]
            self.assertEqual(measurement["status"], "unavailable", field)
            self.assertIsInstance(measurement["reason"], str)
            self.assertTrue(measurement["reason"].strip(), field)

    def test_crash_metrics_without_manifest_stay_unavailable_not_zero(self):
        for outcome in ("failed", "unavailable"):
            with self.subTest(outcome=outcome):
                report = assemble_report(cohort(), self.observations(
                    outcome=outcome, reason="qualification stopped"), self.root)
                trial = report["trials"][0]
                self.assertEqual(trial["unique_crash_signatures"]["status"],
                                 "unavailable")
                self.assertEqual(trial["crash_signature_origins"]["status"],
                                 "unavailable")
                self.assertEqual(trial["time_to_first_crash_secs"]["status"],
                                 "unavailable")
                self.assertEqual(trial["crash_reproducibility"]["status"],
                                 "unavailable")

    def test_project_condition_summary_keeps_failed_and_unmeasured_samples(self):
        plan = cohort()
        second_project = copy.deepcopy(plan["projects"][0])
        second_project["id"] = "other-parser"
        plan["projects"].append(second_project)
        second_trial = copy.deepcopy(plan["trials"][0])
        second_trial["id"] = "other-parser-ranked-1"
        second_trial["project_id"] = "other-parser"
        plan["trials"].append(second_trial)
        observations = self.observations(self.artifact("manifest.json", campaign_manifest(7)))
        observations["trials"].append({
            "id": second_trial["id"],
            "outcome": "failed",
            "reason": "qualification stopped before campaign",
            "campaign_manifest": None,
            "function_coverage": None,
        })

        report = assemble_report(plan, observations, self.root)

        self.assertEqual(report["trials"][1]["project_id"], "other-parser")
        first = report["projects"]["parser"]["ranked-libfuzzer"]
        second = report["projects"]["other-parser"]["ranked-libfuzzer"]
        self.assertEqual(first["peak_edges"], {"samples": [7], "unavailable": 0,
                                               "median": 7})
        self.assertEqual(second["outcomes"]["failed"], 1)
        self.assertEqual(second["peak_edges"], {"samples": [], "unavailable": 1,
                                                "median": None})
        self.assertEqual(second["total_cost_usd"]["unavailable"], 1)
        self.assertEqual(report["conditions"]["ranked-libfuzzer"]["peak_edges_median"], 7)

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

    def test_manifest_integer_settings_reject_equal_decimal_values(self):
        for field in ("duration_secs", "max_mem_mb", "max_cpus", "seed"):
            value = campaign_manifest()
            value["body"]["run_config"][field] = float(value["body"]["run_config"][field])
            manifest = self.artifact("manifest.json", value)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                assemble_report(cohort(), self.observations(manifest), self.root)
        plan = cohort()
        plan["conditions"][0]["max_cpus"] = 1
        value = campaign_manifest()
        value["body"]["run_config"]["max_cpus"] = True
        manifest = self.artifact("manifest.json", value)
        with self.assertRaisesRegex(ValueError, "max_cpus"):
            assemble_report(plan, self.observations(manifest), self.root)

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

    def test_rejects_intermediate_symlink_even_when_it_stays_inside_evidence_root(self):
        real_directory = self.root / "real"
        real_directory.mkdir()
        content = json.dumps(campaign_manifest()).encode("utf-8")
        (real_directory / "manifest.json").write_bytes(content)
        (self.root / "alias").symlink_to(real_directory, target_is_directory=True)
        reference = {"path": "alias/manifest.json",
                     "sha256": hashlib.sha256(content).hexdigest()}

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

    def test_report_refuses_schema_two_manifests(self):
        value = campaign_manifest(findings=[finding()])
        value["body"]["schema_version"] = 2
        manifest = self.artifact("manifest.json", value)
        with self.assertRaisesRegex(ValueError, "schema_version"):
            assemble_report(cohort(), self.observations(manifest), self.root)

    def test_report_refuses_malformed_finding_evidence(self):
        missing_origin = {key: value for key, value in finding().items()
                          if key != "origin"}
        unknown_field = dict(finding(), duplicate_stack="1" * 64)
        cases = [
            ("origin", [finding(origin="mystery")]),
            ("stack_signature", [finding(signature="z" * 64)]),
            ("reproducer_sha256", [dict(finding(), reproducer_sha256="not-a-digest")]),
            ("crash_id", [finding(crash_id="not-a-uuid", identifier=2)]),
            ("minimized", [dict(finding(), minimized="yes")]),
            ("campaign finding", [missing_origin]),
            ("campaign finding", [unknown_field]),
            ("duplicate crash id", [finding(), finding()]),
            ("duplicate crash id", [
                finding(crash_id=numbered_crash_id(1).replace("-", "")), finding()]),
            ("campaign finding", [{"unrelated": True}]),
        ]
        for pattern, findings in cases:
            with self.subTest(pattern=pattern):
                value = campaign_manifest(findings=findings)
                manifest = self.artifact("manifest.json", value)
                with self.assertRaisesRegex(ValueError, pattern):
                    assemble_report(cohort(), self.observations(manifest), self.root)
        not_a_list = campaign_manifest(findings={"sig": "target"})
        manifest = self.artifact("manifest.json", not_a_list)
        with self.assertRaisesRegex(ValueError, "findings"):
            assemble_report(cohort(), self.observations(manifest), self.root)

    def test_signature_distributions_summarize_conditions_and_projects(self):
        plan = cohort()
        second_project = copy.deepcopy(plan["projects"][0])
        second_project["id"] = "other-parser"
        plan["projects"].append(second_project)
        second_trial = copy.deepcopy(plan["trials"][0])
        second_trial["id"] = "other-parser-ranked-1"
        second_trial["project_id"] = "other-parser"
        plan["trials"].append(second_trial)
        findings = [
            finding(signature=TARGET_SIGNATURE, origin="target"),
            finding(signature=HARNESS_SIGNATURE, origin="target", identifier=2),
            finding(signature=HARNESS_SIGNATURE, origin="harness", identifier=3),
        ]
        observations = self.observations(
            self.artifact("manifest.json", campaign_manifest(findings=findings)))
        observations["trials"].append({
            "id": second_trial["id"],
            "outcome": "failed",
            "reason": "qualification stopped before campaign",
            "campaign_manifest": None,
            "function_coverage": None,
        })

        report = assemble_report(plan, observations, self.root)

        condition = report["conditions"]["ranked-libfuzzer"]
        self.assertEqual(condition["unique_crash_signatures"],
                         {"samples": [2], "unavailable": 1, "median": 2})
        self.assertEqual(condition["unique_crash_signatures_median"], 2)
        self.assertEqual(condition["target_origin_signatures"],
                         {"samples": [1], "unavailable": 1, "median": 1})
        parser_summary = report["projects"]["parser"]["ranked-libfuzzer"]
        self.assertEqual(parser_summary["unique_crash_signatures"]["samples"], [2])
        self.assertEqual(parser_summary["target_origin_signatures"]["samples"], [1])
        other = report["projects"]["other-parser"]["ranked-libfuzzer"]
        self.assertEqual(other["unique_crash_signatures"],
                         {"samples": [], "unavailable": 1, "median": None})
        self.assertEqual(other["target_origin_signatures"]["unavailable"], 1)


if __name__ == "__main__":
    unittest.main()
