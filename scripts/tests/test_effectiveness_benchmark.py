"""Behavior tests for the held-out effectiveness cohort format."""

import copy
import unittest

from scripts.effectiveness_benchmark import no_duplicate_keys, validate_cohort


COMMIT = "a" * 40
DIGEST = "b" * 64


def cohort():
    return {
        "schema_version": 1,
        "cohort_id": "held-out-c-1",
        "candidate_commit": COMMIT,
        "projects": [{
            "id": "parser",
            "source_url": "https://example.org/parser.git",
            "revision": COMMIT,
            "license": "MIT",
            "source_sha256": DIGEST,
            "language": "c",
            "selected_functions": ["parse_record"],
        }],
        "conditions": [{
            "id": "ranked-libfuzzer",
            "engine": "libfuzzer",
            "selection_strategy": "ranked",
            "provider_family": "bigmodel",
            "model_id": "glm-5.2",
            "sanitizer": "address",
            "top_k": 5,
            "duration_secs": 60,
            "max_mem_mb": 1024,
            "max_cpus": 2,
            "model_call_budget": 4,
            "model_cost_budget_usd": 1.0,
            "sandbox_image_sha256": DIGEST,
        }],
        "trials": [{
            "id": "parser-ranked-1",
            "project_id": "parser",
            "condition_id": "ranked-libfuzzer",
            "selected_function": "parse_record",
            "seed": 123,
        }],
    }


class CohortValidationTests(unittest.TestCase):
    def test_accepts_complete_immutable_trial_matrix(self):
        self.assertEqual(validate_cohort(cohort())["trials"][0]["id"], "parser-ranked-1")

    def test_uses_the_service_engine_identifier_for_afl_plus_plus(self):
        value = cohort()
        value["conditions"][0]["engine"] = "afl++"
        self.assertEqual(validate_cohort(value)["conditions"][0]["engine"], "afl++")
        value["conditions"][0]["engine"] = "aflpp"
        with self.assertRaisesRegex(ValueError, "unsupported engine"):
            validate_cohort(value)

    def test_rejects_a_trial_with_an_unsupported_language_engine_pair(self):
        value = cohort()
        value["projects"][0]["language"] = "rust"
        self.assertEqual(validate_cohort(value)["projects"][0]["language"], "rust")
        value["conditions"][0]["engine"] = "afl++"
        with self.assertRaisesRegex(ValueError, "unsupported language/engine pair"):
            validate_cohort(value)

    def test_rejects_discovery_only_languages_and_missing_language(self):
        for language in ("go", "python", "C++", ""):
            value = cohort()
            value["projects"][0]["language"] = language
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "language"):
                validate_cohort(value)
        value = cohort()
        del value["projects"][0]["language"]
        with self.assertRaisesRegex(ValueError, "language"):
            validate_cohort(value)

    def test_accepts_cpp_with_all_userspace_engines(self):
        for engine in ("afl++", "honggfuzz", "libfuzzer"):
            value = cohort()
            value["projects"][0]["language"] = "cpp"
            value["conditions"][0]["engine"] = engine
            with self.subTest(engine=engine):
                self.assertEqual(validate_cohort(value)["projects"][0]["language"], "cpp")

    def test_rejects_duplicate_trial_ids(self):
        value = cohort()
        value["trials"].append(copy.deepcopy(value["trials"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate trial id"):
            validate_cohort(value)

    def test_rejects_missing_or_invalid_immutable_identities(self):
        for section, field, replacement in [
            ("projects", "revision", "main"),
            ("projects", "source_sha256", ""),
            ("conditions", "sandbox_image_sha256", ""),
        ]:
            value = cohort()
            value[section][0][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_cohort(value)

    def test_rejects_missing_model_and_sanitizer_settings(self):
        for field in ("provider_family", "model_id", "sanitizer"):
            value = cohort()
            value["conditions"][0][field] = ""
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_cohort(value)

    def test_rejects_unresolved_project_condition_and_function(self):
        for field, replacement in [
            ("project_id", "missing"),
            ("condition_id", "missing"),
            ("selected_function", "another_function"),
        ]:
            value = cohort()
            value["trials"][0][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_cohort(value)

    def test_rejects_invalid_fixed_budgets_and_duplicate_definition_ids(self):
        for field, replacement in [
            ("duration_secs", 0),
            ("max_mem_mb", -1),
            ("model_call_budget", -1),
            ("model_cost_budget_usd", -0.1),
            ("top_k", 0),
        ]:
            value = cohort()
            value["conditions"][0][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                validate_cohort(value)
        value = cohort()
        value["projects"].append(copy.deepcopy(value["projects"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate project id"):
            validate_cohort(value)

    def test_malformed_foreign_values_fail_as_validation_errors(self):
        for section, field, replacement in [
            ("projects", "language", []),
            ("conditions", "engine", []),
            ("conditions", "selection_strategy", {}),
            ("trials", "project_id", []),
            ("trials", "selected_function", {}),
        ]:
            value = cohort()
            value[section][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_cohort(value)

    def test_duplicate_json_keys_are_not_silently_replaced(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            no_duplicate_keys([("id", "first"), ("id", "second")])


if __name__ == "__main__":
    unittest.main()
