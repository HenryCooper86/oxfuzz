"""Reject incomplete retained-history experiments before reporting latency."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_history_samples", ROOT / "scripts" / "check_history_samples.py"
)
history = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(history)


def document():
    return {
        "schema_version": 1,
        "environment": {
            "runner": "fixed-runner", "revision": "a" * 40, "rustc": "rustc 1.94.0",
            "os": "linux", "arch": "x86_64", "profile": "release", "clean": True,
        },
        "cases": [
            {"targets": targets, "runs": runs, "preparation_us": [100] * 5,
             "first_query_us": [10, 20, 30, 40, 50], "repeat_query_us": [20] * 25}
            for targets, runs in ((161, 3200), (161, 6400), (321, 12800))
        ],
    }


class HistorySampleTests(unittest.TestCase):
    def test_reports_first_and_repeat_query_quantiles(self) -> None:
        rows = history.summarize(document())
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["first_query_median_us"], 30)
        self.assertEqual(rows[0]["first_query_p95_us"], 50)
        self.assertEqual(rows[0]["repeat_query_p95_us"], 20)
        self.assertEqual(rows[0]["first_query_samples"], 5)
        self.assertEqual(rows[0]["repeat_query_samples"], 25)

    def test_missing_sizes_samples_and_environment_fail(self) -> None:
        cases = []
        one = document()
        one["cases"].pop()
        cases.append(one)
        one = document()
        one["cases"][0]["first_query_us"].pop()
        cases.append(one)
        one = document()
        one["cases"][1]["repeat_query_us"][0] = -1
        cases.append(one)
        one = document()
        one["cases"][2]["preparation_us"][0] = float("nan")
        cases.append(one)
        one = document()
        one["environment"]["revision"] = "dirty"
        cases.append(one)
        one = document()
        one["environment"]["profile"] = "unknown"
        cases.append(one)
        one = document()
        one["environment"]["clean"] = False
        cases.append(one)
        one = document()
        one["cases"][1] = one["cases"][0]
        cases.append(one)
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    history.summarize(case)

    def test_size_identifiers_require_json_integers(self) -> None:
        for field in ("targets", "runs"):
            for value in (float(document()["cases"][0][field]), True, "161", [161]):
                source = document()
                source["cases"][0][field] = value
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        history.summarize(source)


if __name__ == "__main__":
    unittest.main()
