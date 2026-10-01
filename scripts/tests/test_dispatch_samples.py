"""Validate retained dispatch timing samples before publishing a latency claim."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_dispatch_samples", ROOT / "scripts" / "check_dispatch_samples.py"
)
samples = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(samples)


def document(values=None):
    values = list(range(1, 1001)) if values is None else values
    return {
        "schema_version": 1,
        "environment": {"os": "linux", "arch": "x86_64", "rustc": "1.94.0", "runner": "fixed-runner", "revision": "a" * 40,
                        "profile": "release", "runtime_workers": 4, "fixture": "noop-schema-v1", "clean": True},
        "cases": [
            {"decision": decision, "concurrency": concurrency, "dispatch_us": list(values),
             "queue_us": [0] * len(values), "total_us": list(values)}
            for decision in ("accepted", "denied")
            for concurrency in (1, 8, 32)
        ],
    }


class DispatchSampleTests(unittest.TestCase):
    def test_summarizes_exact_median_and_nearest_rank_p95(self) -> None:
        result = samples.summarize(document())
        self.assertEqual(len(result), 6)
        self.assertEqual(result[0], {
            "decision": "accepted", "concurrency": 1, "samples": 1000,
            "dispatch_median_us": 500.5, "dispatch_p95_us": 950, "dispatch_max_us": 1000,
            "queue_median_us": 0, "queue_p95_us": 0, "queue_max_us": 0,
            "total_median_us": 500.5, "total_p95_us": 950, "total_max_us": 1000,
        })
        samples.require_dispatch_limit(result, 1000)
        with self.assertRaises(ValueError):
            samples.require_dispatch_limit(result, 949)

    def test_incomplete_or_untrusted_samples_cannot_support_a_claim(self) -> None:
        cases = [
            {**document(), "cases": document()["cases"][:-1]},
            document([1] * 999),
            document([1] * 999 + [float("nan")]),
            document([1] * 999 + [-1]),
            {**document(), "environment": {}},
            {**document(), "environment": {**document()["environment"], "revision": "unknown"}},
            {**document(), "environment": {**document()["environment"], "runtime_workers": 0}},
            {**document(), "environment": {**document()["environment"], "clean": False}},
            {**document(), "schema_version": 2},
        ]
        missing_queue = document()
        del missing_queue["cases"][0]["queue_us"]
        cases.append(missing_queue)
        inconsistent_total = document()
        inconsistent_total["cases"][0]["total_us"][0] = 0
        cases.append(inconsistent_total)
        duplicate = document()
        duplicate["cases"][1] = duplicate["cases"][0]
        cases.append(duplicate)
        for source in cases:
            with self.subTest(source=source.get("schema_version"), count=len(source.get("cases", []))):
                with self.assertRaises(ValueError):
                    samples.summarize(source)

    def test_concurrency_identity_requires_a_json_integer(self) -> None:
        for value in (True, 1.0, "1", [1]):
            source = document()
            source["cases"][0]["concurrency"] = value
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    samples.summarize(source)


if __name__ == "__main__":
    unittest.main()
