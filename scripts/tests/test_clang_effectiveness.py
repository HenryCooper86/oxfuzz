import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest

from scripts.clang_effectiveness import CallBudget, prepare, report, verify_packet, qualification_command


class ClangEffectivenessTests(unittest.TestCase):
    def prepared(self, root):
        return prepare(root / "comparison", "sha256:" + "a" * 64, "sha256:" + "b" * 64,
                       "glm-5.3", 30)

    def test_preparation_is_immutable_and_cannot_execute_a_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet = self.prepared(root)
            self.assertEqual(len(packet["trials"]), 6)
            self.assertEqual(packet["identity"]["max_model_calls"], 12)
            self.assertEqual(len({t["directory"] for t in packet["trials"]}), 6)
            for trial in packet["trials"]:
                directory = root / "comparison" / trial["directory"]
                self.assertTrue((directory / "project" / trial["source_file"]).is_file())
                config = (directory / "config" / "oxfuzz.toml").read_text()
                self.assertEqual("[clang_analysis.exploration]" in config, trial["mode"] == "enriched")
                command, env = qualification_command(packet, trial, root / "comparison", Path("/oxfuzz"))
                self.assertEqual(env["HF_AUTO_APPROVE"], "0")
                self.assertEqual(env["HF_GUARDRAILS"], "strict")
                self.assertIn("qualify", command)
                self.assertNotIn("--no-llm-review", command)
            self.assertEqual(verify_packet(packet, root / "comparison"), packet)
            with self.assertRaises(FileExistsError):
                self.prepared(root)
            trial = packet["trials"][0]
            (root / "comparison" / trial["directory"] / "project" / trial["source_file"]).write_text("changed")
            with self.assertRaisesRegex(ValueError, "source"):
                verify_packet(packet, root / "comparison")

    def test_report_rejects_mixed_identities_and_keeps_missing_counters_null(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet = self.prepared(root)
            observation = {"packet_id": packet["id"], "trial_id": packet["trials"][0]["id"],
                           "identity": copy.deepcopy(packet["identity"]),
                           "metrics": {"compiled": True, "target_entered": None, "edges": 0},
                           "execution_evidence": {"run_id":"0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
                               "harness_id":"0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6", "source_sha256":"a" * 64,
                               "binary_sha256":"b" * 64, "review_source_sha256":"a" * 64,
                               "review_binary_sha256":"b" * 64, "review_approved":True,"human_approved":True}}
            observation["trial_identity"] = packet["trials"][0]
            result = report(packet, [observation])
            self.assertIsNone(result["trials"][0]["metrics"]["target_entered"])
            self.assertEqual(result["trials"][0]["metrics"]["edges"], 0)
            self.assertIsNone(result["trials"][0]["metrics"]["execs_per_sec"])
            observation["metrics"].update(target_branches_covered=0, target_branches_total=2)
            branch_result = report(packet, [observation])
            self.assertEqual(branch_result["trials"][0]["metrics"]["target_branches_covered"], 0)
            for field in ["model", "sandbox_image", "duration_secs", "seed"]:
                bad = copy.deepcopy(observation)
                bad["identity"][field] = "different"
                with self.assertRaisesRegex(ValueError, "identity"):
                    report(packet, [bad])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                report(packet, [observation, observation])
            bad = copy.deepcopy(observation)
            bad["metrics"]["target_entered"] = True
            bad["execution_evidence"]["human_approved"] = False
            with self.assertRaisesRegex(ValueError, "evidence"):
                report(packet, [bad])
            copied = copy.deepcopy(observation)
            copied["trial_id"] = packet["trials"][1]["id"]
            with self.assertRaisesRegex(ValueError, "trial identity"):
                report(packet, [copied])
            copied["trial_identity"] = packet["trials"][1]
            with self.assertRaisesRegex(ValueError, "execution.*reused"):
                report(packet, [observation, copied])
            bad = copy.deepcopy(observation)
            bad.pop("execution_evidence")
            with self.assertRaisesRegex(ValueError, "evidence"):
                report(packet, [bad])

    def test_call_budget_is_durable_and_counts_concurrent_reservations_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "budget.db"
            admitted = []
            def reserve():
                try:
                    admitted.append(CallBudget(database, 12).reserve({"model":"glm-5.3"}))
                except ValueError:
                    pass
            threads = [threading.Thread(target=reserve) for _ in range(30)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(admitted), list(range(1, 13)))
            with self.assertRaisesRegex(ValueError, "exhausted"):
                CallBudget(database, 12).reserve({"model":"glm-5.3"})
            with self.assertRaisesRegex(ValueError, "limit"):
                CallBudget(database, 13)


if __name__ == "__main__":
    unittest.main()
