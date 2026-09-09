"""Exercise the demo's command sequence without providers or target execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ATTEMPT = "33333333-3333-4333-8333-333333333333"
SUBMISSION = "22222222-2222-4222-8222-222222222222"
STUB = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["DEMO_TRACE"], "a") as stream:
    stream.write(json.dumps(args) + "\\n")
stage = " ".join(args[:2]) if args[0] == "work-order" else args[0]
if stage == os.environ.get("DEMO_FAIL_STAGE"):
    print("stage failed", file=sys.stderr)
    sys.exit(1)
if stage == os.environ.get("DEMO_BAD_JSON"):
    print("not JSON")
    sys.exit(0)
if args[0] == "doctor":
    if os.environ.get("DEMO_DENY"):
        print(os.environ["DEMO_DENY"], file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"ready": True}))
elif args[:2] == ["work-order", "export"]:
    print(json.dumps({"id": "a" * 64, "payload": {"target": {
        "relative_source": "packet.c", "symbol": "parse_packet"}}}))
elif args[0] == "harness":
    print(json.dumps({"source": "int exact_draft;\\n", "generator": "llm"}))
elif args[:2] == ["work-order", "import"]:
    source = Path(args[args.index("--source") + 1]).read_text()
    assert source == "int exact_draft;\\n"
    print(json.dumps({"id": "22222222-2222-4222-8222-222222222222", "source": source}))
elif args[:2] == ["work-order", "qualify"]:
    print(json.dumps({"id": "33333333-3333-4333-8333-333333333333",
                      "status": os.environ.get("DEMO_STATUS", "smoke_passed")}))
elif args[:2] == ["work-order", "promote"] and os.environ.get("DEMO_STALE"):
    print("attempt no longer active", file=sys.stderr)
    sys.exit(1)
'''


class DemoTests(unittest.TestCase):
    def run_demo(self, arguments=(), answer="y\n", **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "oxfuzz"
            stub.write_text(STUB)
            stub.chmod(0o700)
            trace = root / "trace.jsonl"
            env = dict(os.environ, OXFUZZ_BIN=str(stub), DEMO_TRACE=str(trace), **settings)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/demo-cve-rediscovery.sh"), *arguments],
                input=answer, text=True, capture_output=True, env=env, timeout=20,
            )
            calls = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            return result, calls

    def test_approval_promotes_the_qualified_attempt_without_regeneration(self):
        result, calls = self.run_demo()
        self.assertEqual(result.returncode, 0, result.stderr)
        drafts = [call for call in calls if call[0] == "harness"]
        self.assertEqual(len(drafts), 1)
        for flag in ("--draft-only", "--json", "--ai"):
            self.assertIn(flag, drafts[0])
        self.assertEqual(drafts[0][drafts[0].index("--ai") + 1], "require")
        self.assertIn(["work-order", "qualify", "--submission", SUBMISSION], calls)
        self.assertIn(["work-order", "promote", "--attempt", ATTEMPT], calls)
        for command in ("run", "triage"):
            call = next(call for call in calls if call[0] == command)
            self.assertEqual(call[call.index("--target") + 1], "packet.c::parse_packet")
        self.assertIn("int exact_draft;\n", result.stdout)
        self.assertLess(result.stdout.index("int exact_draft"), result.stdout.index("Approve"))
        self.assertIn(ATTEMPT, result.stdout)

    def test_decline_and_eof_never_promote_or_run(self):
        for answer in ("n\n", ""):
            with self.subTest(answer=answer):
                result, calls = self.run_demo(answer=answer)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == "run" or call[:2] == ["work-order", "promote"] for call in calls))

    def test_selected_engine_duration_and_provider_are_preflighted(self):
        result, calls = self.run_demo(["--preflight-only", "--engine", "honggfuzz", "--duration", "30s"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        for token in ("--engine", "honggfuzz", "--duration", "30s", "--require-provider"):
            self.assertIn(token, calls[0])
        self.assertNotIn("can run the full demo", result.stdout)

    def test_preflight_failure_stops_before_discovery(self):
        for problem in ("no provider configured", "selected engine unavailable", "engine disabled"):
            result, calls = self.run_demo(DEMO_DENY=problem)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(calls), 1)
            self.assertIn(problem, result.stderr)

    def test_failed_qualification_and_stale_promotion_never_run(self):
        for settings in ({"DEMO_STATUS": "review_failed"}, {"DEMO_STATUS": "smoke_failed"}, {"DEMO_STALE": "1"}):
            result, calls = self.run_demo(**settings)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(call[0] == "run" for call in calls))

    def test_example_symbols_are_selected_before_authoring(self):
        for example, symbol in (("libfuzzer_fuzzme", "FuzzMe"), ("honggfuzz_magic", "match_magic"), ("json_number_parser", "parse_number"), ("utf8_decoder", "decode_utf8")):
            result, calls = self.run_demo(["--example", example], answer="n\n")
            draft = next(call for call in calls if call[0] == "harness")
            self.assertEqual(draft[draft.index("--target") + 1], symbol)

    def test_command_failure_and_invalid_json_stop_before_promotion(self):
        for variable, stages in (
            ("DEMO_FAIL_STAGE", ("discover", "work-order export", "harness", "work-order import", "work-order qualify")),
            ("DEMO_BAD_JSON", ("work-order export", "harness", "work-order import", "work-order qualify")),
        ):
            for stage in stages:
                with self.subTest(variable=variable, stage=stage):
                    result, calls = self.run_demo(**{variable: stage})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(call[0] == "run" or call[:2] == ["work-order", "promote"] for call in calls))

    def test_invalid_options_do_not_start_any_operation(self):
        for args in (["--yes"], ["--example", "../"], ["--engine", "syzkaller"], ["--duration"]):
            result, calls = self.run_demo(args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])
