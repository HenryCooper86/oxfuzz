"""Offline behavior tests for the effectiveness benchmark runner.

The end-to-end tests drive `scripts.effectiveness_run` against a stub oxfuzz
binary (a Python script) that fakes `--version`, `doctor`, `fuzz`, `coverage`,
and `serve`: no Docker, no provider, no network. The stub reads the values the
runner would bind from environment variables the test sets, which keeps the
runner's conformance and evidence-binding checks exercised for real.
"""

import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.effectiveness_benchmark import validate_cohort
from scripts.effectiveness_run import (
    RunnerError, binding_mismatches, collect_coverage, collect_db_metrics,
    collect_run_metrics, derive_trial_seed, dry_run, freeze_cohort,
    time_to_first_crash, validate_manifest,
)


COMMIT = "a" * 40
SOURCE_DIGEST = "b" * 64
IMAGE_DIGEST = "c" * 64
RUN_ID = "11111111-1111-4111-8111-111111111111"
BINARY_DIGEST = "d" * 64


def manifest():
    return {
        "schema_version": 1,
        "manifest_id": "test-manifest",
        "notes": "fixture manifest",
        "projects": [{
            "id": "parser",
            "source_url": "https://example.org/parser.git",
            "revision": COMMIT,
            "license": "MIT",
            "language": "c",
            "selected_functions": ["parse_record"],
            "notes": "fixture project",
        }],
    }


def condition():
    return {
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
    }


def cohort(source_sha256=SOURCE_DIGEST, seed=None):
    seed = derive_trial_seed("test-cohort", "parser--parse_record--ranked-libfuzzer--r0") \
        if seed is None else seed
    project = {key: manifest()["projects"][0][key]
               for key in ("id", "source_url", "revision", "license", "language",
                           "selected_functions")}
    project["source_sha256"] = source_sha256
    return {
        "schema_version": 1,
        "cohort_id": "test-cohort",
        "candidate_commit": COMMIT,
        "projects": [project],
        "conditions": [dict(condition(), sandbox_image_sha256=IMAGE_DIGEST)],
        "trials": [{
            "id": "parser--parse_record--ranked-libfuzzer--r0",
            "project_id": "parser",
            "condition_id": "ranked-libfuzzer",
            "selected_function": "parse_record",
            "seed": seed,
        }],
    }


STUB = r"""#!/usr/bin/env python3
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

RUN_ID = "11111111-1111-4111-8111-111111111111"


def env(name, default=""):
    return os.environ.get(name, default)


def rfc3339(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds")


def requested_seed():
    value = sys.argv[sys.argv.index("--seed") + 1] if "--seed" in sys.argv else "1"
    return int(env("STUB_SEED", value))

def cmd_fuzz():
    db_path = env("HF_DB_PATH")
    workspace = env("HF_WORKSPACE_DIR")
    if env("STUB_FUZZ_EXIT"):
        print("stub: forced failure", file=sys.stderr)
        return int(env("STUB_FUZZ_EXIT"))
    now = time.time()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    crash = os.path.join(workspace, "crash-input")
    os.makedirs(workspace, exist_ok=True)
    with open(crash, "wb") as output:
        output.write(b"crash")
    crash_time = now - float(env("STUB_TTFC", "30"))
    os.utime(crash, (crash_time, crash_time))
    connection = sqlite3.connect(db_path)
    connection.executescript(
        "CREATE TABLE runs (id TEXT, run_kind TEXT, engine TEXT, status TEXT,"
        " started_at TEXT, ended_at TEXT, edges INTEGER, execs REAL,"
        " crash_count INTEGER, source_rev TEXT, sandbox_rev TEXT, config_json TEXT);"
        "CREATE TABLE crashes (id TEXT, run_id TEXT, target_id TEXT,"
        " stack_signature TEXT, kind TEXT, summary TEXT, minimized INTEGER,"
        " bug_report_json TEXT, data_json TEXT);"
        "CREATE TABLE diag_observations (id TEXT, obs_type TEXT, cost_usd REAL,"
        " input_tokens INTEGER, output_tokens INTEGER);")
    config = {
        "duration": {"secs": int(env("STUB_DURATION", "60")), "nanos": 0},
        "max_mem_mb": int(env("STUB_MEM", "1024")),
        "max_cpus": int(env("STUB_CPUS", "2")),
        "sanitizer": env("STUB_SANITIZER", "Address"),
        "seed": requested_seed(),
    }
    connection.execute(
        "INSERT INTO runs VALUES (?, 'campaign', ?, 'done', ?, ?, 42, 500.0, 1, ?, ?, ?)",
        (RUN_ID, env("STUB_ENGINE", "libfuzzer"), rfc3339(now - 60), rfc3339(now),
         env("STUB_SOURCE_REV"), "docker-image-id-sha256:" + env("STUB_IMAGE"),
         json.dumps(config)))
    connection.execute(
        "INSERT INTO crashes VALUES ('00000000-0000-0000-0000-000000000001',"
        " ?, 't1', 'sig-1', 'segv', 'summary', 0, NULL, ?)",
        (RUN_ID, json.dumps({"input_path": crash, "origin": "target"})))
    connection.execute(
        "INSERT INTO crashes VALUES ('00000000-0000-0000-0000-000000000002',"
        " ?, 't1', 'sig-1', 'segv', 'dup', 0, NULL, ?)",
        (RUN_ID, json.dumps({"input_path": crash, "origin": "target"})))
    connection.execute(
        "INSERT INTO diag_observations VALUES ('o1', 'generation', 0.25, 100, 50)")
    connection.commit()
    connection.close()
    print(json.dumps({"target": "parse_record", "campaign": {"crashes": 1}}))
    return 0


def manifest_body():
    with sqlite3.connect(env("HF_DB_PATH")) as connection:
        retained_seed = json.loads(connection.execute(
            "SELECT config_json FROM runs WHERE run_kind='campaign'").fetchone()[0])["seed"]
        findings = []
        for crash_id, signature, minimized, data in connection.execute(
                "SELECT id, stack_signature, minimized, data_json FROM crashes WHERE run_id=?",
                (RUN_ID,)):
            crash = json.loads(data)
            with open(crash["input_path"], "rb") as source:
                reproducer = hashlib.sha256(source.read()).hexdigest()
            findings.append({
                "crash_id": crash_id,
                "stack_signature": hashlib.sha256(signature.encode()).hexdigest(),
                "reproducer_sha256": reproducer,
                "minimized": bool(minimized),
                "origin": crash["origin"],
            })
    return {
        "schema_version": 3,
        "run_id": RUN_ID,
        "target": env("STUB_TARGET", "parse_record"),
        "status": "done",
        "engine": env("STUB_ENGINE", "libfuzzer"),
        "source_revision": env("STUB_SOURCE_REV"),
        "sandbox_image_sha256": env("STUB_IMAGE"),
        "binary_sha256": "d" * 64,
        "run_config": {
            "duration_secs": int(env("STUB_DURATION", "60")),
            "max_mem_mb": int(env("STUB_MEM", "1024")),
            "max_cpus": int(env("STUB_CPUS", "2")),
            "sanitizer": env("STUB_SANITIZER_ID", "address"),
            "seed": retained_seed,
        },
        "coverage": {"edges": 42, "delta_edges": 42},
        "cost": {"compute_cost_usd": 0.0, "model_cost_usd": 0.25},
        "findings": findings,
    }


def cmd_serve(port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                return self.reply(200, "")
            match = re.fullmatch(r"/runs/([0-9a-f-]+)/function-coverage", self.path)
            if match:
                return self.reply(200, {
                    "status": "available",
                    "run_id": match.group(1),
                    "binary_sha256": "d" * 64,
                    "export_sha256": "e" * 64,
                    "functions": [{"name": "parse_record", "count": "3",
                                   "files": ["parser.c"]}],
                    "observed_functions": 1,
                    "limitation": "zero counters do not prove non-entry",
                })
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            if self.path == "/campaign/evidence":
                return self.reply(200, {"body": manifest_body(),
                                        "manifest_sha256": "f" * 64})
            self.reply(404, {"error": "not found"})

        def reply(self, status, payload):
            body = json.dumps(payload).encode("utf-8") if payload != "" else b"ok"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


def main():
    args = sys.argv[1:]
    if args == ["--version"]:
        print("oxfuzz 0.0.0-stub")
        return 0
    if args and args[0] == "doctor":
        ready = env("STUB_DOCTOR_READY", "1") != "0"
        report = {"engine": "libfuzzer", "ready": ready,
                  "provider_configured": ready,
                  "problems": [] if ready else ["sandbox image missing"]}
        print(json.dumps(report))
        return 0 if ready else 1
    if args and args[0] == "fuzz":
        return cmd_fuzz()
    if args and args[0] == "coverage":
        print("Coverage for parse_record:")
        print("  lines:     8/10 (80.0%)")
        print("  functions: 1/2 (50.0%)")
        print("  regions:   6/12 (50.0%)")
        return 0
    if args and args[0] == "serve":
        port = int(args[args.index("--port") + 1])
        return cmd_serve(port)
    print("stub: unknown args {}".format(args), file=sys.stderr)
    return 2


sys.exit(main())
"""


def make_stub(directory):
    stub = Path(directory) / "oxfuzz-stub"
    stub.write_text(textwrap.dedent(STUB), encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub


def make_vendored_target(directory, revision_holder):
    """A real git checkout; the caller pins the manifest to its HEAD."""
    import subprocess as git_subprocess
    root = Path(directory)
    root.mkdir(parents=True)
    # Background Git maintenance must not race deletion of this disposable checkout.
    for step in (["git", "init", "--quiet", str(root)],
                 ["git", "-C", str(root), "config", "maintenance.auto", "false"],
                 ["git", "-C", str(root), "config", "gc.auto", "0"],
                 ["git", "-C", str(root), "config", "user.email", "t@example.org"],
                 ["git", "-C", str(root), "config", "user.name", "t"]):
        git_subprocess.run(step, check=True, capture_output=True)
    (root / "parser.c").write_text("int parse_record(void){return 0;}\n")
    (root / "LICENSE").write_text("MIT\n")
    git_subprocess.run(["git", "-C", str(root), "add", "."], check=True,
                       capture_output=True)
    git_subprocess.run(["git", "-C", str(root), "commit", "--quiet", "-m", "init"],
                       check=True, capture_output=True)
    head = git_subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    revision_holder["revision"] = head
    return root


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class ManifestValidationTests(unittest.TestCase):
    def test_accepts_the_checked_in_manifest(self):
        path = Path(__file__).resolve().parents[2] / "docs" / "acceptance" / "held-out-targets.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(validate_manifest(value)["projects"]), 3)

    def test_rejects_mutable_revisions_and_non_https_sources(self):
        value = manifest()
        value["projects"][0]["revision"] = "main"
        with self.assertRaisesRegex(ValueError, "revision"):
            validate_manifest(value)
        value = manifest()
        value["projects"][0]["source_url"] = "http://example.org/parser.git"
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_manifest(value)

    def test_rejects_duplicate_ids_and_unknown_fields(self):
        value = manifest()
        value["projects"].append(dict(value["projects"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate project id"):
            validate_manifest(value)
        value = manifest()
        value["projects"][0]["extra"] = True
        with self.assertRaisesRegex(ValueError, "unknown"):
            validate_manifest(value)


class FreezeTests(unittest.TestCase):
    def test_freeze_builds_a_valid_cohort_with_deterministic_seeds(self):
        frozen = freeze_cohort(manifest(), [condition()], "test-cohort", COMMIT,
                               {"parser": SOURCE_DIGEST}, IMAGE_DIGEST, 1)
        validate_cohort(frozen)
        trial = frozen["trials"][0]
        self.assertEqual(trial["id"], "parser--parse_record--ranked-libfuzzer--r0")
        self.assertEqual(trial["seed"],
                         derive_trial_seed("test-cohort", trial["id"]))
        again = freeze_cohort(manifest(), [condition()], "test-cohort", COMMIT,
                              {"parser": SOURCE_DIGEST}, IMAGE_DIGEST, 1)
        self.assertEqual(frozen, again)

    def test_replicates_expand_each_cell(self):
        frozen = freeze_cohort(manifest(), [condition()], "c", COMMIT,
                               {"parser": SOURCE_DIGEST}, IMAGE_DIGEST, 2)
        self.assertEqual([t["id"] for t in frozen["trials"]],
                         ["parser--parse_record--ranked-libfuzzer--r0",
                          "parser--parse_record--ranked-libfuzzer--r1"])
        self.assertNotEqual(frozen["trials"][0]["seed"], frozen["trials"][1]["seed"])

    def test_freeze_rejects_an_invalid_condition_through_cohort_validation(self):
        bad = condition()
        bad["engine"] = "syzkaller"
        with self.assertRaisesRegex(RunnerError, "validation"):
            freeze_cohort(manifest(), [bad], "c", COMMIT,
                          {"parser": SOURCE_DIGEST}, IMAGE_DIGEST, 1)


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def make_db(self, rows=True):
        db_path = self.root / "oxfuzz.db"
        connection = sqlite3.connect(db_path)
        connection.executescript(
            "CREATE TABLE runs (id TEXT, run_kind TEXT, engine TEXT, status TEXT,"
            " started_at TEXT, ended_at TEXT, edges INTEGER, execs REAL,"
            " crash_count INTEGER, source_rev TEXT, sandbox_rev TEXT, config_json TEXT);"
            "CREATE TABLE crashes (id TEXT, run_id TEXT, target_id TEXT,"
            " stack_signature TEXT, kind TEXT, summary TEXT, minimized INTEGER,"
            " bug_report_json TEXT, data_json TEXT);"
            "CREATE TABLE diag_observations (id TEXT, obs_type TEXT, cost_usd REAL,"
            " input_tokens INTEGER, output_tokens INTEGER);")
        if rows:
            crash = self.root / "crash-input"
            crash.write_bytes(b"crash")
            started = time.time() - 60
            from datetime import datetime, timezone

            def stamp(epoch):
                return datetime.fromtimestamp(epoch, timezone.utc).isoformat(
                    timespec="milliseconds")
            os.utime(crash, (started + 12, started + 12))
            config = {"duration": {"secs": 60, "nanos": 0}, "max_mem_mb": 1024,
                      "max_cpus": 2, "sanitizer": "Address", "seed": 7}
            connection.execute(
                "INSERT INTO runs VALUES (?, 'campaign', 'libfuzzer', 'done', ?, ?,"
                " 42, 500.0, 2, ?, ?, ?)",
                (RUN_ID, stamp(started), stamp(started + 60), SOURCE_DIGEST,
                 "docker-image-id-sha256:" + IMAGE_DIGEST, json.dumps(config)))
            for crash_id, signature in (("c1", "sig-1"), ("c2", "sig-2"), ("c3", "sig-1")):
                connection.execute(
                    "INSERT INTO crashes VALUES (?, ?, 't1', ?, 'segv', 's', 0, NULL, ?)",
                    (crash_id, RUN_ID, signature, json.dumps({"input_path": str(crash)})))
            connection.execute(
                "INSERT INTO diag_observations VALUES ('o1', 'generation', 0.5, 10, 5)")
            connection.execute(
                "INSERT INTO diag_observations VALUES ('o2', 'tool', 9.9, 0, 0)")
        connection.commit()
        connection.close()
        return db_path

    def test_collects_runs_crashes_and_cost_with_dedup(self):
        data = collect_db_metrics(self.make_db())
        self.assertTrue(data["available"])
        runs, signatures, crash_files = collect_run_metrics(
            data, condition(), SOURCE_DIGEST, IMAGE_DIGEST, 7)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["conformance"], [])
        self.assertEqual(runs[0]["edges"], 42)
        self.assertEqual(signatures, {"sig-1", "sig-2"})
        self.assertEqual(len(crash_files), 3)
        self.assertEqual(data["cost"], (1, 0.5, 10, 5))

    def test_ttfc_uses_the_earliest_crash_artifact_timestamp(self):
        data = collect_db_metrics(self.make_db())
        runs, _signatures, crash_files = collect_run_metrics(
            data, condition(), SOURCE_DIGEST, IMAGE_DIGEST, 7)
        self.assertEqual(len(runs), 1)
        ttfc = time_to_first_crash(crash_files)
        self.assertIsNotNone(ttfc)
        self.assertTrue(10 <= ttfc <= 20, ttfc)

    def test_conformance_names_each_mismatch(self):
        data = collect_db_metrics(self.make_db())
        drifted = dict(condition(), duration_secs=120)
        runs, _s, _c = collect_run_metrics(data, drifted, "0" * 64, "0" * 64, 8)
        problems = runs[0]["conformance"]
        self.assertTrue(any("duration" in problem for problem in problems))
        self.assertTrue(any("source_rev" in problem for problem in problems))
        self.assertTrue(any("sandbox_rev" in problem for problem in problems))
        self.assertTrue(any("seed" in problem for problem in problems))

    def test_missing_database_is_unavailable_not_zero(self):
        data = collect_db_metrics(self.root / "absent.db")
        self.assertFalse(data["available"])
        self.assertIn("not created", data["reasons"][0])


class DryRunTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.stub = make_stub(self.root)
        self.workspace = self.root / "workspace"
        holder = {}
        make_vendored_target(self.workspace / "targets" / "parser", holder)
        self.manifest = manifest()
        self.manifest["projects"][0]["revision"] = holder["revision"]
        self.cohort = cohort()
        self.cohort["projects"][0]["revision"] = holder["revision"]
        self.config = self.root / "config"
        self.config.mkdir()
        (self.config / "providers.toml").write_text(
            '[[providers]]\nmodel = "glm-5.2"\n', encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def args(self, **overrides):
        values = {
            "manifest": self.root / "manifest.json",
            "workspace": self.workspace,
            "config": self.config,
        }
        values.update(overrides)
        return type("Args", (), values)()

    def write_manifest(self):
        write_json(self.root / "manifest.json", self.manifest)

    def test_dry_run_passes_with_a_ready_stub_and_vendored_targets(self):
        self.write_manifest()
        warnings = dry_run(self.cohort, self.manifest, self.stub, self.args())
        self.assertFalse(any("vendored" in warning for warning in warnings))

    def test_dry_run_fails_when_a_target_is_not_vendored(self):
        import shutil
        self.write_manifest()
        shutil.rmtree(self.workspace / "targets" / "parser")
        with self.assertRaisesRegex(RunnerError, "blocking"):
            dry_run(self.cohort, self.manifest, self.stub, self.args())

    def test_dry_run_warns_but_passes_when_doctor_is_not_ready(self):
        self.write_manifest()
        with mock.patch.dict(os.environ, {"STUB_DOCTOR_READY": "0"}):
            warnings = dry_run(self.cohort, self.manifest, self.stub, self.args())
        self.assertTrue(any("not ready" in warning for warning in warnings))

    def test_dry_run_names_unexported_provider_key_variables(self):
        self.write_manifest()
        (self.config / "providers.toml").write_text(
            '[[providers]]\nmodel = "glm-5.2"\napi_key_env = "STUB_MISSING_KEY"\n',
            encoding="utf-8")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STUB_MISSING_KEY", None)
            warnings = dry_run(self.cohort, self.manifest, self.stub,
                               self.args())
        self.assertTrue(any("STUB_MISSING_KEY" in warning for warning in warnings))
        self.assertTrue(any("providers.toml" in warning for warning in warnings))


class CoverageParseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.stub = make_stub(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_parses_the_three_coverage_rows(self):
        coverage = collect_coverage(self.stub, os.environ.copy(), self.root,
                                    "parse_record", self.root / "coverage.log")
        self.assertEqual(coverage["lines"], {"covered": 8, "total": 10, "percent": 80.0})
        self.assertEqual(coverage["regions"]["total"], 12)
        self.assertEqual(coverage["functions"]["covered"], 1)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.stub = make_stub(self.root)
        self.workspace = self.root / "workspace"
        holder = {}
        make_vendored_target(self.workspace / "targets" / "parser", holder)
        self.manifest = manifest()
        self.manifest["projects"][0]["revision"] = holder["revision"]
        self.manifest_path = self.root / "manifest.json"
        write_json(self.manifest_path, self.manifest)
        self.cohort = cohort()
        self.cohort["projects"][0]["revision"] = holder["revision"]
        self.cohort_path = self.root / "cohort.json"
        write_json(self.cohort_path, self.cohort)
        self.out = self.root / "out"
        self.env = {
            "STUB_SOURCE_REV": SOURCE_DIGEST,
            "STUB_IMAGE": IMAGE_DIGEST,
            "STUB_TTFC": "30",
        }

    def tearDown(self):
        self.directory.cleanup()

    def run_cli(self, *argv, env=None):
        repo = Path(__file__).resolve().parents[2]
        merged = dict(os.environ)
        merged.update(self.env)
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, "-m", "scripts.effectiveness_run", *argv],
            cwd=repo, capture_output=True, text=True, check=False, env=merged,
            timeout=120)

    def run_args(self):
        return ["run", "--cohort", str(self.cohort_path),
                "--manifest", str(self.manifest_path),
                "--workspace", str(self.workspace),
                "--out", str(self.out),
                "--oxfuzz", str(self.stub)]

    def test_full_trial_produces_results_summary_and_reportable_observations(self):
        result = self.run_cli(*self.run_args())
        self.assertEqual(result.returncode, 0, result.stderr)

        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(results["cohort_id"], "test-cohort")
        trial = results["trials"][0]
        self.assertEqual(trial["outcome"], "completed")
        self.assertEqual(trial["runs_executed"], 1)
        self.assertEqual(trial["campaign_runs"][0]["seed"],
                         self.cohort["trials"][0]["seed"])
        self.assertEqual(trial["unique_crashes"], 1)
        self.assertEqual(trial["peak_edges"], 42)
        self.assertIsNotNone(trial["time_to_first_crash_secs"])
        self.assertEqual(trial["llm"], {"calls": 1, "input_tokens": 100,
                                        "output_tokens": 50, "cost_usd": 0.25})
        self.assertEqual(trial["coverage"]["lines"]["covered"], 8)
        self.assertEqual(trial["budgets"]["model_cost_exceeded"], False)
        self.assertTrue((self.out / "summary.md").read_text(encoding="utf-8")
                        .startswith("# Held-out effectiveness baseline -- test-cohort"))

        observations_path = self.out / "observations.json"
        self.assertTrue(observations_path.is_file(),
                        "bound evidence must produce observations.json: "
                        + results["observations_note"])
        from scripts.effectiveness_report import assemble_report
        observations = json.loads(observations_path.read_text(encoding="utf-8"))
        report = assemble_report(self.cohort, observations, self.out)
        self.assertEqual(report["outcomes"]["completed"], 1)
        self.assertEqual(report["trials"][0]["peak_edges"],
                         {"status": "available", "value": 42})
        self.assertEqual(report["trials"][0]["selected_function_entry"]["status"],
                         "observed")
        self.assertEqual(report["trials"][0]["total_cost_usd"],
                         {"status": "available", "value": 0.25})
        self.assertEqual(report["trials"][0]["unique_crash_signatures"],
                         {"status": "available", "value": 1})
        self.assertEqual(report["trials"][0]["crash_signature_origins"]["value"]["target"], 1)
        self.assertEqual(report["trials"][0]["crash_reproducibility"]["status"], "unavailable")

    def test_a_seed_mismatch_keeps_metrics_but_blocks_the_observation_index(self):
        result = self.run_cli(*self.run_args(), env={"STUB_SEED": "12345"})
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        trial = results["trials"][0]
        self.assertEqual(trial["outcome"], "completed")
        self.assertEqual(trial["unique_crashes"], 1)
        self.assertTrue(any("seed" in limitation for limitation in trial["limitations"]))
        self.assertFalse((self.out / "observations.json").exists())

    def test_a_failing_pipeline_records_a_failed_trial_with_evidence(self):
        result = self.run_cli(*self.run_args(), env={"STUB_FUZZ_EXIT": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        trial = results["trials"][0]
        self.assertEqual(trial["outcome"], "failed")
        self.assertIn("status 1", trial["reason"])
        self.assertIsNone(trial["unique_crashes"])
        # A failed trial with no manifest is a reader-valid observation; the
        # protocol keeps failed and zero-progress outcomes visible.
        observations = json.loads((self.out / "observations.json").read_text(encoding="utf-8"))
        from scripts.effectiveness_report import assemble_report
        report = assemble_report(self.cohort, observations, self.out)
        self.assertEqual(report["outcomes"]["failed"], 1)
        self.assertEqual(report["trials"][0]["peak_edges"]["status"], "unavailable")

    def test_no_evidence_export_skips_serve(self):
        result = self.run_cli(*self.run_args(), "--no-evidence-export")
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads((self.out / "results.json").read_text(encoding="utf-8"))
        trial = results["trials"][0]
        self.assertEqual(trial["outcome"], "completed")
        self.assertIsNone(trial["evidence"])
        self.assertTrue(any("disabled" in l for l in trial["limitations"]))

    def test_binding_check_rejects_an_exported_seed_mismatch(self):
        manifest_doc = {"body": {
            "schema_version": 3,
            "run_id": RUN_ID,
            "target": "parse_record",
            "status": "done",
            "engine": "libfuzzer",
            "source_revision": SOURCE_DIGEST,
            "sandbox_image_sha256": IMAGE_DIGEST,
            "binary_sha256": BINARY_DIGEST,
            "run_config": {"duration_secs": 60, "max_mem_mb": 1024, "max_cpus": 2,
                           "sanitizer": "address", "seed": 1},
            "coverage": {"edges": 0, "delta_edges": 0},
            "cost": {"compute_cost_usd": 0.0, "model_cost_usd": 0.0},
            "findings": [],
        }, "manifest_sha256": "f" * 64}
        problems = binding_mismatches(
            manifest_doc, self.cohort["trials"][0], self.cohort["projects"][0],
            self.cohort["conditions"][0], "completed")
        self.assertTrue(any("seed" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
