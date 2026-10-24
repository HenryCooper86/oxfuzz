#!/usr/bin/env python3
"""Prepare immutable Clang comparisons and report retained service measurements.

No command in this module executes a harness. Qualification command preparation
explicitly denies execution; existing service review and human gates own runs.
CallBudget reserves each real upstream request durably, including failed calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import uuid


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/clang_effectiveness"
COHORT = (("record", "parser.c", "c", "parse_record", "a5030001414243"),
          ("handle", "handle.c", "c", "decode_message", "01ff010241"),
          ("command", "command.cpp", "cpp", "parse_command", "3a733d4121"))
EXECUTION_METRICS = ("target_entered", "covered_functions", "total_functions", "target_branches_covered",
                     "target_branches_total", "edges", "execs_per_sec", "wall_secs")
METRICS = ("analysis_secs", "compiled", *EXECUTION_METRICS, "draft_input_tokens", "draft_output_tokens",
           "review_input_tokens", "review_output_tokens")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def prepare(root, sandbox_image, analyzer_image, model, duration_secs):
    """Create six isolated trials without starting a provider or runtime."""
    for image in (sandbox_image, analyzer_image):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("an immutable image identity is required")
    if not isinstance(model, str) or not model or type(duration_secs) is not int or not 1 <= duration_secs <= 300:
        raise ValueError("invalid model or duration")
    identity = {"provider": "bigmodel-standard", "endpoint": "https://open.bigmodel.cn/api/paas/v4",
                "model": model, "sandbox_image": sandbox_image, "analyzer_image": analyzer_image,
                "duration_secs": duration_secs, "engine": "libfuzzer", "sanitizer": "address",
                "seed": 1337, "max_mem_mb": 2048, "max_cpus": 1, "max_model_calls": 12}
    identity.update(max_output_tokens=8192, reasoning_effort="low", temperature=0.2)
    root = Path(root)
    if root.exists() or root.is_symlink():
        # mkdir(exist_ok=False) semantics: a retry on an existing comparison
        # fails loudly instead of merging into it.
        raise FileExistsError("comparison root already exists: {}".format(root))
    # Build into a staging sibling and publish with one rename, so a prepare
    # that fails or is interrupted leaves no partial comparison root a retry
    # would have to hand-delete.
    root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=root.name + ".preparing-", dir=root.parent))
    try:
        trials = []
        for fixture, filename, language, target, seed in COHORT:
            source = (FIXTURES / fixture / filename).read_bytes()
            for mode in ("baseline", "enriched"):
                trial_id = f"{fixture}-{mode}"
                directory = staging / trial_id
                project = directory / "project"
                config = directory / "config"
                seeds = directory / "seeds"
                for path in (project, config, seeds):
                    path.mkdir(parents=True)
                (project / filename).write_bytes(source)
                (seeds / "initial").write_bytes(bytes.fromhex(seed))
                # The compile database names the trial's final location: the
                # staging directory is renamed to `root` before anyone reads it.
                write_json(project / "compile_commands.json", [{"directory": str((root / trial_id / "project").resolve()), "file": filename,
                    "arguments": ["clang++" if language == "cpp" else "clang", "-c", filename,
                                  "-std=c++17" if language == "cpp" else "-std=c11"]}])
                configuration = ('[fuzzing]\ncollect_function_coverage = true\ndefault_sanitizer = "address"\n'
                                 '[fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 300\n'
                                 f'[clang_analysis]\nimage = "{analyzer_image}"\nmax_context_bytes = 32768\n')
                if mode == "enriched":
                    configuration += "[clang_analysis.exploration]\n"
                (config / "oxfuzz.toml").write_text(configuration)
                trials.append({"id": trial_id, "directory": trial_id, "mode": mode, "fixture": fixture,
                               "source_file": filename, "language": language, "target": f"{filename}::{target}",
                               "source_sha256": digest(source), "seed_sha256": digest(bytes.fromhex(seed)),
                               "config_sha256": digest(configuration.encode())})
        packet = {"schema_version": 1, "identity": identity, "trials": trials}
        packet["id"] = digest(canonical(packet))
        write_json(staging / "comparison.json", packet)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    os.replace(staging, root)
    return packet


def verify_packet(packet, root=None):
    """Refuse modified packets, cross-trial project aliases and changed sources."""
    if set(packet) != {"schema_version", "identity", "trials", "id"} or packet["schema_version"] != 1:
        raise ValueError("invalid comparison packet")
    body = {k: v for k, v in packet.items() if k != "id"}
    if packet["id"] != digest(canonical(body)):
        raise ValueError("comparison packet identity changed")
    if packet["identity"]["max_model_calls"] != 12 or len(packet["trials"]) != 6:
        raise ValueError("comparison budget or cohort changed")
    ids = set()
    for trial in packet["trials"]:
        if trial["id"] in ids or trial["directory"] != trial["id"] or not re.fullmatch(r"[a-z]+-(baseline|enriched)", trial["id"]):
            raise ValueError("duplicate or invalid trial identity")
        ids.add(trial["id"])
        if Path(trial["source_file"]).name != trial["source_file"]:
            raise ValueError("invalid source file")
        if root is not None:
            directory = root / trial["directory"]
            for path, expected in ((directory / "project" / trial["source_file"], trial["source_sha256"]),
                                   (directory / "seeds/initial", trial["seed_sha256"]),
                                   (directory / "config/oxfuzz.toml", trial["config_sha256"])):
                if path.is_symlink() or digest(path.read_bytes()) != expected:
                    raise ValueError("comparison source, seed or config changed")
    return packet


def qualification_command(packet, trial, root, cli):
    """Prepare compile/review with execution denied until exact-source approval."""
    verify_packet(packet, root)
    if trial not in packet["trials"]:
        raise ValueError("unknown trial")
    directory = (root / trial["directory"]).resolve()
    env = {"HF_CONFIG_DIR": str(directory / "config"), "HF_DB_PATH": str(directory / "state.db"),
           "HF_WORKSPACE_DIR": str(directory / "workspace"), "HF_USE_DOCKER": "1", "HF_AUTO_APPROVE": "0",
           "HF_GUARDRAILS": "strict"}
    return [str(cli), "work-order", "qualify", "--submission", "<submission-id>"], env


def report(packet, observations):
    """Compare matching retained measurements; never convert absent metrics to zero."""
    verify_packet(packet)
    by_id = {}
    trials = {trial["id"]: trial for trial in packet["trials"]}
    seen_runs = set()
    for observation in observations:
        trial_id = observation["trial_id"]
        if observation["packet_id"] != packet["id"] or observation["identity"] != packet["identity"]:
            raise ValueError("mixed comparison identity")
        if trial_id not in trials or trial_id in by_id:
            raise ValueError("unknown or duplicate trial")
        if observation.get("trial_identity") != trials[trial_id]:
            raise ValueError("mixed trial identity")
        metrics = observation["metrics"]
        if set(metrics) - set(METRICS):
            raise ValueError("unknown metric")
        if any(metrics.get(key) is not None for key in EXECUTION_METRICS):
            evidence = observation.get("execution_evidence", {})
            required = {"run_id", "harness_id", "source_sha256", "binary_sha256", "review_source_sha256",
                        "review_binary_sha256", "review_approved", "human_approved"}
            if (set(evidence) != required or metrics.get("compiled") is not True
                    or evidence["review_approved"] is not True or evidence["human_approved"] is not True
                    or evidence["source_sha256"] != evidence["review_source_sha256"]
                    or evidence["binary_sha256"] != evidence["review_binary_sha256"]
                    or any(not re.fullmatch(r"[0-9a-f]{64}", evidence[key]) for key in ("source_sha256", "binary_sha256"))):
                raise ValueError("execution metrics require retained service evidence")
            try:
                uuid.UUID(evidence["run_id"])
                uuid.UUID(evidence["harness_id"])
            except (ValueError, TypeError, AttributeError) as error:
                raise ValueError("invalid execution evidence identity") from error
            if evidence["run_id"] in seen_runs:
                raise ValueError("execution evidence reused across independent trials")
            seen_runs.add(evidence["run_id"])
        by_id[trial_id] = observation
    rows = []
    for trial in packet["trials"]:
        observed = by_id.get(trial["id"], {})
        rows.append({"trial_id": trial["id"], "fixture": trial["fixture"], "mode": trial["mode"],
                     "metrics": {key: observed.get("metrics", {}).get(key) for key in METRICS},
                     "evidence": {k: v for k, v in observed.items() if k not in ("metrics", "identity")}})
    return {"schema_version": 1, "packet_id": packet["id"], "cohort_size": len(COHORT),
            "identity": packet["identity"], "trials": rows,
            "interpretation": "Small fixed cohort; measured differences do not establish general effectiveness."}


class CallBudget:
    """Cross-process durable admission, before any upstream request is sent."""
    def __init__(self, database, limit):
        if type(limit) is not int or not 1 <= limit <= 12:
            raise ValueError("call limit must be between 1 and 12")
        self.database = str(database)
        self.limit = limit
        with sqlite3.connect(self.database, timeout=30) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1), maximum INTEGER NOT NULL)")
            connection.execute("INSERT OR IGNORE INTO budget VALUES (1, ?)", (limit,))
            if connection.execute("SELECT maximum FROM budget").fetchone()[0] != limit:
                raise ValueError("retained call limit differs")
            connection.execute("CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY, request_json TEXT NOT NULL)")

    def reserve(self, request):
        with sqlite3.connect(self.database, timeout=30) as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT count(*) FROM calls").fetchone()[0]
            if count >= self.limit:
                raise ValueError("model call budget exhausted")
            call_id = count + 1
            connection.execute("INSERT INTO calls VALUES (?, ?)", (call_id, canonical(request).decode()))
        return call_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--out", required=True, type=Path)
    preparation.add_argument("--sandbox-image", required=True)
    preparation.add_argument("--analyzer-image", required=True)
    preparation.add_argument("--model", required=True)
    preparation.add_argument("--duration-secs", type=int, default=30)
    reporting = commands.add_parser("report")
    reporting.add_argument("--packet", required=True, type=Path)
    reporting.add_argument("--observations", required=True, type=Path)
    reporting.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        value = prepare(args.out, args.sandbox_image, args.analyzer_image, args.model, args.duration_secs)
        print(json.dumps({"packet_id": value["id"], "trials": len(value["trials"])}))
    else:
        value = report(json.loads(args.packet.read_text()), json.loads(args.observations.read_text()))
        write_json(args.out, value)


if __name__ == "__main__":
    main()
