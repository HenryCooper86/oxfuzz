#!/usr/bin/env python3
"""Run a frozen held-out effectiveness cohort and retain per-trial evidence.

Pipeline (every step except `run` is offline):

  fetch   Clone the manifest's pinned targets into <workspace>/targets/<id>
          and check out the exact reviewed revision. `--check` only verifies
          an already-vendored tree (no network).
  freeze  Assemble a cohort JSON from the target manifest, a conditions file,
          the sandbox image digest, and the per-project staged-source digests
          from a calibration run; validate it with
          `scripts.effectiveness_benchmark.validate_cohort` before writing.
  run     Execute every declared trial through `oxfuzz fuzz` (one campaign
          iteration of the frozen duration), one isolated HF_CONFIG_DIR /
          HF_DB_PATH / HF_WORKSPACE_DIR per trial so runs, crashes, and LLM
          cost attribute to exactly one trial. Collect metrics from the
          trial database and `oxfuzz coverage`, export the schema-2 campaign
          evidence manifest and the function-coverage export through a
          runner-managed `oxfuzz serve`, pre-check each manifest against the
          cohort binding, then write results.json + summary.md and, when
          every completed trial's evidence binds, observations.json for
          `scripts.effectiveness_report`.

`run --dry-run` validates the whole setup without Docker, providers, or
network: cohort and manifest validation, CLI availability, config resolution,
vendored-target revisions, per-engine doctor readiness (reported, not
enforced), the full run matrix, and an estimated duration.

Invoke from the repository root as `python3 -m scripts.effectiveness_run`.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from scripts.effectiveness_benchmark import (
    HEX_40, HEX_64, PROJECT_ENGINES, digest, no_duplicate_keys, nonempty,
    nonempty_list, record, unique_ids, validate_cohort,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "docs" / "acceptance" / "held-out-targets.json"
DEFAULT_WORKSPACE = REPO_ROOT / "fuzz_workspace" / "effectiveness"

# Per-trial estimate for target discovery, harness drafting, compiling, smoke
# qualification, and promotion around the frozen campaign duration. An
# estimate for planning only; measured wall-clock is reported per trial.
TRIAL_OVERHEAD_SECS = 300
SERVE_HEALTH_TIMEOUT_SECS = 60
SEED_DOMAIN = "oxfuzz-effectiveness-seed-v1"
SANDBOX_REV_PREFIX = "docker-image-id-sha256:"
NO_PROVIDER = "none"

MANIFEST_PROJECT_FIELDS = (
    "id", "source_url", "revision", "license", "language",
    "selected_functions", "notes",
)
CONDITION_FILE_FIELDS = (
    "id", "engine", "selection_strategy", "provider_family", "model_id",
    "sanitizer", "top_k", "duration_secs", "max_mem_mb", "max_cpus",
    "model_call_budget", "model_cost_budget_usd",
)

# FuzzRunConfig serializes the Sanitizer enum by variant name; the cohort and
# the evidence manifest use the canonical lowercase id.
CONFIG_SANITIZER_IDS = {
    "address": "Address",
    "undefined": "Undefined",
    "none": "None",
    "memory": "Memory",
    "thread": "Thread",
}

COVERAGE_ROW = re.compile(
    r"^\s*(lines|functions|regions):\s+(\d+)/(\d+)\s+\((\d+(?:\.\d+)?)%\)\s*$"
)
API_KEY_ENV = re.compile(r'^\s*api_key_env\s*=\s*"([^"]+)"', re.MULTILINE)


class RunnerError(Exception):
    """An operator-facing failure: the message is the whole report."""


def utc_now():
    return datetime.now(timezone.utc)


def rfc3339(moment):
    return moment.isoformat(timespec="milliseconds")


RFC3339_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$")


def parse_rfc3339(value):
    """Parse the service's RFC 3339 timestamps on Python 3.9 as well: cap the
    fractional second at six digits (fromisoformat's bound there)."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be RFC 3339 text")
    match = RFC3339_LINE.match(value)
    if match is None:
        raise ValueError("timestamp must be RFC 3339 text: {!r}".format(value))
    base, fraction, offset = match.groups()
    fraction = (fraction or "")[:6].ljust(6, "0")
    offset = "+00:00" if offset == "Z" else offset
    return datetime.fromisoformat("{}.{}{}".format(base, fraction, offset))


def read_json(path):
    with path.open(encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=no_duplicate_keys)


def sha256_file(path):
    digest_value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest_value.update(chunk)
    return digest_value.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


# ---------------------------------------------------------------------------
# Target manifest
# ---------------------------------------------------------------------------

def validate_manifest(value):
    """Reject incomplete or mutable target identities in the manifest JSON."""
    record(value, "manifest", ("schema_version", "manifest_id", "notes", "projects"))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("unsupported manifest schema_version")
    nonempty(value["manifest_id"], "manifest_id")
    nonempty(value["notes"], "notes")
    projects = nonempty_list(value["projects"], "projects")
    for project in projects:
        record(project, "project", MANIFEST_PROJECT_FIELDS)
        nonempty(project["id"], "project id")
        if nonempty(project["language"], "project language") not in PROJECT_ENGINES:
            raise ValueError("unsupported project language")
        if not nonempty(project["source_url"], "source_url").startswith("https://"):
            raise ValueError("source_url must use HTTPS")
        digest(project["revision"], "revision", HEX_40)
        nonempty(project["license"], "license")
        nonempty(project["notes"], "project notes")
        functions = nonempty_list(project["selected_functions"], "selected_functions")
        if any(not isinstance(function, str) or not function.strip()
               or function != function.strip() for function in functions):
            raise ValueError("selected_functions must contain symbols")
        if len(functions) != len(set(functions)):
            raise ValueError("duplicate selected_function")
    unique_ids(projects, "project")
    return value


def cross_check(cohort, manifest):
    """Every cohort project and selected function must come from the manifest."""
    projects = {project["id"]: project for project in manifest["projects"]}
    for project in cohort["projects"]:
        known = projects.get(project["id"])
        if known is None:
            raise RunnerError("cohort project '{}' is not in the target manifest".format(
                project["id"]))
        for field in ("source_url", "revision", "license", "language"):
            if known[field] != project[field]:
                raise RunnerError("cohort project '{}' {} differs from the manifest".format(
                    project["id"], field))
        if set(project["selected_functions"]) - set(known["selected_functions"]):
            raise RunnerError(
                "cohort project '{}' selects a function the manifest does not list".format(
                    project["id"]))


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def git(destination, *args):
    result = subprocess.run(
        ["git", "-C", str(destination), *args],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError("git -C {} {} failed: {}".format(
            destination, " ".join(args), result.stderr.strip()))
    return result.stdout.strip()


def checkout_revision(project, destination):
    """Clone and detach at the pinned revision, verifying the checkout."""
    partial = destination.with_name(destination.name + ".partial")
    if partial.exists():
        shutil.rmtree(partial)
    result = subprocess.run(
        ["git", "clone", "--quiet", project["source_url"], str(partial)],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        shutil.rmtree(partial, ignore_errors=True)
        raise RunnerError("clone of {} failed: {}".format(
            project["source_url"], result.stderr.strip()))
    try:
        git(partial, "checkout", "--detach", project["revision"])
        head = git(partial, "rev-parse", "HEAD")
    except RunnerError:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    if head != project["revision"]:
        shutil.rmtree(partial, ignore_errors=True)
        raise RunnerError("{}: checked out {} but the manifest pins {}".format(
            project["id"], head, project["revision"]))
    partial.rename(destination)


def verify_vendored(project, destination):
    """Offline check: the vendored tree exists and sits at the pinned revision."""
    if not destination.is_dir():
        return "missing"
    if not (destination / ".git").exists():
        return "present but not a git checkout"
    try:
        head = git(destination, "rev-parse", "HEAD")
    except RunnerError as error:
        return "unreadable: {}".format(error)
    if head != project["revision"]:
        return "HEAD is {} but the manifest pins {}".format(head, project["revision"])
    return None


def license_note(destination):
    names = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING")
    if any((destination / name).is_file() for name in names):
        return None
    return "no license file at the pinned revision root; confirm the license by review"


def cmd_fetch(args):
    manifest = validate_manifest(read_json(args.manifest))
    targets_dir = args.workspace / "targets"
    failures = 0
    for project in manifest["projects"]:
        destination = targets_dir / project["id"]
        if args.check:
            problem = verify_vendored(project, destination)
            if problem is None:
                note = license_note(destination)
                print("[fetch] {}: vendored at {}{}".format(
                    project["id"], project["revision"],
                    "" if note is None else " ({})".format(note)))
            else:
                failures += 1
                print("[fetch] {}: {}".format(project["id"], problem), file=sys.stderr)
            continue
        if destination.exists():
            problem = verify_vendored(project, destination)
            if problem is None:
                print("[fetch] {}: already vendored at {}".format(
                    project["id"], project["revision"]))
                continue
            raise RunnerError(
                "{}: {} -- remove {} or fix it manually; fetch never overwrites"
                .format(project["id"], problem, destination))
        print("[fetch] {}: cloning {} at {}".format(
            project["id"], project["source_url"], project["revision"]))
        checkout_revision(project, destination)
        note = license_note(destination)
        print("[fetch] {}: vendored{}".format(
            project["id"], "" if note is None else " ({})".format(note)))
    if failures:
        raise RunnerError(
            "{} target(s) are not vendored; run without --check: "
            "python3 -m scripts.effectiveness_run fetch --manifest {} --workspace {}".format(
                failures, args.manifest, args.workspace))
    print("[fetch] {} target(s) ready under {}".format(
        len(manifest["projects"]), targets_dir))


# ---------------------------------------------------------------------------
# freeze
# ---------------------------------------------------------------------------

def derive_trial_seed(cohort_id, trial_id):
    material = "{}\0{}\0{}".format(SEED_DOMAIN, cohort_id, trial_id).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "little")


def slug(text):
    return re.sub(r"[^0-9A-Za-z_.-]+", "_", text)


def repo_head():
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError("git rev-parse HEAD failed: {}".format(result.stderr.strip()))
    return result.stdout.strip()


def parse_source_digests(pairs, manifest):
    digests = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise RunnerError("--source-sha256 expects <project_id>=<64-hex>, got '{}'".format(pair))
        project_id, value = pair.split("=", 1)
        try:
            digest(value, "source_sha256", HEX_64)
        except ValueError as error:
            raise RunnerError(str(error)) from error
        digests[project_id] = value
    known = {project["id"] for project in manifest["projects"]}
    unknown = set(digests) - known
    if unknown:
        raise RunnerError("--source-sha256 names unknown project(s): {}".format(
            ", ".join(sorted(unknown))))
    missing = known - set(digests)
    if missing:
        raise RunnerError(
            "missing --source-sha256 for {}: take each value from a calibration "
            "run's runs.source_rev (see the protocol's calibration step)".format(
                ", ".join(sorted(missing))))
    return digests


def load_conditions(path):
    conditions = read_json(path)
    if not isinstance(conditions, list) or not conditions:
        raise RunnerError("conditions file must hold a nonempty JSON array")
    for condition in conditions:
        try:
            record(condition, "condition", CONDITION_FILE_FIELDS)
        except ValueError as error:
            raise RunnerError(str(error)) from error
    return conditions


def freeze_cohort(manifest, conditions, cohort_id, candidate_commit,
                  source_digests, sandbox_image_sha256, replicates):
    projects = []
    for project in manifest["projects"]:
        projects.append({
            "id": project["id"],
            "source_url": project["source_url"],
            "revision": project["revision"],
            "license": project["license"],
            "source_sha256": source_digests[project["id"]],
            "language": project["language"],
            "selected_functions": project["selected_functions"],
        })
    frozen_conditions = []
    for condition in conditions:
        frozen = dict(condition)
        frozen["sandbox_image_sha256"] = sandbox_image_sha256
        frozen_conditions.append(frozen)
    trials = []
    for project in manifest["projects"]:
        for function in project["selected_functions"]:
            for condition in frozen_conditions:
                for replicate in range(replicates):
                    trial_id = "{}--{}--{}--r{}".format(
                        slug(project["id"]), slug(function),
                        slug(condition["id"]), replicate)
                    trials.append({
                        "id": trial_id,
                        "project_id": project["id"],
                        "condition_id": condition["id"],
                        "selected_function": function,
                        "seed": derive_trial_seed(cohort_id, trial_id),
                    })
    cohort = {
        "schema_version": 1,
        "cohort_id": cohort_id,
        "candidate_commit": candidate_commit,
        "projects": projects,
        "conditions": frozen_conditions,
        "trials": trials,
    }
    try:
        validate_cohort(cohort)
    except ValueError as error:
        raise RunnerError("generated cohort failed validation: {}".format(error)) from error
    return cohort


def cmd_freeze(args):
    manifest = validate_manifest(read_json(args.manifest))
    conditions = load_conditions(args.conditions)
    candidate_commit = args.candidate_commit or repo_head()
    try:
        digest(candidate_commit, "candidate_commit", HEX_40)
        digest(args.sandbox_image_sha256, "sandbox_image_sha256", HEX_64)
    except ValueError as error:
        raise RunnerError(str(error)) from error
    source_digests = parse_source_digests(args.source_sha256, manifest)
    cohort = freeze_cohort(
        manifest, conditions, args.cohort_id, candidate_commit, source_digests,
        args.sandbox_image_sha256, args.replicates)
    write_json(args.output, cohort)
    print("[freeze] wrote {}: {} project(s), {} condition(s), {} trial(s)".format(
        args.output, len(cohort["projects"]), len(cohort["conditions"]),
        len(cohort["trials"])))
    print("[freeze] validate with: python3 scripts/effectiveness_benchmark.py {}".format(
        args.output))


# ---------------------------------------------------------------------------
# CLI discovery and readiness probes (offline-tolerant)
# ---------------------------------------------------------------------------

def resolve_binary(requested):
    candidates = []
    if requested is not None:
        candidates.append(Path(requested))
    elif os.environ.get("OXFUZZ_BIN"):
        candidates.append(Path(os.environ["OXFUZZ_BIN"]))
    else:
        candidates.append(REPO_ROOT / "target" / "release" / "oxfuzz")
        candidates.append(REPO_ROOT / "target" / "debug" / "oxfuzz")
        found = shutil.which("oxfuzz")
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RunnerError(
        "no oxfuzz binary found; pass --oxfuzz, set OXFUZZ_BIN, or build one "
        "(cargo build --release -p hf-cli)")


def binary_version(binary):
    result = subprocess.run([str(binary), "--version"], capture_output=True,
                            text=True, check=False, timeout=30)
    if result.returncode != 0:
        raise RunnerError("`{} --version` failed: {}".format(binary, result.stderr.strip()))
    return result.stdout.strip().splitlines()[0]


def doctor_probe(binary, config_dir, engine, duration_secs, require_provider):
    """Run `oxfuzz doctor` for one condition; the JSON prints before the exit."""
    command = [str(binary), "doctor", "--engine", engine,
               "--duration", "{}s".format(duration_secs), "--json"]
    if require_provider:
        command.append("--require-provider")
    env = os.environ.copy()
    if config_dir is not None:
        env["HF_CONFIG_DIR"] = str(config_dir)
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, env=env, timeout=60)
    except subprocess.TimeoutExpired:
        return {"ready": False, "problems": ["doctor timed out after 60s"]}
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"ready": False,
                "problems": ["doctor produced no JSON: {}".format(result.stderr.strip()[:200])]}
    if not isinstance(report, dict) or type(report.get("ready")) is not bool:
        return {"ready": False, "problems": ["doctor JSON has no ready flag"]}
    problems = report.get("problems")
    return {
        "ready": report["ready"],
        "problems": problems if isinstance(problems, list) else [],
        "provider_configured": report.get("provider_configured"),
    }


def config_key_names(config_dir):
    """Provider key variable NAMES from providers.toml; values are never read."""
    providers = config_dir / "providers.toml"
    if not providers.is_file():
        return None
    return sorted(set(API_KEY_ENV.findall(providers.read_text(encoding="utf-8"))))


def config_mentions_model(config_dir, model_id):
    providers = config_dir / "providers.toml"
    if not providers.is_file():
        return False
    return model_id in providers.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# dry run
# ---------------------------------------------------------------------------

def dry_run(cohort, manifest, binary, args):
    """Validate everything short of Docker, provider calls, and execution."""
    failures = []
    warnings = []

    version = binary_version(binary)
    print("[check] oxfuzz binary: {} ({})".format(binary, version))

    conditions = {condition["id"]: condition for condition in cohort["conditions"]}
    needs_provider = any(
        condition["provider_family"] != NO_PROVIDER for condition in conditions.values())
    config_dir = args.config
    if config_dir is None and os.environ.get("HF_CONFIG_DIR"):
        config_dir = Path(os.environ["HF_CONFIG_DIR"])
    if config_dir is None:
        message = ("no operator config dir; pass --config or set HF_CONFIG_DIR "
                   "(materialize one with `oxfuzz init`)")
        if needs_provider:
            failures.append(message)
        else:
            warnings.append(message)
        key_names = None
    else:
        if not config_dir.is_dir():
            failures.append("config dir {} does not exist".format(config_dir))
        else:
            if needs_provider and not (config_dir / "providers.toml").is_file():
                failures.append(
                    "config dir {} has no providers.toml, but the cohort has "
                    "provider-backed conditions".format(config_dir))
            if not (config_dir / "oxfuzz.toml").is_file():
                warnings.append("config dir {} has no oxfuzz.toml; trials write a "
                                "condition-frozen one and copy providers.toml only".format(
                                    config_dir))
        key_names = config_key_names(config_dir)
    for condition in conditions.values():
        if condition["provider_family"] == NO_PROVIDER:
            continue
        if config_dir is not None and config_dir.is_dir():
            if not config_mentions_model(config_dir, condition["model_id"]):
                warnings.append("providers.toml does not mention model '{}' of "
                                "condition '{}'".format(condition["model_id"],
                                                        condition["id"]))
    if needs_provider and key_names is not None:
        missing = [name for name in key_names if not os.environ.get(name)]
        for name in missing:
            warnings.append("provider key variable {} is not exported in this "
                            "environment".format(name))

    targets_dir = args.workspace / "targets"
    for project in cohort["projects"]:
        problem = verify_vendored(project, targets_dir / project["id"])
        if problem is None:
            print("[check] target {}: vendored at {}".format(project["id"],
                                                             project["revision"]))
        else:
            failures.append("target {}: {} (fetch with: python3 -m "
                            "scripts.effectiveness_run fetch --manifest {} "
                            "--workspace {})".format(project["id"], problem,
                                                     args.manifest, args.workspace))

    probes = {}
    for condition in conditions.values():
        key = (condition["engine"], condition["duration_secs"],
               condition["provider_family"] != NO_PROVIDER)
        probes.setdefault(key, condition["id"])
    for engine, duration_secs, require_provider in sorted(probes):
        probe = doctor_probe(binary, config_dir, engine, duration_secs, require_provider)
        label = "engine={} duration={}s provider={}".format(
            engine, duration_secs, "required" if require_provider else "off")
        if probe["ready"]:
            print("[check] doctor {}: READY".format(label))
        else:
            warnings.append("doctor {}: not ready: {} (fix before running; "
                            "`oxfuzz doctor --build-image` builds a missing "
                            "sandbox image)".format(
                                label, "; ".join(probe["problems"]) or "see doctor output"))

    total_fuzz = 0
    print("[check] run matrix:")
    for trial in cohort["trials"]:
        condition = conditions[trial["condition_id"]]
        total_fuzz += condition["duration_secs"]
        print("  {}: project={} function={} engine={} sanitizer={} "
              "duration={}s seed={} provider={}/{}".format(
                  trial["id"], trial["project_id"], trial["selected_function"],
                  condition["engine"], condition["sanitizer"],
                  condition["duration_secs"], trial["seed"],
                  condition["provider_family"], condition["model_id"]))
    estimate = total_fuzz + TRIAL_OVERHEAD_SECS * len(cohort["trials"])
    print("[check] {} trial(s); fuzz time {}s; estimated total ~{}s "
          "(+{}s/trial harness+smoke allowance)".format(
              len(cohort["trials"]), total_fuzz, estimate, TRIAL_OVERHEAD_SECS))

    for warning in warnings:
        print("[check] WARNING: {}".format(warning), file=sys.stderr)
    for failure in failures:
        print("[check] FAIL: {}".format(failure), file=sys.stderr)
    if failures:
        raise RunnerError("dry run found {} blocking problem(s)".format(len(failures)))
    print("[check] dry run passed ({} warning(s)); rerun without --dry-run to execute"
          .format(len(warnings)))
    return warnings


# ---------------------------------------------------------------------------
# Trial execution
# ---------------------------------------------------------------------------

def trial_environment(trial_dir):
    config_dir = trial_dir / "config"
    db_dir = trial_dir / "db"
    workspace_dir = trial_dir / "workspace"
    for directory in (config_dir, db_dir, workspace_dir):
        directory.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HF_CONFIG_DIR"] = str(config_dir)
    env["HF_DB_PATH"] = str(db_dir / "oxfuzz.db")
    env["HF_WORKSPACE_DIR"] = str(workspace_dir)
    # Unattended execution: the promotion gate is satisfied by environment
    # policy, exactly as documented for headless CLI runs.
    env["HF_AUTO_APPROVE"] = "1"
    return env, config_dir, workspace_dir


def write_trial_config(config_dir, operator_config, condition):
    lines = [
        "[fuzzing]",
        'default_engine = "{}"'.format(condition["engine"]),
        "default_duration_secs = {}".format(condition["duration_secs"]),
        'default_sanitizer = "{}"'.format(condition["sanitizer"]),
        "",
        "[fuzzing.sandbox]",
        "max_mem_mb = {}".format(condition["max_mem_mb"]),
        "max_cpus = {}".format(condition["max_cpus"]),
        "max_duration_secs = {}".format(max(7200, condition["duration_secs"])),
        "",
    ]
    (config_dir / "oxfuzz.toml").write_text("\n".join(lines), encoding="utf-8")
    if operator_config is not None:
        providers = operator_config / "providers.toml"
        if providers.is_file():
            shutil.copyfile(providers, config_dir / "providers.toml")


def fuzz_command(binary, project_dir, project, trial, condition):
    command = [
        str(binary), "fuzz", str(project_dir),
        "--target", trial["selected_function"],
        "--engine", condition["engine"],
        "--lang", project["language"],
        "--duration-secs", str(condition["duration_secs"]),
        "--iterations", "1",
        "--sanitizer", condition["sanitizer"],
        "--json",
    ]
    if condition["provider_family"] == NO_PROVIDER:
        command += ["--ai", "off", "--no-llm-review"]
    else:
        command += ["--ai", "require"]
    return command


def tail_text(text, limit=2000):
    if len(text) <= limit:
        return text
    return "[...truncated {} chars...]\n{}".format(len(text) - limit, text[-limit:])


# ---------------------------------------------------------------------------
# Trial database metrics (read-only)
# ---------------------------------------------------------------------------

def open_trial_db(db_path):
    if not db_path.is_file():
        return None
    uri = "file:{}?mode=ro".format(urllib.parse.quote(str(db_path)))
    return sqlite3.connect(uri, uri=True)


def query_all(connection, sql, name, reasons):
    try:
        return connection.execute(sql).fetchall()
    except sqlite3.Error as error:
        reasons.append("{} unavailable: {}".format(name, error))
        return None


def collect_db_metrics(db_path):
    """Read runs, deduped crashes, and LLM cost from one trial database."""
    reasons = []
    connection = open_trial_db(db_path)
    if connection is None:
        return {"available": False, "reasons": ["trial database was not created"]}
    try:
        runs = query_all(
            connection,
            "SELECT id, run_kind, engine, status, started_at, ended_at, edges, "
            "execs, crash_count, source_rev, sandbox_rev, config_json FROM runs",
            "runs", reasons)
        crashes = query_all(
            connection,
            "SELECT run_id, stack_signature, data_json FROM crashes",
            "crashes", reasons)
        cost = query_all(
            connection,
            "SELECT COUNT(*), COALESCE(SUM(cost_usd), 0.0), "
            "COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0) "
            "FROM diag_observations WHERE obs_type = 'generation'",
            "llm cost", reasons)
    finally:
        connection.close()
    return {
        "available": True,
        "reasons": reasons,
        "runs": runs or [],
        "crashes": crashes or [],
        "cost": cost[0] if cost else None,
    }


def collect_run_metrics(data, condition, source_sha256, image_sha256):
    """Project raw rows into per-run records with cohort conformance checks."""
    campaign_runs = []
    crashes_by_run = {}
    for run_id, stack_signature, data_json in data["crashes"]:
        crashes_by_run.setdefault(run_id, []).append((stack_signature, data_json))
    for (run_id, kind, engine, status, started_at, ended_at, edges, execs,
         crash_count, source_rev, sandbox_rev, config_json) in data["runs"]:
        if kind != "campaign":
            continue
        mismatches = []
        config = {}
        if config_json:
            try:
                config = json.loads(config_json)
            except json.JSONDecodeError:
                mismatches.append("run config_json is not parseable")
        if engine != condition["engine"]:
            mismatches.append("engine {} != {}".format(engine, condition["engine"]))
        duration = config.get("duration")
        duration_secs = (duration or {}).get("secs") if isinstance(duration, dict) else None
        if duration_secs != condition["duration_secs"]:
            mismatches.append("duration {}s != {}s".format(
                duration_secs, condition["duration_secs"]))
        if config.get("max_mem_mb") != condition["max_mem_mb"]:
            mismatches.append("max_mem_mb {} != {}".format(
                config.get("max_mem_mb"), condition["max_mem_mb"]))
        if config.get("max_cpus") != condition["max_cpus"]:
            mismatches.append("max_cpus {} != {}".format(
                config.get("max_cpus"), condition["max_cpus"]))
        sanitizer = CONFIG_SANITIZER_IDS.get(condition["sanitizer"])
        if config.get("sanitizer") != sanitizer:
            mismatches.append("sanitizer {} != {}".format(
                config.get("sanitizer"), sanitizer))
        if source_rev != source_sha256:
            mismatches.append("source_rev does not equal the frozen source_sha256")
        if sandbox_rev != SANDBOX_REV_PREFIX + image_sha256:
            mismatches.append("sandbox_rev does not carry the frozen image digest")
        campaign_runs.append({
            "run_id": run_id,
            "engine": engine,
            "status": status,
            "started_at": started_at,
            "ended_at": ended_at,
            "edges": edges,
            "execs_per_sec": execs,
            "crashes": crash_count,
            "seed": config.get("seed"),
            "conformance": mismatches,
        })
    signatures = set()
    crash_files = []
    for run in campaign_runs:
        for stack_signature, data_json in crashes_by_run.get(run["run_id"], []):
            if stack_signature:
                signatures.add(stack_signature)
            try:
                input_path = json.loads(data_json).get("input_path")
            except json.JSONDecodeError:
                input_path = None
            if input_path:
                crash_files.append((run, input_path))
    return campaign_runs, signatures, crash_files


def time_to_first_crash(crash_files):
    """Seconds from campaign start to the earliest retained crash artifact.

    The timestamp is the crash input's file mtime minus the run's persisted
    start, an upper bound on true discovery time: ingestion can copy the file
    seconds after the engine wrote it.
    """
    best = None
    for run, input_path in crash_files:
        try:
            started = parse_rfc3339(run["started_at"]).timestamp()
            mtime = Path(input_path).stat().st_mtime
        except (OSError, ValueError):
            continue
        candidate = mtime - started
        if candidate >= 0 and (best is None or candidate < best):
            best = candidate
    return best


def collect_coverage(binary, env, project_dir, target, log_path):
    """`oxfuzz coverage` text; absent coverage stays unavailable, never zero."""
    result = subprocess.run(
        [str(binary), "coverage", str(project_dir), "--target", target],
        capture_output=True, text=True, check=False, env=env, timeout=300)
    log_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode != 0 or "No coverage available" in result.stderr:
        return None
    found = {}
    for line in result.stdout.splitlines():
        match = COVERAGE_ROW.match(line)
        if match:
            found[match.group(1)] = {
                "covered": int(match.group(2)),
                "total": int(match.group(3)),
                "percent": float(match.group(4)),
            }
    if not found:
        return None
    return {
        "lines": found.get("lines"),
        "functions": found.get("functions"),
        "regions": found.get("regions"),
    }


# ---------------------------------------------------------------------------
# Evidence export through a runner-managed `oxfuzz serve`
# ---------------------------------------------------------------------------

def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def http_json(url, token, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="GET" if data is None else "POST")
    request.add_header("Authorization", "Bearer {}".format(token))
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")[:400]
        raise RunnerError("GET/POST {} failed: HTTP {}: {}".format(url, error.code, body))
    except urllib.error.URLError as error:
        raise RunnerError("GET/POST {} failed: {}".format(url, error.reason))


def wait_for_health(base_url, process, deadline):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RunnerError("oxfuzz serve exited early with status {}".format(
                process.returncode))
        try:
            with urllib.request.urlopen(base_url + "/health", timeout=5) as response:
                if response.status == 200:
                    return
        except urllib.error.URLError:
            pass
        time.sleep(0.25)
    raise RunnerError("oxfuzz serve did not become healthy within {}s".format(
        SERVE_HEALTH_TIMEOUT_SECS))


def stop_serve(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def export_trial_evidence(binary, trial_env, approved_root, campaign_runs,
                          model_cost_usd, compute_rate, evidence_dir, serve_log):
    """Export schema-2 campaign manifests and function coverage via REST.

    The serve process shares the trial's config, database, and workspace so
    the manifests bind the exact retained run. Read-only endpoints only.
    """
    if not campaign_runs:
        return None, "no campaign run was recorded"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    port = free_port()
    token = secrets.token_hex(16)
    env = trial_env.copy()
    env["HF_WEB_TOKEN"] = token
    env["HF_WEB_PROJECT_ROOTS"] = str(approved_root)
    base_url = "http://127.0.0.1:{}".format(port)
    with serve_log.open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "serve", "--host", "127.0.0.1", "--port", str(port)],
            env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_for_health(base_url, process,
                        time.monotonic() + SERVE_HEALTH_TIMEOUT_SECS)
        manifests = {}
        functions = {}
        for run in campaign_runs:
            run_id = run["run_id"]
            _, manifest = http_json(
                base_url + "/campaign/evidence", token, {
                    "run_id": run_id,
                    "compute_usd_per_hour": compute_rate,
                    "model_cost_usd": model_cost_usd,
                })
            manifest_path = evidence_dir / "campaign-manifest-{}.json".format(run_id)
            write_json(manifest_path, manifest)
            manifests[run_id] = manifest_path
            _, coverage = http_json(
                base_url + "/runs/{}/function-coverage".format(run_id), token)
            if isinstance(coverage, dict) and coverage.get("status") == "available":
                coverage_path = evidence_dir / "function-coverage-{}.json".format(run_id)
                write_json(coverage_path, coverage)
                functions[run_id] = coverage_path
        return {"manifests": manifests, "function_coverage": functions}, None
    finally:
        stop_serve(process)


def binding_mismatches(manifest, trial, project, condition, outcome):
    """Pre-check the exported manifest against the cohort binding exactly as
    `scripts.effectiveness_report.validate_manifest` would."""
    problems = []
    if not isinstance(manifest, dict) or not isinstance(manifest.get("body"), dict):
        return ["campaign manifest needs a body"]
    body = manifest["body"]
    if body.get("schema_version") != 2:
        problems.append("manifest schema_version is not 2")
    expected = {
        "target": trial["selected_function"],
        "engine": condition["engine"],
        "source_revision": project["source_sha256"],
        "sandbox_image_sha256": condition["sandbox_image_sha256"],
        "status": "done" if outcome == "completed" else outcome,
    }
    for field, wanted in expected.items():
        if body.get(field) != wanted:
            problems.append("manifest {} is {!r}, cohort wants {!r}".format(
                field, body.get(field), wanted))
    run_config = body.get("run_config")
    if not isinstance(run_config, dict):
        problems.append("manifest run_config is missing")
    else:
        for field in ("duration_secs", "max_mem_mb", "max_cpus"):
            wanted = condition[field]
            if type(run_config.get(field)) is not int or run_config[field] != wanted:
                problems.append("manifest run_config.{} is {!r}, cohort wants {!r}".format(
                    field, run_config.get(field), wanted))
        seed = run_config.get("seed")
        if type(seed) is not int or seed != trial["seed"]:
            problems.append(
                "manifest run_config.seed is {!r} but the frozen trial seed is {!r}; "
                "the CLI derives seeds from run ids and cannot pin a frozen seed "
                "yet (see the protocol's known gaps)".format(seed, trial["seed"]))
        if run_config.get("sanitizer") != condition["sanitizer"]:
            problems.append("manifest sanitizer is {!r}, cohort wants {!r}".format(
                run_config.get("sanitizer"), condition["sanitizer"]))
    coverage = body.get("coverage")
    if not isinstance(coverage, dict) or type(coverage.get("edges")) is not int \
            or coverage["edges"] < 0:
        problems.append("manifest coverage.edges must be a non-negative integer")
    for field in ("binary_sha256",):
        try:
            digest(body.get(field), field, HEX_64)
        except ValueError as error:
            problems.append(str(error))
    try:
        digest(manifest.get("manifest_sha256"), "manifest_sha256", HEX_64)
    except ValueError as error:
        problems.append(str(error))
    cost = body.get("cost")
    if not isinstance(cost, dict):
        problems.append("manifest cost is missing")
    else:
        model_cost = cost.get("model_cost_usd")
        if type(model_cost) not in (int, float) or model_cost < 0:
            problems.append("manifest model_cost_usd must be non-negative")
        elif model_cost > condition["model_cost_budget_usd"]:
            problems.append("manifest model cost {} exceeds the frozen budget {}".format(
                model_cost, condition["model_cost_budget_usd"]))
    return problems


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def artifact_reference(root, path):
    return {
        "path": str(path.relative_to(root)),
        "sha256": sha256_file(path),
    }


def observation_entry(trial_record):
    return {
        "id": trial_record["id"],
        "outcome": trial_record["outcome"],
        "reason": trial_record["reason"],
        "campaign_manifest": trial_record["observation_manifest"],
        "function_coverage": trial_record["observation_function_coverage"],
    }


def observations_eligible(trial_records):
    """The report reader needs a bound manifest for every completed trial."""
    for record in trial_records:
        if record["outcome"] == "completed" and record["observation_manifest"] is None:
            return record["id"]
    return None


def render_summary_markdown(cohort, results):
    conditions = {condition["id"]: condition for condition in cohort["conditions"]}
    lines = [
        "# Held-out effectiveness baseline -- {}".format(cohort["cohort_id"]),
        "",
        "Status: **{}**.".format(results["record_status"]),
        "",
        "Generated by `scripts.effectiveness_run` on {} from candidate commit `{}`."
        .format(results["generated_at"], cohort["candidate_commit"]),
        "",
        "## Claim and outcome",
        "",
        "Operation: held-out held-target effectiveness baseline (discover -> harness "
        "-> smoke -> human-approved promote -> one bounded campaign iteration per "
        "trial). A clean bounded run does not prove the absence of vulnerabilities.",
        "",
        "| Trial | Project | Function | Engine | Outcome | TTFC (s) | Unique crashes | Peak edges | Lines | Regions | Wall (s) | LLM cost (USD) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for trial in results["trials"]:
        coverage = trial["coverage"]
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            trial["id"], trial["project_id"], trial["selected_function"],
            conditions[trial["condition_id"]]["engine"], trial["outcome"],
            format_optional(trial["time_to_first_crash_secs"], "{:.1f}"),
            format_optional(trial["unique_crashes"], "{}"),
            format_optional(trial["peak_edges"], "{}"),
            format_coverage(coverage, "lines"),
            format_coverage(coverage, "regions"),
            "{:.1f}".format(trial["wall_clock_secs"]),
            format_optional(
                None if trial["llm"] is None else trial["llm"]["cost_usd"], "{:.4f}"),
        ))
    lines += [
        "",
        "## Source identity",
        "",
        "| Project | Source | Pinned revision | Staged-source SHA-256 | License |",
        "| --- | --- | --- | --- | --- |",
    ]
    for project in cohort["projects"]:
        lines.append("| {} | {} | `{}` | `{}` | {} |".format(
            project["id"], project["source_url"], project["revision"],
            project["source_sha256"], project["license"]))
    lines += [
        "",
        "## Runtime identity",
        "",
        "- oxfuzz: {} (`{}`)".format(results["oxfuzz"]["version"],
                                     results["oxfuzz"]["binary"]),
        "- host: {} {}, Python {}".format(
            results["host"]["os"], results["host"]["arch"], results["host"]["python"]),
        "- sandbox image digest: `" + cohort["conditions"][0]["sandbox_image_sha256"] + "`",
        "- provider: " + ", ".join(sorted({
            "{}/{}".format(condition["provider_family"], condition["model_id"])
            for condition in cohort["conditions"]
        })),
        "",
        "## Execution limits",
        "",
        "| Condition | Duration (s) | Mem (MB) | CPUs | Model calls | Model USD | Trials |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for condition in cohort["conditions"]:
        count = sum(t["condition_id"] == condition["id"] for t in cohort["trials"])
        lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            condition["id"], condition["duration_secs"], condition["max_mem_mb"],
            condition["max_cpus"], condition["model_call_budget"],
            condition["model_cost_budget_usd"], count))
    lines += [
        "",
        "Approval: unattended runs satisfied the promotion gate with "
        "`HF_AUTO_APPROVE=1`; every decision is in `oxfuzz policy decisions` of "
        "each trial's retained database.",
        "",
        "## Evidence",
        "",
        "- `results.json` -- the machine-readable record of this table.",
        "- `observations.json` -- {}".format(results["observations_note"]),
        "- per-trial directories: `trials/<id>/` with the CLI transcript, the "
        "trial database, the trial workspace, and exported evidence.",
        "",
        "## Review",
        "",
        "- Operator / reviewer: (fill in at review time)",
        "- Limitations:",
        "  - Trial seeds are frozen in the cohort, but the CLI derives each run's "
        "seed from its random run id (`hf_engine::seed::derive_run_seed`); a "
        "manifest can therefore not bind the frozen seed today. Reproduce a run "
        "with `oxfuzz run . --replay <run-id>`, which re-executes the recorded "
        "seed exactly.",
        "  - Time-to-first-crash is the crash artifact's file timestamp minus "
        "the persisted run start -- an upper bound on true discovery time.",
        "  - honggfuzz reports no edge count; edge coverage stays unavailable "
        "for honggfuzz conditions rather than reading as zero.",
        "  - The LLM smoke-review bypass (`--no-llm-review`) is used for "
        "conditions whose provider family is `none` and is recorded per trial.",
    ]
    return "\n".join(lines) + "\n"


def format_optional(value, pattern):
    return "n/a" if value is None else pattern.format(value)


def format_coverage(coverage, section):
    if coverage is None or coverage.get(section) is None:
        return "n/a"
    entry = coverage[section]
    return "{}/{} ({:.1f}%)".format(entry["covered"], entry["total"], entry["percent"])


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def run_trial(binary, args, trial, condition, project):
    trial_dir = args.out / "trials" / trial["id"]
    log_dir = trial_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    env, config_dir, _workspace_dir = trial_environment(trial_dir)
    write_trial_config(config_dir, args.config, condition)

    record_data = {
        "id": trial["id"],
        "project_id": trial["project_id"],
        "condition_id": trial["condition_id"],
        "selected_function": trial["selected_function"],
        "outcome": "unavailable",
        "reason": None,
        "limitations": [],
        "wall_clock_secs": 0.0,
        "runs_executed": 0,
        "campaign_runs": [],
        "unique_crashes": None,
        "time_to_first_crash_secs": None,
        "peak_edges": None,
        "coverage": None,
        "llm": None,
        "budgets": {
            "model_call_budget": condition["model_call_budget"],
            "model_calls_exceeded": None,
            "model_cost_budget_usd": condition["model_cost_budget_usd"],
            "model_cost_exceeded": None,
        },
        "evidence": None,
        "observation_manifest": None,
        "observation_function_coverage": None,
        "logs": {
            "fuzz_stdout": str(log_dir / "fuzz.stdout.log"),
            "fuzz_stderr": str(log_dir / "fuzz.stderr.log"),
        },
    }

    project_dir = args.workspace / "targets" / project["id"]
    command = fuzz_command(binary, project_dir, project, trial, condition)
    print("[run] {}: {} on {} ({}) for {}s".format(
        trial["id"], trial["selected_function"], project["id"],
        condition["engine"], condition["duration_secs"]))
    started = time.monotonic()
    timeout = condition["duration_secs"] + args.trial_timeout_grace_secs
    exit_code = None
    outcome_json = None
    stderr_text = ""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False, env=env,
            timeout=timeout)
        (log_dir / "fuzz.stdout.log").write_text(completed.stdout, encoding="utf-8")
        (log_dir / "fuzz.stderr.log").write_text(completed.stderr, encoding="utf-8")
        exit_code = completed.returncode
        stderr_text = completed.stderr
        if completed.returncode == 0:
            try:
                outcome_json = json.loads(completed.stdout)
            except json.JSONDecodeError:
                record_data["limitations"].append(
                    "fuzz --json output did not parse; see the stdout log")
    except subprocess.TimeoutExpired as expired:
        # Swallowed: partial output is diagnostic-only; the timeout itself is
        # the recorded outcome and nothing else can reach this text.
        for name, text in (("fuzz.stdout.log", expired.stdout),
                           ("fuzz.stderr.log", expired.stderr)):
            if text:
                if isinstance(text, bytes):
                    text = text.decode("utf-8", "replace")
                (log_dir / name).write_text(text, encoding="utf-8")
        record_data["outcome"] = "failed"
        record_data["reason"] = "runner timeout after {}s".format(timeout)
        record_data["wall_clock_secs"] = time.monotonic() - started
        return record_data
    except OSError as error:
        record_data["outcome"] = "failed"
        record_data["reason"] = "could not launch the CLI: {}".format(error)
        record_data["wall_clock_secs"] = time.monotonic() - started
        return record_data
    record_data["wall_clock_secs"] = time.monotonic() - started

    data = collect_db_metrics(trial_dir / "db" / "oxfuzz.db")
    record_data["limitations"].extend(data["reasons"])
    model_cost = None
    if data["available"]:
        campaign_runs, signatures, crash_files = collect_run_metrics(
            data, condition, project["source_sha256"],
            condition["sandbox_image_sha256"])
        record_data["campaign_runs"] = campaign_runs
        record_data["runs_executed"] = len(campaign_runs)
        # Zero campaign runs means nothing was measured: crash and timing
        # fields stay unavailable rather than reading as a false zero.
        if campaign_runs:
            record_data["unique_crashes"] = len(signatures)
            record_data["time_to_first_crash_secs"] = time_to_first_crash(crash_files)
        edges = [run["edges"] for run in campaign_runs if run["edges"] is not None]
        record_data["peak_edges"] = max(edges) if edges else None
        if not campaign_runs:
            record_data["limitations"].append("no campaign run was recorded")
        if data["cost"] is not None:
            calls, cost_usd, input_tokens, output_tokens = data["cost"]
            model_cost = cost_usd
            record_data["llm"] = {
                "calls": calls,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost_usd,
            }
            record_data["budgets"]["model_calls_exceeded"] = (
                calls > condition["model_call_budget"])
            record_data["budgets"]["model_cost_exceeded"] = (
                cost_usd > condition["model_cost_budget_usd"])

    if exit_code == 0 and outcome_json is not None:
        record_data["outcome"] = "completed"
    elif record_data["outcome"] == "unavailable":
        record_data["outcome"] = "failed"
        record_data["reason"] = "oxfuzz fuzz exited with status {}: {}".format(
            exit_code, tail_text(stderr_text.strip(), 400))

    record_data["coverage"] = collect_coverage(
        binary, env, project_dir, trial["selected_function"],
        log_dir / "coverage.log")
    if record_data["coverage"] is None:
        record_data["limitations"].append("line/function/region coverage unavailable")

    can_export = (not args.no_evidence_export and record_data["campaign_runs"]
                  and model_cost is not None)
    if model_cost is None and record_data["campaign_runs"]:
        record_data["limitations"].append(
            "model cost is unknown, so no evidence manifest is exported: binding "
            "0.0 would fabricate a zero")
    if can_export:
        try:
            exported, problem = export_trial_evidence(
                binary, env, args.workspace / "targets", record_data["campaign_runs"],
                model_cost, args.compute_usd_per_hour,
                args.out / "evidence" / trial["id"], log_dir / "serve.log")
        except RunnerError as error:
            exported, problem = None, str(error)
        if exported is not None:
            bind_trial_evidence(args.out, record_data, exported, trial, project,
                                condition)
        elif problem:
            record_data["limitations"].append("evidence export failed: {}".format(problem))
    elif args.no_evidence_export:
        record_data["limitations"].append("evidence export disabled (--no-evidence-export)")
    return record_data


def bind_trial_evidence(out_dir, record_data, exported, trial, project, condition):
    evidence = {"manifests": {}, "function_coverage": {}, "binding": {}}
    for run_id, path in exported["manifests"].items():
        manifest = json.loads(path.read_text(encoding="utf-8"))
        problems = binding_mismatches(manifest, trial, project, condition,
                                      record_data["outcome"])
        reference = artifact_reference(out_dir, path)
        evidence["manifests"][run_id] = reference
        evidence["binding"][run_id] = problems
        coverage_path = exported["function_coverage"].get(run_id)
        if coverage_path is not None:
            evidence["function_coverage"][run_id] = artifact_reference(
                out_dir, coverage_path)
        if problems:
            record_data["limitations"].append(
                "campaign manifest does not bind the cohort: {}".format("; ".join(problems)))
        elif record_data["outcome"] in ("completed", "failed", "cancelled"):
            record_data["observation_manifest"] = reference
            if coverage_path is not None:
                record_data["observation_function_coverage"] = evidence[
                    "function_coverage"][run_id]
    record_data["evidence"] = evidence


def cmd_run(args):
    cohort = validate_cohort(read_json(args.cohort))
    manifest = validate_manifest(read_json(args.manifest))
    cross_check(cohort, manifest)
    binary = resolve_binary(args.oxfuzz)
    if args.dry_run:
        dry_run(cohort, manifest, binary, args)
        return
    args.out.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    # The cohort's project entries are the run-time truth (they carry the frozen
    # staged-source digest); the manifest covers fetching and cross-checking.
    projects = {p["id"]: p for p in cohort["projects"]}
    conditions = {c["id"]: c for c in cohort["conditions"]}
    trial_records = []
    for trial in cohort["trials"]:
        if args.only_trial and trial["id"] not in args.only_trial:
            continue
        record_data = run_trial(
            binary, args, trial, conditions[trial["condition_id"]],
            projects[trial["project_id"]])
        trial_records.append(record_data)
        print("[run] {}: {} ({}s wall, {} campaign run(s), {} unique crash(es))".format(
            record_data["id"], record_data["outcome"],
            round(record_data["wall_clock_secs"], 1), record_data["runs_executed"],
            format_optional(record_data["unique_crashes"], "{}")))

    skipped = {t["id"] for t in cohort["trials"]} - {t["id"] for t in trial_records}
    blocker = observations_eligible(trial_records)
    observations_note = "not emitted (--only-trial filtered the matrix)"
    if not skipped and blocker is None:
        observations = {
            "schema_version": 1,
            "cohort_id": cohort["cohort_id"],
            "trials": [observation_entry(t) for t in trial_records],
        }
        write_json(args.out / "observations.json", observations)
        observations_note = ("written; generate the aggregate report with "
                             "`python3 -m scripts.effectiveness_report {} {}`".format(
                                 args.cohort, args.out / "observations.json"))
    elif not skipped:
        observations_note = (
            "not emitted: trial {} completed without cohort-bound evidence, and "
            "the report reader requires one bound campaign manifest per completed "
            "trial (see results.json limitations)".format(blocker))

    finished = utc_now()
    outcomes = {}
    for record_data in trial_records:
        outcomes[record_data["outcome"]] = outcomes.get(record_data["outcome"], 0) + 1
    results = {
        "schema_version": 1,
        "kind": "oxfuzz-effectiveness-results",
        "cohort_id": cohort["cohort_id"],
        "candidate_commit": cohort["candidate_commit"],
        "generated_at": rfc3339(finished),
        "started_at": rfc3339(started),
        "wall_clock_secs": (finished - started).total_seconds(),
        "record_status": "unreviewed measurement record; not an approved baseline",
        "host": {
            "os": platform.system(),
            "arch": platform.machine(),
            "python": platform.python_version(),
        },
        "oxfuzz": {"binary": str(binary), "version": binary_version(binary)},
        "outcomes": outcomes,
        "observations_note": observations_note,
        "trials": [
            {key: value for key, value in record_data.items()
             if key not in ("observation_manifest", "observation_function_coverage")}
            for record_data in trial_records
        ],
    }
    write_json(args.out / "results.json", results)
    (args.out / "summary.md").write_text(
        render_summary_markdown(cohort, results), encoding="utf-8")
    print("[run] wrote {} and {}".format(
        args.out / "results.json", args.out / "summary.md"))
    print("[run] observations.json: {}".format(observations_note))


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="subcommand", required=True)

    fetch = subcommands.add_parser("fetch", help="vendor the pinned targets")
    fetch.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    fetch.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    fetch.add_argument("--check", action="store_true",
                       help="verify vendored targets offline; never clone")
    fetch.set_defaults(handler=cmd_fetch)

    freeze = subcommands.add_parser("freeze", help="assemble and validate a cohort")
    freeze.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    freeze.add_argument("--conditions", type=Path, required=True,
                        help="JSON array of condition objects (sandbox image excluded)")
    freeze.add_argument("--cohort-id", required=True)
    freeze.add_argument("--candidate-commit", default=None,
                        help="40-hex oxfuzz commit; defaults to this checkout's HEAD")
    freeze.add_argument("--sandbox-image-sha256", required=True,
                        help="64-hex docker image id of the built sandbox image")
    freeze.add_argument("--source-sha256", action="append", default=None,
                        metavar="PROJECT=DIGEST",
                        help="staged-source oxfuzz-run-source-v1 digest per project; "
                             "repeat for every project (from a calibration run)")
    freeze.add_argument("--replicates", type=int, default=1,
                        help="trials per project/function/condition cell")
    freeze.add_argument("--output", type=Path, required=True)
    freeze.set_defaults(handler=cmd_freeze)

    run = subcommands.add_parser("run", help="execute the cohort and collect metrics")
    run.add_argument("--cohort", type=Path, required=True)
    run.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    run.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--oxfuzz", default=None, help="path to the oxfuzz binary")
    run.add_argument("--config", type=Path, default=None,
                     help="operator config dir holding providers.toml "
                          "(defaults to HF_CONFIG_DIR)")
    run.add_argument("--compute-usd-per-hour", type=float, default=0.0,
                     help="operator compute price bound into evidence manifests")
    run.add_argument("--trial-timeout-grace-secs", type=int, default=900,
                     help="runner kill margin on top of the frozen trial duration")
    run.add_argument("--no-evidence-export", action="store_true",
                     help="skip the serve-based campaign-evidence export")
    run.add_argument("--only-trial", action="append", default=None,
                     help="run only the named trial id (repeatable)")
    run.add_argument("--dry-run", action="store_true",
                     help="validate everything and print the matrix without Docker, "
                          "providers, or execution")
    run.set_defaults(handler=cmd_run)
    return parser


def main():
    args = build_parser().parse_args()
    if getattr(args, "replicates", 1) < 1:
        print("error: --replicates must be at least 1", file=sys.stderr)
        return 2
    try:
        args.handler(args)
    except (RunnerError, ValueError, OSError) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
