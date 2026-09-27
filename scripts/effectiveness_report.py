#!/usr/bin/env python3
"""Summarize frozen trials from hashed service evidence exports."""

import argparse
import hashlib
import json
import math
import statistics
import uuid
from pathlib import Path

from scripts.effectiveness_benchmark import (
    HEX_64, digest, no_duplicate_keys, nonempty, record, validate_cohort,
)


MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
OUTCOMES = {"completed", "failed", "cancelled", "unavailable"}


def unavailable(reason):
    return {"status": "unavailable", "reason": reason}


def available(value):
    return {"status": "available", "value": value}


def read_limited(path, name):
    with path.open("rb") as source:
        data = source.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("{} exceeds 16 MiB".format(name))
    return data


def read_json(path):
    data = read_limited(path, "evidence file")
    return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)


def read_artifact(root, reference):
    record(reference, "artifact", ("path", "sha256"))
    name = nonempty(reference["path"], "artifact path")
    digest(reference["sha256"], "artifact sha256", HEX_64)
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must stay below the observation directory")
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("artifact path cannot contain a symlink")
    if not path.is_file():
        raise ValueError("artifact must be a regular file")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("artifact path must stay below the observation directory")
    data = read_limited(path, "artifact")
    if hashlib.sha256(data).hexdigest() != reference["sha256"]:
        raise ValueError("artifact sha256 mismatch")
    return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)


def measured_number(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("{} must be finite and non-negative".format(name))
    return value


def checked_run_id(value):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("invalid run_id") from error


def validate_manifest(manifest, trial, project, condition, outcome):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("body"), dict):
        raise ValueError("campaign_manifest needs a body")
    digest(manifest.get("manifest_sha256"), "manifest_sha256", HEX_64)
    body = manifest["body"]
    if body.get("schema_version") != 2:
        raise ValueError("unsupported campaign manifest schema_version")
    run_id = checked_run_id(body.get("run_id"))
    expected = {
        "target": trial["selected_function"],
        "engine": condition["engine"],
        "source_revision": project["source_sha256"],
        "sandbox_image_sha256": condition["sandbox_image_sha256"],
        "status": "done" if outcome == "completed" else outcome,
    }
    for field, wanted in expected.items():
        if body.get(field) != wanted:
            raise ValueError("campaign manifest {} differs from cohort".format(field))
    run_config = body.get("run_config")
    if not isinstance(run_config, dict):
        raise ValueError("campaign manifest run_config is missing")
    for field in ("duration_secs", "max_mem_mb", "max_cpus", "seed"):
        wanted = trial["seed"] if field == "seed" else condition[field]
        if type(run_config.get(field)) is not int or run_config[field] != wanted:
            raise ValueError("campaign manifest {} differs from cohort".format(field))
    if run_config.get("sanitizer") != condition["sanitizer"]:
        raise ValueError("campaign manifest sanitizer differs from cohort")
    coverage = body.get("coverage")
    cost = body.get("cost")
    if not isinstance(coverage, dict) or not isinstance(cost, dict):
        raise ValueError("campaign manifest coverage or cost is missing")
    edges = coverage.get("edges")
    if type(edges) is not int or edges < 0:
        raise ValueError("campaign manifest edges must be non-negative")
    compute_cost = measured_number(cost.get("compute_cost_usd"), "compute_cost_usd")
    model_cost = measured_number(cost.get("model_cost_usd"), "model_cost_usd")
    if model_cost > condition["model_cost_budget_usd"]:
        raise ValueError("model cost exceeds frozen budget")
    binary_sha256 = body.get("binary_sha256")
    digest(binary_sha256, "binary_sha256", HEX_64)
    total_cost = compute_cost + model_cost
    if not math.isfinite(total_cost):
        raise ValueError("total_cost_usd must be finite")
    return run_id, binary_sha256, edges, total_cost


def function_entry(evidence, run_id, binary_sha256, symbol):
    if evidence is None:
        return unavailable("no exact function coverage export")
    if not isinstance(evidence, dict) or evidence.get("run_id") != run_id:
        raise ValueError("function coverage run_id differs from campaign")
    if evidence.get("status") == "unavailable":
        return unavailable(nonempty(evidence.get("reason"), "function coverage reason"))
    if evidence.get("status") != "available":
        raise ValueError("unsupported function coverage status")
    if evidence.get("binary_sha256") != binary_sha256:
        raise ValueError("function coverage binary_sha256 differs from campaign")
    digest(evidence.get("export_sha256"), "export_sha256", HEX_64)
    functions = evidence.get("functions")
    if not isinstance(functions, list):
        raise ValueError("function coverage functions are missing")
    matches = []
    for function in functions:
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise ValueError("invalid function measurement")
        count = function.get("count")
        if (not isinstance(count, str) or not count.isascii() or not count.isdigit()
                or len(count) > 20 or int(count) > 2**64 - 1):
            raise ValueError("invalid function counter")
        if function["name"] == symbol:
            matches.append(int(count))
    if not matches:
        return unavailable("selected function is absent from the exact export")
    if any(count > 0 for count in matches):
        return {"status": "observed"}
    return {"status": "not_observed", "limitation": "zero counters do not prove non-entry"}


def metric_distribution(trials, field):
    samples = sorted(trial[field]["value"] for trial in trials
                     if trial[field]["status"] == "available")
    return {
        "samples": samples,
        "unavailable": len(trials) - len(samples),
        "median": statistics.median(samples) if samples else None,
    }


def summarize_members(members):
    return {
        "declared_trials": len(members),
        "outcomes": {name: sum(trial["outcome"] == name for trial in members)
                     for name in sorted(OUTCOMES)},
        "peak_edges": metric_distribution(members, "peak_edges"),
        "total_cost_usd": metric_distribution(members, "total_cost_usd"),
    }


def assemble_report(cohort, observations, root):
    """Join every declared trial with one outcome and exact hashed evidence."""
    validate_cohort(cohort)
    record(observations, "observations", ("schema_version", "cohort_id", "trials"))
    if observations["schema_version"] != 1 or observations["cohort_id"] != cohort["cohort_id"]:
        raise ValueError("observation cohort identity mismatch")
    if not isinstance(observations["trials"], list):
        raise ValueError("observation trials must be a list")
    declared = {trial["id"]: trial for trial in cohort["trials"]}
    entries = {}
    for entry in observations["trials"]:
        record(entry, "trial outcome", (
            "id", "outcome", "reason", "campaign_manifest", "function_coverage",
        ))
        trial_id = nonempty(entry["id"], "trial id")
        if trial_id in entries:
            raise ValueError("duplicate trial outcome: {}".format(trial_id))
        if trial_id not in declared:
            raise ValueError("unknown trial outcome: {}".format(trial_id))
        if nonempty(entry["outcome"], "outcome") not in OUTCOMES:
            raise ValueError("unsupported trial outcome")
        if entry["outcome"] != "completed":
            nonempty(entry["reason"], "trial reason")
        elif entry["reason"] is not None:
            raise ValueError("completed trial cannot have a failure reason")
        entries[trial_id] = entry
    if set(entries) != set(declared):
        raise ValueError("every declared trial needs one outcome")

    projects = {item["id"]: item for item in cohort["projects"]}
    conditions = {item["id"]: item for item in cohort["conditions"]}
    outcomes = {name: 0 for name in sorted(OUTCOMES)}
    trials = []
    for trial in cohort["trials"]:
        entry = entries[trial["id"]]
        outcome = entry["outcome"]
        outcomes[outcome] += 1
        result = {
            "id": trial["id"],
            "project_id": trial["project_id"],
            "condition_id": trial["condition_id"],
            "outcome": outcome,
            "reason": entry["reason"],
            "peak_edges": unavailable("no terminal campaign manifest"),
            "total_cost_usd": unavailable("no terminal campaign manifest"),
            "selected_function_entry": unavailable("no exact function coverage export"),
        }
        reference = entry["campaign_manifest"]
        if reference is None:
            if outcome == "completed" or entry["function_coverage"] is not None:
                raise ValueError("completed trial or function evidence needs a campaign manifest")
        else:
            if outcome == "unavailable":
                raise ValueError("unavailable trial cannot have campaign evidence")
            manifest = read_artifact(root, reference)
            run_id, binary_sha256, edges, cost = validate_manifest(
                manifest, trial, projects[trial["project_id"]],
                conditions[trial["condition_id"]], outcome,
            )
            result["peak_edges"] = available(edges)
            result["total_cost_usd"] = available(cost)
            function_reference = entry["function_coverage"]
            function_evidence = (read_artifact(root, function_reference)
                                 if function_reference is not None else None)
            result["selected_function_entry"] = function_entry(
                function_evidence, run_id, binary_sha256, trial["selected_function"])
        trials.append(result)

    condition_reports = {}
    for condition_id in conditions:
        members = [trial for trial in trials if trial["condition_id"] == condition_id]
        summary = summarize_members(members)
        summary["peak_edges_median"] = summary["peak_edges"]["median"]
        summary["total_cost_usd_median"] = summary["total_cost_usd"]["median"]
        condition_reports[condition_id] = summary
    project_reports = {
        project_id: {
            condition_id: summarize_members([
                trial for trial in trials
                if trial["project_id"] == project_id
                and trial["condition_id"] == condition_id
            ])
            for condition_id in conditions
        }
        for project_id in projects
    }
    return {
        "schema_version": 1,
        "cohort_id": cohort["cohort_id"],
        "candidate_commit": cohort["candidate_commit"],
        "outcomes": outcomes,
        "conditions": condition_reports,
        "projects": project_reports,
        "trials": trials,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=Path)
    parser.add_argument("observations", type=Path)
    args = parser.parse_args()
    cohort = read_json(args.cohort)
    observations = read_json(args.observations)
    report = assemble_report(cohort, observations, args.observations.parent)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
