#!/usr/bin/env python3
"""Validate a frozen held-out effectiveness cohort before collecting trials."""

import argparse
import json
import math
import re
from pathlib import Path


HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
ENGINES = {"libfuzzer", "afl++", "honggfuzz"}
STRATEGIES = {"ranked", "heuristic", "random"}


def record(value, name, fields):
    if not isinstance(value, dict):
        raise ValueError("{} must be an object".format(name))
    missing = set(fields) - set(value)
    extra = set(value) - set(fields)
    if missing or extra:
        raise ValueError("{} fields: missing {}, unknown {}".format(
            name, sorted(missing), sorted(extra)))
    return value


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("{} must be nonempty text".format(name))
    return value


def digest(value, name, pattern):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("{} must be a lowercase immutable digest".format(name))


def integer(value, name, minimum):
    if type(value) is not int or value < minimum:
        raise ValueError("{} must be an integer >= {}".format(name, minimum))


def unique_ids(items, kind):
    ids = set()
    for item in items:
        item_id = nonempty(item["id"], "{} id".format(kind))
        if item_id in ids:
            raise ValueError("duplicate {} id: {}".format(kind, item_id))
        ids.add(item_id)
    return ids


def nonempty_list(value, name):
    if not isinstance(value, list) or not value:
        raise ValueError("{} must be a nonempty list".format(name))
    return value


def validate_cohort(value):
    """Reject incomplete identities, budgets, and trial references in JSON data."""
    record(value, "cohort", (
        "schema_version", "cohort_id", "candidate_commit", "projects",
        "conditions", "trials",
    ))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("unsupported cohort schema_version")
    nonempty(value["cohort_id"], "cohort_id")
    digest(value["candidate_commit"], "candidate_commit", HEX_40)

    projects = nonempty_list(value["projects"], "projects")
    for project in projects:
        record(project, "project", (
            "id", "source_url", "revision", "license", "source_sha256",
            "selected_functions",
        ))
        nonempty(project["id"], "project id")
        if not nonempty(project["source_url"], "source_url").startswith("https://"):
            raise ValueError("source_url must use HTTPS")
        digest(project["revision"], "revision", HEX_40)
        nonempty(project["license"], "license")
        digest(project["source_sha256"], "source_sha256", HEX_64)
        functions = nonempty_list(project["selected_functions"], "selected_functions")
        if any(not isinstance(function, str) or not function.strip()
               or function != function.strip() for function in functions):
            raise ValueError("selected_functions must contain symbols")
        if len(functions) != len(set(functions)):
            raise ValueError("duplicate selected_function")
    project_ids = unique_ids(projects, "project")
    functions_by_project = {
        project["id"]: set(project["selected_functions"]) for project in projects
    }

    conditions = nonempty_list(value["conditions"], "conditions")
    for condition in conditions:
        record(condition, "condition", (
            "id", "engine", "selection_strategy", "provider_family", "model_id",
            "sanitizer", "top_k", "duration_secs", "max_mem_mb", "max_cpus", "model_call_budget",
            "model_cost_budget_usd", "sandbox_image_sha256",
        ))
        nonempty(condition["id"], "condition id")
        for field in ("provider_family", "model_id", "sanitizer"):
            nonempty(condition[field], field)
        if nonempty(condition["engine"], "engine") not in ENGINES:
            raise ValueError("unsupported engine")
        if nonempty(condition["selection_strategy"], "selection_strategy") not in STRATEGIES:
            raise ValueError("unsupported selection_strategy")
        for field, minimum in (
            ("top_k", 1), ("duration_secs", 1), ("max_mem_mb", 1),
            ("max_cpus", 1), ("model_call_budget", 0),
        ):
            integer(condition[field], field, minimum)
        cost = condition["model_cost_budget_usd"]
        if type(cost) not in (int, float) or not math.isfinite(cost) or cost < 0:
            raise ValueError("model_cost_budget_usd must be finite and non-negative")
        digest(condition["sandbox_image_sha256"], "sandbox_image_sha256", HEX_64)
    condition_ids = unique_ids(conditions, "condition")

    trials = nonempty_list(value["trials"], "trials")
    for trial in trials:
        record(trial, "trial", (
            "id", "project_id", "condition_id", "selected_function", "seed",
        ))
        nonempty(trial["id"], "trial id")
        if nonempty(trial["project_id"], "project_id") not in project_ids:
            raise ValueError("unknown project_id")
        if nonempty(trial["condition_id"], "condition_id") not in condition_ids:
            raise ValueError("unknown condition_id")
        if nonempty(trial["selected_function"], "selected_function") not in functions_by_project[trial["project_id"]]:
            raise ValueError("unknown selected_function")
        integer(trial["seed"], "seed", 0)
    unique_ids(trials, "trial")
    return value


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: {}".format(key))
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cohort", type=Path)
    args = parser.parse_args()
    with args.cohort.open(encoding="utf-8") as source:
        cohort = validate_cohort(json.load(source, object_pairs_hook=no_duplicate_keys))
    print(json.dumps({
        "cohort_id": cohort["cohort_id"],
        "projects": len(cohort["projects"]),
        "conditions": len(cohort["conditions"]),
        "trials": len(cohort["trials"]),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
