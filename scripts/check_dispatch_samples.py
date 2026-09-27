#!/usr/bin/env python3
"""Check individual dispatch timings and report median and nearest-rank P95."""

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys


DECISIONS = ("accepted", "denied")
CONCURRENCY = (1, 8, 32)
MIN_SAMPLES = 1000


def summarize(document):
    """Validate six complete cases and return their measured quantiles."""
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("dispatch sample schema is invalid")
    environment = document.get("environment")
    if not isinstance(environment, dict) or any(
        not isinstance(environment.get(field), str) or not environment[field].strip()
        for field in ("os", "arch", "rustc", "runner", "revision", "profile", "fixture")
    ):
        raise ValueError("dispatch sample environment is incomplete")
    if not re.fullmatch(r"[0-9a-f]{40}", environment["revision"]):
        raise ValueError("dispatch sample revision is invalid")
    if environment.get("clean") is not True:
        raise ValueError("dispatch samples require a clean measured revision")
    if type(environment.get("runtime_workers")) is not int or environment["runtime_workers"] < 1:
        raise ValueError("dispatch sample worker count is invalid")
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise ValueError("dispatch sample cases are missing")
    expected = {(decision, concurrency) for decision in DECISIONS for concurrency in CONCURRENCY}
    seen = set()
    summary = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("dispatch sample case is not an object")
        identity = (case.get("decision"), case.get("concurrency"))
        if identity not in expected or identity in seen:
            raise ValueError("dispatch sample case is unknown or duplicated")
        seen.add(identity)
        measures = {}
        for name in ("dispatch", "queue", "total"):
            values = case.get(f"{name}_us")
            if not isinstance(values, list) or len(values) < MIN_SAMPLES or any(
                type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in values
            ):
                raise ValueError(f"{name} samples are missing or invalid for {identity}")
            measures[name] = values
        count = len(measures["dispatch"])
        if any(len(values) != count for values in measures.values()) or any(
            total < max(dispatch, queued) for dispatch, queued, total in zip(
                measures["dispatch"], measures["queue"], measures["total"]
            )
        ):
            raise ValueError(f"dispatch sample timing is inconsistent for {identity}")
        row = {"decision": identity[0], "concurrency": identity[1], "samples": count}
        for name, values in measures.items():
            ordered = sorted(values)
            row[f"{name}_median_us"] = statistics.median(ordered)
            row[f"{name}_p95_us"] = ordered[math.ceil(count * 0.95) - 1]
            row[f"{name}_max_us"] = ordered[-1]
        summary.append(row)
    if seen != expected:
        raise ValueError("dispatch sample cases are incomplete")
    return sorted(summary, key=lambda row: (DECISIONS.index(row["decision"]), row["concurrency"]))


def require_dispatch_limit(summary, limit_us):
    if type(limit_us) not in (int, float) or not math.isfinite(limit_us) or limit_us <= 0:
        raise ValueError("dispatch limit must be positive and finite")
    exceeded = [row for row in summary if row["dispatch_p95_us"] >= limit_us]
    if exceeded:
        names = ", ".join(f"{row['decision']} at {row['concurrency']}" for row in exceeded)
        raise ValueError(f"dispatch P95 did not stay below {limit_us} us: {names}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--limit-us", type=float)
    args = parser.parse_args()
    try:
        report = summarize(json.loads(args.input.read_text()))
        if args.limit_us is not None:
            require_dispatch_limit(report, args.limit_us)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Dispatch measurement invalid: {error}", file=sys.stderr)
        return 1
    for row in report:
        print(
            f"{row['decision']} concurrency={row['concurrency']} "
            f"samples={row['samples']} dispatch P95={row['dispatch_p95_us']:.2f}us "
            f"queue P95={row['queue_p95_us']:.2f}us "
            f"total P95={row['total_p95_us']:.2f}us"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
