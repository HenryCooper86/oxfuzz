#!/usr/bin/env python3
"""Validate retained-history samples and print first/repeat query quantiles."""

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys


SIZES = ((161, 3200), (161, 6400), (321, 12800))
SAMPLE_COUNTS = {"preparation": 5, "first_query": 5, "repeat_query": 25}


def quantiles(values):
    ordered = sorted(values)
    return statistics.median(ordered), ordered[math.ceil(len(ordered) * 0.95) - 1], ordered[-1]


def summarize(document):
    """Require each declared size and its independent fixture/query samples."""
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("history sample schema is invalid")
    environment = document.get("environment")
    if not isinstance(environment, dict) or any(
        not isinstance(environment.get(name), str) or not environment[name].strip()
        for name in ("runner", "revision", "rustc", "os", "arch", "profile")
    ):
        raise ValueError("history sample environment is incomplete")
    if not re.fullmatch(r"[0-9a-f]{40}", environment["revision"]):
        raise ValueError("history sample revision is invalid")
    if environment.get("clean") is not True:
        raise ValueError("history samples require a clean measured revision")
    if environment["profile"] not in ("debug", "release"):
        raise ValueError("history sample build profile is invalid")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != len(SIZES):
        raise ValueError("history sample sizes are incomplete")
    seen = set()
    rows = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("history sample case is not an object")
        size = (case.get("targets"), case.get("runs"))
        if size not in SIZES or size in seen:
            raise ValueError("history sample size is unknown or duplicated")
        seen.add(size)
        row = {"targets": size[0], "runs": size[1]}
        for name, count in SAMPLE_COUNTS.items():
            values = case.get(f"{name}_us")
            if not isinstance(values, list) or len(values) != count or any(
                type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in values
            ):
                raise ValueError(f"{name} samples are missing or invalid for {size}")
            median, p95, maximum = quantiles(values)
            row[f"{name}_samples"] = count
            row[f"{name}_median_us"] = median
            row[f"{name}_p95_us"] = p95
            row[f"{name}_max_us"] = maximum
        rows.append(row)
    return sorted(rows, key=lambda row: row["runs"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()
    try:
        rows = summarize(json.loads(args.input.read_text()))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"History measurement invalid: {error}", file=sys.stderr)
        return 1
    for row in rows:
        print(
            f"targets={row['targets']} runs={row['runs']} "
            f"first query median={row['first_query_median_us'] / 1000:.2f}ms "
            f"P95={row['first_query_p95_us'] / 1000:.2f}ms; "
            f"repeat query median={row['repeat_query_median_us'] / 1000:.2f}ms "
            f"P95={row['repeat_query_p95_us'] / 1000:.2f}ms"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
