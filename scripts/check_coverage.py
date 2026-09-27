#!/usr/bin/env python3
"""Validate per-package line coverage from cargo-llvm-cov JSON summaries."""

import argparse
import json
from pathlib import Path
import sys


def _line_counts(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    lines, covered = value.get("lines"), value.get("covered")
    if type(lines) is not int or type(covered) is not int or lines < 1 or not 0 <= covered <= lines:
        raise ValueError(f"{label} has invalid line counts")
    return lines, covered


def parse_report(report, root, packages):
    """Aggregate exact covered and total source lines for every named package."""
    if not isinstance(report, dict) or report.get("type") != "llvm.coverage.json.export" or not isinstance(report.get("data"), list) or len(report["data"]) != 1:
        raise ValueError("coverage JSON must contain exactly one data entry")
    data = report["data"][0]
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        raise ValueError("coverage JSON has no file summaries")
    expected = set(packages)
    if len(expected) != len(packages) or not expected:
        raise ValueError("coverage package list is empty or duplicated")
    totals = {package: {"lines": 0, "covered": 0} for package in packages}
    seen = set()
    root = root.resolve()
    for entry in data["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            raise ValueError("coverage file entry has no filename")
        try:
            relative = Path(entry["filename"]).resolve().relative_to(root)
        except ValueError as error:
            raise ValueError("coverage file is outside the repository") from error
        parts = relative.parts
        if len(parts) < 4 or parts[0] != "crates" or parts[1] not in expected or parts[2] != "src":
            continue
        if relative in seen:
            raise ValueError(f"coverage file is duplicated: {relative}")
        seen.add(relative)
        summary = entry.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"coverage file has no summary: {relative}")
        line_summary = summary.get("lines")
        if not isinstance(line_summary, dict):
            raise ValueError(f"coverage file has no line summary: {relative}")
        lines, covered = _line_counts(
            {"lines": line_summary.get("count"), "covered": line_summary.get("covered")},
            str(relative),
        )
        totals[parts[1]]["lines"] += lines
        totals[parts[1]]["covered"] += covered
    missing = [package for package, counts in totals.items() if counts["lines"] == 0]
    if missing:
        raise ValueError(f"coverage is missing required packages: {', '.join(missing)}")
    return totals


def verify_baseline(measured, baseline, platform):
    """Require complete baseline data and no exact-ratio regression."""
    if not isinstance(baseline, dict) or baseline.get("schema_version") != 1 or baseline.get("platform") != platform:
        raise ValueError("coverage baseline schema or platform does not match")
    packages = baseline.get("packages")
    if not isinstance(packages, dict) or set(packages) != set(measured):
        raise ValueError("coverage baseline package set does not match measurement")
    for package, current in measured.items():
        base_lines, base_covered = _line_counts(packages[package], f"baseline {package}")
        current_lines, current_covered = _line_counts(current, f"measurement {package}")
        if current_covered * base_lines < base_covered * current_lines:
            raise ValueError(
                f"{package} line coverage regressed: "
                f"{current_covered}/{current_lines} below {base_covered}/{base_lines}"
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True, type=Path)
    parser.add_argument("--infrastructure", required=True, type=Path)
    parser.add_argument("--domain-packages", required=True, nargs="+")
    parser.add_argument("--infrastructure-packages", required=True, nargs="+")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--measure", action="store_true")
    choice.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if set(args.domain_packages) & set(args.infrastructure_packages):
            raise ValueError("coverage package groups overlap")
        domain = parse_report(json.loads(args.domain.read_text()), root, args.domain_packages)
        infrastructure = parse_report(
            json.loads(args.infrastructure.read_text()), root, args.infrastructure_packages
        )
        measured = {**domain, **infrastructure}
        if args.baseline:
            verify_baseline(measured, json.loads(args.baseline.read_text()), sys.platform)
        for package, counts in measured.items():
            target = 80 if package in args.domain_packages else 70 if package != "hf-service" else None
            percent = 100 * counts["covered"] / counts["lines"]
            target_text = f"; target {target}%" if target is not None else "; no-regression baseline"
            print(f"{package}: {counts['covered']}/{counts['lines']} lines ({percent:.2f}%){target_text}")
        if args.measure:
            print(json.dumps({"schema_version": 1, "platform": sys.platform, "packages": measured}, indent=2))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(f"Coverage validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
