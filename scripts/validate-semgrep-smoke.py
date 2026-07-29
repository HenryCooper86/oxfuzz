#!/usr/bin/env python3
"""Validate the bounded host-side output of the Semgrep sandbox smoke."""

import json
import os
import pathlib
import stat
import sys


def read_regular_bounded(report_path: pathlib.Path, limit: int) -> bytes:
    """Open a report without blocking on special files and read at most limit bytes."""
    report_fd = os.open(
        report_path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    report_stat = os.fstat(report_fd)
    if not stat.S_ISREG(report_stat.st_mode):
        os.close(report_fd)
        raise SystemExit("Semgrep report is not a regular file")
    if report_stat.st_size > limit:
        os.close(report_fd)
        raise SystemExit(f"Semgrep report exceeds {limit} bytes")
    with os.fdopen(report_fd, "rb") as report_file:
        report_bytes = report_file.read(limit + 1)
    if not report_bytes:
        raise SystemExit("Semgrep report is empty")
    if len(report_bytes) > limit:
        raise SystemExit(f"Semgrep report exceeds {limit} bytes")
    return report_bytes


def normalized_path(raw_path: str) -> str:
    """Return one safe project-relative POSIX path."""
    normalized = pathlib.PurePosixPath(raw_path)
    if (
        normalized.is_absolute()
        or ".." in normalized.parts
        or normalized.as_posix() in {"", "."}
    ):
        raise SystemExit(f"unsafe Semgrep path: {raw_path!r}")
    return normalized.as_posix().removeprefix("./")


def validate_report(report_path: pathlib.Path, limit: int) -> None:
    """Validate the fixed two-file Semgrep release fixture report."""
    report = json.loads(read_regular_bounded(report_path, limit))
    if "errors" not in report or report["errors"] != []:
        raise SystemExit(
            f"unexpected or missing Semgrep errors: {report.get('errors')!r}"
        )

    paths = report.get("paths")
    if not isinstance(paths, dict):
        raise SystemExit(f"invalid or missing Semgrep paths object: {paths!r}")
    if paths.get("skipped", []) != []:
        raise SystemExit(f"unexpected skipped Semgrep paths: {paths.get('skipped')!r}")

    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or not all(
        isinstance(path, str) for path in scanned
    ):
        raise SystemExit(f"invalid or missing scanned Semgrep paths: {scanned!r}")

    normalized_scanned = {normalized_path(path) for path in scanned}
    expected_scanned = {"clean.c", "vulnerable.c"}
    if normalized_scanned != expected_scanned:
        raise SystemExit(
            f"unexpected scanned Semgrep paths: {sorted(normalized_scanned)!r}"
        )

    results = report.get("results")
    if not isinstance(results, list):
        raise SystemExit(f"invalid or missing Semgrep results: {results!r}")

    matching_paths = []
    for result in results:
        if not isinstance(result, dict):
            raise SystemExit(f"invalid Semgrep result: {result!r}")
        path = result.get("path")
        if not isinstance(path, str):
            raise SystemExit(f"invalid Semgrep result path: {path!r}")
        normalized = normalized_path(path)
        if normalized not in expected_scanned:
            raise SystemExit(
                f"Semgrep result path is outside the fixture manifest: {path!r}"
            )
        if normalized == "clean.c":
            raise SystemExit(
                f"clean.c unexpectedly produced result {result.get('check_id')!r}"
            )
        if result.get("check_id") == "raptor-insecure-api-gets":
            matching_paths.append(normalized)

    if matching_paths != ["vulnerable.c"]:
        raise SystemExit(
            "expected exactly one raptor-insecure-api-gets result in vulnerable.c "
            f"and none in clean.c, got {matching_paths!r}"
        )

    print("Verified regular, symlink-safe, bounded Semgrep JSON")
    print("Verified empty errors and absent-or-empty skipped paths")
    print("Verified exact scanned fixture manifest: clean.c, vulnerable.c")
    print("Verified one raptor-insecure-api-gets result in vulnerable.c")
    print("Verified clean.c has no result from any rule")


def main(argv: list[str]) -> None:
    """Parse the fixed command line and validate one report."""
    if len(argv) != 3:
        raise SystemExit("usage: validate-semgrep-smoke.py REPORT MAX_BYTES")
    try:
        limit = int(argv[2])
    except ValueError as error:
        raise SystemExit("MAX_BYTES must be an integer") from error
    if limit <= 0:
        raise SystemExit("MAX_BYTES must be positive")
    validate_report(pathlib.Path(argv[1]), limit)


if __name__ == "__main__":
    main(sys.argv)
