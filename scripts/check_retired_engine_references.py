#!/usr/bin/env python3
"""Reject active references to the retired fuzzing engine."""

from __future__ import annotations

import pathlib
import re
import sys


SCANNED_SUFFIXES = {
    ".json", ".md", ".py", ".rs", ".sh", ".sql", ".toml",
    ".ts", ".tsx", ".txt", ".yaml", ".yml",
}
SCANNED_FILENAMES = {"Dockerfile", "Makefile"}
SKIPPED_PARTS = {
    ".git", ".claude", ".superpowers", "data", "fuzz_workspace", "node_modules", "target",
    "third_party",
}
ALLOWED_FILES = {
    pathlib.Path("crates/hf-core/src/retired_engine.rs"),
    pathlib.Path("crates/hf-storage/migrations/0024_retired_engine_records.sql"),
    pathlib.Path("crates/hf-storage/tests/retired_engine_migration.rs"),
    pathlib.Path("docs/superpowers/specs/2026-08-11-clusterfuzzlite-removal-design.md"),
    pathlib.Path("docs/superpowers/plans/2026-08-11-clusterfuzzlite-removal-implementation.md"),
    pathlib.Path("scripts/check_retired_engine_references.py"),
    pathlib.Path("scripts/tests/test_retired_engine_references.py"),
}
PATTERNS = (
    re.compile(r"cluster[\s_-]*fuzz[\s_-]*lite", re.IGNORECASE),
    re.compile(r"\bcflite\b", re.IGNORECASE),
    re.compile(r"\bcfl\b", re.IGNORECASE),
)


def find_forbidden_references(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_SUFFIXES and path.name not in SCANNED_FILENAMES:
            continue
        relative = path.relative_to(root)
        if any(part in SKIPPED_PARTS for part in relative.parts):
            continue
        if relative in ALLOWED_FILES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.append(f"{relative}:{line_number}:{line.strip()}")
    return findings


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    findings = find_forbidden_references(root)
    if findings:
        print("\n".join(findings))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
