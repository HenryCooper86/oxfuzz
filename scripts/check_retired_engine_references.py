#!/usr/bin/env python3
"""Reject active references to the retired fuzzing engine."""

from __future__ import annotations

import os
import pathlib
import re
import sys


# This is the complete tracked text source, configuration, documentation, and
# frontend surface. Binary media and untyped fixture data remain unscanned.
SCANNED_SUFFIXES = {
    ".c", ".cc", ".command", ".cpp", ".css", ".cxx", ".h", ".hpp",
    ".html", ".in", ".js", ".json", ".jsx", ".lock", ".md", ".mjs",
    ".py", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt",
    ".yaml", ".yml",
}
SCANNED_FILENAMES = {".gitattributes", ".gitignore", "Dockerfile", "LICENSE", "Makefile"}
SCANNED_COMPOUND_SUFFIXES = {".env.example", ".yaml.example", ".yml.example"}
SKIPPED_DIRECTORY_NAMES = {
    ".git", ".claude", "data", "fuzz_workspace", "node_modules", "target",
    "third_party",
}
SDD_ARTIFACT_PREFIX = (".superpowers", "sdd")
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
    re.compile(
        r"(?<![A-Za-z0-9])cluster[\s_-]*fuzz[\s_-]*lite(?![A-Za-z0-9])",
        re.IGNORECASE,
    ),
    re.compile(r"(?<![A-Za-z0-9])cflite(?![A-Za-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9])cfl(?![A-Za-z0-9])", re.IGNORECASE),
)


def is_scanned_file(path: pathlib.Path) -> bool:
    return (
        path.suffix in SCANNED_SUFFIXES
        or path.name in SCANNED_FILENAMES
        or any(path.name.endswith(suffix) for suffix in SCANNED_COMPOUND_SUFFIXES)
    )


def is_skipped_directory(path: pathlib.Path) -> bool:
    return (
        path.name in SKIPPED_DIRECTORY_NAMES
        or path.parts[:2] == SDD_ARTIFACT_PREFIX
    )


def iter_scanned_files(root: pathlib.Path):
    for directory, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = pathlib.Path(directory)
        relative_directory = directory_path.relative_to(root)
        directories[:] = [
            name
            for name in sorted(directories)
            if not (directory_path / name).is_symlink()
            and not is_skipped_directory(relative_directory / name)
        ]
        for filename in sorted(filenames):
            path = directory_path / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root)
            if is_scanned_file(relative):
                yield path, relative


def find_forbidden_references(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path, relative in iter_scanned_files(root):
        if relative in ALLOWED_FILES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
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
