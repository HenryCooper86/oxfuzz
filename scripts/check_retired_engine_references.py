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


class ScanError(Exception):
    def __init__(self, relative: pathlib.PurePath) -> None:
        self.relative = relative
        super().__init__(f"scan error: {relative.as_posix()}")


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


def scan_error_for(
    root: pathlib.Path,
    error: OSError,
    fallback: pathlib.Path,
) -> ScanError:
    error_path = pathlib.Path(error.filename) if error.filename else fallback
    try:
        relative = error_path.relative_to(root)
    except ValueError:
        relative = error_path if not error_path.is_absolute() else pathlib.Path(error_path.name)
    return ScanError(relative)


def format_finding(relative: pathlib.PurePath, line_number: int, line: str) -> str:
    return f"{relative.as_posix()}:{line_number}:{line.strip()}"


def iter_scanned_files(root: pathlib.Path):
    pending_directories = [(root, pathlib.Path("."))]
    files: list[tuple[pathlib.Path, pathlib.Path]] = []
    while pending_directories:
        directory, relative_directory = pending_directories.pop()
        try:
            with os.scandir(directory) as entries:
                sorted_entries = sorted(entries, key=lambda entry: entry.name)
        except OSError as error:
            raise scan_error_for(root, error, relative_directory) from error
        child_directories: list[tuple[pathlib.Path, pathlib.Path]] = []
        for entry in sorted_entries:
            relative = relative_directory / entry.name
            path = directory / entry.name
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as error:
                raise scan_error_for(root, error, relative) from error
            try:
                is_symlink = entry.is_symlink()
            except OSError as error:
                raise scan_error_for(root, error, relative) from error
            if is_symlink:
                continue
            if is_directory:
                if not is_skipped_directory(relative):
                    child_directories.append((path, relative))
            elif is_scanned_file(relative):
                files.append((path, relative))
        pending_directories.extend(reversed(child_directories))
    yield from sorted(files, key=lambda item: item[1].as_posix())


def find_forbidden_references(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path, relative in iter_scanned_files(root):
        if relative in ALLOWED_FILES:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            # Invalid UTF-8 is intentionally outside the text-only scan surface.
            continue
        except OSError as error:
            raise ScanError(relative) from error
        for line_number, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in PATTERNS):
                findings.append(format_finding(relative, line_number, line))
    return findings


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        findings = find_forbidden_references(root)
    except ScanError as error:
        print(error, file=sys.stderr)
        return 2
    if findings:
        print("\n".join(findings))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
