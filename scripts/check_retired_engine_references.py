#!/usr/bin/env python3
"""Reject active references to the retired fuzzing engine."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import pathlib
import re
import subprocess
import sys
from typing import Optional


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
PATTERNS = (
    re.compile(
        r"(?<![A-Za-z0-9])cluster[\s_-]*fuzz[\s_-]*lite(?![A-Za-z0-9])",
        re.IGNORECASE,
    ),
    re.compile(r"(?<![A-Za-z0-9])cflite(?![A-Za-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9])cfl(?![A-Za-z0-9])", re.IGNORECASE),
)


@dataclass(frozen=True)
class HistoricalOccurrenceContract:
    count: int
    digest: str


HISTORICAL_OCCURRENCE_CONTRACTS = {
    pathlib.Path("crates/hf-core/src/retired_engine.rs"): HistoricalOccurrenceContract(4, "e15a24a055064af3f6a954a4005caa84b985a4f2158964905efa2b6860baf5ec"),
    pathlib.Path("crates/hf-storage/migrations/0024_retired_engine_records.sql"): HistoricalOccurrenceContract(27, "e46fc9e9205499e7b572c09f8657713a049057e5d359e5b5dfe08ac92470ddf3"),
    pathlib.Path("crates/hf-storage/tests/retired_engine_migration.rs"): HistoricalOccurrenceContract(26, "ea9f3c04f1780be97da27c454d54907ec22671d9c6cb76ec8489bf25983e48fb"),
    pathlib.Path("docs/superpowers/specs/2026-08-11-clusterfuzzlite-removal-design.md"): HistoricalOccurrenceContract(14, "ba68718775b5b9b6db38e28a93a702d20ee5fe4ff75a73922849a686902355b1"),
    pathlib.Path("docs/superpowers/plans/2026-08-11-clusterfuzzlite-removal-implementation.md"): HistoricalOccurrenceContract(0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    pathlib.Path("scripts/check_retired_engine_references.py"): HistoricalOccurrenceContract(4, "34473f0e27978458a3b2ebfb10937175597c80d0140956b3b1b9dad33983c8ad"),
    pathlib.Path("scripts/tests/test_retired_engine_references.py"): HistoricalOccurrenceContract(50, "e5668aff6ce4cd36ab20c722299dc14b930c40a70452c06fea3d1f1e6fe1f527"),
}
ALLOWED_FILES = set(HISTORICAL_OCCURRENCE_CONTRACTS)


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
    return len(path.parts) == 1 and path.name in SKIPPED_DIRECTORY_NAMES


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


def matching_occurrences(lines: list[str]) -> list[tuple[int, str]]:
    return [
        (line_number, line)
        for line_number, line in enumerate(lines, start=1)
        if any(pattern.search(line) for pattern in PATTERNS)
    ]


def occurrence_digest(occurrences: list[tuple[int, str]]) -> str:
    digest = hashlib.sha256()
    for _, line in occurrences:
        digest.update((line + "\n").encode("utf-8"))
    return digest.hexdigest()


def matches_historical_contract(
    relative: pathlib.Path,
    occurrences: list[tuple[int, str]],
) -> bool:
    contract = HISTORICAL_OCCURRENCE_CONTRACTS.get(relative)
    return (
        contract is not None
        and contract.count == len(occurrences)
        and contract.digest == occurrence_digest(occurrences)
    )


def tracked_selected_files(root: pathlib.Path) -> Optional[set[pathlib.Path]]:
    git_marker = root / ".git"
    if not (git_marker.is_file() or (git_marker / "HEAD").is_file()):
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise ScanError(pathlib.Path(".")) from error
    if result.returncode != 0:
        raise ScanError(pathlib.Path("."))
    try:
        names = result.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise ScanError(pathlib.Path(".")) from error
    return {
        relative
        for name in names
        if name and (relative := pathlib.Path(name)) and is_scanned_file(relative)
    }


def selected_directories(files: set[pathlib.Path]) -> set[pathlib.Path]:
    directories = {pathlib.Path(".")}
    for path in files:
        parent = path.parent
        while parent != pathlib.Path("."):
            directories.add(parent)
            parent = parent.parent
    return directories


def iter_scanned_files(
    root: pathlib.Path,
    selected_files: Optional[set[pathlib.Path]],
):
    pending_directories = [(root, pathlib.Path("."))]
    files: list[tuple[pathlib.Path, pathlib.Path]] = []
    directories = selected_directories(selected_files) if selected_files is not None else None
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
                if not is_skipped_directory(relative) and (
                    directories is None or relative in directories
                ):
                    child_directories.append((path, relative))
            elif is_scanned_file(relative) and (
                selected_files is None or relative in selected_files
            ):
                files.append((path, relative))
        pending_directories.extend(reversed(child_directories))
    yield from sorted(files, key=lambda item: item[1].as_posix())


def find_forbidden_references(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path, relative in iter_scanned_files(root, tracked_selected_files(root)):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise ScanError(relative) from error
        except OSError as error:
            raise ScanError(relative) from error
        occurrences = matching_occurrences(lines)
        if relative in ALLOWED_FILES and matches_historical_contract(relative, occurrences):
            continue
        if relative in ALLOWED_FILES and not occurrences:
            findings.append(format_finding(relative, 0, "historical occurrence contract mismatch"))
            continue
        findings.extend(
            format_finding(relative, line_number, line)
            for line_number, line in occurrences
        )
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
