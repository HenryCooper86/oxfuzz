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
CANONICAL_PREFIX = "cluster"
CANONICAL_MIDDLE = "fuzz"
CANONICAL_SUFFIX = "lite"
SHORT_ALIASES = ("cflite", "cfl")
MAX_CANONICAL_JOINERS = 64
# Long canonical components may be adjacent or separated by at most 64 of
# these syntax characters (or Unicode whitespace).  The matcher never
# evaluates source or removes arbitrary characters.
CANONICAL_JOINER_PUNCTUATION = frozenset(' _-"\'`.,;:!?()[]{}+-=*/\\|&<>~^%$#@')
DIRECT_CANONICAL_JOINERS = frozenset(" _-")
ASCII_ESCAPE = re.compile(
    r"\\(?:x(?P<hex>[0-9A-Fa-f]{2})|u(?P<unicode>[0-9A-Fa-f]{4})|u\{(?P<braced>[0-9A-Fa-f]{1,6})\})"
)


@dataclass(frozen=True)
class HistoricalOccurrenceContract:
    count: int
    digest: str


@dataclass(frozen=True)
class DecodedSource:
    text: str
    source_offsets: tuple[int, ...]
    escaped_offsets: frozenset[int]


@dataclass(frozen=True)
class Occurrence:
    line_number: int
    line: str
    direct: bool


HISTORICAL_OCCURRENCE_CONTRACTS = {
    pathlib.Path("crates/hf-core/src/retired_engine.rs"): HistoricalOccurrenceContract(4, "e15a24a055064af3f6a954a4005caa84b985a4f2158964905efa2b6860baf5ec"),
    pathlib.Path("crates/hf-storage/migrations/0024_retired_engine_records.sql"): HistoricalOccurrenceContract(27, "e46fc9e9205499e7b572c09f8657713a049057e5d359e5b5dfe08ac92470ddf3"),
    pathlib.Path("crates/hf-storage/tests/retired_engine_migration.rs"): HistoricalOccurrenceContract(28, "28989e3f83b797ef990b6a8ffa88c2b377120422acfb87282fc65ce51c6e1d22"),
    pathlib.Path("docs/superpowers/specs/2026-08-11-clusterfuzzlite-removal-design.md"): HistoricalOccurrenceContract(14, "ba68718775b5b9b6db38e28a93a702d20ee5fe4ff75a73922849a686902355b1"),
    pathlib.Path("docs/superpowers/plans/2026-08-11-clusterfuzzlite-removal-implementation.md"): HistoricalOccurrenceContract(0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    pathlib.Path("scripts/check_retired_engine_references.py"): HistoricalOccurrenceContract(3, "a4802adbb30ec6feb4ac97a2eb48bccce5e6a4d19310b47b3e4308031b823e5d"),
    pathlib.Path("scripts/tests/test_retired_engine_references.py"): HistoricalOccurrenceContract(61, "b0bfa14333f0a895e4fa28d921ed17191f74beeaf8170ff0049d94712ed3442a"),
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


def decode_ascii_escapes(source: str) -> DecodedSource:
    decoded: list[str] = []
    source_offsets: list[int] = []
    escaped_offsets: set[int] = set()
    offset = 0
    while offset < len(source):
        match = ASCII_ESCAPE.match(source, offset)
        if match is None:
            decoded.append(source[offset])
            source_offsets.append(offset)
            offset += 1
            continue
        codepoint = int(next(value for value in match.groups() if value is not None), 16)
        character = chr(codepoint)
        if character.isascii() and character.isalpha():
            escaped_offsets.add(len(decoded))
            decoded.append(character)
            source_offsets.append(offset)
            offset = match.end()
            continue
        for source_offset in range(offset, match.end()):
            decoded.append(source[source_offset])
            source_offsets.append(source_offset)
        offset = match.end()
    return DecodedSource("".join(decoded), tuple(source_offsets), frozenset(escaped_offsets))


def is_canonical_joiner(character: str) -> bool:
    return character.isspace() or character in CANONICAL_JOINER_PUNCTUATION


def component_after_joiners(text: str, offset: int, component: str) -> Optional[int]:
    for joiner_count in range(MAX_CANONICAL_JOINERS + 1):
        candidate = offset + joiner_count
        if text.startswith(component, candidate):
            return candidate
        if candidate == len(text) or not is_canonical_joiner(text[candidate]):
            return None
    return None


def long_canonical_spans(decoded: DecodedSource) -> list[tuple[int, int, bool]]:
    text = decoded.text
    lowered = text.lower()
    spans: list[tuple[int, int, bool]] = []
    search_offset = 0
    while True:
        start = lowered.find(CANONICAL_PREFIX, search_offset)
        if start < 0:
            return spans
        fuzz_start = component_after_joiners(
            lowered,
            start + len(CANONICAL_PREFIX),
            CANONICAL_MIDDLE,
        )
        if fuzz_start is not None:
            lite_start = component_after_joiners(
                lowered,
                fuzz_start + len(CANONICAL_MIDDLE),
                CANONICAL_SUFFIX,
            )
            if lite_start is not None:
                end = lite_start + len(CANONICAL_SUFFIX)
                joiners = (
                    text[start + len(CANONICAL_PREFIX):fuzz_start]
                    + text[fuzz_start + len(CANONICAL_MIDDLE):lite_start]
                )
                direct = (
                    not decoded.escaped_offsets.intersection(range(start, end))
                    and all(character in DIRECT_CANONICAL_JOINERS for character in joiners)
                )
                spans.append((start, end, direct))
        search_offset = start + 1


def is_alias_start(text: str, offset: int) -> bool:
    if offset == 0:
        return True
    previous = text[offset - 1]
    first = text[offset]
    return (
        not (previous.isascii() and previous.isalnum())
        or (previous.islower() and first.isupper())
    )


def is_alias_end(text: str, offset: int) -> bool:
    if offset == len(text):
        return True
    previous = text[offset - 1]
    following = text[offset]
    return (
        not (following.isascii() and following.isalnum())
        or (following.isupper() and (previous.islower() or previous.isupper()))
    )


def short_alias_spans(decoded: DecodedSource) -> list[tuple[int, int, bool]]:
    text = decoded.text
    lowered = text.lower()
    spans: list[tuple[int, int, bool]] = []
    for alias in SHORT_ALIASES:
        search_offset = 0
        while True:
            start = lowered.find(alias, search_offset)
            if start < 0:
                break
            end = start + len(alias)
            if is_alias_start(text, start) and is_alias_end(text, end):
                direct = not decoded.escaped_offsets.intersection(range(start, end))
                spans.append((start, end, direct))
            search_offset = start + 1
    return spans


def matching_occurrences(source: str) -> list[Occurrence]:
    decoded = decode_ascii_escapes(source)
    source_lines = source.splitlines()
    occurrences_by_line: dict[int, Occurrence] = {}
    for start, _, direct in long_canonical_spans(decoded) + short_alias_spans(decoded):
        source_offset = decoded.source_offsets[start]
        line_number = source.count("\n", 0, source_offset) + 1
        occurrence = Occurrence(line_number, source_lines[line_number - 1], direct)
        existing = occurrences_by_line.get(line_number)
        if existing is None:
            occurrences_by_line[line_number] = occurrence
        else:
            occurrences_by_line[line_number] = Occurrence(
                line_number,
                existing.line,
                existing.direct and direct,
            )
    return [occurrences_by_line[line_number] for line_number in sorted(occurrences_by_line)]


def occurrence_digest(occurrences: list[Occurrence]) -> str:
    digest = hashlib.sha256()
    for occurrence in occurrences:
        digest.update((occurrence.line + "\n").encode("utf-8"))
    return digest.hexdigest()


def matches_historical_contract(
    relative: pathlib.Path,
    occurrences: list[Occurrence],
) -> bool:
    contract = HISTORICAL_OCCURRENCE_CONTRACTS.get(relative)
    return (
        contract is not None
        and contract.count == len(occurrences)
        and contract.digest == occurrence_digest(occurrences)
        and all(occurrence.direct for occurrence in occurrences)
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
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ScanError(relative) from error
        except OSError as error:
            raise ScanError(relative) from error
        occurrences = matching_occurrences(source)
        if relative in ALLOWED_FILES and matches_historical_contract(relative, occurrences):
            continue
        if relative in ALLOWED_FILES and not occurrences:
            findings.append(format_finding(relative, 0, "historical occurrence contract mismatch"))
            continue
        findings.extend(
            format_finding(relative, occurrence.line_number, occurrence.line)
            for occurrence in occurrences
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
