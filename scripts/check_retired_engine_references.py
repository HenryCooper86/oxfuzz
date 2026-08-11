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


# Every tracked regular file is selected and scanned before binary handling.
# Strictly invalid UTF-8 is skipped only when its bytes begin with one of these
# genuine media/container signatures; file names and NUL bytes are never used
# as binary evidence. These cover the repository's PNG/ICO inventory and
# common media, font, SQLite, and ZIP formats without claiming arbitrary data
# is safe to ignore.
BINARY_MEDIA_MAGIC_SIGNATURES = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"\x00\x00\x01\x00",
    b"\x00\x00\x02\x00",
    b"icns",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"SQLite format 3\x00",
    b"\x00\x01\x00\x00",
    b"OTTO",
    b"wOFF",
    b"wOF2",
)
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
    source_length: int


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
    pathlib.Path("crates/hf-gui/src/lib/retiredEngine.ts"): HistoricalOccurrenceContract(3, "0c84e97c315144c25b4db1128c6dd9c1b22374666f7b91f6318f5e6e273e11df"),
    pathlib.Path("scripts/check_retired_engine_references.py"): HistoricalOccurrenceContract(2, "19fe94b96ae26495bd3633c46648d264d33bbd222b371e5971fd5dd4a1b23c43"),
    pathlib.Path("scripts/tests/test_retired_engine_references.py"): HistoricalOccurrenceContract(57, "fb8d834739da1f65c6f6796061ef7fe65498e568f97923fc2adc025e89f65e01"),
}
ALLOWED_FILES = set(HISTORICAL_OCCURRENCE_CONTRACTS)


class ScanError(Exception):
    def __init__(self, relative: pathlib.PurePath) -> None:
        self.relative = relative
        super().__init__(f"scan error: {relative.as_posix()}")


def is_skipped_directory(path: pathlib.Path) -> bool:
    return len(path.parts) == 1 and path.name in SKIPPED_DIRECTORY_NAMES


def is_genuine_binary_media(contents: bytes) -> bool:
    return any(contents.startswith(signature) for signature in BINARY_MEDIA_MAGIC_SIGNATURES)


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
    rendered = line.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    rendered = rendered.replace("\0", "\\0")
    return f"{relative.as_posix()}:{line_number}:{rendered.strip()}"


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
    return DecodedSource(
        "".join(decoded),
        tuple(source_offsets),
        frozenset(escaped_offsets),
        len(source),
    )


def is_canonical_joiner(character: str) -> bool:
    return character.isspace() or character in CANONICAL_JOINER_PUNCTUATION


def ascii_lower(text: str) -> str:
    return "".join(
        chr(ord(character) + (ord("a") - ord("A")))
        if "A" <= character <= "Z"
        else character
        for character in text
    )


def is_ascii_lower(character: str) -> bool:
    return "a" <= character <= "z"


def is_ascii_upper(character: str) -> bool:
    return "A" <= character <= "Z"


def source_offset_after(decoded: DecodedSource, offset: int) -> int:
    if offset == len(decoded.text):
        return decoded.source_length
    return decoded.source_offsets[offset]


def block_comment_end(text: str, offset: int) -> Optional[int]:
    # The matcher uses the supported-language union for every filename. Nested
    # depth is conservative: an inner close cannot end an outer Rust comment.
    depth = 1
    candidate = offset + 2
    while depth:
        opening = text.find("/*", candidate)
        closing = text.find("*/", candidate)
        if closing < 0:
            return None
        if opening >= 0 and opening < closing:
            depth += 1
            candidate = opening + 2
        else:
            depth -= 1
            candidate = closing + 2
    return candidate


def line_comment_end(text: str, offset: int, marker_length: int) -> Optional[int]:
    for candidate in range(offset + marker_length, len(text)):
        if text[candidate] in "\n\r\u2028\u2029":
            return candidate + 1
    return None


def comment_end(text: str, offset: int) -> Optional[int]:
    if text.startswith("/*", offset):
        return block_comment_end(text, offset)
    if text.startswith("//", offset):
        return line_comment_end(text, offset, 2)
    if text.startswith("#", offset):
        return line_comment_end(text, offset, 1)
    return None


def starts_comment(text: str, offset: int) -> bool:
    return text.startswith(("/*", "//", "#"), offset)


def component_after_joiners(
    decoded: DecodedSource,
    normalized: str,
    offset: int,
    component: str,
) -> Optional[int]:
    text = normalized
    candidate = offset
    while True:
        if text.startswith(component, candidate):
            return candidate
        if candidate == len(text):
            return None
        if starts_comment(text, candidate):
            comment = comment_end(text, candidate)
            if comment is None:
                return None
            candidate = comment
        elif is_canonical_joiner(text[candidate]):
            candidate += 1
        else:
            return None
        raw_span = source_offset_after(decoded, candidate) - source_offset_after(decoded, offset)
        # This bound is measured in original source characters, so a comment's
        # complete raw spelling and content cannot disappear from the budget.
        if raw_span > MAX_CANONICAL_JOINERS:
            return None


def long_canonical_spans(decoded: DecodedSource) -> list[tuple[int, int, bool]]:
    text = decoded.text
    lowered = ascii_lower(text)
    spans: list[tuple[int, int, bool]] = []
    search_offset = 0
    while True:
        start = lowered.find(CANONICAL_PREFIX, search_offset)
        if start < 0:
            return spans
        fuzz_start = component_after_joiners(
            decoded,
            lowered,
            start + len(CANONICAL_PREFIX),
            CANONICAL_MIDDLE,
        )
        if fuzz_start is not None:
            lite_start = component_after_joiners(
                decoded,
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
        or (is_ascii_lower(previous) and is_ascii_upper(first))
    )


def is_alias_end(text: str, offset: int) -> bool:
    if offset == len(text):
        return True
    previous = text[offset - 1]
    following = text[offset]
    return (
        not (following.isascii() and following.isalnum())
        or (is_ascii_upper(following) and (is_ascii_lower(previous) or is_ascii_upper(previous)))
    )


def short_alias_spans(decoded: DecodedSource) -> list[tuple[int, int, bool]]:
    text = decoded.text
    lowered = ascii_lower(text)
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
    source_lines = source.split("\n")
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
        digest.update((occurrence.line + "\n").encode("utf-8", "surrogateescape"))
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
        if name
        and (relative := pathlib.Path(name))
        and not relative.is_absolute()
        and ".." not in relative.parts
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
            else:
                try:
                    is_regular_file = entry.is_file(follow_symlinks=False)
                except OSError as error:
                    raise scan_error_for(root, error, relative) from error
                if is_regular_file and (selected_files is None or relative in selected_files):
                    files.append((path, relative))
        pending_directories.extend(reversed(child_directories))
    yield from sorted(files, key=lambda item: item[1].as_posix())


def find_forbidden_references(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path, relative in iter_scanned_files(root, tracked_selected_files(root)):
        try:
            contents = path.read_bytes()
        except OSError as error:
            raise ScanError(relative) from error
        source = contents.decode("utf-8", "surrogateescape")
        is_utf8 = not any("\udc80" <= character <= "\udcff" for character in source)
        occurrences = matching_occurrences(source)
        historical_match = (
            relative in ALLOWED_FILES
            and matches_historical_contract(relative, occurrences)
        )
        # Findings take precedence over the binary-media exemption for this
        # file. A malformed media payload that embeds a retired identifier is
        # therefore reported (exit 1), never silently skipped.
        if occurrences and not historical_match:
            findings.extend(
                format_finding(relative, occurrence.line_number, occurrence.line)
                for occurrence in occurrences
            )
            continue
        if not is_utf8:
            if is_genuine_binary_media(contents):
                continue
            raise ScanError(relative)
        if historical_match:
            continue
        if relative in ALLOWED_FILES:
            findings.append(format_finding(relative, 0, "historical occurrence contract mismatch"))
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
