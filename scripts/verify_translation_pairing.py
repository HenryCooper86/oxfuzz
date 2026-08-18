#!/usr/bin/env python3
"""Verify that every bilingual document pair was confirmed consistent.

A pair is three sibling files: the English ``foo.md``, the Chinese
``foo.zh.md``, and a consistency record ``foo.i18n.yaml`` holding the git blob
hash of each side as of the last confirmed-consistent state. Editing either
side without re-recording turns this gate red.

Blob hashes rather than commit hashes, so the record is computable for files
edited in the same change and consistency is a pure content comparison.

Both languages carry equal authority: a document may be authored and reviewed in
either language first. The record says the two were confirmed consistent at
these exact contents. It does not say the confirmation was sound -- a
re-recorded pair with a sloppy counterpart passes this gate and must not pass
review.

Usage:

    scripts/verify_translation_pairing.py                 # verify every pair
    scripts/verify_translation_pairing.py --write README.md
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import pathlib
import re
import sys

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Paths excluded from the corpus, matched against the repository-relative path.
# Test fixtures are localized sample data, not documentation: their pairing is
# asserted by the tests that consume them. The rest are build and dependency
# output that no one authors.
EXCLUDED_PREFIXES = (
    "target/",
    "fuzz_workspace/",
    "third_party/",
    "vendor/",
    "crates/hf-service/tests/fixtures/",
)

# Directory names skipped wholesale during discovery, at any depth.
EXCLUDED_DIRECTORY_NAMES = frozenset({".git", "node_modules", "target", "dist", "build"})

RECORD_HEADER = """\
# Bilingual-pair consistency record: the git blob hash of each side as of the
# last confirmed-consistent state. Both languages carry equal authority. After
# editing either side, bring the other along, then re-record with:
#   scripts/verify_translation_pairing.py --write {name}
# Re-recording is the reviewable act of confirming consistency, which is why it
# names the pair rather than sweeping the repository.
"""

ENGLISH_SWITCHER = re.compile(r"^\*\*English\*\*\s+&middot;\s+\[[^\]]+\]\([^)]+\)\s*$")
CHINESE_SWITCHER = re.compile(r"^\[English\]\([^)]+\)\s+&middot;\s+\*\*[^*]+\*\*\s*$")

ATX_HEADING = re.compile(r"^(#{1,6})\s+\S")
FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*(.*)$")
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
BULLET_ITEM = re.compile(r"^(\s*)([-*+])\s+\S")
ORDERED_ITEM = re.compile(r"^(\s*)(\d+)[.)]\s+\S")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)")
# A trailing comment inside a fenced block, for the strip below. Requires
# whitespace or line start before the marker so a `#` inside an argument (a
# fragment, an anchor, a colour) is not mistaken for a comment.
TRAILING_COMMENT = re.compile(r"(?<!\S)#.*$")


class PairingError(Exception):
    """A pair failed verification. The message is the operator-facing report."""


@dataclasses.dataclass(frozen=True)
class Signature:
    """The structure of a document, with all prose removed.

    Two sides of a pair translate prose, so prose cannot be compared. Structure
    must survive translation exactly: a missing section, a dropped table row, or
    a code block that drifted from its counterpart is a real divergence.
    """

    headings: tuple[int, ...]
    code_blocks: tuple[tuple[str, str], ...]
    tables: tuple[tuple[int, int], ...]
    lists: tuple[tuple[str, int], ...]
    links: frozenset[str]

    def diff(self, other: "Signature") -> list[str]:
        differences = []
        if self.headings != other.headings:
            differences.append(
                f"heading outline: english {list(self.headings)}, "
                f"chinese {list(other.headings)}"
            )
        if self.code_blocks != other.code_blocks:
            differences.append(
                f"code blocks: english has {len(self.code_blocks)}, chinese has "
                f"{len(other.code_blocks)} (compared with comments stripped)"
                if len(self.code_blocks) != len(other.code_blocks)
                else "code blocks: same count, but a command differs between sides"
            )
        if self.tables != other.tables:
            differences.append(
                f"tables: english {list(self.tables)}, chinese {list(other.tables)} "
                "(row count, column count)"
            )
        if self.lists != other.lists:
            differences.append(
                f"lists: english {list(self.lists)}, chinese {list(other.lists)} "
                "(kind, item count)"
            )
        if self.links != other.links:
            english_only = sorted(self.links - other.links)
            chinese_only = sorted(other.links - self.links)
            differences.append(
                "link targets: "
                + (f"only in english: {english_only} " if english_only else "")
                + (f"only in chinese: {chinese_only}" if chinese_only else "")
            )
        return differences


def is_switcher(line: str) -> bool:
    return bool(ENGLISH_SWITCHER.match(line) or CHINESE_SWITCHER.match(line))


def signature(text: str) -> Signature:
    """Reduce a document to its translation-invariant structure."""
    headings: list[int] = []
    code_blocks: list[tuple[str, str]] = []
    tables: list[tuple[int, int]] = []
    lists: list[tuple[str, int]] = []
    links: list[str] = []

    lines = text.splitlines()
    index = 0
    open_table: int | None = None
    table_columns = 0
    open_list: str | None = None
    list_items = 0

    def close_table() -> None:
        nonlocal open_table, table_columns
        if open_table is not None:
            tables.append((open_table, table_columns))
            open_table, table_columns = None, 0

    def close_list() -> None:
        nonlocal open_list, list_items
        if open_list is not None:
            lists.append((open_list, list_items))
            open_list, list_items = None, 0

    while index < len(lines):
        line = lines[index]

        fence = FENCE.match(line)
        if fence:
            close_table()
            close_list()
            marker, info = fence.group(2), fence.group(3).strip()
            body: list[str] = []
            index += 1
            while index < len(lines):
                closing = FENCE.match(lines[index])
                if closing and closing.group(2)[0] == marker[0] and len(closing.group(2)) >= len(marker):
                    break
                body.append(lines[index])
                index += 1
            # Commands are identical on both sides; comments inside a block are
            # prose and this repository localizes them. Stripping comments keeps
            # the check able to catch a command that drifted between sides,
            # which comparing line counts alone would miss.
            stripped = [
                line
                for line in (TRAILING_COMMENT.sub("", entry).rstrip() for entry in body)
                if line
            ]
            code_blocks.append((info, "\n".join(stripped)))
            index += 1
            continue

        if is_switcher(line):
            # The switcher is the one construct that legitimately differs: each
            # side links to the other. Its links are not compared.
            index += 1
            continue

        heading = ATX_HEADING.match(line)
        if heading:
            close_table()
            close_list()
            headings.append(len(heading.group(1)))

        if TABLE_ROW.match(line):
            columns = len([cell for cell in line.strip().strip("|").split("|")])
            if open_table is None:
                open_table, table_columns = 0, columns
            open_table += 1
        else:
            close_table()

        bullet = BULLET_ITEM.match(line)
        ordered = ORDERED_ITEM.match(line)
        if bullet or ordered:
            kind = "bullet" if bullet else "ordered"
            if open_list != kind:
                close_list()
                open_list, list_items = kind, 0
            list_items += 1
        elif not line.strip():
            pass  # A blank line does not end a list; a non-list content line does.
        elif not line.startswith((" ", "\t")):
            close_list()

        links.extend(LINK.findall(line))
        index += 1

    close_table()
    close_list()
    # Links compare as a set, not a sequence: translation reorders a sentence,
    # and one side may reference a document twice where the other references it
    # once. The defect worth catching is a document linked from one language and
    # not the other, which set comparison catches exactly.
    return Signature(
        tuple(headings),
        tuple(code_blocks),
        tuple(tables),
        tuple(lists),
        frozenset(links),
    )


def blob_hash(path: pathlib.Path) -> str:
    """The git blob hash of a file's current contents.

    Computed in-process rather than by shelling out to `git hash-object`, so the
    gate runs in a container that carries a Python interpreter and nothing else.
    The formula is git's own: sha1 over ``blob <length>\0`` followed by the
    bytes, which is why the recorded value is comparable with `git hash-object`
    and with what `git log` will show once the file is committed.
    """
    data = path.read_bytes()
    digest = hashlib.sha1(b"blob %d\0" % len(data) + data)  # noqa: S324 - git's format, not a security hash
    return digest.hexdigest()


def parse_record(text: str) -> dict[str, str]:
    """Parse the record's ``name: hash`` lines.

    A deliberately minimal parser rather than a YAML dependency: the format is
    two comment-prefixed lines and two mappings, the script-tests gate runs on a
    bare interpreter, and a full parser would accept files this gate should
    reject.
    """
    record: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            raise PairingError(f"record line {number} is not `name: hash`: {stripped!r}")
        name, _, value = stripped.partition(":")
        record[name.strip()] = value.strip()
    return record


def render_record(english: pathlib.Path, chinese: pathlib.Path) -> str:
    return (
        RECORD_HEADER.format(name=english.name)
        + f"{english.name}: {blob_hash(english)}\n"
        + f"{chinese.name}: {blob_hash(chinese)}\n"
    )


def tracked_files() -> list[str]:
    """Repository-relative paths of every candidate document, in path order."""
    found = []
    for path in REPOSITORY_ROOT.rglob("*.md"):
        relative = path.relative_to(REPOSITORY_ROOT)
        if any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts[:-1]):
            continue
        found.append(str(relative))
    return sorted(found)


def discover_pairs(paths: list[str]) -> list[tuple[pathlib.Path, pathlib.Path, pathlib.Path]]:
    """Every ``foo.md`` whose ``foo.zh.md`` sibling is tracked, in path order.

    Discovery is by sibling existence rather than a rollout list, so a new
    translated document joins the corpus the moment it is added.
    """
    tracked = set(paths)
    pairs = []
    for entry in sorted(tracked):
        if entry.endswith(".zh.md") or not entry.endswith(".md"):
            continue
        if entry.startswith(EXCLUDED_PREFIXES):
            continue
        counterpart = entry[: -len(".md")] + ".zh.md"
        if counterpart not in tracked:
            continue
        record = entry[: -len(".md")] + ".i18n.yaml"
        pairs.append(
            (
                REPOSITORY_ROOT / entry,
                REPOSITORY_ROOT / counterpart,
                REPOSITORY_ROOT / record,
            )
        )
    return pairs


def switcher_present(text: str) -> bool:
    """A switcher must follow the H1 so a reader can reach the counterpart."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if ATX_HEADING.match(line) and line.startswith("# "):
            return any(is_switcher(candidate) for candidate in lines[index + 1 : index + 4])
    return False


def verify_pair(
    english: pathlib.Path, chinese: pathlib.Path, record: pathlib.Path
) -> list[str]:
    """Return this pair's failures. An empty list means the pair is confirmed."""
    failures: list[str] = []
    relative = english.relative_to(REPOSITORY_ROOT)

    if not record.exists():
        return [
            f"{relative}: no consistency record. Create it with:\n"
            f"    scripts/verify_translation_pairing.py --write {relative}"
        ]

    try:
        recorded = parse_record(record.read_text(encoding="utf-8"))
    except PairingError as error:
        return [f"{record.relative_to(REPOSITORY_ROOT)}: {error}"]

    for side in (english, chinese):
        expected = recorded.get(side.name)
        if expected is None:
            failures.append(f"{relative}: record has no entry for {side.name}")
            continue
        actual = blob_hash(side)
        if actual != expected:
            failures.append(
                f"{side.relative_to(REPOSITORY_ROOT)}: edited since the pair was confirmed\n"
                f"    recorded {expected}\n    current  {actual}\n"
                f"    Bring the counterpart along, then re-record with:\n"
                f"    scripts/verify_translation_pairing.py --write {relative}"
            )

    english_text = english.read_text(encoding="utf-8")
    chinese_text = chinese.read_text(encoding="utf-8")

    for side, text in ((english, english_text), (chinese, chinese_text)):
        if not switcher_present(text):
            failures.append(
                f"{side.relative_to(REPOSITORY_ROOT)}: no language switcher within three "
                "lines of the H1"
            )

    differences = signature(english_text).diff(signature(chinese_text))
    if differences:
        failures.append(
            f"{relative}: structure diverges from its counterpart\n"
            + "".join(f"    {difference}\n" for difference in differences)
            + "    The heading outline, code blocks (comments stripped), table and list\n"
            "    shapes, and the set of link targets must survive translation unchanged."
        )

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        metavar="PAIR",
        nargs="+",
        help="re-record the named English-side paths as confirmed consistent",
    )
    arguments = parser.parse_args(argv)

    pairs = discover_pairs(tracked_files())

    if arguments.write:
        wanted = {pathlib.Path(entry).name for entry in arguments.write}
        written = []
        for english, chinese, record in pairs:
            if english.name in wanted or str(english.relative_to(REPOSITORY_ROOT)) in set(
                arguments.write
            ):
                record.write_text(render_record(english, chinese), encoding="utf-8")
                written.append(str(record.relative_to(REPOSITORY_ROOT)))
        if not written:
            print(f"no pair matched {arguments.write}", file=sys.stderr)
            return 2
        for entry in written:
            print(f"recorded {entry}")
        return 0

    if not pairs:
        print("no bilingual pairs found")
        return 0

    failures = []
    for english, chinese, record in pairs:
        failures.extend(verify_pair(english, chinese, record))

    if failures:
        print("Translation pairing failed:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}\n", file=sys.stderr)
        return 1

    print(f"{len(pairs)} bilingual pair(s) confirmed consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
