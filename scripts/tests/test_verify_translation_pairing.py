"""Tests for the bilingual-pair consistency gate.

Each test that asserts a rule first proves the violating case fails: a guard
only guards if the regression actually turns it red
(docs/standards/DEFENSIVE_PATTERNS.md, Verification).
"""

import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import verify_translation_pairing as pairing
from verify_translation_pairing import PairingError, Signature, parse_record, signature

ENGLISH = """\
# Title

**English** &middot; [中文](doc.zh.md)

Some prose.

| Column | Other |
| --- | --- |
| a | b |

- one
- two

```bash
run --now   # start it
```

See the [guide](docs/guide.md).
"""

CHINESE = """\
# 标题

[English](doc.md) &middot; **中文**

一些散文。

| 列 | 其他 |
| --- | --- |
| 甲 | 乙 |

- 一
- 二

```bash
run --now   # 现在开始
```

参见[指南](docs/guide.md)。
"""


class SignatureTest(unittest.TestCase):
    def test_translated_prose_produces_an_identical_signature(self):
        self.assertEqual(signature(ENGLISH), signature(CHINESE))

    def test_switcher_links_are_excluded(self):
        # Each side links to the other, so including the switcher would make
        # every correct pair fail.
        self.assertEqual(signature(ENGLISH).links, frozenset({"docs/guide.md"}))

    def test_localized_comments_inside_a_code_block_are_not_a_divergence(self):
        self.assertEqual(signature(ENGLISH).code_blocks, signature(CHINESE).code_blocks)

    def test_a_changed_command_inside_a_code_block_is_a_divergence(self):
        drifted = CHINESE.replace("run --now", "run --later")
        self.assertTrue(signature(ENGLISH).diff(signature(drifted)))

    def test_a_dropped_heading_is_a_divergence(self):
        self.assertTrue(signature(ENGLISH + "\n## Extra\n").diff(signature(CHINESE)))

    def test_a_link_present_in_only_one_language_is_a_divergence(self):
        extra = CHINESE.replace("参见[指南](docs/guide.md)。", "参见[指南](docs/other.md)。")
        differences = signature(ENGLISH).diff(signature(extra))
        self.assertTrue(any("link targets" in entry for entry in differences))

    def test_link_order_and_repetition_are_not_divergences(self):
        # Translation reorders sentences, and one side may reference a document
        # twice where the other references it once.
        repeated = CHINESE.replace(
            "参见[指南](docs/guide.md)。",
            "[指南](docs/guide.md)参见[指南](docs/guide.md)。",
        )
        self.assertFalse(signature(ENGLISH).diff(signature(repeated)))

    def test_a_dropped_table_row_is_a_divergence(self):
        shortened = CHINESE.replace("| 甲 | 乙 |\n", "")
        self.assertTrue(signature(ENGLISH).diff(signature(shortened)))

    def test_a_dropped_list_item_is_a_divergence(self):
        shortened = CHINESE.replace("- 二\n", "")
        self.assertTrue(signature(ENGLISH).diff(signature(shortened)))


class SwitcherTest(unittest.TestCase):
    def test_both_switcher_directions_are_recognized(self):
        self.assertTrue(pairing.switcher_present(ENGLISH))
        self.assertTrue(pairing.switcher_present(CHINESE))

    def test_a_missing_switcher_is_detected(self):
        without = ENGLISH.replace("**English** &middot; [中文](doc.zh.md)\n", "")
        self.assertFalse(pairing.switcher_present(without))

    def test_a_switcher_far_below_the_heading_is_not_accepted(self):
        # A reader who cannot see the switcher from the title cannot use it.
        buried = ENGLISH.replace(
            "# Title\n\n**English**", "# Title\n\nprose\n\nprose\n\nprose\n\n**English**"
        )
        self.assertFalse(pairing.switcher_present(buried))


class RecordTest(unittest.TestCase):
    def test_comments_and_blank_lines_are_ignored(self):
        self.assertEqual(
            parse_record("# a comment\n\nREADME.md: abc\nREADME.zh.md: def\n"),
            {"README.md": "abc", "README.zh.md": "def"},
        )

    def test_a_malformed_line_is_rejected_rather_than_skipped(self):
        with self.assertRaises(PairingError):
            parse_record("README.md abc\n")


class DiscoveryTraversalTest(unittest.TestCase):
    def test_excluded_directories_are_never_opened(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            excluded = [
                "target",
                ".git",
                "crates/ui/node_modules",
                "crates/ui/dist",
                "third_party",
                "vendor",
                "fuzz_workspace",
                "crates/hf-service/tests/fixtures",
            ]
            for name in excluded:
                child = root / name
                child.mkdir(parents=True)
                (child / "ignored.md").write_text("ignored", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs/guide.md").write_text("guide", encoding="utf-8")
            (root / "README.md").write_text("readme", encoding="utf-8")
            forbidden = {root / name for name in excluded}
            original_scandir = os.scandir

            def guarded_scandir(path):
                self.assertNotIn(pathlib.Path(path), forbidden)
                return original_scandir(path)

            with mock.patch.object(pairing, "REPOSITORY_ROOT", root):
                with mock.patch("os.scandir", side_effect=guarded_scandir):
                    self.assertEqual(pairing.tracked_files(), ["README.md", "docs/guide.md"])


class WriteSelectionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        for relative in ("README.md", "docs/README.md", ".superpowers/archive/README.md"):
            english = self.root / relative
            english.parent.mkdir(parents=True, exist_ok=True)
            english.write_text(ENGLISH, encoding="utf-8")
            english.with_name("README.zh.md").write_text(CHINESE, encoding="utf-8")
            english.with_name("README.i18n.yaml").write_text("unchanged", encoding="utf-8")
        self.patch = mock.patch.object(pairing, "REPOSITORY_ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def invoke(self, *paths):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return pairing.main(["--write", *paths])

    def changed_records(self):
        return {
            record.relative_to(self.root).as_posix()
            for record in self.root.rglob("*.i18n.yaml")
            if record.read_text(encoding="utf-8") != "unchanged"
        }

    def test_root_readme_does_not_confirm_same_basename_in_nested_or_ignored_directories(self):
        self.assertEqual(self.invoke("README.md"), 0)
        self.assertEqual(self.changed_records(), {"README.i18n.yaml"})

    def test_nested_path_only_confirms_its_requested_pair_and_names_it_in_guidance(self):
        self.assertEqual(self.invoke("docs/README.md"), 0)
        self.assertEqual(self.changed_records(), {"docs/README.i18n.yaml"})
        record = (self.root / "docs/README.i18n.yaml").read_text(encoding="utf-8")
        self.assertIn("--write docs/README.md", record)
        self.assertEqual(pairing.verify_pair(self.root / "docs/README.md", self.root / "docs/README.zh.md", self.root / "docs/README.i18n.yaml"), [])

    def test_dot_prefix_selects_the_same_repository_relative_path(self):
        self.assertEqual(self.invoke("./docs/README.md"), 0)
        self.assertEqual(self.changed_records(), {"docs/README.i18n.yaml"})

    def test_unmatched_nested_name_never_falls_back_to_basename(self):
        self.assertEqual(self.invoke("missing/README.md"), 2)
        self.assertEqual(self.changed_records(), set())

    def test_invalid_or_unknown_paths_do_not_partially_confirm_a_batch(self):
        for path in ("missing/README.md", "../README.md", str(self.root / "README.md")):
            with self.subTest(path=path):
                self.assertEqual(self.invoke("README.md", path), 2)
                self.assertEqual(self.changed_records(), set())


class RepositoryCorpusTest(unittest.TestCase):
    def test_every_tracked_pair_is_confirmed_consistent(self):
        result = subprocess.run(
            [sys.executable, "scripts/verify_translation_pairing.py"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_discovery_finds_the_readme_pair_and_skips_fixtures(self):
        pairs = pairing.discover_pairs(pairing.tracked_files())
        names = {english.name for english, _, _ in pairs}
        self.assertIn("README.md", names)
        self.assertFalse(
            any("tests/fixtures" in str(english) for english, _, _ in pairs),
            "localized test fixtures are sample data, not documentation",
        )


if __name__ == "__main__":
    unittest.main()
