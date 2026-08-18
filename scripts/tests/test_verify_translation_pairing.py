"""Tests for the bilingual-pair consistency gate.

Each test that asserts a rule first proves the violating case fails: a guard
only guards if the regression actually turns it red
(docs/standards/DEFENSIVE_PATTERNS.md, Verification).
"""

import pathlib
import subprocess
import sys
import unittest

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
