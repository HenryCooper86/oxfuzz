#!/usr/bin/env python3
"""Regression tests for the sandbox image's Bazel compile-database tool."""

import importlib.machinery
import importlib.util
import pathlib
import tempfile
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPOSITORY_ROOT / "docker" / "sandbox" / "bazel" / "oxfuzz-bazel-compdb"


def load_tool():
    loader = importlib.machinery.SourceFileLoader("oxfuzz_bazel_compdb", str(TOOL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class VendorPinTests(unittest.TestCase):
    def vendor_directory(self, root: pathlib.Path) -> pathlib.Path:
        vendor = root / "third_party" / "bazel"
        for name in ("rules_cc+", "abseil-cpp+", "odd name"):
            (vendor / name).mkdir(parents=True)
            (vendor / f"@{name}.marker").write_text("0" * 64)
        # A marker whose repository directory is absent names nothing to pin.
        (vendor / "@gone+.marker").write_text("0" * 64)
        (vendor / "VENDOR.bazel").write_text("# written by bazel vendor\n")
        return vendor

    def test_every_vendored_repository_is_pinned(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as root:
            vendor = self.vendor_directory(pathlib.Path(root))
            tool.pin_vendored_repositories(str(vendor))
            text = (vendor / "VENDOR.bazel").read_text()
        self.assertTrue(text.startswith("# written by bazel vendor\n"))
        self.assertIn('pin("@@abseil-cpp+")\n', text)
        self.assertIn('pin("@@rules_cc+")\n', text)
        self.assertNotIn("gone", text)
        # A name that is not a canonical repository name is never written
        # into the Starlark file.
        self.assertNotIn("odd name", text)

    def test_pinning_twice_adds_nothing(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as root:
            vendor = self.vendor_directory(pathlib.Path(root))
            tool.pin_vendored_repositories(str(vendor))
            first = (vendor / "VENDOR.bazel").read_text()
            tool.pin_vendored_repositories(str(vendor))
            second = (vendor / "VENDOR.bazel").read_text()
        self.assertEqual(first, second)

    def test_a_pin_the_project_already_carries_is_kept_once(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as root:
            vendor = self.vendor_directory(pathlib.Path(root))
            (vendor / "VENDOR.bazel").write_text("pin('@@rules_cc+')\n")
            tool.pin_vendored_repositories(str(vendor))
            text = (vendor / "VENDOR.bazel").read_text()
        self.assertEqual(text.count("rules_cc+"), 1)
        self.assertIn('pin("@@abseil-cpp+")\n', text)


if __name__ == "__main__":
    unittest.main()
