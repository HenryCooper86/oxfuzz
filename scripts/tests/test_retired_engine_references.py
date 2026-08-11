import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER_SOURCE = REPOSITORY_ROOT / "scripts" / "check_retired_engine_references.py"
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from check_retired_engine_references import find_forbidden_references


class RetiredEngineReferenceTests(unittest.TestCase):
    def test_detector_rejects_an_active_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "src" / "engine.rs"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const ENGINE: &str = "ClusterFuzzLite";\n',
                encoding="utf-8",
            )
            findings = find_forbidden_references(root)
        self.assertEqual(
            findings,
            ['src/engine.rs:1:const ENGINE: &str = "ClusterFuzzLite";'],
        )

    def test_detector_selects_the_tracked_text_surface(self) -> None:
        cases = (
            ("source.c", True),
            ("source.h", True),
            ("source.cc", True),
            ("source.cpp", True),
            ("source.cxx", True),
            ("source.hpp", True),
            ("page.html", True),
            ("style.css", True),
            ("script.js", True),
            ("component.jsx", True),
            ("bundle.mjs", True),
            ("setup.command", True),
            (".env.example", True),
            ("workflow.yml.example", True),
            ("workflow.yaml.example", True),
            ("Cargo.lock", True),
            ("MANIFEST.in", True),
            ("Dockerfile", True),
            ("Makefile", True),
            ("LICENSE", True),
            (".gitignore", True),
            ("asset.png", False),
            ("icon.ico", False),
            ("document.pdf", False),
            ("payload.bin", False),
            ("untyped", False),
        )
        for relative, should_detect in cases:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("ClusterFuzzLite\n", encoding="utf-8")
                    findings = find_forbidden_references(root)
                expected = [f"{relative}:1:ClusterFuzzLite"] if should_detect else []
                self.assertEqual(findings, expected)

    def test_detector_matches_canonical_separator_and_case_variants(self) -> None:
        cases = (
            ("clusterfuzzlite", True),
            ("ClusterFuzzLite", True),
            ("cluster fuzz lite", True),
            ("CLUSTER_FUZZ_LITE", True),
            ("Cluster-Fuzz-Lite", True),
            ("cluster_fuzz-lite", True),
            ("xclusterfuzzlite", False),
            ("clusterfuzzlite2", False),
        )
        for reference, should_detect in cases:
            with self.subTest(reference=reference):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    path = root / "src" / "engine.rs"
                    path.parent.mkdir(parents=True)
                    path.write_text(reference + "\n", encoding="utf-8")
                    findings = find_forbidden_references(root)
                expected = [f"src/engine.rs:1:{reference}"] if should_detect else []
                self.assertEqual(findings, expected)

    def test_detector_matches_alias_identifier_and_punctuation_variants(self) -> None:
        cases = (
            ("cfl", True),
            ("CFL", True),
            ("cflite", True),
            ("CFLITE", True),
            ("CFL_ENGINE", True),
            ("cflite_config", True),
            ("(cfl)", True),
            ("cflite:", True),
            ("xcfl", False),
            ("cfl2", False),
            ("xcflite", False),
            ("cflite2", False),
        )
        for reference, should_detect in cases:
            with self.subTest(reference=reference):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    path = root / "src" / "engine.rs"
                    path.parent.mkdir(parents=True)
                    path.write_text(reference + "\n", encoding="utf-8")
                    findings = find_forbidden_references(root)
                expected = [f"src/engine.rs:1:{reference}"] if should_detect else []
                self.assertEqual(findings, expected)

    def test_detector_ignores_build_and_dependency_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for relative in ["target/generated.rs", "node_modules/pkg/index.js"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("ClusterFuzzLite\n", encoding="utf-8")
            self.assertEqual(find_forbidden_references(root), [])

    def test_detector_ignores_only_root_sdd_orchestration_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = (
                root / ".superpowers" / "sdd" / "task.md",
                root / ".superpowers" / "active.rs",
                root / "feature" / ".superpowers" / "sdd" / "active.rs",
            )
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("ClusterFuzzLite\n", encoding="utf-8")
            findings = find_forbidden_references(root)
        self.assertEqual(
            findings,
            [
                ".superpowers/active.rs:1:ClusterFuzzLite",
                "feature/.superpowers/sdd/active.rs:1:ClusterFuzzLite",
            ],
        )

    def test_detector_skips_file_and_directory_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = pathlib.Path(directory)
            root = temporary_root / "repository"
            root.mkdir()
            outside_file = temporary_root / "outside.rs"
            outside_file.write_text("ClusterFuzzLite\n", encoding="utf-8")
            outside_directory = temporary_root / "outside-directory"
            outside_directory.mkdir()
            (outside_directory / "active.rs").write_text(
                "ClusterFuzzLite\n",
                encoding="utf-8",
            )
            file_link = root / "linked.rs"
            directory_link = root / "linked-directory"
            try:
                file_link.symlink_to(outside_file)
                directory_link.symlink_to(outside_directory, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assertEqual(find_forbidden_references(root), [])

    def test_detector_ignores_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "src" / "invalid.rs"
            path.parent.mkdir(parents=True)
            path.write_bytes(b'const ENGINE: &str = "ClusterFuzzLite";\xff\n')
            self.assertEqual(find_forbidden_references(root), [])

    def test_detector_reports_sorted_paths_lines_and_exact_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "a" / "config.toml"
            second = root / "b" / "engine.rs"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.write_text(
                'first = "cfl"\nignored = "active"\nsecond = "ClusterFuzzLite"\n',
                encoding="utf-8",
            )
            second.write_text('const ENGINE: &str = "cflite";\n', encoding="utf-8")
            findings = find_forbidden_references(root)
        self.assertEqual(
            findings,
            [
                'a/config.toml:1:first = "cfl"',
                'a/config.toml:3:second = "ClusterFuzzLite"',
                'b/engine.rs:1:const ENGINE: &str = "cflite";',
            ],
        )

    def test_cli_is_silent_for_a_clean_isolated_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_checker(pathlib.Path(directory))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_cli_reports_a_finding_for_an_isolated_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "src" / "engine.rs"
            source.parent.mkdir(parents=True)
            source.write_text("CFL_ENGINE\n", encoding="utf-8")
            result = self.run_checker(root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "src/engine.rs:1:CFL_ENGINE\n")
        self.assertEqual(result.stderr, "")

    def test_repository_contains_only_historical_references(self) -> None:
        self.assertEqual(find_forbidden_references(REPOSITORY_ROOT), [])

    def run_checker(self, root: pathlib.Path) -> subprocess.CompletedProcess[str]:
        checker = root / "scripts" / "check_retired_engine_references.py"
        checker.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CHECKER_SOURCE, checker)
        return subprocess.run(
            [sys.executable, str(checker)],
            cwd=root,
            check=False,
            text=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
