import contextlib
import io
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER_SOURCE = REPOSITORY_ROOT / "scripts" / "check_retired_engine_references.py"
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_retired_engine_references as checker
from check_retired_engine_references import find_forbidden_references


class ScandirEntries:
    def __init__(self, entries: tuple[mock.Mock, ...]) -> None:
        self.entries = iter(entries)

    def __enter__(self) -> "ScandirEntries":
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        return None

    def __iter__(self) -> "ScandirEntries":
        return self

    def __next__(self) -> mock.Mock:
        return next(self.entries)


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
            ("source.cc", True),
            ("setup.command", True),
            ("source.cpp", True),
            ("style.css", True),
            ("source.cxx", True),
            ("source.h", True),
            ("source.hpp", True),
            ("page.html", True),
            ("MANIFEST.in", True),
            ("script.js", True),
            ("config.json", True),
            ("component.jsx", True),
            ("Cargo.lock", True),
            ("guide.md", True),
            ("bundle.mjs", True),
            ("guard.py", True),
            ("engine.rs", True),
            ("setup.sh", True),
            ("migration.sql", True),
            ("config.toml", True),
            ("component.ts", True),
            ("component.tsx", True),
            ("prompt.txt", True),
            ("config.yaml", True),
            ("config.yml", True),
            (".gitattributes", True),
            (".gitignore", True),
            ("Dockerfile", True),
            ("Makefile", True),
            ("LICENSE", True),
            (".env.example", True),
            ("workflow.yaml.example", True),
            ("workflow.yml.example", True),
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

    def test_detector_uses_the_exact_historical_allowlist(self) -> None:
        expected = {
            pathlib.Path("crates/hf-core/src/retired_engine.rs"),
            pathlib.Path("crates/hf-storage/migrations/0024_retired_engine_records.sql"),
            pathlib.Path("crates/hf-storage/tests/retired_engine_migration.rs"),
            pathlib.Path(
                "docs/superpowers/specs/2026-08-11-clusterfuzzlite-removal-design.md"
            ),
            pathlib.Path(
                "docs/superpowers/plans/2026-08-11-clusterfuzzlite-removal-implementation.md"
            ),
            pathlib.Path("scripts/check_retired_engine_references.py"),
            pathlib.Path("scripts/tests/test_retired_engine_references.py"),
        }
        self.assertEqual(checker.ALLOWED_FILES, expected)
        self.assertEqual(set(checker.HISTORICAL_OCCURRENCE_CONTRACTS), expected)

    def test_detector_rejects_historical_occurrence_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            relative = pathlib.Path("crates/hf-core/src/retired_engine.rs")
            source = REPOSITORY_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True)
            destination.write_text(
                source.read_text(encoding="utf-8").replace("clusterfuzzlite", "active-engine", 1),
                encoding="utf-8",
            )
            findings = find_forbidden_references(root)
        self.assertTrue(any(finding.startswith("crates/hf-core/src/retired_engine.rs:") for finding in findings))

    def test_detector_accepts_historical_occurrences_after_unrelated_line_insertion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            relative = pathlib.Path("crates/hf-core/src/retired_engine.rs")
            source = REPOSITORY_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True)
            destination.write_text(
                "// unrelated header\n" + source.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            self.assertEqual(find_forbidden_references(root), [])

    def test_detector_rejects_active_additions_in_each_allowlisted_file(self) -> None:
        for relative in sorted(checker.ALLOWED_FILES):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    destination = root / relative
                    destination.parent.mkdir(parents=True)
                    source = REPOSITORY_ROOT / relative
                    baseline = source.read_text(encoding="utf-8") if source.exists() else ""
                    addition_line = len(baseline.splitlines()) + 1
                    destination.write_text(
                        baseline
                        + ("" if not baseline or baseline.endswith("\n") else "\n")
                        + 'ACTIVE_ENGINE = "ClusterFuzzLite"\n',
                        encoding="utf-8",
                    )
                    findings = find_forbidden_references(root)
                self.assertIn(
                    f'{relative.as_posix()}:{addition_line}:ACTIVE_ENGINE = "ClusterFuzzLite"',
                    findings,
                )

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

    def test_detector_prunes_every_configured_ignored_tree_before_descent(self) -> None:
        expected_skipped_names = {
            ".claude",
            ".git",
            "data",
            "fuzz_workspace",
            "node_modules",
            "target",
            "third_party",
        }
        self.assertEqual(checker.SKIPPED_DIRECTORY_NAMES, expected_skipped_names)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "src" / "engine.rs"
            source.parent.mkdir()
            source.write_text("ClusterFuzzLite\n", encoding="utf-8")
            for parent in [root, root / "component"]:
                for name in expected_skipped_names:
                    skipped_source = parent / name / "engine.rs"
                    skipped_source.parent.mkdir(parents=True)
                    skipped_source.write_text("ClusterFuzzLite\n", encoding="utf-8")
            scanned_directories: list[str] = []
            real_scandir = checker.os.scandir

            def recording_scandir(path: pathlib.Path):
                scanned_directories.append(pathlib.Path(path).relative_to(root).as_posix())
                return real_scandir(path)

            with mock.patch.object(checker.os, "scandir", recording_scandir):
                findings = find_forbidden_references(root)
        nested_directories = [f"component/{name}" for name in sorted(expected_skipped_names)]
        self.assertEqual(scanned_directories, [".", "component", *nested_directories, "src"])
        self.assertEqual(
            findings,
            [
                *[f"component/{name}/engine.rs:1:ClusterFuzzLite" for name in sorted(expected_skipped_names)],
                "src/engine.rs:1:ClusterFuzzLite",
            ],
        )

    def test_detector_scans_superpowers_paths_in_fixture_roots(self) -> None:
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
                ".superpowers/sdd/task.md:1:ClusterFuzzLite",
                "feature/.superpowers/sdd/active.rs:1:ClusterFuzzLite",
            ],
        )

    def test_detector_scans_only_tracked_selected_files_in_repository_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tracked = root / "src" / "engine.rs"
            tracked.parent.mkdir(parents=True)
            tracked.write_text("ClusterFuzzLite\n", encoding="utf-8")
            untracked = root / "untracked.rs"
            untracked.write_text("ClusterFuzzLite\n", encoding="utf-8")
            orchestration_artifact = root / ".superpowers" / "sdd" / "task.md"
            orchestration_artifact.parent.mkdir(parents=True)
            orchestration_artifact.write_text("ClusterFuzzLite\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", str(tracked)], check=True)
            findings = find_forbidden_references(root)
        self.assertEqual(findings, ["src/engine.rs:1:ClusterFuzzLite"])

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

    def test_detector_fails_closed_on_invalid_utf8_in_selected_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "src" / "invalid.py"
            path.parent.mkdir(parents=True)
            path.write_bytes(b'ENGINE = "ClusterFuzzLite"\n\xff')
            with self.assertRaisesRegex(
                checker.ScanError,
                r"^scan error: src/invalid\.py$",
            ):
                find_forbidden_references(root)

    def test_detector_fails_closed_when_a_selected_file_cannot_be_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "src" / "engine.rs"
            path.parent.mkdir(parents=True)
            path.write_text("ClusterFuzzLite\n", encoding="utf-8")
            with mock.patch.object(pathlib.Path, "read_text", side_effect=OSError("denied")):
                with self.assertRaisesRegex(
                    checker.ScanError,
                    r"^scan error: src/engine\.rs$",
                ):
                    find_forbidden_references(root)

    def test_detector_fails_closed_when_directory_enumeration_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            blocked = root / "blocked"
            with mock.patch.object(
                checker.os,
                "scandir",
                side_effect=OSError(5, "unreadable", str(blocked)),
            ):
                with self.assertRaisesRegex(
                    checker.ScanError,
                    r"^scan error: blocked$",
                ):
                    find_forbidden_references(root)

    def test_detector_fails_closed_when_a_directory_entry_is_dir_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            entry = self.directory_entry(root / "blocked")
            entry.is_dir.side_effect = OSError(13, "denied", str(root / "blocked"))
            with mock.patch.object(
                checker.os,
                "scandir",
                return_value=self.scandir_with(entry),
            ):
                with self.assertRaisesRegex(
                    checker.ScanError,
                    r"^scan error: blocked$",
                ):
                    find_forbidden_references(root)
            entry.is_dir.assert_called_once_with(follow_symlinks=False)

    def test_detector_fails_closed_when_a_file_entry_is_symlink_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            entry = self.file_entry(root / "engine.rs")
            entry.is_symlink.side_effect = OSError(13, "denied", str(root / "engine.rs"))
            with mock.patch.object(
                checker.os,
                "scandir",
                return_value=self.scandir_with(entry),
            ):
                with self.assertRaisesRegex(
                    checker.ScanError,
                    r"^scan error: engine\.rs$",
                ):
                    find_forbidden_references(root)
            entry.is_dir.assert_called_once_with(follow_symlinks=False)
            entry.is_symlink.assert_called_once_with()

    def test_detector_fails_closed_when_a_directory_entry_is_symlink_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            entry = self.directory_entry(root / "src")
            entry.is_symlink.side_effect = OSError(13, "denied", str(root / "src"))
            with mock.patch.object(
                checker.os,
                "scandir",
                side_effect=[self.scandir_with(entry), self.scandir_with()],
            ):
                with self.assertRaisesRegex(
                    checker.ScanError,
                    r"^scan error: src$",
                ):
                    find_forbidden_references(root)
            entry.is_dir.assert_called_once_with(follow_symlinks=False)
            entry.is_symlink.assert_called_once_with()

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

    def test_diagnostic_paths_are_normalized_to_posix(self) -> None:
        diagnostic = checker.format_finding(
            pathlib.PureWindowsPath("src") / "engine.rs",
            7,
            "  CFL_ENGINE  ",
        )
        self.assertEqual(diagnostic, "src/engine.rs:7:CFL_ENGINE")

    def test_scan_errors_do_not_expose_host_paths(self) -> None:
        error = OSError(13, "denied", "/private/host-only/engine.rs")
        scan_error = checker.scan_error_for(pathlib.Path("/repository"), error, pathlib.Path("."))
        self.assertEqual(str(scan_error), "scan error: engine.rs")

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

    def test_cli_reports_invalid_utf8_as_a_scan_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "src" / "invalid.py"
            source.parent.mkdir(parents=True)
            source.write_bytes(b'ENGINE = "ClusterFuzzLite"\n\xff')
            result = self.run_checker(root)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "scan error: src/invalid.py\n")

    def test_cli_reports_a_scan_error_with_exit_two(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            checker,
            "find_forbidden_references",
            side_effect=checker.ScanError(pathlib.Path("src") / "engine.rs"),
        ):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(checker.main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "scan error: src/engine.rs\n")

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

    @staticmethod
    def scandir_with(*entries: mock.Mock) -> ScandirEntries:
        return ScandirEntries(entries)

    @staticmethod
    def file_entry(path: pathlib.Path) -> mock.Mock:
        entry = mock.Mock()
        entry.name = path.name
        entry.path = str(path)
        entry.is_dir.return_value = False
        entry.is_symlink.return_value = False
        return entry

    @staticmethod
    def directory_entry(path: pathlib.Path) -> mock.Mock:
        entry = RetiredEngineReferenceTests.file_entry(path)
        entry.is_dir.return_value = True
        return entry


if __name__ == "__main__":
    unittest.main()
