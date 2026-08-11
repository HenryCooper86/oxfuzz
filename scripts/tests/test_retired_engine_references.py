import pathlib
import sys
import tempfile
import unittest

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
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
        self.assertEqual(len(findings), 1)
        self.assertIn("src/engine.rs:1", findings[0])

    def test_detector_ignores_build_and_dependency_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for relative in ["target/generated.rs", "node_modules/pkg/index.js"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("ClusterFuzzLite\n", encoding="utf-8")
            self.assertEqual(find_forbidden_references(root), [])

    def test_detector_ignores_orchestration_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / ".superpowers" / "task.md"
            path.parent.mkdir(parents=True)
            path.write_text("ClusterFuzzLite\n", encoding="utf-8")
            self.assertEqual(find_forbidden_references(root), [])

    def test_repository_contains_only_historical_references(self) -> None:
        self.assertEqual(find_forbidden_references(REPOSITORY_ROOT), [])


if __name__ == "__main__":
    unittest.main()
