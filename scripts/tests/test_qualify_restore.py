"""Disposable SQLite/WAL and artifact restore probes use synthetic data."""

import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qualify_restore


class RestoreQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.database = self.root / "source.db"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.evidence = self.workspace / "project-1234" / "parser" / "runs" / "run-1" / "out"
        self.evidence.mkdir(parents=True)
        (self.evidence / "result.json").write_text('{"status":"done"}')
        self.writer = sqlite3.connect(self.database)
        self.addCleanup(self.writer.close)
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.executescript("""
            CREATE TABLE runs (id TEXT PRIMARY KEY, evidence_dir TEXT);
            CREATE TABLE harness_approvals (id TEXT PRIMARY KEY);
            CREATE TABLE unrelated_writes (id INTEGER PRIMARY KEY);
            INSERT INTO runs VALUES ('run-1', 'runs/run-1/out');
            INSERT INTO harness_approvals VALUES ('approval-1');
        """)
        self.writer.commit()

    def archive(self, progress=None):
        return qualify_restore.backup(
            self.database, self.workspace, self.root / "archive", progress=progress
        )

    def test_active_wal_backup_restores_approvals_runs_and_artifact_link(self):
        wrote = False

        def while_backing_up(status, remaining, total):
            nonlocal wrote
            if not wrote:
                self.writer.execute("INSERT INTO unrelated_writes VALUES (1)")
                self.writer.commit()
                wrote = True

        manifest = self.archive(progress=while_backing_up)
        self.assertTrue(wrote)
        self.assertEqual(manifest["approvals"], ["approval-1"])
        self.assertEqual(manifest["runs"], [{"id": "run-1", "evidence_dir": "runs/run-1/out"}])
        restored = qualify_restore.restore(self.root / "archive", self.root / "restored")
        self.assertEqual(restored["runs"], manifest["runs"])
        connection = sqlite3.connect(self.root / "restored/database.sqlite")
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(connection.execute("SELECT id FROM harness_approvals").fetchone()[0],
                         "approval-1")
        self.assertEqual((self.root / "restored/workspace/project-1234/parser/runs/run-1/out/result.json")
                         .read_text(), '{"status":"done"}')

    def test_missing_changed_extra_and_unsafe_archive_files_refuse_restore(self):
        for case in ("missing", "changed", "extra", "unsafe", "truncated", "bad-directories"):
            with self.subTest(case=case):
                archive = self.root / f"archive-{case}"
                qualify_restore.backup(self.database, self.workspace, archive)
                artifact = archive / "workspace/project-1234/parser/runs/run-1/out/result.json"
                if case == "missing":
                    artifact.unlink()
                elif case == "changed":
                    artifact.write_text("changed")
                elif case == "extra":
                    (archive / "unexpected").write_text("extra")
                elif case == "unsafe":
                    manifest = json.loads((archive / "manifest.json").read_text())
                    manifest["files"][0]["path"] = "../escape"
                    (archive / "manifest.json").write_text(json.dumps(manifest))
                elif case == "bad-directories":
                    manifest = json.loads((archive / "manifest.json").read_text())
                    manifest["directories"] = [[]]
                    (archive / "manifest.json").write_text(json.dumps(manifest))
                else:
                    (archive / "manifest.json").write_text("{")
                target = self.root / f"restored-{case}"
                with self.assertRaises((ValueError, OSError)):
                    qualify_restore.restore(archive, target)
                self.assertFalse(target.exists())

    def test_backup_rejects_symlink_and_leaves_incomplete_archive(self):
        (self.workspace / "outside").symlink_to(self.database)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.archive()
        self.assertFalse((self.root / "archive/manifest.json").exists())

    def test_database_symlink_refuses_backup_before_output_creation(self):
        alias = self.root / "database-link"
        alias.symlink_to(self.database)
        with self.assertRaisesRegex(ValueError, "symlink"):
            qualify_restore.backup(alias, self.workspace, self.root / "archive")
        self.assertFalse((self.root / "archive").exists())

    def test_retained_input_copy_does_not_confuse_run_evidence_link(self):
        nested = self.evidence.parent / "input/workspace/runs/run-1/out"
        nested.mkdir(parents=True)
        (nested / "result.json").write_text("retained copy")
        self.archive()
        qualify_restore.restore(self.root / "archive", self.root / "restored")
        restored = self.root / "restored/workspace/project-1234/parser/runs/run-1"
        self.assertEqual((restored / "out/result.json").read_text(), '{"status":"done"}')

    def test_restore_preserves_empty_run_evidence_directory(self):
        (self.evidence / "result.json").unlink()
        self.archive()
        qualify_restore.restore(self.root / "archive", self.root / "restored")
        self.assertTrue((self.root / "restored/workspace/project-1234/parser/runs/run-1/out")
                        .is_dir())

    def test_pre_0019_migration_fixture_survives_backup_and_restore(self):
        legacy = self.root / "pre-0019.db"
        migrations = pathlib.Path(__file__).resolve().parents[2] / "crates/hf-storage/migrations"
        connection = sqlite3.connect(legacy)
        connection.execute("PRAGMA journal_mode=WAL")
        for number in range(1, 19):
            script = next(migrations.glob(f"{number:04d}_*.sql"))
            connection.executescript(script.read_text())
        connection.execute("INSERT INTO runs (id, project_root, engine, status, started_at, "
                           "evidence_dir) VALUES (?, ?, ?, ?, ?, ?)",
                           ("run-1", "/disposable/project", "libfuzzer", "done",
                            "2026-09-27T00:00:00Z", "runs/run-1/out"))
        connection.commit()
        archive = self.root / "legacy-archive"
        qualify_restore.backup(legacy, self.workspace, archive)
        connection.close()
        manifest = qualify_restore.restore(archive, self.root / "legacy-restored")
        self.assertEqual(manifest["approvals"], [])
        restored = sqlite3.connect(self.root / "legacy-restored/database.sqlite")
        self.addCleanup(restored.close)
        self.assertEqual(restored.execute("SELECT id FROM runs").fetchone()[0], "run-1")
        self.assertFalse(restored.execute("SELECT 1 FROM sqlite_master WHERE name = "
                                          "'harness_approvals'").fetchall())


if __name__ == "__main__":
    unittest.main()
