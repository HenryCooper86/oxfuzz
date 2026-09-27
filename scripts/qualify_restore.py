#!/usr/bin/env python3
"""Back up and reopen a disposable SQLite/WAL store with run artifacts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import sys

MAX_FILES = 50_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


def safe_relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or "\0" in value:
        raise ValueError("archive contains an invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("archive contains an unsafe relative path")
    return path


def regular_file(path):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("backup or archive contains a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("backup or archive contains a non-regular file")
    return metadata


def copy_regular(source, destination):
    before = regular_file(source)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    input_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(source, input_flags), "rb") as reader:
        if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
            raise ValueError("source changed from a regular file")
        with os.fdopen(os.open(destination, output_flags, 0o600), "wb") as writer:
            for block in iter(lambda: reader.read(CHUNK_BYTES), b""):
                size += len(block)
                if size > MAX_TOTAL_BYTES:
                    raise ValueError("one file exceeds the qualification byte limit")
                digest.update(block)
                writer.write(block)
            writer.flush()
            os.fsync(writer.fileno())
        after = os.fstat(reader.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise ValueError("source file changed during backup")
    return {"sha256": digest.hexdigest(), "size": size}


def digest_file(path):
    metadata = regular_file(path)
    if metadata.st_size > MAX_TOTAL_BYTES:
        raise ValueError("archive file exceeds the qualification byte limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(block)
    return {"sha256": digest.hexdigest(), "size": metadata.st_size}


def open_database(path):
    regular_file(path)
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)


def inspect_database(path):
    connection = open_database(path)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("SQLite integrity check failed")
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "runs" not in tables:
            raise ValueError("qualification database has no runs table")
        runs = [{"id": run_id, "evidence_dir": evidence_dir} for run_id, evidence_dir in
                connection.execute("SELECT id, evidence_dir FROM runs ORDER BY id LIMIT ?",
                                   (MAX_FILES + 1,))]
        approvals = ([row[0] for row in
                      connection.execute("SELECT id FROM harness_approvals ORDER BY id LIMIT ?",
                                         (MAX_FILES + 1,))]
                     if "harness_approvals" in tables else [])
    finally:
        connection.close()
    if len(runs) > MAX_FILES or len(approvals) > MAX_FILES:
        raise ValueError("database row count exceeds qualification limit")
    for run in runs:
        if not isinstance(run["id"], str) or not run["id"]:
            raise ValueError("run has no stable id")
        if run["evidence_dir"] is not None:
            safe_relative_path(run["evidence_dir"])
    return {"runs": runs, "approvals": approvals,
            "has_approval_table": "harness_approvals" in tables}


def verify_evidence_links(workspace, runs):
    directories = []
    for path in workspace.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("workspace contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            directories.append(path.relative_to(workspace).parts)
        elif not stat.S_ISREG(metadata.st_mode):
            raise ValueError("workspace contains a special file")
    for run in runs:
        evidence_dir = run["evidence_dir"]
        if evidence_dir is None:
            continue
        suffix = safe_relative_path(evidence_dir).parts
        matches = [parts for parts in directories if len(parts) >= len(suffix)
                   and parts[-len(suffix):] == suffix]
        if not matches:
            raise ValueError("run evidence link has no directory")
        shallowest = min(len(parts) for parts in matches)
        if sum(len(parts) == shallowest for parts in matches) != 1:
            raise ValueError("run evidence link has multiple owning directories")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_manifest(path, manifest):
    encoded = (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ValueError("qualification manifest exceeds its byte limit")
    temporary = path.with_suffix(".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def backup(database, workspace, archive, *, progress=None):
    database, workspace = Path(database), Path(workspace)
    regular_file(database)
    workspace_metadata = workspace.lstat()
    if stat.S_ISLNK(workspace_metadata.st_mode):
        raise ValueError("backup workspace is a symlink")
    database, workspace, archive = database.resolve(), workspace.resolve(), Path(archive).resolve()
    if not database.is_file() or not workspace.is_dir():
        raise ValueError("backup needs an existing database and workspace")
    if database == workspace or workspace in database.parents:
        raise ValueError("database must be outside the copied workspace")
    if archive == workspace or workspace in archive.parents or archive == database:
        raise ValueError("archive must be outside both backup inputs")
    regular_file(database)
    if archive.exists():
        raise ValueError("archive directory already exists")
    archive.mkdir(mode=0o700, parents=True)
    backup_path = archive / "database.sqlite"
    source = open_database(database)
    destination = sqlite3.connect(backup_path)
    try:
        if source.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
            raise ValueError("qualification source is not a WAL database")
        source.backup(destination, pages=32, progress=progress, sleep=0.01)
        if destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0].lower() != "delete":
            raise ValueError("backup database could not become self-contained")
    finally:
        destination.close()
        source.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(backup_path) + suffix)
        if sidecar.exists():
            if regular_file(sidecar).st_size and suffix == "-wal":
                raise ValueError("backup database has an uncheckpointed WAL")
            sidecar.unlink()
    backup_path.chmod(0o600)
    database_view = inspect_database(backup_path)
    files = [{"path": "database.sqlite", **digest_file(backup_path)}]
    artifact_root = archive / "workspace"
    artifact_root.mkdir(mode=0o700)
    directories = ["workspace"]
    total = files[0]["size"]
    for source in sorted(workspace.rglob("*")):
        metadata = source.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("workspace contains a symlink")
        relative = source.relative_to(workspace)
        destination = artifact_root / relative
        if stat.S_ISDIR(metadata.st_mode):
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.append((PurePosixPath("workspace") / relative.as_posix()).as_posix())
        elif stat.S_ISREG(metadata.st_mode):
            identity = copy_regular(source, destination)
            total += identity["size"]
            files.append({"path": (PurePosixPath("workspace") / relative.as_posix()).as_posix(),
                          **identity})
        else:
            raise ValueError("workspace contains a special file")
        if len(files) > MAX_FILES or len(directories) > MAX_FILES or total > MAX_TOTAL_BYTES:
            raise ValueError("backup exceeds qualification file or byte limit")
    verify_evidence_links(artifact_root, database_view["runs"])
    with backup_path.open("rb") as stream:
        os.fsync(stream.fileno())
    for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        sync_directory(archive / name)
    manifest = {"version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                "files": files, "directories": directories, **database_view}
    write_manifest(archive / "manifest.json", manifest)
    sync_directory(archive)
    return manifest


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest repeats a field")
        result[key] = value
    return result


def verified_archive(archive):
    manifest_path = archive / "manifest.json"
    if regular_file(manifest_path).st_size > MAX_MANIFEST_BYTES:
        raise ValueError("qualification manifest exceeds its byte limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    if (not isinstance(manifest, dict) or manifest.get("version") != 1
            or not isinstance(manifest.get("files"), list)
            or not isinstance(manifest.get("directories"), list)):
        raise ValueError("qualification manifest has an unsupported format")
    files = manifest["files"]
    if not files or len(files) > MAX_FILES:
        raise ValueError("qualification manifest has invalid file count")
    expected = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ValueError("qualification manifest has an invalid file entry")
        name = safe_relative_path(entry["path"]).as_posix()
        if name != "database.sqlite" and not name.startswith("workspace/"):
            raise ValueError("qualification manifest names a file outside the workspace")
        if name in expected:
            raise ValueError("qualification manifest has a duplicate file")
        expected.add(name)
        identity = digest_file(archive / name)
        if entry["sha256"] != identity["sha256"] or entry["size"] != identity["size"]:
            raise ValueError("archive file digest or size changed")
        total += identity["size"]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("archive exceeds qualification byte limit")
    if "database.sqlite" not in expected:
        raise ValueError("archive has no database snapshot")
    actual = set()
    actual_directories = set()
    for path in archive.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("archive contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            actual.add(path.relative_to(archive).as_posix())
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.add(path.relative_to(archive).as_posix())
        else:
            raise ValueError("archive contains a special file")
    if actual != expected | {"manifest.json"}:
        raise ValueError("archive file set is incomplete or has extra files")
    directories = manifest["directories"]
    if (len(directories) > MAX_FILES or any(not isinstance(name, str) for name in directories)
            or len(directories) != len(set(directories))
            or any((name != "workspace" and not name.startswith("workspace/")) or
                   safe_relative_path(name).as_posix() != name for name in directories)
            or set(directories) != actual_directories):
        raise ValueError("archive directory set is incomplete or unsafe")
    view = inspect_database(archive / "database.sqlite")
    if any(manifest.get(name) != view[name] for name in
           ("runs", "approvals", "has_approval_table")):
        raise ValueError("archive database no longer matches its manifest")
    verify_evidence_links(archive / "workspace", view["runs"])
    return manifest


def restore(archive, destination):
    archive = Path(archive)
    if stat.S_ISLNK(archive.lstat().st_mode):
        raise ValueError("restore archive is a symlink")
    archive, destination = archive.resolve(), Path(destination).resolve()
    if not archive.is_dir() or destination.exists() or archive == destination or archive in destination.parents:
        raise ValueError("restore needs an existing archive and a new separate destination")
    manifest = verified_archive(archive)
    destination.mkdir(mode=0o700, parents=True)
    for name in sorted(manifest["directories"], key=lambda value: (value.count("/"), value)):
        (destination / name).mkdir(mode=0o700, parents=True, exist_ok=False)
    for entry in manifest["files"]:
        identity = copy_regular(archive / entry["path"], destination / entry["path"])
        if identity != {"sha256": entry["sha256"], "size": entry["size"]}:
            raise ValueError("archive changed during restore")
    copy_regular(archive / "manifest.json", destination / "manifest.json")
    verify_evidence_links(destination / "workspace", manifest["runs"])
    if inspect_database(destination / "database.sqlite") != {
        "runs": manifest["runs"], "approvals": manifest["approvals"],
        "has_approval_table": manifest["has_approval_table"]
    }:
        raise ValueError("restored database does not match manifest")
    for name in sorted(manifest["directories"], key=lambda value: value.count("/"), reverse=True):
        sync_directory(destination / name)
    sync_directory(destination)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("backup")
    create.add_argument("--database", required=True, type=Path)
    create.add_argument("--workspace", required=True, type=Path)
    create.add_argument("--archive", required=True, type=Path)
    reopen = commands.add_parser("restore")
    reopen.add_argument("--archive", required=True, type=Path)
    reopen.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "backup":
            result = backup(args.database, args.workspace, args.archive)
        else:
            result = restore(args.archive, args.destination)
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError) as error:
        print(f"Restore qualification refused: {error}", file=sys.stderr)
        return 2
    print(f"{args.command} verified: {len(result['runs'])} runs, "
          f"{len(result['approvals'])} approvals, {len(result['files'])} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
