# Disposable backup and restore qualification

Status: implemented for A3 acceptance. Owner: `scripts/qualify_restore.py`; this is
an operator-run probe, not a production backup API.

## Scope and sequence

The caller selects a file-backed SQLite database, its managed workspace root,
and a new private archive directory outside both inputs. The probe uses
SQLite's online backup API while the source remains open in WAL mode. It then
copies regular workspace files, retaining SHA-256 and size for every file.
Symlinks, special files, missing inputs, and changed source files fail the
backup. The archive remains marked incomplete until the database and every
file have been flushed and a bounded manifest is written last.

Restore takes an existing archive and a new disposable destination. It checks
the manifest schema, file names, complete file set, file hashes, SQLite
integrity, and the retained approval/run counts before writing the destination.
It then copies verified files and opens the restored database read-only. Every
non-null run `evidence_dir` must resolve to one shallowest directory under the
restored workspace. Deeper copies inside a run's retained input snapshot do
not count as another owner; ties at the shallowest depth are refused. The probe
never executes a restored harness or fuzzer.

The database snapshot and workspace copy are separate operations. For this
qualification, referenced run artifacts must already be immutable while an
unrelated SQLite writer remains active. A database row that points to a file
being changed during the copy is refused; this procedure does not claim an
atomic snapshot of a mutable project tree.

The older-schema probe uses `sqlx` to build a real pre-0019 migration database,
backs it up through the same script, restores it, and opens it with the current
`Store`. That final open applies all remaining migrations and verifies the
retained run and artifact link without inventing a historical approval.

## Acceptance

- A writer can commit to the source WAL while the online database backup runs.
- Restored approvals, run IDs, and evidence-directory links match the backup
  manifest and can be read from the restored database.
- A missing file, changed hash, extra file, unsafe path, or truncated manifest
  refuses restore before the destination is created.
- A database built from migrations 0001 through 0018, before the approval
  table existed, also survives backup and restore without inventing approvals.
- The probe leaves incomplete evidence for inspection and never deletes or
  mutates the source database or workspace.
