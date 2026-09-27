# Disposable SQLite/WAL and artifact restore, 2026-09-27

Outcome: **passed for the approved A2 fixture's retained database and workspace**
on a local macOS arm64 host. This is partial A3 recovery evidence.

The probe ran from clean commit
`1dd5ee3cb2cf139b8a1d1d2d2067e9dd3584afe0`. The
[script](../../scripts/qualify_restore.py) had SHA-256
`aa507a300cf1e0b5cf7b504f65e29a2a695903878ab37fd8cc4ab8b33af820c7`.
Its [synthetic tests](../../scripts/tests/test_qualify_restore.py) had SHA-256
`35e11d970f6e210b86c47dc365e339d647273548eded1b486706a0a9f087fb80`.
The `script-tests` gate passed 129 Python and 18 Node tests.

An online SQLite backup of A2 cycle 10 and its workspace produced a private,
owner-only archive. A separate destination restored **9 run rows, 3 human
approval rows, 9 non-null run evidence links, and 386 hashed files**. The
restored database passed `PRAGMA integrity_check`; every run evidence link
resolved to its owning directory, including empty output directories. The
archive and restored copy each occupied about 38 MiB. The archive manifest at
`/Users/admin/.codex/qualification-evidence/a3-backup-restore-2026-09-27/archive-v4/manifest.json`
has SHA-256 `f2b9b500f1cd73059914b47b4253eea85fdc5198243201f9c854a732ee95af4c`.

The unit suite also commits through an active source WAL writer during online
backup, restores a database built from migrations 0001 through 0018, and
refuses missing, changed, extra, unsafe, and truncated archive entries before
creating the restore destination. Earlier incomplete local trials remain
outside the repository and are not counted as passing evidence.

The A2 database was no longer being written during this live fixture copy;
the active-writer behavior is covered by the synthetic test. Database and
workspace files are copied in separate steps, so this probe applies to
immutable referenced artifacts and does not establish an atomic backup of a
changing project tree. It does not run restored harnesses, check application
migration of the older fixture, or satisfy the remaining service-fault and
12-hour-soak scenarios.
