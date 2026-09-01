# Windows-Confined Harness Work-Order Reads

Status: **approved for implementation**. Owner: `hf-service`. Target release:
`v0.3.0`.

## 1. Goal

Harness Work Order export must read an ordinary retained source file on Windows
without weakening the existing project-root and non-symlink requirements.
Linux and macOS accepted inputs and errors remain unchanged.

## 2. Confirmed failure

The exact `main` commit `94ba68e2` passes the complete local macOS workspace
suite but fails the GitHub Windows test job. Three REST tests reach ordinary
work-order export and receive `invalid_project_path` instead of a successful
packet.

The source-to-file-open path is:

1. `hf-web` approves the requested project root and calls
   `ServiceContainer::export_harness_work_order`.
2. `hf-service` canonicalizes the project, loads the retained target, and
   reduces its source to non-empty `Component::Normal` path components.
3. `project_relative_regular_file` validates one opened handle, after which
   `source_evidence` opens the path again for the bounded read.
4. Unix opens the root and every component with descriptor-relative
   `openat`, `NOFOLLOW`, and `CLOEXEC`.
5. The non-Unix implementation always returns
   `descriptor-confined project reads are unavailable on this platform`.

The Windows failure is therefore an intentional platform stub, not a fixture,
REST, storage, or discovery defect.

## 3. Required behavior

The file-open operation must preserve these properties:

- the project root is the already canonical service-owned root;
- the project-root handle is opened without following a name-surrogate reparse
  point and cannot be renamed or deleted while traversal uses it;
- every supplied relative component is a normal component;
- each parent component is opened relative to the previously opened directory;
- a link-like parent or final component is rejected;
- the returned handle names a regular file;
- metadata, size checks, and reads apply to the returned handle rather than a
  path checked earlier; and
- failures continue to use `invalid_project_path` without exposing a host path
  or operating-system diagnostic.

Ordinary nested files remain valid. Export still invokes no provider, runtime,
build, review, smoke run, or promotion.

On Windows, a name-surrogate reparse point is link-like. Non-name-surrogate
reparse points, such as hydrated cloud files, remain eligible when Windows
reports the opened handle as a regular file. Opening the final component with
`FILE_FLAG_OPEN_REPARSE_POINT` prevents normal reparse processing while its
handle is classified.

## 4. Selected implementation

Keep the current Unix `rustix` traversal and add `NONBLOCK` to the final open so
a non-regular node cannot stall before it is classified. Replace the Windows
stub with the following sequence:

1. Collect and revalidate normal path components.
2. Open the canonical project root with `cap_primitives::fs::open_ambient`,
   `FILE_FLAG_BACKUP_SEMANTICS`, and `FILE_FLAG_OPEN_REPARSE_POINT`; omit
   delete sharing and reject the returned handle unless Windows reports a
   directory rather than a name-surrogate reparse point.
3. Open every parent component individually with
   `cap_primitives::fs::open_dir_nofollow`.
4. Open the final component relative to the last directory handle with
   `cap_primitives::fs::open`, read-only, and
   `FILE_FLAG_OPEN_REPARSE_POINT`.
5. Return the `std::fs::File` handle to common source-evidence code.

The common code is adjusted so one operation validates the relative path,
opens the file, reads metadata from that handle, applies the regular-file and
size requirements, and then performs the bounded read and digest through the
same handle. Export and qualification receive the validated relative path and
source evidence together. This removes the current three separate opens per
source-evidence calculation and the validation-to-use gap between them.

`cap-primitives` is a Windows-only `hf-service` dependency. Its Windows
implementation uses `NtCreateFile` with an open directory as
`OBJECT_ATTRIBUTES.RootDirectory`. The explicit root options and subsequent
directory opens omit `FILE_SHARE_DELETE`, preventing each active directory
handle from being renamed or deleted while traversal uses it. Version `4.0.3`
is selected.
The known special-device-name traversal issue affected versions before `3.4.1`
and is fixed in the selected version.

`windows-sys` is also a Windows-only direct dependency so the implementation
uses the named `FILE_FLAG_OPEN_REPARSE_POINT` constant rather than repeating a
numeric Windows API value.

Primary references:

- [cap-std capability filesystem design](https://github.com/bytecodealliance/cap-std/blob/main/README.md)
- [CreateFileW reparse-point behavior](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Windows reparse-point operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations)
- [Rust Windows `OpenOptionsExt`](https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html)
- [patched cap-primitives device-name advisory](https://github.com/bytecodealliance/cap-std/security/advisories/GHSA-hxf5-99xg-86hw)

## 5. Tests

The existing failing Windows REST exports are the initial red evidence. Add
focused service regressions before production code:

- an ordinary nested retained source exports successfully on Windows;
- a retained source reached through a Windows directory junction is rejected;
- a canonical project-root pathname replaced by a Windows directory junction
  before the confined open is rejected;
- absolute paths and parent traversal retain their existing cross-platform
  rejection;
- oversized and non-regular sources retain their existing stable errors; and
- Unix symlink rejection remains green.

The Windows junction fixture uses the operating system's junction creation
operation and asserts that setup succeeds, so a missing security fixture cannot
be mistaken for a passing denial test.

Focused verification includes `cargo check -p hf-service` for the Windows MSVC
target when the local toolchain supports it, the `hf-service` and `hf-web`
work-order tests, and the exact-commit GitHub Windows job. The release tag is
blocked until that job and every other CI job are green.

## 6. Dependency and release checks

Adding the Windows-only dependencies requires:

- `cargo deny check` for advisory, license, source, and duplicate-version
  policy;
- the repository's no-default-features check;
- the ordered Rust gates and full filtered workspace suite;
- the complete release checklist, including sandbox checks; and
- verification that the exact candidate commit builds all four release
  targets before `v0.3.0` is published.

## 7. Rejected alternatives

### Keep Windows export unavailable

Rejected because Harness Work Order is enabled in Windows products and the
release workflow ships Windows installers. A feature that always fails on an
advertised platform is not an acceptable `v0.3.0` result.

### Canonicalize a joined path and then call `File::open`

Rejected because validation and use would be separate filesystem operations.
A parent could be replaced between them, and the opened object would not be the
one whose location was approved.

### Handwrite a `CreateFileW` and final-path comparison loop

Rejected because `FILE_FLAG_OPEN_REPARSE_POINT` applies to the final component,
so every parent needs separate handling. Correct handling also needs rename
prevention, Windows device-name rules, reparse classification, long paths, and
handle-relative opening. Reimplementing those details adds unnecessary unsafe
code to `hf-service`.

### Replace the existing Unix traversal

Rejected for this release. The `rustix` descriptor traversal is already green
and directly expresses the required Unix behavior. Only its final flags and
the shared single-handle validation flow change; a cross-platform traversal
rewrite would increase release risk without fixing another observed failure.
