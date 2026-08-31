# Changelog

Notable user-facing changes, newest first. Entries are written when a change
lands rather than at release time: section 1 of `docs/guides/RELEASE_CHECKLIST.md`
asks the releaser to review user-facing changes, migrations, and configuration
compatibility, and this is what that review reads from.

Versions match the release commits that bump `Cargo.toml`.

## Unreleased

## 0.3.0 - 2026-08-31

### Added

- **Native C/C++ analysis now complements optional Semgrep enrichment.** The
  bounded tree-sitter analyzer reports deterministic memory, lifetime,
  arithmetic, and dangerous-API signals, with measured benchmark recall and
  no observed false positives on the retained evaluation corpus.
- **Harness generation now consumes real project build context.** Nested C/C++
  sources retain their layout, compile databases supply allowlisted include
  paths, definitions, and language standards, generated source is linted
  before sandbox compilation, and crash reports distinguish harness defects
  from target findings.
- **Bounded concolic corpus enrichment is available through CLI and REST.**
  SymCC with the QSym backend runs only through the sandbox, enforces input and
  time limits, and promotes solver-produced inputs only when their content is
  novel.
- **Harness Work Order v2 provides durable provider-free authoring.** Operators
  can export content-addressed target evidence, import immutable external
  candidates, qualify them through sandbox compile, independent review, and
  smoke stages, rank retained attempts, and explicitly promote one exact
  qualified revision.
- **Evidence-backed professional workflows cover the campaign lifecycle.**
  Finding proof cards, sandboxed patch verification, change-aware comparison,
  build diagnosis, non-crash oracles, coverage-blocker ranking, crash
  disposition, campaign trust and health, unreached-surface reporting, and
  resumable run closeout are available through service-owned operations.
- **Automotive workflows now include responder modeling, state-sequence
  planning, state coverage, and approved state-corpus promotion** across CLI,
  REST, and desktop surfaces.
- **Syzkaller campaigns persist runs and ingest kernel crash evidence** through
  the existing sandboxed campaign and triage path.

### Changed

- Existing SQLite stores migrate automatically on first open. Work-order,
  campaign-evidence, automotive, and run-closeout records are retained as
  durable service evidence.

- **The campaign scheduler starts disarmed, and missed occurrences are held
  until it is armed.** A schedule with a `catch_up` or `backfill` missed policy
  used to replay everything it missed as soon as the process came back up.
  Recovery still restores that work, but it now waits for an explicit decision:
  `POST /schedule/arm`, or `oxfuzz arm` for a headless server (`--status` to
  check, `--off` to withdraw). A restart on its own is no longer treated as
  consent to resume a campaign that may be hours stale and pointed at a project
  which has changed in the meantime.

  **If you rely on catch-up firing automatically after a restart, you must now
  arm the server.** Nothing fires until you do, and held work is discarded on
  shutdown.

- **Oversized tool results are written to disk and replaced with a preview plus
  a locator**, instead of being truncated to a head and tail with the middle
  discarded. Artifacts live under the app's private state directory beside the
  run journal, not in your project. The store bounds itself at roughly 256 MiB,
  evicting the oldest artifacts as new ones arrive.

### Security

- **Windows Harness Work Order exports now use handle-relative project reads.**
  Ordinary project files work on Windows while link-like parent and leaf
  components remain rejected; source metadata, size validation, and bounded
  reads use one opened handle.

  **Known Windows limitation:** the project-root pathname is reopened after
  canonicalization. Another local process that can rename that selected root
  and create a directory junction in its parent could redirect the confined
  read. Until root-handle hardening lands, keep the selected project parent
  trusted and immutable during export, or avoid Harness Work Order export on
  Windows.

- **Processes oxfuzz spawns on the host no longer inherit its environment.**
  The `docker` CLI, `git`, `pandoc`, the DefectDojo lifecycle commands, and the
  daemon-start helpers now start from a scrubbed copy: variables whose names
  contain `KEY`, `SECRET`, `TOKEN`, or `PASSWORD`, plus everything prefixed
  `HF_`, are dropped. `PATH`, `HOME`, locale, and proxy settings survive. If a
  helper on your system needed one of the dropped variables, it will no longer
  see it.
