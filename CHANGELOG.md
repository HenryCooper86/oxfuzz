# Changelog

Notable user-facing changes, newest first. Entries are written when a change
lands rather than at release time: section 1 of `docs/guides/RELEASE_CHECKLIST.md`
asks the releaser to review user-facing changes, migrations, and configuration
compatibility, and this is what that review reads from.

Versions match the release commits that bump `Cargo.toml`.

## Unreleased

### Added

- **The 90-second CVE-pattern rediscovery demo.**
  `scripts/demo-cve-rediscovery.sh` runs the full pipeline against a
  deliberately vulnerable example target -- discovery, harness qualification,
  the human promotion gate (the script stops and waits), a bounded fuzz run,
  and triage -- ending in the rediscovery of a planted length-field-trust
  bug, the pattern behind a long line of real parser CVEs. Honest by design:
  the fixture is modeled on the CVE class, never claimed as a specific
  historical CVE. `--preflight-only` checks readiness side-effect-free.
- **External corpora can be imported.** `oxfuzz corpus import --project ...
  --target ... --from <dir>` brings an OSS-Fuzz corpus checkout (or any flat
  corpus directory) into the target's corpus: bounded, hash-deduplicated,
  content-addressed, and idempotent -- re-importing adds nothing. A source
  path that is not a regular directory fails loudly.
- **Coverage attribution ranks the whole inventory for the next harness.**
  `oxfuzz attribution <project>` attributes every discovered target against
  the union of retained coverage -- untouched, partial (the stall frontier),
  or saturated -- and orders the list untouched-first, saturated-last, with
  discovery's own order preserved inside each tier and no score rewritten.
  Saturated targets stop headlining the next-harness list even when their
  static score is the project's highest.
- **Dying seeds can now be regenerated.** `oxfuzz corpus regen <project>
  <target>` runs one bounded pass: remove the generated seeds the survival
  metric flags as dying at entry, request that many replacements from the
  provider, write them, and re-measure so the outcome reports how the
  replacements fared. Only entries in the reserved generated-seed name
  namespace (`seed_`, `llmseed_`, `regen_`) are eligible; earned inputs are
  never removed.
- **Seed survival is now measured.** `oxfuzz corpus survival <project>
  <target>` runs each corpus seed once through `afl-showmap` on the promoted
  AFL++ harness and classifies it against the empty input's edge coverage:
  seeds that reach past the harness's entry validation, seeds that die at it
  (the most common reason a seed corpus finds nothing), and seeds that could
  not be measured are counted separately, with a survival ratio. Read-only
  and advisory: it tells the operator which seeds to regenerate.
- **Harness drafts learn from accepted harnesses.** The draft prompt is
  conditioned on the project's previously promoted harnesses (accepted
  examples): house style, entry-point shape, and working include paths, read
  from the persisted harness records -- at most two, same language as the
  target, each source bounded. Projects without promotions draft exactly as
  before.
- **Harness lint now covers Rust and Python harnesses.** Lexical rules are
  scoped per language: Rust (cargo-fuzz) harnesses are checked for
  `std::process::exit`, `Command::new`, `thread::sleep`, socket use, and
  `catch_unwind`; Python (Atheris) harnesses for `sys.exit`, `subprocess`,
  `time.sleep`, socket use, `random`, and bare `except:`. Go still returns no
  findings (unchecked rather than clean). Harness Work Order packets now carry
  exactly the rules that apply to the target's language instead of the C table
  for every language.
- **Repair prompts now receive summarized compiler diagnostics.** Distinct
  diagnostic lines (clang/GCC and rustc formats) are extracted, deduplicated,
  and bounded before reaching the model, instead of a raw head-truncated dump
  that could spend the whole budget on build noise before the first error.
- **A coverage gate measures the TEST_STRATEGY targets.** `scripts/tests/gates.sh
  coverage` reports per-crate line coverage for the four domain crates via
  cargo-llvm-cov, and CI records it on every push; thresholds are not enforced
  until a trusted baseline exists.

### Changed

- Corrected stale documentation references: the repository layout no longer
  lists nonexistent `config/agents/` and `skills/` directories, the harness
  prompt template location now names the real renderer, and the design
  overview's dead "y-agent" rows name their actual owners.

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

- **Patch-to-Proof is unavailable on Windows in this release.** The service
  fails closed before creating a remediation draft because secure
  handle-relative reads of retained crash evidence are not implemented there.
  Use Patch-to-Proof on Linux or macOS; Windows does not fall back to a
  canonicalize-then-open read.

- **Processes oxfuzz spawns on the host no longer inherit its environment.**
  The `docker` CLI, `git`, `pandoc`, the DefectDojo lifecycle commands, and the
  daemon-start helpers now start from a scrubbed copy: variables whose names
  contain `KEY`, `SECRET`, `TOKEN`, or `PASSWORD`, plus everything prefixed
  `HF_`, are dropped. `PATH`, `HOME`, locale, and proxy settings survive. If a
  helper on your system needed one of the dropped variables, it will no longer
  see it.
