# Crash Triage Design

Status: **draft**. Owner: `hf-crash`.

## 1. Goal

Ingest crash artifacts from a fuzz run, deduplicate, minimize, and produce a
draft bug report for human review.

## 2. Crash

```rust
pub struct Crash {
    pub id: Uuid,
    pub run_id: Uuid,
    pub target_id: Uuid,
    pub input_path: PathBuf,
    pub stack_signature: String,   // sha256 of top-N frames
    pub kind: CrashKind,           // Asan | Ubsan | Segv | Abort | ...
    pub summary: String,
    pub minimized: bool,
    pub bug_report: Option<BugReport>,
    pub casr: Option<CasrReport>,  // exploitability, when CASR ran
    pub origin: CrashOrigin,       // Target | Harness | Runtime | Unknown
}
```

## 3. Pipeline

1. **Ingest** -- classify filenames with the producing engine's contract and
   scan only a bounded number of regular, non-symlink artifacts. AFL++ accepts
   entries below instance `crashes/` directories except `README.txt`;
   honggfuzz accepts `SIG*.PC.*`; libFuzzer-family engines accept their known
   `crash-`, `leak-`, `timeout-`, and `oom-` prefixes. Coverage corpus files,
   reports, metadata, and unknown names are not crash evidence.
2. **Classify** -- parse sanitizer log / engine log -> `CrashKind` + stack,
   and from the same read, which layer the fault lies in. oxfuzz's harnesses are
   LLM-authored, so a fault inside the harness is an expected failure mode
   rather than an unusual one; without this every downstream artifact presents a
   harness bug as a finding about the project. The verdict keys on the first
   non-runtime frame: an ASan frame `#0` is the faulting access, so a target bug
   reached through the harness still reports `#0` inside the target, and only a
   fault whose innermost non-runtime frame is the harness is a harness defect.
   Classification uses names oxfuzz itself writes -- the harness source is
   always `harness.<ext>` and the engine entry points are fixed -- so it is a
   lookup, not a heuristic. A report with no symbolized frames is `Unknown`
   rather than guessed.
3. **Dedup** -- group by `stack_signature`; keep one representative per group.
4. **Minimize** -- call `engine.minimize` (afl-tmin / libFuzzer `-minimize_crash`).
5. **Draft report** -- LLM produces a bug report: title, summary, repro steps,
   stack, severity guess.
6. **HITL** -- human reviews, edits, and approves/closes.

## 4. Reporting Origin

A `CrashOrigin::Harness` crash is a harness bug to fix, not a statement about
the project under test, so it is excluded from the findings list, every severity
and kind count, both Mermaid charts, SARIF results, and DefectDojo findings. It
is listed instead under its own report section, which says what it is and why it
sits apart.

Nothing is hidden or deleted: the crash is still ingested, still persisted, and
still visible in the crash list. The separation is applied inside the renderer
and each exporter rather than at their call sites, so a caller assembling report
data directly gets the same result. SARIF filters before computing the per-CWE
maximum severity, which would otherwise let a harness defect raise a rule's
score with no result of its own. `DefectDojo` has its own mapper rather than
reusing the SARIF path and carries the same filter; filing a finding is not
reversible.

An optional remediation handoff may bind the reviewed finding, patch candidate,
minimized reproducer, exact run evidence manifest, and a later sandbox
verification result. A draft is explicitly unverified. The state can become
verified only when the service supplies matching original-crash, patched-replay,
and regression evidence as specified by
`proof-carrying-campaign-intelligence.md`.

## 5. Safety

- Crash inputs are untrusted; minimization runs in sandbox.
- Minimization accepts only a bounded regular crash artifact owned by the exact
  persisted run. The original run output remains immutable. Derived artifacts
  are written below `runs/<run-id>/triage/minimized` through a fresh partial
  file and atomically published only after validation.
- The primary workspace, staged harness, and original crash input are mounted
  read-only. Only the run-owned minimization directory is writable; networking
  remains disabled and the command is constructed as argv without a shell.
- A triage pass attempts at most 20 unique crashes. Only AFL++ and libFuzzer
  use their native minimizers; unsupported engines retain the original input
  and `minimized = false`.
- `minimized = true` means the sandbox completed with status zero and produced
  a non-empty regular file within the crash-input size ceiling. Timeout,
  cancellation, non-zero exit, missing/oversized output, or atomic publication
  failure leaves the original crash unchanged and is surfaced in diagnostics.
- Ingestion and report parsing enforce entry, per-file, and aggregate byte
  limits before allocating or replaying data. Truncation is surfaced rather
  than silently treating an unbounded directory as fully triaged.
- A timeout or cancellation is not a crash classification. Only a completed
  sandbox replay may produce a stack signature or a "fixed" regression result.
- Triage uses one bounded deadline across CASR, replay, and report drafting;
  forced CASR termination does not fan out into a longer fallback pass.
- Bug reports never auto-publish; HITL gate mandatory.

## 6. Tests

- Unit: dedup groups two crashes with the same top-3 frames.
- Unit: classify parses an ASan log into `CrashKind::Asan`.
- Unit: a fault whose innermost non-runtime frame is `LLVMFuzzerTestOneInput`
  or a `harness.*` file classifies as `Harness`; a fault in project code
  through the same harness classifies as `Target`; a frameless log is `Unknown`.
- Unit: a crash persisted before `origin` existed decodes as `Unknown` rather
  than failing, so no migration is needed.
- Integration: a harness-origin crash appears in the report's harness-defect
  section and in neither the findings list, the SARIF results, nor the
  `DefectDojo` findings.
- Integration: ingest engine-specific real/false-positive fixtures, directory
  floods, and oversized reports from a mocked engine output dir.
- Integration: mocked AFL++/libFuzzer minimizers receive only run-owned paths;
  successful output is persisted and timeout/non-zero/missing output never sets
  the minimized flag or replaces the original evidence path.
