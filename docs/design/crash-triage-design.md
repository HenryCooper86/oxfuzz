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
}
```

## 3. Pipeline

1. **Ingest** -- classify filenames with the producing engine's contract and
   scan only a bounded number of regular, non-symlink artifacts. AFL++ accepts
   entries below instance `crashes/` directories except `README.txt`;
   honggfuzz accepts `SIG*.PC.*`; libFuzzer-family engines accept their known
   `crash-`, `leak-`, `timeout-`, and `oom-` prefixes. Coverage corpus files,
   reports, metadata, and unknown names are not crash evidence.
2. **Classify** -- parse sanitizer log / engine log -> `CrashKind` + stack.
3. **Dedup** -- group by `stack_signature`; keep one representative per group.
4. **Minimize** -- call `engine.minimize` (afl-tmin / libFuzzer `-minimize_crash`).
5. **Draft report** -- LLM produces a bug report: title, summary, repro steps,
   stack, severity guess.
6. **HITL** -- human reviews, edits, and approves/closes.

## 4. Safety

- Crash inputs are untrusted; minimization runs in sandbox.
- Ingestion and report parsing enforce entry, per-file, and aggregate byte
  limits before allocating or replaying data. Truncation is surfaced rather
  than silently treating an unbounded directory as fully triaged.
- A timeout or cancellation is not a crash classification. Only a completed
  sandbox replay may produce a stack signature or a "fixed" regression result.
- Triage uses one bounded deadline across CASR, replay, and report drafting;
  forced CASR termination does not fan out into a longer fallback pass.
- Bug reports never auto-publish; HITL gate mandatory.

## 5. Tests

- Unit: dedup groups two crashes with the same top-3 frames.
- Unit: classify parses an ASan log into `CrashKind::Asan`.
- Integration: ingest engine-specific real/false-positive fixtures, directory
  floods, and oversized reports from a mocked engine output dir.
