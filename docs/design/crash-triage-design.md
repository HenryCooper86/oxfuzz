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

1. **Ingest** -- scan engine output dir for crash artifacts; copy into
   `fuzz_workspace/crashes/`.
2. **Classify** -- parse sanitizer log / engine log -> `CrashKind` + stack.
3. **Dedup** -- group by `stack_signature`; keep one representative per group.
4. **Minimize** -- call `engine.minimize` (afl-tmin / libFuzzer `-minimize_crash`).
5. **Draft report** -- LLM produces a bug report: title, summary, repro steps,
   stack, severity guess.
6. **HITL** -- human reviews, edits, and approves/closes.

## 4. Safety

- Crash inputs are untrusted; minimization runs in sandbox.
- Bug reports never auto-publish; HITL gate mandatory.

## 5. Tests

- Unit: dedup groups two crashes with the same top-3 frames.
- Unit: classify parses an ASan log into `CrashKind::Asan`.
- Integration: ingest from a mocked engine output dir.