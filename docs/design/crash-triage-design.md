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
   stack, severity guess, root cause, and suggested fix. The prompt
   (`hf_prompt::render_bug_report_prompt`, version 2) shows the code under
   test: the target's definition and the source lines around the faulting
   line (the log's innermost project frame, else CASR's crashline; `/work/`
   maps to the project root, read with containment checks). It carries the
   fault origin, CASR crash class, crashline and normalized frames, and the
   log fenced and bounded as untrusted output. The run's harness is labelled
   as the driver, not the code under test; the dedup hash is not sent. The
   prompt is retained in `crash_report_drafts` before dispatch and the
   response after, so a report is reconstructable from durable state. Every campaign report also carries a deterministic
   `CASR Vulnerability Verdicts` section. It records CASR's exploitability
   classification for every target finding, or states that CASR evidence is
   unavailable; it does not treat that classification as independent proof
   that the crash is a target vulnerability.
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

The deterministic CASR verdict section is rendered by `hf-service`, not left to
provider prose. Provider-composed campaign reports are checked at the operation
that returns them and receive the exact deterministic section when the provider
drops or changes it. This applies equally to dashboard, triage, CLI, REST, and
scheduled callers because they all use the same service operation. A report
with no target findings still includes the section and explicitly states that
there is no crash to classify.

The finding review DTO carries both the display symbol and an actionable target
selector derived by `hf-service` from the finding's exact retained run, harness,
and target. Latest report and `DefectDojo` actions submit that selector together
with the retained run identifier. Reproduction submits the selector and exact
crash identifier; the service recovers the crash's retained run and requires it
to be the latest selected-target run before reading the retained workspace. The
executing service operation still resolves the target and refuses stale action
selection. Legacy runs without retained corpus provenance use their bare-symbol
workspace; qualified Work Order runs keep the complete relative-file-qualified
selector. Presentation code never converts every finding to qualified form or
reconstructs this decision from the display symbol.

Re-triage preserves the identifier of an existing finding with matching run,
stack signature, and input provenance. A confirmed minimization retains the
original input path for this lookup even when the active input is the smaller
candidate. New identifiers include the complete input path so worker-local files
with the same basename remain distinct.

An optional remediation handoff may bind the reviewed finding, patch candidate,
minimized reproducer, exact run evidence manifest, and a later sandbox
verification result. A draft is explicitly unverified. The state can become
verified only when the service supplies matching original-crash, patched-replay,
and regression evidence as specified by
`proof-carrying-campaign-intelligence.md`.

When `patch-to-proof` is enabled, Triage can persist that handoff, record an
exact-scope human approval, and start the service-owned sandbox workflow
described in `patch-to-proof-design.md`. Draft or running state never changes a
finding's fix-verification determination.

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
- `minimized = true` requires successful native minimization followed by
  repeated independent sandbox confirmation of both original and candidate.
  Replay uses the retained binary and content-addressed image, read-only inputs,
  and no network. The original and candidate must reproduce the same nonempty
  normalized stack signature, crash kind, failure class, and origin on every
  attempt, and that identity must match the retained log and classification of
  the finding being minimized. The report retains that bounded reference log,
  run/finding identities, version, and requested repetition count. CASR findings
  without a comparable original sanitizer log remain explicitly unconfirmed.
  Failure categories exclude variable process IDs, addresses, and operand values;
  unrecognized categories cannot support confirmation. Clean exits, different failures, incomplete runs, and frameless
  reports cannot confirm identity. Native minimizer success alone is insufficient.
- `[triage] confirmation_runs` defaults to 3 (range 2–10), and
  `replay_timeout_secs` defaults to 10 (range 1–30). The existing total triage
  deadline still bounds the operation. Legacy runs without an immutable image
  remain classified but cannot receive confirmed minimized evidence.
- Crash records retain original/candidate paths and digests, binary/image
  identity, individual bounded replay logs and observed outcomes. Reproduction
  counts describe observations, never a promise of future determinism. Failed
  confirmation keeps the original input and log. Confirmed candidates use their
  actual replay logs; original logs are never relabelled as candidate evidence.
- Proof cards and markdown use one assessment of durable replay evidence. It
  recomputes matching from completed nonzero outcomes and actual logs, validates
  reference identity, count completeness, artifact identifiers and run-owned
  paths, and treats saved booleans only as consistency checks. A clean exit or
  missing reference cannot become confirmed by changing saved flags.
- Ingestion and report parsing enforce entry, per-file, and aggregate byte
  limits before allocating or replaying data. Truncation is surfaced rather
  than silently treating an unbounded directory as fully triaged.
- A timeout or cancellation is not a crash classification. Only a completed
  sandbox replay may produce a stack signature or a no-crash observation. A
  clean replay alone does not verify a fix; only the complete Patch-to-Proof
  workflow can establish fix verification. `RegressionResult.verified` records
  replay completion, never patch verification.
- Triage uses one bounded deadline across CASR, replay, and report drafting;
  forced CASR termination does not fan out into a longer fallback pass.
- Raw crash artifacts are interpreted by CASR or replayed only inside the
  sandbox. The host decodes only CASR's normalized JSON reports and accepts
  regular, non-symlink files through a deterministic walk capped by depth,
  report count, per-report bytes, and aggregate bytes.
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
- Unit: deterministic and provider-composed reports contain the complete CASR
  vulnerability-verdict section, including explicit unavailable and no-crash
  states.
- Integration: ingest engine-specific real/false-positive fixtures, directory
  floods, and oversized reports from a mocked engine output dir.
- Integration: mocked AFL++/libFuzzer minimizers receive only run-owned paths;
  successful output is persisted and timeout/non-zero/missing output never sets
  the minimized flag or replaces the original evidence path.
