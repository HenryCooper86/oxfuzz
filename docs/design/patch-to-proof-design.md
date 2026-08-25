# Patch-to-Proof

Status: **active implementation**. Owner: `hf-service`, with evidence types in
`hf-crash`, persistence in `hf-storage`, sandbox execution in `hf-runtime`, and
rendering in `hf-gui`.

## 1. Goal

Turn a reviewed patch candidate into a durable verification result without
allowing a draft, model response, exported directory, or presentation-supplied
boolean to claim that a finding is fixed.

The first release supports findings produced by AFL++, honggfuzz, and
libFuzzer-family harnesses. Syzkaller verification remains unavailable because
its kernel build, VM reset, and reproducer requirements need a separate typed
workflow. A visible unavailable result is preferable to reusing userspace
assumptions for a kernel finding.

## 2. Feature and Ownership

The subsystem is enabled by the `patch-to-proof` feature, which depends on
`proof-carrying`. `hf-service` owns every workflow transition and all derived
status. REST and Tauri serialize service requests and views. React renders the
view and collects an explicit confirmation; it does not derive verification
from command output or crash fields.

`hf-crash` owns remediation evidence version 3. Version 3 corrects the previous
binary identity model by naming the original binary in the immutable binding
and the patched binary separately in execution evidence. The patched digest is
not known until the approved sandbox build completes and therefore cannot be
copied from the original binding.

## 3. Durable Workflow

`hf-storage` retains one `remediation_operations` row per attempt. The row
contains the immutable binding JSON, exact approval scope, current stage,
terminal evidence, bounded failure information, and an operation-owned artifact
directory.

The allowed states are:

```text
draft -> approved -> running -> verified
                             -> rejected
                             -> inconclusive
```

Only the service draft operation inserts `draft`. Only the explicit approval
operation may transition the exact row to `approved`. Only the execution
operation may claim `approved`, set `running`, and produce a terminal state.
Every transition is compare-and-set in SQLite. Retrying a stale transition
fails rather than overwriting newer evidence.

On startup, a `running` row has no live sandbox process and becomes
`inconclusive` with `interrupted_after_restart`. Draft and approved rows remain
reviewable. Terminal evidence is retained.

## 4. Immutable Review Scope

The binding names:

- finding and run UUIDs;
- original source revision;
- patch text and SHA-256;
- minimized reproducer SHA-256;
- approved harness source SHA-256;
- original binary SHA-256;
- pinned sandbox image SHA-256;
- campaign evidence manifest SHA-256;
- retained regression corpus SHA-256; and
- the complete verification specification and its SHA-256.

The specification contains the replay deadline, regression-case ceiling,
follow-up fuzzing duration, memory, CPU, engine, and deterministic seed. The
service resolves it before draft persistence. Approval records a UUID,
operator label, timestamp, and SHA-256 of the complete immutable scope.

Patch paths must be relative source paths. Absolute paths, parent traversal,
backslashes, NUL, version-control metadata, generated output directories, and
empty file names fail draft validation. The patch is applied only to an
operation-owned source snapshot.

## 5. Sandboxed Verification

After durable approval and guardrail authorization, the service performs these
steps through `hf-runtime` with the pinned image and no network access:

1. **Original replay** -- execute the exact retained original binary with the
   exact minimized reproducer. If the finding does not reproduce normally, the
   result is inconclusive and later steps are skipped.
2. **Patch and build** -- copy the current staged source snapshot into the
   operation directory, prove that its digest still equals the original source
   revision, apply the reviewed patch with fixed arguments, and compile the
   approved harness. A patch or build failure rejects the candidate.
3. **Patched replay** -- execute the patched binary with the same reproducer. A
   matching crash rejects the candidate. Timeout, cancellation, or sandbox
   failure is inconclusive.
4. **Regression corpus** -- replay a bounded, deterministic ordering of the
   retained starting corpus. An empty set is inconclusive; a crash rejects the
   candidate.
5. **Follow-up fuzzing** -- run the original engine against a disposable copy
   of the retained corpus for the approved duration and seed. A new crash
   rejects the candidate. Missing completion is inconclusive.

Each command uses an operation-owned writable directory below the managed
workspace. The original run inputs and corpus remain read-only. The service
revalidates retained digests before the first command and the patched binary
digest before every patched execution.

## 6. Evidence and Result Rules

Each stage is `passed`, `failed`, `inconclusive`, or `skipped`, with a stable
detail code and bounded counters. Terminal status is derived in one function:

- any inconclusive required stage makes the attempt `inconclusive`;
- otherwise any failed stage makes it `rejected`;
- all five required stages passed makes it `verified`;
- every other combination is `inconclusive`.

Exact input mismatches fail without mutating the retained row. A completed
verified claim is revalidated from the immutable binding and terminal evidence
whenever it is read.

The Finding Proof Card uses the latest terminal remediation for the finding.
`verified`, `rejected`, and `inconclusive` retain those exact meanings. Draft,
approved, running, missing, feature-disabled, or unreadable data remains
`not_verified` or `unavailable`; it is never converted to a positive result.

## 7. Operator Experience

The selected Triage finding contains a Patch-to-Proof panel:

- bounded unified-diff editor and follow-up duration;
- draft review with immutable digest summary;
- explicit confirmation before sandbox execution;
- durable status and current-stage polling;
- five stage results with evidence references; and
- optional draft-bundle export after persistence.

Closing the application does not lose the operation. A restarted application
shows an interrupted run as inconclusive and allows a new attempt. Pull-request
creation is not part of this phase; a verified result remains a reviewable
handoff until a later, separately approved integration is added.

## 8. Rejected Alternatives

- **Accepting verification booleans over REST or IPC** -- a caller could bypass
  the executor that actually runs the checks.
- **Scanning exported remediation directories** -- mutable files outside the
  indexed workflow cannot supply authoritative state.
- **Using a clean patched replay alone** -- it omits original reproduction,
  regression, and follow-up evidence.
- **Binding the patched binary to the original binary digest** -- a source patch
  normally changes the binary; equality would prove the wrong artifact.
- **Running synchronously from the UI** -- it hides intermediate durable state
  and cannot recover an interrupted desktop session.
- **Host patching or execution** -- all patch application, compilation, replay,
  and fuzzing operate through `hf-runtime`.

## 9. Verification Criteria

- Domain tests reject every identity mismatch and unsafe patch path.
- Storage tests prove compare-and-set transitions, immutable scope, cleanup,
  and interrupted-run recovery.
- Service tests prove command order, read-only original inputs, bounded limits,
  terminal status derivation, and no execution before approval.
- Cancellation, timeout, missing corpus, patch failure, build failure, and new
  crashes produce their documented terminal state.
- A verified result requires matching original replay, patched replay,
  non-empty regression, and completed follow-up fuzzing evidence.
- Finding Proof Card, REST, Tauri, and GUI consume the same service-owned view.
- Feature-disabled builds compile and show fix verification as not verified.
- Tests use runtime doubles and execute no generated harness, target, patch,
  fuzzer, or host process.
