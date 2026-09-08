# Fuzzing engineer daily-work delivery evidence

This record identifies the delivered phases, support corrections, and measured
verification used by the operator guides. It preserves the original assessment
in [2026-09-07-fuzzing-engineer-daily-work.md](2026-09-07-fuzzing-engineer-daily-work.md)
as historical source inspection. It does not reinterpret that assessment as a
live campaign result.

## Delivered phases

| Phase | Commit on `origin/main` | Delivered behavior | Final recorded local results |
| --- | --- | --- | --- |
| 1 | `55b73f6efbe948e8900bdf9dab43c9b925eeaf37` | Observational cross-revision findings, matched retained settings for descriptive coverage comparison, and qualified issue/DefectDojo wording | 2,950 Rust, 344 GUI, 85 script; 0 failed; 4 existing Rust ignores |
| 2 | `0b203b61c165e83a695056c84c4fe325bf102e7f` | Durable finding queue, exact historical selection and project ownership, and guarded latest-run report/publication operations | 2,963 Rust, 351 GUI; 0 failed; 4 existing Rust ignores |
| 3 | `020265d84ce0c7176b1817f6aabc3eefaf653d8f` | Retained external Work Orders with exact-attempt approval, resumable closeout, and exact review evidence in the desktop app | 2,989 Rust, 374 GUI; 0 failed; 4 existing Rust ignores |
| 4 | `1b3b575d8894b9fced2722f15c153b8487940af3` | Exact corpus import accounting, qualified desktop survival/reduction operations, and stale-scope UI isolation | 3,002 Rust, 391 GUI; 0 failed; 4 existing Rust ignores |
| 5 | `f1b7e154276f120f94d9a470b79d3bb04952b963` | Retained Campaign Health, cumulative telemetry, request-scoped run admission identity, and owned run-output isolation | 3,042 Rust, 461 GUI in 63 files; 0 failed; 4 existing Rust ignores; 91.09% measured domain line coverage |
| 6 | `8e93d817c152fb271751b461052f12a86f0ec5ba` | Configurable CMake/plain-Make profiles, sandbox build plan/history, immutable compilation inputs, and proactive desktop readiness | 3,155 Rust, 479 GUI; 0 failed; 91.12% measured domain line coverage; the later one-file disabled-CLI correction had 4 default and 2 feature-off focused tests |
| 7 | `f8cb49f4dd45fc642553d615ce3a45c5fb1db465` | Retained coverage experiments, strict setup comparison and run-reference protection, authorized REST/native access, and the Corpus proposal/history/result workflow | 3,212 Rust, 507 GUI in 69 files, 85 script; 0 failed; 6 Rust ignores; 91.12% measured domain line coverage |

The Phase 1-4 measured domain aggregate stayed at 91.09%. These percentages
cover the specified fuzzing-domain crates; they are not whole-product coverage
and do not measure live fuzzing effectiveness.

## Support corrections and hosted CI

- `2425c1cf49d2ec6bb40497acc39d4e3902713490` corrected the required llvm-cov
  subcommand. `c88dea27293f79212011f95deedf61fe9dc2e42f` guarded CLI unreached import
  for isolated feature builds. `a91080213f3e86649ec5f976a85751e99780c232`
  refreshed the Browserslist lock after the canonical frontend audit exposed a
  failure omitted by shorter helpers. `c9e43b16c2eafdef5671f035f7345a00e6099975`
  made the CI aggregate require explicit success from every required job.
- Phase 4 CI `34119316104` at `1b3b575d` passed Windows, macOS, Linux, frontend,
  dependency policy, coverage, and corrected aggregate. Support run
  `34116019496` attempt 2 also passed. The separate run for `c9e43b16` was
  cancelled by the Phase 4 push and is not recorded as green.
- Phase 5 CI `34146435999` failed only the Windows missing-workspace capacity
  test. Support `3e958bbdca39021416b38ea4316038f13d67af1c` validates metadata before the
  Windows capacity query; CI `34149115759` passed all required jobs, including
  hosted Windows. The original failed CI remains failed.
- Phase 6 CI `34159745083` passed Linux, macOS, frontend, dependencies, and
  coverage but failed Windows native loader/JSON assertions. Support
  `ec3dd41e26a6ebfbcdab7104f752df05e83c2e0d` fixed the loader and semantic JSON
  assertion; CI `34161973786` then exposed native origin/path defects. Final
  support `e783de30210493222cdd4034f2bd1dd5be331365` corrected those defects and
  rejected rooted output suffixes; CI `34164085268` passed all required jobs.
  Neither earlier failed Phase 6 run is reclassified as passing.
- Phase 7 CI `34168836494` at exact commit `f8cb49f4` passed all seven jobs:
  Linux Rust gates, Windows tests, macOS tests, frontend, dependency policy,
  coverage, and aggregate.

## Phase 8 acceptance work before integration

Phase 8 Task 1 changes four selected SQLite operations from deferred
transactions to immediate write intent. Its focused RED produced five actual
`SQLITE_BUSY` failures under an unrelated writer; after correction, the five WAL
tests and 219 storage tests passed. The change is approved in the cumulative
Task 2 source freeze but has no independent public commit.

Phase 8 Task 2 completes a controlled service chain: Work Order export/import,
qualification, exact-attempt promotion, a synthetic runtime campaign with 32
callbacks and preterminal retained health, terminal seven-step closeout,
fresh-store reopening, exact historical finding identity, corpus import,
fixed-seed replay, and experiment result attachment. It uses controlled adapters
and inert synthetic artifacts. Final scoped results were 134 service tests plus
2 intentional ignores, 8 selector tests, 23 REST tests, 2 native tests, and 165
GUI tests; all passed. No provider, generated harness byte, or real fuzzer was
executed.

The same debug-profile queue fixture contained 161 targets, 3,200 runs, and 160
findings. Six complete `finding_review_queue` calls changed from a mean of
3,941.5395 ms and median of 3,680.0545 ms to a mean of 53.4345 ms and median of
52.844 ms. UUIDs and timestamps were regenerated between structurally identical
databases. This is local service-call evidence on one Apple M5 Max, not P95,
release, CI, or end-user latency evidence.
These timings precede the final finding-selector correction below; no new
latency measurement is claimed for that correction.

Final integration review reproduced four qualified-run deletion/provenance
failures and a reproduction bundle selecting unrelated bare-workspace source.
The shared retained selector now controls evidence deletion and finding action
handoff. The public reproduction exporter resolves the retained selector before
reading source; its lower assembly helper is private. Direct service and real
component/transport regressions cover these changes, exact selected run/crash
IDs, legacy bare selectors, and successful inventory refresh after a failure.
Focused verification passed 100 service tests with two intentional ignores and
86 GUI/transport tests. The scoped independent re-review approved these fixes;
nonblocking lookup/test-sensitivity and theoretical workspace digest limitations
remain explicit in engineering decisions 60-61.

The Phase 8 integration change is identified by the subject and verification
scope “complete acceptance workflows and operator evidence.” Its commit SHA and
hosted CI cannot exist before this document is committed. Final publication must
report the exact integrated SHA and hosted CI separately rather than adding a
self-referential value here.

The resumed final workspace run passed all 3,230 Rust tests across 177 test
summaries, with seven intentional ignores and no failures. Formatting,
Clippy-fix, strict all-target Clippy, workspace compilation, documentation with
warnings denied, and dependency policy passed. Measured domain line coverage
remained 91.12%. The canonical frontend gate passed a clean dependency install,
audit with zero reported vulnerabilities, 518 tests in 72 files, production
build and bundle budgets, and strict lint. Translation pairing and all 85
script tests also passed. These results are fresh resumed verification, distinct
from the earlier per-phase records above.
The canonical no-default-features gate, all 20 standalone product-feature
builds, and seven standalone native GUI builds also passed. The native checks
covered Work Orders, coverage experiments, triage disposition, Patch to Proof,
run closeout, campaign health, and Build Doctor. The captured implementation
inputs were unchanged throughout final verification.

## Actual Docker evidence and limits

Phase 6 performed one real disposable plain-Make project build through
`hf-runtime` and the actual Dockerfile image
`sha256:1a416dae015da4da47f2e6ddf6d1a3a97185a36d30b33aa569e2375f6b62d916`.
It observed NeedsBuild to Ready publication, nested-component handling, and a
named missing-tool Invalid result. This is real sandbox build verification. It
is not generated-harness execution, real-engine qualification, campaign
certification, crash reproduction/minimization, or a physical Tauri test.

Phase 8 rendered inspection used a dedicated synthetic loopback HTTP service,
an explicit `VITE_API_URL`, and a private browser profile. The actual desktop
web presentation showed retained Work Order, submission, attempt, review, and
file-qualified target evidence; separate current, whole-run mean, and peak
rates; raw crash signals separately from retained crash artifacts; an exact
prepared-experiment replay command; and a capability-specific unavailable
reason. The enabled promotion and experiment completion controls were inspected
but not invoked. At a 720-by-900 viewport, the initial three-column run metrics
made 49-pixel cards whose labels extended outside the cards. A responsive
minimum-width metric grid produced 168-pixel cards with all three throughput
labels inside both card and main content bounds, without horizontal document
overflow. Native browser error inspection found no page exceptions or Vite
error overlay after correction. This verifies presentation and request routing
only; it is not backend or live fuzzing evidence.

## Canonical reproduction commands

Run repository Rust gates in this order:

```bash
CARGO_TARGET_DIR=target/daily-work cargo fmt --all
CARGO_TARGET_DIR=target/daily-work cargo clippy --fix --allow-dirty --workspace -- -D warnings
CARGO_TARGET_DIR=target/daily-work cargo clippy --workspace -- -D warnings
CARGO_TARGET_DIR=target/daily-work cargo check --workspace
CARGO_TARGET_DIR=target/daily-work cargo doc --workspace --no-deps
```

Run Rust tests with the repository filter while preserving the original Cargo
exit from the first pipeline process:

```bash
raw_log=${TMPDIR:-/tmp}/oxfuzz-workspace-tests.$$.log
set +e
CARGO_TARGET_DIR=target/daily-work cargo test --workspace 2>&1 \
  | tee "$raw_log" \
  | grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' \
  | head -200
pipeline_status=("${PIPESTATUS[@]}")
set -e
exit "${pipeline_status[0]}"
```

Canonical frontend verification is:

```bash
npm --prefix crates/hf-gui ci
npm --prefix crates/hf-gui audit
npm --prefix crates/hf-gui test -- --run
npm --prefix crates/hf-gui run lint
npm --prefix crates/hf-gui run build
```

The repository gate suite also runs dependency policy, translation pairing,
script tests, feature combinations, and measured domain coverage. Exact final
Phase 8 totals and hosted CI belong to the integration review and publication
record because they follow this uncommitted documentation.
