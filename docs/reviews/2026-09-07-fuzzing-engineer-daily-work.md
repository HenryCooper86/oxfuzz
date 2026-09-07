# Fuzzing engineer daily-work review

Date: 2026-09-07. Repository revision: `b7d835de`.

This is a source-based assessment of daily workflows, with individual engineers as the primary audience and overnight operation as the secondary audience. It is not a visual usability audit, security audit, or end-to-end campaign certification. Recommendations are proposals, not approved implementation designs.

**Assessment:** oxfuzz has substantial capability already. The largest near-term opportunity is to make existing operations easy to complete, revisit, and trust across runs. Prioritize accurate findings, an actionable daily queue, practical build setup, and complete operational feedback.

## Existing strengths

The repository already provides ranked discovery, sandboxed harness qualification and exact-revision promotion, harness tournaments, external harness work orders, crash attribution and minimization, corpus import and minimization, coverage blockers, scheduled target rotation, retained evidence, and patch verification. A connected desktop workflow already embeds discovery, harness, run, and triage; a new wizard is not the principal missing piece.

Evidence: [architecture alignment](../design/DESIGN_OVERVIEW.md), [connected workflow](../../crates/hf-gui/src/views/WorkflowView.tsx), [work-order lifecycle](../design/harness-work-order-design.md), [corpus operations](../../crates/hf-service/src/container/corpus.rs), [portfolio scheduling](../design/portfolio-campaigns.md), and [patch verification](../design/patch-to-proof-design.md).

## Daily workflow assessment

| Engineer's task | Current support | Main improvement |
| --- | --- | --- |
| Check yesterday's results | Dashboard, run history, crash proof cards, schedule history | Actionable queue with durable run/finding selection |
| Bring a real project online | Readiness checks, compile-database ingestion, Build Doctor | Diagnose before generation; retain reusable build profiles |
| Write or repair a harness | Generation, repair, tournament, external work orders | Expose work-order import and qualification in desktop |
| Leave campaigns running | Budgets, concurrency limits, cancellation, recovery | Complete worker/disk health collection and retained alert delivery |
| Investigate stalled coverage | Coverage history, blockers, seed survival, corpus tools | Make advanced operations accessible and track experiment outcomes |
| Finish a run | Individual analysis operations and service-owned closeout | Offer explicit closeout and resumption from run history |
| Hand off or verify a bug | Reports, issue integrations, repro evidence, Patch to Proof | Keep observational comparisons distinct from verified fix claims |

## Prioritized findings

### 1. P0: Change comparisons overstate what two fuzzing runs establish

**Observed:** `classify_findings` labels a signature present only in the base run as `Resolved`; a head-only signature becomes `Introduced` whenever the base contains any crash. `compare_revisions` passes retained signature sets directly to that function, without cross-revision reproducer replay. Existing tests explicitly expect these results.

Evidence: [classification and comparison inputs](../../crates/hf-service/src/change_impact.rs), [service comparison](../../crates/hf-service/src/change_comparison.rs), [tests](../../crates/hf-service/tests/change_comparison.rs).

**Daily impact:** an engineer reviewing a change can read a sampling difference as a fixed bug or a newly introduced defect. Seeing some other crash in the base does not establish that a head-only crash was absent there. This contrasts with the project's stronger Patch to Proof evidence requirements.

**Proposal:** first rename observational outcomes to `observed_only_in_base`, `observed_only_in_head`, and `observed_in_both`. Reserve verified remediation for the existing verification workflow. Offer explicit sandboxed cross-revision replay to investigate whether a finding is introduced or no longer reproduces, with repeated trials for flaky inputs and an inconclusive outcome when evidence is missing.

Comparability also omits harness revision, sanitizer, run budget, resource limits, engine arguments, and random seed from `RunComparisonInput`. Extend the service-owned comparison specification to state which factors must match and which differences make a result descriptive only. A peak-edge count change across different source revisions should be presented as a measurement requiring investigation, rather than proof that particular code stopped being exercised.

**Acceptance:** a base-only signature never becomes a verified fix solely through set subtraction; an unrelated base crash never establishes introduction; incompatible sanitizer or harness configurations receive explicit explanations. Update the design, serialized values, translations, and behavior tests together.

The external reference supports the replay distinction: ClusterFuzz's fixed-testing workflow reruns testcases against newer builds. [ClusterFuzz: fixing a bug](https://google.github.io/clusterfuzz/using-clusterfuzz/workflows/fixing-a-bug/).

### 2. P1: Make the daily triage queue prioritize unfinished work

**Observed:** `Disposition::Resolved` sorts before every open disposition. `workbench::crash_review_items` sorts ascending with this key; a test explicitly asserts that resolved findings outrank open ones. Separately, the Triage view uses `lastTarget` from the last-run context, maintains a local crash array, and renders that array without the dashboard's disposition ordering or search/filter controls. Last-run summaries do survive restart in local storage, so this is not a claim that run history is lost.

Evidence: [disposition order](../../crates/hf-service/src/triage_disposition.rs), [dashboard queue](../../crates/hf-service/src/workbench.rs), [ordering test](../../crates/hf-service/tests/triage_disposition.rs), [Triage view](../../crates/hf-gui/src/views/TriageView.tsx), [persisted summaries](../../crates/hf-gui/src/providers/RunOutputContext.tsx).

**Proposal:** put open findings first by default, with resolved findings available through an explicit filter. Give Dashboard and Triage the same service-owned queue and durable project/target/run/finding identifiers. Add filters for origin, disposition, severity, and run. Separate report drafting from the question of whether investigation is finished. Team assignment and issue synchronization can follow after the individual workflow works well.

**Acceptance:** with 100 resolved and 3 actionable findings, the default queue starts with the 3 actionable findings; opening an older finding selects its exact run and reproducer; project switching and application restart preserve the intended selection. A completed report alone must not hide unresolved investigation work.

### 3. P1: Diagnose build requirements before spending harness-generation effort

**Observed:** Build Doctor recognizes several build systems but offers a plan only for CMake; Make/Autotools, Meson, and Bazel report missing tools. Its CMake plan is fixed. Compile-database discovery checks four fixed relative locations. In the desktop Harness view, Build Doctor appears after a failed compilation.

Evidence: [build diagnosis](../../crates/hf-service/src/build_doctor.rs), [compile-context resolution](../../crates/hf-service/src/container/build_context.rs), [failure-triggered panel](../../crates/hf-gui/src/views/HarnessView.tsx).

**Proposal:** offer a read-only project build diagnosis before generation. Persist a validated per-project build profile covering component root, compile-database location, supported configure options, required dependencies, and sandbox image identity. Start with configurable CMake and one frequently used additional build system. Show a reviewable sandbox plan and retain its output. Support selecting an existing fuzz target or importing a hand-authored harness through work orders.

**Acceptance:** agreed CMake and Make/Autotools fixtures can reach a qualified harness using a saved profile without hand-editing oxfuzz internals; missing dependencies are explained before repeated model repair; a second engineer can reuse the profile with the same sandbox inputs. Measure active setup time and repair attempts on real projects before setting time targets.

OSS-Fuzz's project setup is a useful reference for explicit build recipes and project metadata, without adopting OSS-Fuzz as oxfuzz's execution owner. [OSS-Fuzz: setting up a project](https://google.github.io/oss-fuzz/getting-started/new-project-guide/).

### 4. P1: Finish overnight health monitoring and attribute live metrics to runs

**Observed:** campaign health has typed conditions and an assessment endpoint, but the service gatherer supplies zero expected/live workers and no disk-space figure. Consequently, that gathering path cannot detect missing workers or disk pressure. `undelivered` is a pure helper taking a caller-provided set; no production call site connecting it to persisted alert delivery was found in the inspected service sources. The desktop has a scheduled-crash toast, which is useful but distinct from health monitoring.

Evidence: [health gatherer](../../crates/hf-service/src/container/campaign_health.rs), [assessment/dedup helper](../../crates/hf-service/src/campaign_health.rs), [REST health route](../../crates/hf-web/src/router.rs), [crash toast](../../crates/hf-gui/src/App.tsx).

A separate source-observed risk affects concurrent runs: the SSE adapter preserves `run_id`, while the root progress listener consumes only type/data and writes into one active project bucket. It also retains the maximum throughput sample, so that displayed value cannot represent a throughput decrease. Runtime cross-run contamination was not reproduced in this review.

Evidence: [SSE event identity](../../crates/hf-gui/src/lib/sseAdapter.ts), [progress listener](../../crates/hf-gui/src/providers/RunOutputContext.tsx).

**Proposal:** retain worker heartbeats and workspace capacity measurements; connect assessment to durable event delivery through existing infrastructure; add a morning summary of failed, stalled, interrupted, and unprocessed runs. Key live state by run ID and distinguish current, average, and peak throughput. Unknown telemetry must remain visibly unknown.

**Acceptance:** fake worker-loss, stale-progress, disk-pressure, and service-restart scenarios produce the intended retained alerts without duplicates. Two interleaved run streams never share metrics. A falling throughput sample appears as falling current throughput. No alert automatically restarts untrusted execution.

### 5. P1: Expose existing expert operations in the desktop workflow

**Observed:** work-order export/import/qualification/ranking/promotion exists in service, CLI, and REST. No corresponding work-order references were found in desktop source or Tauri commands. Run closeout also has a service operation, CLI command, and REST route, but no matching desktop workflow was found. The Corpus view exposes seed, AI seed, grow, basic prune, and list; service operations additionally provide corpus import, seed survival, coverage pruning, and minimization.

Evidence: [work-order design](../design/harness-work-order-design.md), [CLI work orders](../../crates/hf-cli/src/work_order.rs), [REST work orders](../../crates/hf-web/src/work_order_routes.rs), [closeout operation](../../crates/hf-service/src/container/run_closeout.rs), [desktop corpus controls](../../crates/hf-gui/src/views/CorpusView.tsx), [corpus service](../../crates/hf-service/src/container/corpus.rs).

**Proposal:** add three focused entry points using the existing service operations: import/edit/qualify a harness submission; explicitly analyze a finished run and resume interrupted closeout; import and minimize an existing corpus. Display engine-specific availability, including AFL++ requirements for seed-survival measurement. Keep source import separate from qualification and exact-revision promotion.

**Acceptance:** an engineer can author a harness externally, import it, inspect lint and qualification evidence, and promote the selected attempt from desktop; closeout exposes each step's persisted outcome; corpus import/minimization reports counts and retained evidence. Reopening a completed operation does not execute it again.

This is a practical corpus workflow: libFuzzer documents both regression execution of corpus inputs and coverage-preserving corpus reduction. [LLVM: libFuzzer](https://llvm.org/docs/LibFuzzer.html).

### 6. P2: Turn coverage advice into trackable experiments

**Observed:** Coverage Blocker exploration displays a target function, reason, and proposed kind of experiment. The panel has an Explore action, but no operation to prepare the proposed change or associate its result with that proposal. Existing corpus and harness operations can perform the work.

Evidence: [blocker panel](../../crates/hf-gui/src/components/CoverageBlockerPanel.tsx), [blocker design](../design/coverage-blocker-design.md).

**Proposal:** let the engineer prepare an experiment from the advice: retain the hypothesis, baseline run, intended target function, requested corpus or harness change, and budget. After explicit approval through existing execution paths, link the resulting run and compare relevant coverage. Record ineffective attempts so the next recommendation can cite them rather than repeat them.

**Acceptance:** every accepted experiment has a baseline and result or named failure; harness changes invalidate prior promotion; claims distinguish target-entry reach from aggregate edge growth; all advice sent to a provider can be reconstructed from persisted records.

### 7. P2: Validate complete engineer tasks, and keep guides aligned

**Observed:** selected frontend tests inspect source strings rather than exercising user interactions. These tests can establish wiring conventions but cannot show that an engineer can select an older finding, keep two campaigns separate, or complete an import. Some design documents still say planned despite service implementations. The README quick-start goes from harness generation directly to run without an explicit promotion step, while the CLI guide documents `--promote`.

Evidence: [change-view source assertions](../../crates/hf-gui/src/__tests__/changeAwareSurface.test.ts), [health design status](../design/campaign-health-design.md), [closeout design status](../design/run-closeout-design.md), [README](../../README.md), [CLI guide](../guides/CLI_REFERENCE.md).

**Proposal:** maintain a small task-based acceptance suite: onboard a project, qualify a manual harness, investigate yesterday's crash, inspect two active campaigns, resume interrupted closeout, and verify a patch. Use fake adapters for normal CI and a separately approved sandbox campaign matrix for real engine/toolchain validation. Update guides to explain complete commands, prerequisites, review steps, and recovery outcomes.

**Acceptance:** each task has an interaction test or recorded operator walkthrough; documentation examples include the required promotion; implemented, partially wired, and planned status are clearly distinguished. Passing mocked tests must not be described as real-project build success.

## Suggested delivery order

1. **Correct evidence claims:** finding-comparison terminology and comparability rules. Update the relevant design before code and use behavior tests that demonstrate the old overclaim.
2. **Improve the daily queue:** fix resolved-first ordering, introduce durable finding navigation, and expose explicit run closeout. Keep these as separate concerns in implementation changes.
3. **Complete desktop access to existing operations:** work orders and advanced corpus tools.
4. **Make unattended work observable:** retain worker/disk evidence, connect alert delivery, and isolate live run metrics.
5. **Reduce project setup cost:** reusable build profiles, then measure them on representative real projects.
6. **Track coverage experiments:** build on the reliable run identity and comparison work above.

For team operations, move item 4 ahead of desktop authoring. For onboarding, move item 5 immediately after evidence correctness. These rankings reflect engineering judgment from source inspection; user interviews and timed task observations have not been conducted.

## Success measurements

| Measurement | What it tells us |
| --- | --- |
| Active engineer minutes to first qualified harness | Whether build and authoring improvements reduce setup work |
| Build failures and model repair attempts per target | Whether project context is adequate before generation |
| Time to open the correct reproducer from yesterday's queue | Whether daily navigation and run identity work |
| Time from run completion to completed closeout | Whether results are actually analyzed |
| Time spent running after a detectable worker/disk failure | Whether overnight monitoring saves resources |
| Fraction of displayed fixed claims backed by verification | Whether reports remain trustworthy; target 100% |
| Coverage experiments completed with interpretable before/after evidence | Whether advice produces measurable engineering progress |

Measure the current baseline before promising percentage improvements. Track both operator effort and sandbox/model consumption.

## Scope and verification

Read architecture and workflow designs, CLI/desktop documentation, selected service and presentation implementations, and related tests. Checked primary upstream documentation for build recipes, corpus workflows, and fix verification. No generated harness or real fuzzer was executed. No production code was changed. Full workspace quality gates are not claimed for this assessment.

Focused verification: `cargo test -p hf-service --test change_aware --test triage_disposition --test campaign_health` passed all 36 tests (14 + 7 + 15; zero failures). Cargo exit status was verified separately because the mandated output filter returns 1 when there are no retained lines. These tests exercise classification and health logic, not live campaigns or desktop interactions. All 36 local Markdown links in this report resolve. The tests preserve the current comparison labels and resolved-first ordering; passing does not establish that those behaviors meet the engineer workflow needs described above.
