# Milestone 1: retained-attempt demo and selected campaign preflight

Date: 2026-09-09. Follow-up to the
[feature assessment](2026-09-09-feature-verification.md). This milestone addresses
its demo approval and preflight findings. It does not establish best-in-class
performance or live campaign reliability.

## Delivered behavior

The demo discovers a bundled example, exports a retained Work Order as JSON,
generates one model-authored draft, imports its exact source, and qualifies that
submission. It prints the submission and qualification evidence before asking
for human approval of the retained attempt UUID. Approval promotes only that
attempt. Run and triage use the packet's file-qualified target selector.

Declined approval, EOF, qualification failure, malformed JSON, command errors,
and stale promotion stop before a campaign starts. Blanket `--yes` approval is
rejected. Smoke crashes remain failed qualification evidence for investigation;
the demo does not automatically repair or approve them.

Selected campaign preflight belongs to `hf-service`. It checks Docker, the
sandbox image, the requested engine, enabled-engine and duration policy, and
optionally constructible provider configuration. `doctor --engine ...` exposes
that result with named problems and a nonzero failure exit. Ordinary `doctor`
keeps its general any-engine check. Provider configuration does not establish
credentials or model connectivity, and preflight does not authorize execution.

Tracing diagnostics go to stderr so JSON remains parseable under verbose
logging and configuration warnings.

The CLI adds `work-order export --json` and `harness --draft-only --json`.
Draft JSON excludes compile, repair, refinement, and promotion flags; packet
JSON excludes Markdown file output. The demo uses these structured outputs
instead of extracting IDs from human-readable prose.

## Acceptance evidence

- Red tests reproduced the original command-flow and missing-option defects.
- Eight demo tests use a traced fake CLI and cover exact-attempt approval,
  decline/EOF, selected preflight inputs, preflight denial, failed qualification,
  stale promotion, all five bundled examples, command/JSON failures, and invalid
  options. No target code or provider is executed by these tests.
- Three CLI argument tests enforce safe JSON combinations and scoped doctor
  flags. Three service tests cover selected-engine readiness, named prerequisite
  failures, and optional provider checks.
- Two subprocess regression tests reproduce invalid provider configuration with
  logging enabled and disabled. They verify pure JSON stdout, stderr diagnostics,
  the requested log filter, a failed preflight, and no database creation.
- A real CLI check passed missing-provider/selected-tool and engine/duration
  policy denials without database creation, followed by discovery, packet JSON,
  draft JSON, and exact-source import using an offline fixture. It did not compile
  or execute a harness.
- Real Docker/libFuzzer probes confirmed that missing provider configuration
  still denies readiness when the selected engine is present. A deliberately
  unreachable local provider endpoint with a dummy credential passed the
  configuration-only check, confirming it does not claim model connectivity.
  Neither case created a database or executed a target.
- Final workspace run: **3,238 passed, 0 failed, 7 ignored**, across 178 test
  groups. The initial logging-filter regression was fixed before this clean run.
- Script suite: **93 passed**. After the final source-display change, all eight
  demo tests passed again. GUI: **518 tests in 72 files passed**, with build,
  bundle budget, and lint checks passing.
- Formatting, fixing and strict Clippy, workspace compilation, documentation,
  expanded all-target Clippy, and CLI no-default-feature Clippy checks passed.
- Dependency policy passed with warnings denied. Strict documentation passed
  with warnings denied and private items included. Domain coverage was **91.12%
  aggregate line coverage** across discovery, harness, engine, and crash crates;
  this is not whole-workspace coverage. Translation pairing passed.

## Next milestone: live userspace campaign acceptance

Use libFuzzer, AFL++, and honggfuzz separately, with a supported provider and
pinned sandbox image. Retain the provider/model identity, image digest, target
revision, source/binary digests, run settings, and all attempt/run IDs. Every
harness must pass independent review and receive the required human approval.
Do not execute a generated harness on the host. Use valid smoke seeds for the
successful campaign path and retain a separate known crash trigger for replay.
Also exercise a smoke-crash path and confirm it remains ineligible for promotion.

| Workflow | Acceptance evidence required |
| --- | --- |
| Author and qualify | Each engine produces a retained attempt. Build, independent review, and smoke results are inspectable. A failing stage identifies its cause and preserves evidence. Approval names the reviewed attempt. |
| Launch and monitor | An approved attempt starts with the requested duration and engine. Progress and terminal status agree with retained run evidence. Unsupported or disabled settings fail before launch. |
| Cancel and recover | Cancel a running sandbox campaign, record acknowledgement and termination latency, verify no surviving worker/container, and reopen persisted results. Interrupt during work and verify recovery reports incomplete work without claiming success. |
| Crash handling | Retain a known-trigger crash with its input and origin; reproduce against the same approved binary in the sandbox. A clean replay reports only the observed result. A smoke crash is investigated before preparing a new submission. |
| Coverage and corpus | Retain before/after coverage and corpus identity; show useful inputs remain available after merge. Record whether the selected engine supports each requested measurement. |
| Daily operation | Repeat a campaign from retained configuration and evidence without manually reconstructing a target selector. Record failures and time spent on setup, approval, diagnosis, and restart. |

Passing unit tests or doctor is insufficient for this milestone. Record engine
results individually, including failed and blocked cases. Set performance targets
from these measurements before making comparative claims.

## Follow-up from live preparation

Live preparation exposed a missing case: a configured pool could contain zero
providers after every API-key lookup failed. Its constructor still returned
success, so the configuration-only preflight overstated readiness. The
[second-phase admission fixes](2026-09-09-campaign-admission.md) add regression
coverage and reject that configuration at its owning constructor. The prior
fixture evidence above did not cover this case.
