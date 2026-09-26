# AI Target Ranking in Discover

Status: proposed written spec; design direction approved 2026-09-26. Owner: oxfuzz core team.

## Purpose and success criteria

Desktop users should be able to click **Discover**, see scan results promptly,
and then receive an automatic AI recommendation that explains three factors:
bug-finding potential, reachable code, and harness feasibility. The result is
advice for choosing a target. Selecting a target remains an explicit action;
harness qualification, promotion, and execution keep their existing review and
sandbox requirements.

Success means a configured provider is attempted automatically after a scan;
the heuristic inventory appears before the provider finishes; the final order
and every displayed factor have an honest source label; and missing, failed,
partial, or malformed provider results never masquerade as AI assessments.
Desktop and browser clients receive the same service result. The GUI works in
English and Chinese, at narrow and wide window sizes, and with keyboard and
screen-reader navigation.
An empty scan completes without a provider call and shows the empty state.

## Existing behavior and scope

`hf-discovery` scans and heuristically scores targets. The CLI can call the
existing AI ranker, but desktop and REST `discover` call only the scan. The
ranker currently returns one revised `fit_score` and a rationale; the GUI
cannot distinguish that result from a heuristic score. The current ranking
prompt uses candidate metadata rather than source bodies or campaign outcomes.

This change covers the Discover and target-selection flow, its service API,
durable evidence, and the CLI's existing `--rank` behavior. It does not change
harness generation, start a campaign, add source-body analysis, or learn from
historical runs. Semgrep remains an explicit, separate enrichment action.

## Service operation and data flow

An `ai-target-ranking` feature, enabled in normal product builds, owns the new
operation. `hf-service` exposes `start_ranked_discovery(project, language)`,
`ranked_discovery_status(id)`, `ranked_discovery_result(id)`,
`cancel_ranked_discovery(id)`, and `retry_ranked_discovery(id)`. Retry starts a
new AI assessment against the same retained scan without scanning again.
Presentation crates only translate requests and responses. The existing
deterministic `discover` API remains available.

Start authorizes `Action::Discover`, canonicalizes the project, reserves a
durable operation ID, and returns without waiting for the scan or provider.
The worker scans once and publishes the immutable heuristic inventory as result
revision 1. The GUI fetches that revision and displays it immediately. The
worker then makes the automatic AI attempt. It publishes the assessment overlay
atomically as revision 2 after all admitted batches settle. The GUI makes one
visible reorder, keyed by stable target IDs. Status polling returns only state,
revision, counts, and named failure information; the result read transfers the
inventory only when the revision changes.
The worker repeats authorization immediately before provider dispatch, so a
changed policy cannot be bypassed by an already-started operation.

Operation state is `scanning`, `ranking`, `completed`, `failed`, `cancelled`, or
`interrupted`. A successful scan followed by unavailable or failed AI still
completes with an explicit `heuristic` or `mixed` ranking source and reason.
`failed` means the scan or its required persistence failed. Results carry the
canonical project, language, operation ID, revision, scan time, base inventory,
per-target assessments, assessed count, total count, and ranking source.
Retry repeats the discovery authorization decision, retains the original scan
time and candidate bytes, and publishes under a new operation ID. A user who
wants current source content clicks Discover again.

The service persists the scan snapshot before any provider call. It stores each
rendered, bounded model prompt before dispatch, plus the provider identity,
response status, and validated assessments. This makes model-visible input
reconstructable after restart. An in-progress operation found on startup
becomes `interrupted`; its completed scan remains readable and no model request
is automatically repeated. Cancellation prevents late provider responses from
publishing a newer result. A new Discover action for the same project and
language supersedes the previous GUI selection; a late reply cannot replace
the newer operation's cards.

## Assessment and ordering

The model receives only persisted scan metadata: target ID, relative file,
symbol, language, kind, signature, input surface, complexity, reachable count,
accumulated complexity, and heuristic score. No source excerpt or vulnerability
claim is introduced. The prompt states that these are estimates and asks for
three factor ratings from 0 to 4, with one short explanation tied to the
supplied metadata. `reachable code` may be `unknown` when lexical scanning
provides no call edges. The other two factors must be rated for an AI row to
count. The service computes the overall advisory score as the arithmetic mean
of available ratings divided by 4; the model cannot supply an overriding
overall score.
Candidate strings are untrusted project data. The prompt encodes and bounds
them as data, states that they are not instructions, offers no tools, and caps
each batch prompt at 32 KiB. A candidate that cannot fit after bounded field
truncation stays scan-only rather than being sent in an oversized request.

One automatic operation assesses at most the first 64 candidates in
deterministic heuristic order, in batches of at most 16. This is a fixed
latency and cost limit for this release, not a setting. The service records the
assessed count and the GUI states it as `N of M candidates assessed by AI`.
Remaining candidates retain heuristic order and an explicit scan-only label.
Within the assessed group, ordering is descending advisory score, then
descending heuristic score, then relative file, symbol, and target ID. The
scan-only group follows in deterministic heuristic order. The GUI does not
present this as a globally measured bug probability.

Responses identify targets by the scan's stable target ID. The service rejects
unknown or repeated IDs, out-of-range ratings, overlong explanations, and
malformed or over-64 KiB batch results. One bad batch leaves its targets scan-only without
discarding valid assessments from other batches. When no valid assessment is
available, the order stays heuristic. The original `TargetCandidate.fit_score`
is never overwritten by the assessment overlay; it remains the base for
Semgrep and other existing consumers.

## Discover interface

The initial view shows scan progress, then the heuristic candidate list while
AI is working. A visible status says `Assessing with AI`; completion announces
that recommendations were updated. The list keeps target IDs as React keys and
preserves focus and the selected target when it reorders. A live region reports
the update without reading every card aloud.

The first assessed card receives a `Recommended first` heading. Each assessed
card shows the overall advisory score, three labeled factor ratings, one short
AI explanation, its heuristic score, symbol, file and line, and the existing
call-tree affordance. `Unknown` is shown for an unavailable factor. Scan-only
cards show their heuristic score and do not show empty AI factors. A compact
status above the list names the source and assessed count. Provider absence
links to AI Settings; a failed request offers **Retry AI assessment** against
the retained scan.

The `Use this target and continue` action continues to pass the file-qualified
selector when symbols collide. No target is selected automatically. The
existing Semgrep action remains separate and labeled. The service ties its
result to the immutable base scan; the GUI enables it after AI settles and
shows its signals separately from AI factors. There is no automatic addition
of Semgrep boosts to AI scores.

All new text has paired English and Chinese translations. Cards and status
must fit the supported narrow desktop window without horizontal scrolling;
factor names remain visible without relying only on color. Buttons, progress,
failure messages, and dynamic reorder remain keyboard and screen-reader
accessible.

## Other presentation surfaces

Tauri and REST expose matching start, status, result, cancel, and retry requests. REST
applies its existing project-root authorization at start and protects status
and result reads for the owning project. The GUI uses the same transport
command names in desktop and browser modes. The old REST and Tauri `discover`
responses remain deterministic for clients that explicitly request a scan.

The CLI's `--rank` path uses the same service assessment and fallback policy,
so `auto`, `require`, and `off` retain their documented meanings without
duplicating model-failure decisions in `hf-cli`. CLI output labels scan-only
and AI-assessed rows. A build without `ai-target-ranking` still supports
deterministic discovery, including `--rank --ai off`, and reports an explicit
unsupported error when `--rank` requests AI with `auto` or `require`.

## Verification

Implementation follows the repository's red-green-refactor process. Service
tests use a fake provider and exercise scan publication before AI completion,
all three factors and ordering, duplicate symbols, the 64-candidate limit,
missing/failed/malformed/partial responses, cancellation, restart recovery,
retry against the retained scan, and direct executor authorization. Storage
tests verify retained prompts and
revision transitions. REST and Tauri tests check matching response fields and
project access. GUI tests cover provisional and final lists, no-provider and
retry states, stale operation replies, focus, keyboard selection, and the
file-qualified handoff. Visual review checks narrow and wide layouts in both
languages and the existing light and dark themes. The required workspace
quality gates run after code changes.

## Alternatives considered

- Calling the existing `rank` method directly from the GUI is smaller but
  leaves policy and failure handling in a presentation crate, exposes one
  opaque score, and gives no durable operation to recover after navigation.
- Waiting for one synchronous scan-and-rank response is simpler but withholds
  useful scan results for the full provider latency.
- Ranking from historical campaign outcomes may improve recommendations once
  comparable runs exist. It is excluded here because a new project has no
  history and those observations need a separate validity design.
