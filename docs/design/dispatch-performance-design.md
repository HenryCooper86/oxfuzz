# Dispatch and retained-history performance

Status: local baseline recorded. Owner: `hf-tools`, `hf-agent`, and
`hf-service` maintainers.

## Measurement definition

The P95 under 100 ms objective applies to tool dispatch after a request has
been accepted and before the registered tool starts its own work. Provider
latency, tool execution, result rendering, and durable-history queries have
separate measurements. A no-op registered tool gives a conservative dispatch
upper bound because total call latency also includes its trivial return.
Rejected input is measured from executor entry through schema denial. The
agent's JSON parsing, service-domain authorization, and durable record writes
must be measured separately before any result is described as end-to-end agent
latency.

The benchmark uses the real `ToolRegistryImpl` and `ToolExecutor`, a fixed
valid/invalid JSON input, and a no-network tool. It warms schema caches before
sampling, retains at least 1,000 individual observations per accepted and
rejected case, and repeats at concurrency 1, 8, and 32. Report median, nearest
rank P95, maximum, sample count, architecture, OS, Rust profile, runtime
worker count, and fixture identity. Each request records time waiting in the
benchmark queue, time in `ToolExecutor::execute`, and time from enqueue to
completion. Each worker warms its validator before sampling. The benchmark
queue is a controlled load generator, not a production scheduler observation.
No time spent sleeping in the test tool is credited to dispatch.

The retained-history experiment reuses the existing finding-review fixture at
3,200, 6,400, and 12,800 retained runs without changing the service query.
Five independent SQLite fixtures per size provide first-query samples; five
repeat queries per fixture provide 25 repeat samples. Preparation time is
recorded separately. The first query is cold only for the service operation:
database pages can already be warm from fixture insertion. The 100 ms dispatch
objective does not automatically become a history or campaign Stop objective;
those need their own baselines and decisions.

## Acceptance and limits

Run the benchmark on a named, stable runner without concurrent builds. A
shared CI runner can check benchmark compilation and produce diagnostic
results, but its timing is not an enforced performance gate until variance is
measured. The supported load envelope is the concurrency and fixture range
that meets the stated P95. Failure to meet it is a measured performance gap,
not a reason to bypass schema validation, authorization, or persistence.

Criterion provides repeatable benchmark execution; a small result checker
validates sample count and computes exact quantiles from retained observations.
Parser tests reject missing, nonfinite, or mismatched samples before any timing
claim is published.

The first clean-revision result and its raw samples are in the
[2026-09-27 performance record](../acceptance/performance-2026-09-27.md).

Use an absolute report path because Cargo starts the benchmark in its crate
directory. Run the ignored service profile through `scripts/cargo-test-filtered.sh`
with `OXFUZZ_HISTORY_REPORT` and `OXFUZZ_PERFORMANCE_RUNNER` set. Both outputs
name the measured Git revision, runner, toolchain, OS, architecture, and build
profile and whether the checkout was clean. The checkers reject dirty source,
missing fixture sizes, or missing samples. Retain
raw JSON alongside the published quantiles so another reviewer can recompute
them.
On macOS 27, set `CARGO_PROFILE_RELEASE_STRIP=none` for a release-profile
history run, as the desktop build does, so the system loader can load Rust
proc-macro libraries.

## Opt-in cross-platform diagnostics

A manual GitHub workflow on main may collect diagnostic release-profile
samples on named Ubuntu 24.04, Windows 2025 and macOS 26 runners. These labels
are listed in the [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
The runner image version and architecture are retained for each run; a hosted
runner label alone does not establish stable timing or an enforced SLO.
After main's source CI succeeds, dispatch
`gh workflow run performance.yml --ref main`. The workflow records its exact
dispatch commit; a later main push is a different candidate. Download each
platform's artifact before its 14-day retention expires and recompute the
summary with `python3 -m scripts.check_performance_bundle --directory <bundle>
--revision <commit> --runner <recorded-runner> --max-report-bytes 1048576`.

The workflow pins checkout to its dispatch commit and requires the newest
main push of source CI for that exact commit to be completed and successful,
including the successful `All gates passed` job. Release and diagnostic
admission share this decision. A pending, failed, cancelled, missing or
wrong-commit result refuses measurement. Recheck the same CI run/attempt after
compilation and before measuring; a changed or rerun candidate needs a fresh
diagnostic dispatch.
Query aggregate jobs for the explicit inspected attempt, check their run,
attempt and source identity, then reread the latest candidate after the job
query. Separate API observations cannot provide atomicity against later
GitHub changes, but evidence from different attempts must never be combined.

Compile both selected tools before collecting samples. Only the dispatch
benchmark and the exact ignored `profile_retained_multi_target_finding_queue`
test may run; no ignored live harness test is selected. Run measurements
sequentially, without concurrent builds. Use the release profile and
`CARGO_PROFILE_RELEASE_STRIP=none`; bound each platform job to 90 minutes and
two compiler jobs. Toolchains use the repository pin. Reports and build output
remain outside the checkout so identity checks see a clean source tree.

Retain the CI admission record, runner image identity, raw dispatch/history
samples and a checked summary together as a short-lived workflow artifact.
Report validation must bind both raw reports to the admitted commit and named
runner, require the release profile, and reuse their existing sample validators.
A positive report-byte allowance is resolved by the CLI before reading JSON.
Malformed or incomplete data is a failed measurement; a high diagnostic P95
is a recorded result, not a noisy shared-runner timing gate. Preserve available
reports on failed jobs without calling an incomplete bundle accepted.

The workflow uses read-only repository/Actions permissions and no provider or
signing secret. Checkout does not persist its token. No release, installed
client, live fuzzer, provider, target or generated harness is exercised.
Publishing a sanitized acceptance record requires inspecting the retained
samples and observed outcomes. Dedicated-runner variance and cross-platform
operational qualification remain separate work.

## Rejected alternatives

- Timing only a mock function omits registry lookup and schema validation.
- A single average hides tail latency and queueing.
- Using a noisy shared runner as a hard SLO gate would create failures that do
  not identify a code regression.
