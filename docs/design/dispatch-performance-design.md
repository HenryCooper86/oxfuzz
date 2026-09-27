# Dispatch and retained-history performance

Status: measurement implemented; baseline pending. Owner: `hf-tools`, `hf-agent`, and
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

Use an absolute report path because Cargo starts the benchmark in its crate
directory. Run the ignored service profile through `scripts/cargo-test-filtered.sh`
with `OXFUZZ_HISTORY_REPORT` and `OXFUZZ_PERFORMANCE_RUNNER` set. Both outputs
name the measured Git revision, runner, toolchain, OS, architecture, and build
profile and whether the checkout was clean. The checkers reject dirty source,
missing fixture sizes, or missing samples. Retain
raw JSON alongside the published quantiles so another reviewer can recompute
them.

## Rejected alternatives

- Timing only a mock function omits registry lookup and schema validation.
- A single average hides tail latency and queueing.
- Using a noisy shared runner as a hard SLO gate would create failures that do
  not identify a code regression.
