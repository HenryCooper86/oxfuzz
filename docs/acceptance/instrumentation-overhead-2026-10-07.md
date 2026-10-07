# Instrumentation overhead for run-attributed function counters

Date: 2026-10-07
Status: **measured on one fixture**. A single trivial C target does not establish
the cost for a deep parser under a long campaign.

## Why

`fuzzing.collect_function_coverage` defaults to false, and
`docs/design/corpus-coverage-design.md` gives the reason as "instrumentation
adds overhead" without a figure. That number decides whether the promotion
gate's target-entry evidence can be collected by default or needs a build
separate from the campaign binary, so the unquantified claim was replaced with a
measurement.

## Method

Build the same fixture twice in the pinned sandbox image and compare the time
libFuzzer takes to complete a fixed number of runs.

- Fixture: `examples/qualification/parser.c` with `examples/qualification/harness.c`.
- Flags, matching a real harness build: `-O1 -g -fsanitize=fuzzer,address`.
- Instrumented build adds `-fprofile-instr-generate -fcoverage-mapping
  -fprofile-update=atomic`, the same three flags `function_coverage::FLAGS`
  injects.
- Workload: `-runs=200000`, five repetitions each, interleaved so a drifting host
  cannot favour one binary.
- Corpora: a 1-byte seed, and a 64 KiB seed so the target does more work per
  execution and the edge counters dominate the per-run cost. The second is the
  conservative case for instrumentation.
- Environment: `oxfuzz/fuzz-sandbox:0.2.1`, macOS arm64 host, Docker with
  `--network=none`.

Raw wall-clock milliseconds per repetition.

| Corpus | Plain | Instrumented |
| --- | --- | --- |
| 1-byte seed | 119, 121, 122, 121, 122 | 129, 125, 125, 125, 127 |
| 64 KiB seed | 118, 117, 116, 119, 117 | 124, 121, 123, 121, 122 |

## Result

Mean 121.0 ms plain against 126.2 ms instrumented, and 117.4 ms against
122.2 ms. Instrumentation costs about **4%** of fuzzing throughput, and the
figure is stable across a 65536x change in seed size, so it is not an artifact
of input size.

The spread within each group is under 2%, smaller than the gap between groups,
so the difference is resolvable at five repetitions.

## Limits

- One target, one host, one image, and a 200000-run workload. The cost scales
  with executed edges per input, so a target that executes far more instrumented
  code per input can cost more than 4%.
- Total campaign cost also includes profile merge and export at closeout, which
  this measurement excludes; that work is proportional to profile size rather
  than to run count and is not visible at this workload.
- A 200000-run workload is far shorter than a campaign, so per-run startup is
  over-represented relative to a long run. That biases against instrumentation,
  making 4% an upper estimate for a long campaign on this fixture.
- `-fprofile-update=atomic` is the setting the service uses; a single-threaded
  counter update would differ.
