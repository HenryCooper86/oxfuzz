# Dispatch and retained-history measurement, 2026-09-27

Outcome: the measured `hf-tools` executor path met the P95 under 100 ms
objective at concurrency 1, 8, and 32. The `hf-service` finding-review query
has a separate local baseline through 12,800 retained runs. This record does
not qualify provider latency, agent authorization, campaign Stop, or a public
release.

## Identity and method

The measured checkout was clean at commit
`decf548d4fb228781e85fa437bee1308c9c4b7f7`. The runner was
`local-macos-aarch64`: Mac17,6, 18 logical CPUs, macOS 27.0, Rust 1.94.0
(`4a4ef493e`). The dispatch benchmark used a release build and a four-worker
Tokio runtime. The history experiment used a debug build. No provider, harness,
fuzzer, network request, or target execution was involved.

The dispatch benchmark warmed each worker's schema validator, then retained
1,024 accepted and 1,024 denied calls for each concurrency level. Its no-op
tool includes registry lookup, JSON Schema validation, and trivial tool return
in the executor timer. Queue and enqueue-to-completion timers describe the
benchmark's own work queue. They are not measurements of the agent scheduler.
The first finding-review query of each of five independently populated SQLite
fixtures was measured separately from 25 repeat queries per size. Fixture
preparation time is retained in the raw record. Database pages may already be
warm after insertion.

## Results

All values below are P95, in microseconds. The dispatch acceptance threshold
is strictly below 100,000 microseconds for each executor row.

| Decision | Concurrency | Executor | Benchmark queue | Enqueue to completion |
| --- | ---: | ---: | ---: | ---: |
| Accepted | 1 | 1.83 | 11.29 | 12.79 |
| Accepted | 8 | 3.71 | 8.71 | 11.67 |
| Accepted | 32 | 3.62 | 6.00 | 8.79 |
| Denied | 1 | 1.54 | 7.17 | 8.67 |
| Denied | 8 | 3.96 | 7.67 | 10.25 |
| Denied | 32 | 3.92 | 6.42 | 9.50 |

Finding-review latency is in milliseconds. Each row includes five first-query
and 25 repeat-query observations on independently created service stores.

| Active targets across projects | Retained runs | First median | First P95 | Repeat median | Repeat P95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 161 | 3,200 | 57.16 | 57.72 | 56.04 | 56.78 |
| 161 | 6,400 | 113.42 | 114.33 | 111.58 | 115.81 |
| 321 | 12,800 | 216.28 | 224.87 | 214.53 | 217.31 |

The initial local history objective is P95 below 250 ms at 12,800 runs on
this runner. It is a history-specific target, separate from the 100 ms executor
objective. Campaign Stop retains its separate 15-second objective and requires
the approved live qualification.

## Release-profile history baseline

A second clean checkout at `da01e97833ed44aa3475b6399b84761d958092f9`
used the same `local-macos-aarch64` runner and Rust 1.94.0. The release-profile
history test used `CARGO_PROFILE_RELEASE_STRIP=none`, the macOS 27 setting used
by the desktop build. Without it, macOS rejected the generated `sqlx-macros`
library with a misaligned LINKEDIT string pool before the test ran. No provider,
harness, fuzzer, network request, or target execution was involved.

| Active targets across projects | Retained runs | First median | First P95 | Repeat median | Repeat P95 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 161 | 3,200 | 13.89 | 15.53 | 12.88 | 13.27 |
| 161 | 6,400 | 29.80 | 31.79 | 27.46 | 32.75 |
| 321 | 12,800 | 55.46 | 58.48 | 53.32 | 61.26 |

Values are milliseconds, with five first-query and 25 repeat-query samples
per size. This meets the local history objective in this profile; it does not
establish cross-platform latency or the separate dispatch and Stop objectives.

## Evidence and reproduction

- [Raw dispatch samples](performance-2026-09-27/dispatch.json), SHA-256
  `4e5865a9237eef0422bf350d38bd8db8bfc58fb885bf1675f341b97c2aa935d6`.
- [Raw history samples](performance-2026-09-27/history.json), SHA-256
  `e60071ed831e53e1ca9d140e93e5664bfa5266cb536725dbae34e0dc783a3a08`.
- [Raw release-profile history samples](performance-2026-09-27/history-release.json),
  SHA-256 `ac7520c77582ffa1751fb12dc9f5505768e83c0f7592011d6a97badd9f95e799`.

The published files can be checked with
`python3 scripts/check_dispatch_samples.py --input docs/acceptance/performance-2026-09-27/dispatch.json --limit-us 100000`
and
`python3 scripts/check_history_samples.py --input docs/acceptance/performance-2026-09-27/history.json`.
The same history checker accepts `history-release.json`. Reproduce the release
measurement with `CARGO_PROFILE_RELEASE_STRIP=none`, absolute
`OXFUZZ_HISTORY_REPORT`, and `OXFUZZ_PERFORMANCE_RUNNER=local-macos-aarch64`
when running the ignored `profile_retained_multi_target_finding_queue` test
through `scripts/cargo-test-filtered.sh -p hf-service --release --test finding_review`.
The full commands and fixture definitions are in the
[measurement design](../design/dispatch-performance-design.md). Future
comparisons should use the same runner, build profile, fixture sizes, and
sample counts; a changed environment needs its own baseline.
