# Hosted performance diagnostics, 2026-10-01

Outcome: complete, valid diagnostic bundles on Linux x64, macOS arm64, and
Windows x64. All three jobs of [measurement run 36826934757](https://github.com/HenryCooper86/oxfuzz/actions/runs/36826934757)
completed successfully. Shared hosted runners have no enforced timing threshold;
one run per platform does not establish stable-runner variance or release acceptance.

## Identity and method

The clean measured candidate was `b72fb5c1760af14ca14bd0fde9a69092624ffe15`.
[Source CI 36814154674](https://github.com/HenryCooper86/oxfuzz/actions/runs/36814154674)
and its aggregate passed at this exact commit, attempt 1. The measurement
workflow admitted that source run and rechecked its identity and result after
compilation. Measurement run attempt was 1 on every platform.

Both measurements used the release profile, Rust `1.94.0 (4a4ef493e 2026-03-02)`,
`CARGO_PROFILE_RELEASE_STRIP=none`, and two compiler jobs. Dispatch used the
`noop-schema-v1` fixture and four Tokio workers, with 1,024 samples per decision
and concurrency case. The executor timer covers registry lookup, JSON Schema
validation, and trivial tool return. Queue and total timings describe the
benchmark queue; they do not measure the agent scheduler.

The finding-history fixture created five independent stores per size. Each
has one first query and five repeat queries: five first-query and 25 repeat
query samples per size. Preparation is measured separately. Insertions may
already warm database pages; the first query is not a cold-disk measurement.
Each job collected dispatch and history sequentially with a 90-minute job limit.
No provider, generated harness, target, fuzzer, container, or live campaign ran.
No dedicated CPU or memory reservation was applied to either synthetic fixture.

| Platform | Runner | Actual image version | Successful job |
| --- | --- | --- | --- |
| linux X64 | `gha-linux-ubuntu24-x64-diagnostic` | `ubuntu24 20260920.314.1` | [110254603232](https://github.com/HenryCooper86/oxfuzz/actions/runs/36826934757/job/110254603232) |
| macos ARM64 | `gha-macos26-arm64-diagnostic` | `macos26 20260907.0351.1` | [110254603094](https://github.com/HenryCooper86/oxfuzz/actions/runs/36826934757/job/110254603094) |
| windows X64 | `gha-windows2025-x64-diagnostic` | `win25-vs2026 20260925.250.1` | [110254603324](https://github.com/HenryCooper86/oxfuzz/actions/runs/36826934757/job/110254603324) |

## Observations

Dispatch P95 is in microseconds. Raw bundles also retain median, maximum,
queue, and total observations. No timing threshold was applied.

| Decision | Concurrency | Linux | macOS | Windows |
| --- | ---: | ---: | ---: | ---: |
| accepted | 1 | 14.116 | 5.333 | 3.300 |
| accepted | 8 | 4.779 | 6.541 | 3.800 |
| accepted | 32 | 4.629 | 13.375 | 3.700 |
| denied | 1 | 2.995 | 5.334 | 3.800 |
| denied | 8 | 4.859 | 11.334 | 3.800 |
| denied | 32 | 5.581 | 11.167 | 4.000 |

History P95 is in milliseconds. Fixture preparation P95 is in seconds.
The retained run counts are 3,200 and 6,400 across 161 targets, then 12,800
across 321 targets.

| Platform | Runs | First query P95 (ms) | Repeat query P95 (ms) | Preparation P95 (s) |
| --- | ---: | ---: | ---: | ---: |
| linux | 3,200 | 49.987 | 47.455 | 1.173 |
| linux | 6,400 | 84.760 | 86.398 | 2.146 |
| linux | 12,800 | 157.156 | 167.605 | 4.121 |
| macos | 3,200 | 63.282 | 50.943 | 1.900 |
| macos | 6,400 | 116.190 | 100.078 | 3.028 |
| macos | 12,800 | 247.201 | 225.111 | 6.091 |
| windows | 3,200 | 86.659 | 76.226 | 93.110 |
| windows | 6,400 | 134.895 | 134.441 | 161.911 |
| windows | 12,800 | 257.070 | 249.191 | 111.503 |

Windows fixture preparation was substantially slower than on the other runners.
These samples alone do not establish the cause. Preparation timings are retained
rather than folded into history-query latency or treated as a query failure.
Windows first-query P95 at 12,800 runs was 257.070 ms. The earlier 250 ms history
objective belongs to the named local runner; this hosted measurement does not
extend that objective to Windows or declare it met.

## Evidence and verification

Each platform directory retains original `dispatch.json`, `history.json`,
`source-ci.json`, `runner.json`, and the workflow-produced `summary.json`.
Bounded validation of the four raw inputs reproduced the original summary
exactly as parsed JSON on all three runners. The raw-input SHA-256 digests are
retained in each summary. Original downloaded summaries were preserved before
recomputation; the copies below preserve those original bytes.

| Platform | Raw bundle summary | Summary SHA-256 | GitHub artifact ID |
| --- | --- | --- | --- |
| linux | [linux summary](performance-2026-10-01/linux/summary.json) | `81f6db6436e7869b3b71acd3d4328de65894648bf8d1aba3f6cc15736954cb38` | `11145299295` |
| macos | [macos summary](performance-2026-10-01/macos/summary.json) | `87b4b3e9c0af370f822e3581fb1d37d021373c623349a26ed040a39dc756639c` | `11146180548` |
| windows | [windows summary](performance-2026-10-01/windows/summary.json) | `aca8197eaf8179c70bdb9c2cd4eed47845a20033197fa4dcd076a4c2ac650530` | `11146703328` |

GitHub reported these archive digests (distinct from the raw-file digests):

- Linux: `sha256:b4fd9aa39e75f9d1576d33d6ce4910bba92e673b3b33c8838a0b7a49011afb1e`.
- macOS: `sha256:820573c7f8bd62f52cef1c8556fbf822ce61c7260bc405095b2c241ea892394a`.
- Windows: `sha256:cdfd53644ee06d618ce5ac8e5ccc16b1ef3ce5b321a03ac21d202a8626d514ee`.

Validate a copied platform bundle in a disposable directory, since the checker
rewrites its summary. For example:

```bash
cp -R docs/acceptance/performance-2026-10-01/windows /tmp/oxfuzz-performance-check-windows
python3 -m scripts.check_performance_bundle \
  --directory /tmp/oxfuzz-performance-check-windows \
  --revision b72fb5c1760af14ca14bd0fde9a69092624ffe15 \
  --runner gha-windows2025-x64-diagnostic --max-report-bytes 1048576
```

The equivalent Linux/macOS runner names are in the identity table. The
[measurement design](../design/dispatch-performance-design.md) defines samples
and reproduction; the manually dispatched `performance.yml` requires a
successful source CI for the exact current main candidate. A changed candidate
or runner requires its own result.

## Review and remaining scope

The record was checked on 2026-10-01 against successful job results, retained
runner/source identities, raw inputs, recomputed quantiles and file digests.
It contains synthetic timing data and public workflow identities, without
credentials, private source, or customer crash inputs. Source review accompanies
the evidence publication; this record asserts no operator approval for live code.
Stable-runner repeated measurements, provider latency, end-to-end agent dispatch,
campaign Stop, installed-client task latency, and live fuzzing acceptance remain
open. The [local record](performance-2026-09-27.md) retains its own narrower
objectives and environment.
