# C userspace engine qualification, 2026-09-27

Outcome: **passed for the benign C lifecycle on local macOS arm64**. Ten
independent normal cycles each completed libFuzzer, AFL++, and honggfuzz build,
provider review, bounded smoke, exact-attempt promotion, measured campaign
progress, addressed Stop, retained-input replay, and a positive selected-function
counter. This is not fault-injection, crash-rediscovery, C++, or another host
platform's acceptance.

## Identity and limits

| Item | Tested value |
| --- | --- |
| Candidate source | Clean commit `6cb82cea9ea600b0c94923d0bf8d0684eedc5af6`; empty working-tree patch SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Approved source | `examples/qualification/parser.c` and `harness.c`, NUL-separated combined SHA-256 `a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591`; the operator approved only this digest in the task |
| Selected function | `qualification_parse` |
| Runtime | macOS 27.0 arm64 host; `hf-runtime` Docker image ID `sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c` for all 30 engine runs |
| Toolchain | AFL++ 4.09c-1ubuntu3, Clang 17.0.6 and 18.1.3, honggfuzz source `83a8415a372d84dcc69ac1e2c2f152190bcf76d1` with the tracked LLVM profile-flush patch |
| Review provider | BigModel Coding Plan endpoint, model ID `glm-5.2`; the service performed a fresh real-provider review before each engine's smoke step |
| Bounds | One CPU, 2048 MiB memory, 10-second sandbox campaign limit and 10-second smoke/replay limits; Stop deadline 15 seconds; one cycle process deadline 300 seconds |

The [qualification procedure](../../examples/qualification/README.md) defines
the exact approved fixture and run path. Each engine ran through `hf-runtime`;
the generated harness was not executed on the host. The review provider's key
and raw logs remain outside the repository.

## Results

The runner reported 10 passed cycles and no failed, interrupted, or timed-out
cycle. Each cycle retained distinct campaign and replay IDs. The fixture
verified no new run container remained after each engine, and a final Docker
inventory found no `hf-run-` containers. Each cycle's database held three
completed replay function-profile records tied to the same image ID. All 30
LLVM exports contained a positive `qualification_parse` execution counter;
the minimum observed counts were 10,752,963 for libFuzzer, 1,160,692 for
AFL++, and 1,726,900 for honggfuzz.

Stop timing is in milliseconds, from the addressed cancellation request to
completed campaign closeout. P95 uses nearest rank; with ten samples it is the
maximum, so it is preliminary tail evidence rather than a robust latency
distribution.

| Engine | Samples | Median | P95 | Sorted Stop samples |
| --- | ---: | ---: | ---: | --- |
| libFuzzer | 10 | 475.5 | 489 | 468, 469, 471, 474, 475, 476, 477, 484, 488, 489 |
| AFL++ | 10 | 240.5 | 249 | 239, 239, 239, 240, 240, 241, 243, 245, 247, 249 |
| honggfuzz | 10 | 245.5 | 254 | 234, 239, 239, 243, 244, 247, 248, 249, 250, 254 |

Each cycle began with three manually seeded corpus entries and finished with
74–77 retained `Fuzzer` entries, for 77–80 entries total per fresh cycle. This
demonstrates corpus growth and retention on the benign fixture. It does not
measure whether those entries discover bugs or improve coverage on held-out
projects. Aggregate engine edges were not used as evidence of selected-function
entry; the exact replay-binary LLVM counters were.

## Evidence and review

The private evidence root is
`/Users/admin/.codex/qualification-evidence/a2-cycle-10-bigmodel-coding-candidate/`.
Its `manifest.json` SHA-256 is
`5850002ac943dc32939f4f98ba5614a0293959c6578fd08024457b008a2425c9`.
Each `cycle-NNNNN` contains a process log, SQLite database, retained run inputs,
profiles, and per-engine `qualification.json`. The manifest records the clean
commit, source digest, ten cycle outcomes, unique run IDs, and Stop statistics.
The evidence audit checked all ten databases for the 30 profile rows, positive
selected-function counts, the common image identity, retained corpus entries,
and successful smoke/campaign/replay records.

The [failed and exploratory attempts](userspace-attempts-2026-09-27.md) are
preserved separately and do not contribute to the ten passing samples. Source
approval, replay input/image mismatch, and unavailable-profile behavior also
have controlled regression tests. Further acceptance requires fault injection,
real defect rediscovery and crash handling, C++ and Rust campaigns, other host
platforms, and installed-client testing. This record does not authorize release
publication.
