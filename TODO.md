# Project backlog

Open work is listed here. Completed changes are recorded in [CHANGELOG.md](CHANGELOG.md)
and commit history. Owners are subsystem maintainers unless an issue assigns otherwise.
The [support matrix](docs/guides/SUPPORT_MATRIX.md) records current operation-level
availability; [acceptance records](docs/acceptance/README.md) distinguish live
qualification from implementation.

## Functional improvements

- [x] Qualify retained-input replay and campaign function profiles on real engines.
  Implementation retains source, binary, initial corpus, dictionary, settings,
  and image identity; historical replay rejects missing or changed inputs.
  An explicit current-input rerun supports corpus experiments. C/C++ LLVM
  function profiles are opt-in, persisted against the run binary/image, and
  readable in history; [ten normal C-fixture cycles](docs/acceptance/userspace-2026-09-27.md)
  passed on libFuzzer, AFL++, and honggfuzz. Broader real-project usefulness is
  separate acceptance work. Owner: `hf-service`.
- [x] Broader project builds: Meson and Autotools join CMake and plain Make
  as supported, saved, executable build profiles (sandbox image 0.2.0),
  each plan verified live in the image; a successful build now publishes the
  build tree's generated headers and database-referenced generated sources
  alongside the compile database, and harness staging carries them into the
  sandbox workspace (verified live: a `configure_file` header compiles into
  the harness build). Still open on this item: dependency handling (builds
  stay network-disabled by design), Bazel, and per-system definitions beyond
  CMake's `-D` model. Owner: `hf-service`.
- [ ] Publish and verify language-by-operation support, including a real Rust
  cargo-fuzz campaign in the sandbox. Go/Python discovery does not establish
  harness support; the separate [Go](docs/design/go-native-fuzzing-design.md)
  and [Python](docs/design/python-atheris-fuzzing-design.md) designs await
  implementation and qualification. Owner: `hf-discovery` / `hf-harness`.

## Acceptance work

Use the [capability acceptance checklist](docs/guides/CAPABILITY_ACCEPTANCE.md)
to record results for pinned revisions and environments. Controlled tests do not
replace these live checks.

- [x] Record additional named release-profile dispatch and history runners.
  The [Linux x64, macOS arm64, and Windows x64 hosted diagnostics](docs/acceptance/performance-2026-10-01.md)
  retain raw samples, actual runner identities, and recomputed summaries.
  These shared-runner observations do not establish stable timing objectives.
- [ ] Repeat measurements on stable runners to characterize variance and set
  environment-specific history objectives. Keep campaign Stop and end-to-end
  agent/provider measurements independent of executor dispatch.
  Owner: `hf-service` and test infrastructure maintainers.

- [ ] Complete the [held-out effectiveness baseline](docs/acceptance/effectiveness-baseline-protocol.md).
  Three pinned C parser candidates have curated source snapshots, and the
  trial/report formats are tested; project approvals, frozen trials, live
  measurements, C++/Rust breadth, and result comparisons remain open.
  Owner: discovery, harness, coverage, and crash maintainers.

- [x] Qualify benign reviewed harnesses on libFuzzer, AFL++, and honggfuzz:
  build, bounded smoke, exact-attempt promotion, campaign, corpus retention,
  Stop, and cleanup. Generated source requires review and human approval before
  execution through `hf-runtime`. Ten normal cycles passed for the
  [approved C fixture](docs/acceptance/userspace-2026-09-27.md) on macOS arm64;
  fault and other-platform acceptance remain open.
- [ ] Qualify syzkaller on a dedicated Linux/KVM setup with identified kernel,
  root filesystem, symbols, and VM settings; verify boot, cancellation, cleanup,
  and failure recovery.
- [ ] Qualify automotive workflows on virtual interfaces and an isolated bench;
  record hardware and timing results separately from protocol fixture tests.
- [ ] Exercise finding publication against disposable issue-tracker and
  DefectDojo destinations with approved synthetic payloads; verify retry,
  deduplication, remote identity, and interrupted-operation recovery.
- [ ] Run an overnight soak with disposable storage and runtime resources,
  covering worker loss, disk pressure, restart, scheduler recovery, and Stop
  latency. The bounded fixture and repeated-cycle runner are prepared; normal
  repeated cycles do not replace fault injection or measured overnight acceptance.
- [ ] Validate installed desktop applications on supported platforms with
  representative users: setup, first campaign, historical findings, corpus
  import, keyboard navigation, and interrupted-session recovery. The
  [macOS arm64 experimental bundle](docs/acceptance/macos-installed-candidate-2026-09-27.md)
  has a partial install/launch/restart/provider record; the task list, other
  platforms, signed distribution, and user measurements remain open. Measure
  task completion and median/P95 times under comparable budgets.
- [ ] Complete a separately scoped repository security assessment and live
  isolation tests in a disposable environment. Existing regression and
  dependency checks are not a full security assessment.
- [ ] Run authorized vulnerability-rediscovery and reproduction experiments
  with pinned target/image revisions and retained evidence. A bounded run with
  no crash does not prove safety; crash classification alone does not establish
  exploitability.

## Ideas requiring design

- Source-revision bisection and regression-range investigation for reproducible
  findings.
- Intra-target engine workers through the run CPU allocation are implemented
  for all three userspace engines: libFuzzer (`-fork=N`), honggfuzz
  (`--threads`), and AFL++ (a sandboxed primary/secondary coordinator, with
  run-wide `fuzzer_stats` aggregation), plus `oxfuzz run --cpus N` requesting
  a per-run allocation validated against `fuzzing.sandbox.max_cpus`. Still
  open: measured multi-core efficiency and a retained multi-worker campaign
  acceptance record alongside existing portfolio concurrency (the coordinator
  has a direct sandbox-level engine check only).
- Agent token events after a native function-calling design makes partial
  responses useful. Provider streaming already exists; the current JSON tool
  protocol needs a complete response before dispatch.
- Concurrent specialist delegation, only after defining its scope and operator
  controls. Current delegation is single-depth.
