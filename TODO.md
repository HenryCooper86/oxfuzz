# Project backlog

Open work is listed here. Completed changes are recorded in [CHANGELOG.md](CHANGELOG.md)
and commit history. Owners are subsystem maintainers unless an issue assigns otherwise.

## Functional improvements

- [ ] Immutable-input reruns: retain selected dictionary bytes and complete
  execution-input identity, then execute against those retained inputs. Current
  reviewed replay starts a new campaign using current workspace inputs; it is
  not exact historical reproduction. Owner: `hf-service`.
- [ ] Exact run-scoped function coverage: retain run-linked instrumentation and
  evidence before claiming target-function entry. Aggregate edge counts and a
  separate coverage rebuild do not establish it. Owner: `hf-coverage` / `hf-service`.
- [ ] Broader project builds: extend measured onboarding beyond CMake and plain
  Make, including generated headers and dependencies. Detecting a build system
  does not imply configured build support. Owner: `hf-service`.
- [ ] Bound event-schedule cascades across different schedules. Direct
  self-triggering is suppressed, but two schedules listening to each other's
  run events can still chain. Carry and enforce cascade depth through triggers.
  Owner: `hf-scheduler` / `hf-service`.
- [ ] Publish and verify language-by-operation support, including a real Rust
  cargo-fuzz campaign in the sandbox. Go/Python discovery does not establish
  harness support. Owner: `hf-discovery` / `hf-harness`.

## Acceptance work

Use the [capability acceptance checklist](docs/guides/CAPABILITY_ACCEPTANCE.md)
to record results for pinned revisions and environments. Controlled tests do not
replace these live checks.

- [ ] Qualify benign reviewed harnesses on libFuzzer, AFL++, and honggfuzz:
  build, bounded smoke, exact-attempt promotion, campaign, corpus retention,
  Stop, and cleanup. Generated source requires review and human approval before
  execution through `hf-runtime`.
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
  latency. Update the ignored live cancellation fixture before using it.
- [ ] Validate installed desktop applications on supported platforms with
  representative users: setup, first campaign, historical findings, corpus
  import, keyboard navigation, and interrupted-session recovery. Measure task
  completion and median/P95 times under comparable budgets.
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
- Intra-target engine workers, with measured multi-core efficiency alongside
  existing portfolio concurrency.
- Agent token events after a native function-calling design makes partial
  responses useful. Provider streaming already exists; the current JSON tool
  protocol needs a complete response before dispatch.
- Concurrent specialist delegation, only after defining its scope and operator
  controls. Current delegation is single-depth.
