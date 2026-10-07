# Operation support and qualification

Status at source revision `6cb82cea9ea600b0c94923d0bf8d0684eedc5af6`
(v0.5.1 candidate). Update the implementation column when behavior changes and
the qualification column only after reviewing a corresponding
[acceptance record](../acceptance/README.md). A fixture or mocked-runtime test
establishes implemented behavior, not live engine qualification.

| Target | Discovery | Harness build and smoke | Campaign engine | Run evidence and replay | Host platform scope | Qualification in this checkout |
| --- | --- | --- | --- | --- | --- | --- |
| C | Tree-sitter inventory; optional ranking and Semgrep enrichment | Reviewed source, sandbox compile, smoke, exact-revision promotion | AFL++, honggfuzz, libFuzzer | Shared retained corpus; historical retained-input replay; optional LLVM function counters | Docker-backed desktop/CLI paths on Linux, macOS, Windows; live behavior must be qualified per OS | [Ten normal three-engine cycles passed](../acceptance/userspace-2026-09-27.md) for a benign C fixture on macOS arm64; fault, crash and other-platform acceptance remains open |
| C++ | Tree-sitter inventory; optional ranking and Semgrep enrichment | Same lifecycle with C++ compiler/linker | AFL++, honggfuzz, libFuzzer | Same corpus/replay path; optional LLVM function counters | Docker-backed paths on Linux, macOS, Windows; platform-specific live acceptance open | Implemented and covered by controlled tests; representative real-project acceptance remains open |
| Rust | Conservative lexical inventory | cargo-fuzz/libFuzzer path in the sandbox | libFuzzer | Userspace run history and replay; C/C++ LLVM function-counter path does not establish Rust function entry | Docker-backed paths on Linux, macOS, Windows; image 0.2.1 vendors libfuzzer-sys for offline builds | [One complete live cycle passed](../acceptance/rust-2026-10-07.md) (build, review, smoke, promotion, campaign, Stop, replay) on macOS arm64; multi-cycle and other-platform acceptance remains open |
| Go | Conservative lexical inventory | No supported harness engine; [native fuzzing design](../design/go-native-fuzzing-design.md) is planned | Unavailable | No userspace campaign evidence | Discovery code is cross-platform; no campaign platform claim | Discovery only; no campaign claim |
| Python | Conservative lexical inventory | No supported harness engine; [Atheris design](../design/python-atheris-fuzzing-design.md) is planned | Unavailable | No userspace campaign evidence | Discovery code is cross-platform; no campaign platform claim | Discovery only; no campaign claim |
| Kernel | Not the userspace function inventory | A reviewed syzkaller manager configuration, not a generated userspace harness | syzkaller on Linux/KVM | Kernel-specific crash and run records; userspace replay claims do not apply | Dedicated Linux/KVM only; no macOS/Windows kernel-campaign claim | Implementation and controlled tests exist; dedicated Linux/KVM acceptance remains open |
| Automotive | Versioned protocol and virtual-lab workflows behind optional features and runtime policy | Scapy sidecar and scoped approval, not a C/C++ harness build | Stateful protocol execution, not a userspace fuzzing engine | Transcript/state evidence; novelty is not source coverage | Offline fixtures are platform-neutral; virtual/physical interface platforms need separate qualification | Fixture tests exist; virtual and physical lab acceptance remain separate open work |

Engine admission is decided by `EngineKind::supports_language` and the service
fuzzing policy. A disabled engine or unsupported language/engine pair is refused
before work starts. Syzkaller uses its separate kernel campaign path. Every
generated harness requires independent review, human promotion, and
`hf-runtime` sandboxing. Promotion also requires the selected target function to
have been entered when the smoke run retained a function profile; a run that
retained none is reported as unverified rather than as entry. C/C++ compilation
collects that profile by default, at a measured cost of about 4% of fuzzing
throughput, because otherwise a C/C++ promotion carries no target-exercise
evidence.

Additional operation limits:

- Crash ingestion and deduplication are implemented for userspace engines;
  engine-specific minimization may retain the original input when unavailable.
- Coverage edge counts do not prove entry into a selected function. Optional
  campaign-attributed LLVM function counters apply to instrumented C/C++
  builds; absent evidence is reported as unavailable.
- Historical replay verifies retained inputs and uses the original seed and
  admitted execution settings. An explicit current-input rerun is a separate
  experiment. Legacy runs without the manifest cannot be historical replays.
- Patch-to-Proof applies to reviewed userspace findings on Unix. It is
  unavailable for syzkaller and refuses the operation on Windows. Broader
  platform availability requires secure retained-artifact reading and its own
  acceptance record.
- Build Doctor's configured project-build support covers CMake, plain Make,
  Meson, and Autotools (sandbox image 0.2.0 or later), and a successful build
  publishes the build tree's generated headers and database-referenced
  generated sources alongside the compile database, so harness compiles
  resolve generated includes. Dependency fetching and Bazel remain
  unsupported; it detects those conditions without claiming a configured
  build for them.

For userspace C/C++/Rust, source discovery and the guarded build/smoke,
campaign, corpus, replay, and triage operations have cross-platform code and
CI checks on Linux, macOS, and Windows. Those checks do not qualify a real
Docker campaign on each host. C/C++ LLVM function profiles need instrumented
builds and separate live acceptance. Minimization availability depends on the
engine and is reported per operation; it is not assumed from campaign support.

See [Capability Acceptance](CAPABILITY_ACCEPTANCE.md) for the live checks and
the [backlog](../../TODO.md) for work still open. A successful local test, CI
build, or installed toolchain does not change the qualification column.
