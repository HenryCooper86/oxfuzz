# Operation support and qualification

Status at source revision `6cb82cea9ea600b0c94923d0bf8d0684eedc5af6`
(v0.5.1 candidate). Update the implementation column when behavior changes and
the qualification column only after reviewing a corresponding
[acceptance record](../acceptance/README.md). A fixture or mocked-runtime test
establishes implemented behavior, not live engine qualification.

**Windows is not supported for now.** Windows installers are not built or
published, CI does not compile or test Windows, and no Windows campaign claim
is made. The source paths and the qualification procedure are kept so support
can come back. See [Qualifying a Windows host](WINDOWS_QUALIFICATION.md) and the
[hosted-runner record](../acceptance/windows-host-2026-11-22.md).

| Target | Discovery | Harness build and smoke | Campaign engine | Run evidence and replay | Host platform scope | Qualification in this checkout |
| --- | --- | --- | --- | --- | --- | --- |
| C | Tree-sitter inventory; optional ranking and Semgrep enrichment | Reviewed source, sandbox compile, smoke, exact-revision promotion | AFL++, honggfuzz, libFuzzer | Shared retained corpus; historical retained-input replay; optional LLVM function counters | Docker-backed desktop/CLI paths on Linux and macOS | [Ten normal three-engine cycles passed](../acceptance/userspace-2026-09-27.md) for a benign C fixture on macOS arm64; fault, crash and other-platform acceptance remains open |
| C++ | Tree-sitter inventory; optional ranking and Semgrep enrichment | Same lifecycle with C++ compiler/linker | AFL++, honggfuzz, libFuzzer | Same corpus/replay path; optional LLVM function counters | Docker-backed paths on Linux and macOS | Implemented and covered by controlled tests; representative real-project acceptance remains open |
| Rust | Conservative lexical inventory | cargo-fuzz/libFuzzer path in the sandbox | libFuzzer | Userspace run history and replay; C/C++ LLVM function-counter path does not establish Rust function entry | Docker-backed paths on Linux and macOS; the image vendors libfuzzer-sys for offline builds, and a project's crates.io dependencies build from its own `cargo vendor` tree (`vendor/`); git dependencies and unvendored crates do not build | [One complete live cycle passed](../acceptance/rust-2026-10-07.md) (build, review, smoke, promotion, campaign, Stop, replay) on macOS arm64; multi-cycle and other-platform acceptance remains open |
| Go | Conservative lexical inventory | Fixed template harness for a package-level exported function whose parameters are each `[]byte`, `string`, `bool`, an integer type or a float type (one `[]byte` or `string` is passed through; any other list is decoded from the input); offline `go test -c` build in the sandbox ([design](../design/go-native-fuzzing-design.md)) | Go native fuzzing (`go-native`), enabled by the operator under `[fuzzing] enabled_engines`; no sanitizer selection | Failing inputs collected, replayed by name and classified as panics; corpus translated to and from Go's format; no selected-function coverage | Docker-backed paths on Linux and macOS; modules that need downloaded dependencies must be vendored | Build, smoke, corpus, failing-input collection, replay and classification passed once live in the sandbox on macOS arm64 (2026-11-21); a full review/promotion/campaign/Stop cycle through the commands and the five-trial acceptance remain open |
| Python | Conservative lexical inventory | Fixed template script for a top-level synchronous function of an importable pure-Python module whose required parameters each take `bytes`, `str`, `int`, `float` or `bool` (one `bytes` or `str` is passed through; any other list is decoded with Atheris's data provider); the build parses the script and the module without importing them ([design](../design/python-atheris-fuzzing-design.md)) | Atheris (`atheris`), enabled by the operator under `[fuzzing] enabled_engines`; one interpreter per run; no sanitizer selection | An uncaught exception is the finding: `crash-*` inputs collected, replayed and classified by exception and frames; a run imports the sources retained with it; no selected-function coverage and no minimization | Docker-backed paths on Linux and macOS; standard library, project modules, and pure-Python packages the project carries under `vendor/python/`; nothing is installed and C extensions are out | Build, smoke, finding collection, replay, classification and retained-source import passed once live in sandbox image 0.2.3 on macOS arm64 (2026-11-21); a full review/promotion/campaign/Stop cycle through the commands and the two-project acceptance in the design remain open |
| Java | Conservative lexical inventory: `public static` methods of the class a file is named after | Fixed template class for a `public static` method of a top-level class whose one to eight parameters are each `byte[]`, `String` or a primitive (one `byte[]` or `String` is passed through; any other list is decoded with Jazzer's data provider); one sandboxed `javac` build of the project's own sources, against the jars it carries under `lib/` or `libs/`, into a self-starting jar ([design](../design/jvm-jazzer-fuzzing-design.md)) | Jazzer (`jazzer`), enabled by the operator under `[fuzzing] enabled_engines`; one JVM per run; no sanitizer selection | An uncaught exception or a Jazzer bug-detector report is the finding: `crash-*` inputs collected, replayed and classified by exception and frames; a run executes the classes inside its own staged artifact; no selected-function coverage and no minimization | Docker-backed paths on Linux and macOS; the JDK, the project's own `.java` files and the jars under its `lib/` or `libs/` directory; nothing is resolved or downloaded, so a Maven or Gradle project copies its dependency jars there first (no Kotlin or Scala, no annotation processors) | Build, smoke, finding collection, replay, classification and a corrected-source control passed once live in sandbox image 0.2.3 on macOS arm64 (2026-11-21); a full review/promotion/campaign/Stop cycle through the commands and a multi-project acceptance remain open |
| JavaScript | Conservative lexical inventory: functions declared at the top level of a `.js`, `.mjs` or `.cjs` file and exported under their own name (CommonJS or ES module) | Fixed template module for an exported function whose required parameters are each documented in the JSDoc block directly above it as `Buffer`, `Uint8Array`, `string`, `number` or `boolean` (one `Buffer` or `string` is passed through; any other list is decoded with Jazzer.js's data provider); the build parses the harness and the module with `node --check` without loading them ([design](../design/javascript-jazzerjs-fuzzing-design.md)) | Jazzer.js (`jazzer-js`), enabled by the operator under `[fuzzing] enabled_engines`; one Node.js process per run; no sanitizer selection | An uncaught exception, a rejected promise or a Jazzer.js bug-detector report is the finding: `crash-*` inputs collected, replayed and classified by exception and frames; a run loads the sources and packages retained with it; no selected-function coverage and no minimization | Docker-backed paths on Linux and macOS; the project root must hold `package.json`; Node.js built-ins, the project's own modules and the `node_modules` tree it carries; nothing is installed, symlinked package layouts (pnpm, linked workspaces) are not staged, and native addons built for the host do not load (no TypeScript, no methods or classes, no browser code); driven from the CLI | Build, smoke, finding collection, replay, classification, a retained-source replay and a corrected-source control passed once live in sandbox image 0.2.3 on macOS arm64 (2026-11-22), for a CommonJS module and an `async` ES module; a full review/promotion/campaign/Stop cycle through the commands and a multi-project acceptance remain open |
| Binary only (Linux ELF, no source) | None: the operator names the executable | None: there is no source to draft, review, or compile ([design](../design/binary-only-fuzzing-design.md)) | AFL++ QEMU mode through `oxfuzz binary`, as one standalone session; the input is a file argument, standard input, or with `--socket` the first connection a stream server accepts or one datagram on the UDP socket it binds; `--messages` delivers a sequence of messages, each after the server read the one before | Crash inputs replayed under the emulator with a preloaded crash reporter: signal, crash kind, frames as module offsets, and a stack signature; findings grouped by signature; each distinct finding minimized with `afl-tmin -Q` and kept only when it replays as the same crash; `binary-issue` drafts or files one. No sanitizer, no coverage report, and not stored in the crash table (no triage, proof, or report surfaces). A static target gets the signal only | Docker-backed paths on Linux and macOS; the binary must be a 64-bit ELF for the sandbox image's own architecture | Planted-crash programs were found, confirmed, signed, grouped, and minimized live in file, stdin, and socket mode, and for a UDP server, a stateful UDP exchange, and a stateful TCP exchange, in sandbox image 0.2.3 on macOS arm64 (2026-11-22); no run through the command, no filing against a live tracker, and no real-binary acceptance is recorded |
| Kernel | Not the userspace function inventory | A reviewed syzkaller manager configuration, not a generated userspace harness | syzkaller in sandboxed qemu guests, started by `oxfuzz kernel` or the desktop app | Kernel-specific crash and run records; userspace replay claims do not apply | Linux with `/dev/kvm` for campaigns at useful speed; without KVM the guest is emulated, which proves the setup and not throughput; Windows is not supported | One emulated campaign passed as functional validation on macOS arm64 ([record](../acceptance/kernel-emulated-2026-11-22.md)); two 30-minute KVM campaigns passed on hosted Linux x86_64 runners ([record](../acceptance/kernel-kvm-2026-11-24.md)); throughput qualification, crash reproduction and the `oxfuzz kernel` command line on Linux remain open |

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

Discovery inventories more languages than the harness pipeline can build, and
the distinction is one predicate: `TargetLanguage::harnessable` (hf-core). C,
C++, Rust, Go, Python, Java, and JavaScript are harnessable today (Go only
under the `go-native` engine, Python only under the `atheris` engine, Java
only under the `jazzer` engine, JavaScript only under the `jazzer-js`
engine). TypeScript is not scanned or fuzzed.
`oxfuzz discover`
marks every candidate with a derived `harnessable` flag and notes the
supported set when the scanned language has no harness path. Harness draft/compile/generate, `oxfuzz fuzz`
target auto-selection, and `oxfuzz campaign` enforce the same predicate in the
operation itself, so a discovery-only target fails loud at that boundary --
naming the language and the supported set -- rather than at a late build step.

Sanitizer selection (`--sanitizer`, `[fuzzing] default_sanitizer`): C and C++
harnesses build with AddressSanitizer (`address`, the default) or
UndefinedBehaviorSanitizer (`undefined`, halt-on-error) under all three
userspace engines; the per-engine flag mapping and its toolchain evidence live
in
[ENGINE_ADAPTER_STANDARD.md](../standards/ENGINE_ADAPTER_STANDARD.md#35-sanitizer-selection).
Rust targets build AddressSanitizer-only (cargo-fuzz/libfuzzer-sys has no
UBSan path) and reject any other selection.

| Sanitizer | C | C++ | Engines |
| --- | --- | --- | --- |
| `address`, `undefined` | Yes | Yes | libFuzzer, AFL++, honggfuzz |
| `thread` (ThreadSanitizer) | Yes | Yes | libFuzzer, honggfuzz |
| `memory` (MemorySanitizer) | Yes | Yes, libFuzzer and honggfuzz | libFuzzer, AFL++ (C only), honggfuzz |

ThreadSanitizer is not admitted for AFL++: in the pinned image it reports a
data race inside the AFL++ forkserver runtime for an input that never reaches
a race. A C++ MemorySanitizer build links the MemorySanitizer-instrumented
libc++ that sandbox image 0.2.3 carries, in place of libstdc++; under AFL++
such a binary does not start its forkserver, so that pair is refused. A
prebuilt C++ library the project links is not instrumented and can produce
false reports. Each admitted pair found a planted bug in the pinned sandbox
image on linux/arm64 (C and thread pairs in 0.2.2, C++ memory pairs in
0.2.3), and a correct control target produced no finding; no acceptance
record exists yet. `none` is rejected: a sanitizer-less build has no
sanitizer evidence to classify.
Syzkaller kernel builds take no userspace sanitizer selection.

AFL++ CmpLog/redqueen (`--cmplog` on `harness`, `run`, `campaign`, `fuzz`):
an opt-in companion binary (`AFL_LLVM_CMPLOG=1`) for magic-byte and
multi-byte comparison targets, driven by `afl-fuzz -c`. AFL++-only; a run
that opts in requires the promoted harness revision's recorded companion and
fails loud otherwise. Mechanics and the parallel-mode choice live in
[ENGINE_ADAPTER_STANDARD.md](../standards/ENGINE_ADAPTER_STANDARD.md#36-afl-cmplogredqueen).

Additional operation limits (the Windows items describe code that is kept;
no Windows package ships):

- Native Windows drive-path mount arguments are covered by controlled runtime
  tests. Windows installers and those tests do not establish live Docker build,
  smoke, or campaign qualification. UNC and WSL filesystem configurations
  have not been qualified either. [Qualifying a Windows host](WINDOWS_QUALIFICATION.md)
  is the procedure that produces the record. It has been run in part, once,
  on a hosted Windows Server 2025 runner with Rancher Desktop as the engine
  ([record](../acceptance/windows-host-2026-11-22.md)): the image build, the
  isolation tests, the provider-free source-engine tests and a stopped and
  resumed AFL++ campaign passed; binary-only sessions failed; the reviewed
  campaign and process-loss steps were not run. Windows 10 and 11 and Docker
  Desktop have not been run at all, so no Windows campaign claim is made.
- AFL++ output and resume on Windows NTFS remain unqualified. The packaged
  AFL++ 4.09c uses colon-delimited queue/crash filenames and resume backup
  directories. Through a WSL 2 drive mount such a name was stored with
  U+F03A in place of each colon, and one AFL++ campaign was stopped and
  resumed that way (the record above); a Docker Desktop mount has not been
  observed. Win32 treats colons as
  [alternate-stream separators](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams),
  so host-written fixtures cannot reproduce these as ordinary files.
  AFL++'s [compile-time `SIMPLE_FILES` option](https://github.com/AFLplusplus/AFLplusplus/blob/v4.09c/include/config.h)
  uses portable names, but the shipped sandbox does not enable it. Resume
  tests use that format to exercise copying, byte ceilings, and crash ingestion
  on every CI host; they do not qualify the packaged engine on NTFS. Production
  qualification requires a compatible image and actual Windows Docker
  build/smoke/campaign/resume evidence.
- Crash ingestion and deduplication are implemented for userspace engines;
  engine-specific minimization may retain the original input when unavailable.
- Coverage edge counts do not prove entry into a selected function. Optional
  campaign-attributed LLVM function counters apply to instrumented C/C++
  builds; absent evidence is reported as unavailable.
- Historical replay verifies retained inputs and uses the original seed and
  admitted execution settings. An explicit current-input rerun is a separate
  run. Legacy runs without the manifest cannot be historical replays.
- Patch-to-Proof applies to reviewed userspace findings on Unix. It is
  unavailable for syzkaller and refuses the operation on Windows. Broader
  platform availability requires secure retained-artifact reading and its own
  acceptance record.
- Crash bisection (`oxfuzz bisect`, feature `crash-bisection`) applies to
  promoted C and C++ harnesses on libFuzzer, AFL++, and honggfuzz. It reads
  each tested commit from git as stored objects, builds the harness against it
  in the sandbox, and replays the crash input; the checkout is not changed. It
  searches the first-parent path, skips commits that do not build, and reports
  a commit range when skips leave the answer undecided. A project whose build
  needs generated files that are not in the tree is not covered. A planted
  regression was bisected in sandbox image 0.2.2 on linux/arm64; no acceptance
  record exists yet. See [Crash Bisection](../design/crash-bisection-design.md).
- Line coverage hand-off (`oxfuzz coverage --lcov/--html`) renders the most
  recent C/C++ LLVM coverage measurement of a target as an lcov tracefile or
  one self-contained HTML page. The lcov records match `llvm-cov export
  -format=lcov` on an LLVM 18 fixture. Rust targets and campaigns without a
  measurement have no report.
- Crash alerts (`config/notifications.toml`, feature `crash-alerts`) post one
  message per scheduled run that found crashes to a generic JSON or Slack
  incoming webhook, and `oxfuzz notify` sends the same for the latest run.
  HTTPS is required except for loopback. Email, PagerDuty, and Microsoft
  Teams formats are not implemented.
- Structured input: an operator dictionary (`oxfuzz dict`, `run --dict`) is
  merged ahead of the extracted tokens; C++ harness drafts are pointed at
  `FuzzedDataProvider`; `oxfuzz mutator grammar` generates a reviewed custom
  mutator from a BNF grammar for libFuzzer and AFL++. Protobuf-defined inputs
  (libprotobuf-mutator) are not supported: the sandbox image ships neither
  `protoc` nor the library.
- Build Doctor detects CMake, Meson, Autotools, plain Make, and Bazel from
  root marker files and reports them as supported; its saved build profiles
  cover the same five systems (sandbox image 0.2.0 or later, which installs
  `meson`, `autoconf`/`automake`, and `bear`; Bazel 8.9.0 and 9.3.3 from
  0.2.3). The CLI and REST API accept all five profile types; the desktop
  profile editor currently offers CMake and plain Make. A successful build
  publishes the build tree's generated headers and database-referenced
  generated sources alongside the compile database, so harness compiles
  resolve generated includes.
- Nothing is downloaded during a build: sandbox networking is disabled by
  design and is not an operator setting. A project builds offline from the
  dependencies it carries. For Bazel that is a vendor directory made with
  `bazel vendor` in a Bzlmod workspace (`MODULE.bazel`); a WORKSPACE-only
  project is detected and reported as unsupported. The Bazel step reads
  compile commands from analysis and compiles nothing, so headers a Bazel
  build would generate are not available to a harness.

For userspace C/C++/Rust, source discovery and the guarded build/smoke,
campaign, corpus, replay, and triage operations have cross-platform code and
CI checks on Linux and macOS. Those checks do not qualify a real
Docker campaign on each host. C/C++ LLVM function profiles need instrumented
builds and separate live acceptance. Minimization availability depends on the
engine and is reported per operation; it is not assumed from campaign support.

See [Capability Acceptance](CAPABILITY_ACCEPTANCE.md) for the live checks and
the [backlog](../../TODO.md) for work still open. A successful local test, CI
build, or installed toolchain does not change the qualification column.
