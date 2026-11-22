# Go Native Fuzzing Design

Status: **implemented, acceptance open** (2026-11-21). Implemented and tested:
`EngineKind::GoNative` admission (outside the default engine set; the operator
enables it under `[fuzzing] enabled_engines`), the template harness for the
first target class, Go module staging, the sandboxed `go test -c` build, the
direct-test-binary run adapter, smoke, the corpus bridge, failing-input
ingestion, replay by name, and panic classification. One live cycle of those
building blocks passed in the pinned image on macOS arm64 (see "Implemented
behaviour" below). Not done: a full live `oxfuzz harness` / `oxfuzz run` cycle
through review, promotion, Stop and historical replay; the two-module
five-trial acceptance; Go coverage attribution of the selected function.
Owners: `hf-service` for admission and
workflow, `hf-harness` for generated test source, `hf-engine` for Go progress
and artifact parsing, and `hf-runtime` for every process.

## Implemented behaviour

Evidence is from Go 1.26.5 in `oxfuzz/fuzz-sandbox:0.2.2` (linux/arm64),
network disabled.

- **Harness.** A Go harness is always the fixed template
  (`hf_harness::go_native::template`): one `FuzzXxx` that passes the input to
  the selected function. A function of one `[]byte` or `string` receives the
  input as it is. Any other parameter list made of `[]byte`, `string`,
  `bool`, integer and float types is decoded from one `[]byte` input by a
  small reader the template carries (fixed-width little-endian numbers, a
  length-prefixed slice or string for every parameter but the last, which
  takes the rest), so the fuzz callback, and with it the corpus format, is
  always one `[]byte` or `string`. A provider is never asked for Go source; requiring
  AI for a Go draft is refused. The template registers no `f.Add` seeds and
  lint rejects them (`go-inline-seed`): Go reports a failing seed-corpus entry
  (`failure while testing seed corpus entry`) without saving a failing input,
  so a target that fails on the empty input would leave nothing to triage.
  With an empty corpus Go starts from the zero value and saves every failing
  input.
- **Build.** The staged module (no project `_test.go` files) is compiled with
  `go test -c -fuzz=^FuzzXxx$` under `GOPROXY=off`, `GOSUMDB=off`,
  `GOTOOLCHAIN=local`; build cache and module path live under `/tmp` in the
  container, never in the workspace. No sanitizer selection applies.
- **Run.** `-test.fuzzcachedir` is `<run output>/go-fuzz-cache`, the working
  directory is the run output directory, minimization time is 0, and the
  per-file write limit is 128 MiB: the fuzz coordinator backs each worker's
  shared memory with a 100 MiB temporary file and fails before the first
  input under the 64 MiB default (`truncate /tmp/fuzz-...: file too large`).
- **Corpus.** The run corpus stays a flat directory of raw inputs. Before a
  campaign the service encodes it into the fuzz cache in Go's corpus format;
  after the run it decodes what Go kept back into the run corpus, which then
  merges into the retained corpus like any other engine's. Smoke starts from
  the empty corpus.
- **Findings.** A run that exits non-zero is a finding only when Go printed
  `Failing input written to`; any other failure is a failed run whose output
  is reported. Failing inputs are collected from
  `testdata/fuzz/<FuzzXxx>/` under the run output, shown and deduplicated as
  decoded bytes, replayed with `-test.run=^FuzzXxx$/^<name>$`, and classified
  as a panic signed by the frames of the code under test.

## Goal and admission

Qualify one exported Go function through a generated `FuzzXxx(*testing.F)`
test, then run Go's native coverage-guided fuzzer. The Go engine is a separate
capability, not an alias for C/C++ libFuzzer. Add a disabled-by-default
`go-native-fuzzing` feature in the owning crates and an explicit Go engine kind
only when the implementation and its tests are ready. `hf-service` resolves
the feature, language, allowed-engine policy, saved project input, image, and
budget before provider access or `hf-runtime` dispatch. Direct executor calls
must reject unsupported combinations before side effects.

The qualified target class is a package-level exported function whose
parameters are each `[]byte`, `string`, `bool`, an integer type or a float
type, and which can be called from an adjacent test file. Methods, generic
type instantiation, unsafe packages, cgo, functions requiring external
services, and parameters of struct, interface or other types need separate
typed recipes and evidence. Lexical discovery remains only a suggestion; package
resolution and compilability decide whether a target can enter this workflow.

## Toolchain and exact inputs

Pin the Go toolchain and Linux architecture in a new versioned sandbox image.
Do not install Go tools or compile the target on the host. Stage the selected
module, `go.mod`, `go.sum`, local replacements, generated files, and the exact
package tree into an immutable run input directory. A project with generated
headers, code generation, cgo, or external modules must supply reviewed,
content-addressed offline inputs. Use a vendored module tree or a prefilled,
digest-pinned module cache prepared before the network-disabled run; set
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, and service-owned cache/output
paths. Missing dependencies or toolchain mismatch fail visibly. Never fetch a
module during qualification.

The service captures staged source, module/dependency, generated-test, and
image digests per compile attempt. A stale file or changed selected module
invalidates review and promotion. Package working directory, test name, and
fixed argv are service-resolved values; no provider-supplied shell command or
unreviewed build script runs. The sandbox keeps network disabled, dropped
capabilities, CPU/memory/process limits, an explicit deadline, and only
run-owned writable cache, corpus, and output directories.

## Harness and lifecycle

`hf-harness` emits an adjacent `_test.go` file with one uniquely named
`FuzzXxx(f *testing.F)`. It passes each fuzz input to the selected function
and registers no `f.Add` seeds (see "Implemented behaviour" for why). Deterministic target
errors have a reviewed failure predicate; a returned error is not
automatically a bug. Lint rejects package/init side effects, subprocesses,
network and filesystem writes, unsafe imports, unbounded allocation, input
replacement with constants, and fuzz cases that do not call the selected
function. Compile diagnostics may drive a bounded repair attempt, but a new
source digest needs a new independent model review.

All compilation, review, smoke, promotion, campaign, replay, and crash
reproduction retain the existing service lifecycle. Before any generated target/test build, independent model source review and
exact human source approval are required. After a successful in-sandbox
`go test -c -fuzz=^<FuzzXxx>$ -o <run-owned-binary> .` compile, independent model review
cites the exact test source and binary/build-input digests. An operator
approves the exact attempt before
smoke execution and explicitly promotes the smoke-qualified attempt before a
campaign. Go's ordinary `go test` runs seed cases, so even a compile/check
step must not invoke package tests before this execution approval. Qualification
invokes that exact compiled test binary with Go's `-test.fuzz`, `-test.run`,
`-test.fuzztime`, and `-test.parallel` flags, selecting one exact fuzz target,
skipping unrelated tests, and keeping parallelism within the resolved CPU
ceiling. Verify direct-binary fuzzing behavior with the pinned Go version before
shipping; if it cannot preserve Go's corpus and failure behavior, revise this
design before implementation. Retain the actual test binary identity and full
argv. Plain `go test -c` does not enable fuzz instrumentation: the versioned
[Go 1.26.5 test builder](https://github.com/golang/go/blob/go1.26.5/src/cmd/go/internal/test/test.go)
and [Go 1.27.1 test builder](https://github.com/golang/go/blob/go1.27.1/src/cmd/go/internal/test/test.go)
set instrumentation only when the fuzz selector is present. Compilation keeps
`-c`, so this selector does not authorize test execution. Bound or disable
`-test.fuzzminimizetime` explicitly; its 60-second default must not silently
extend the resolved operation duration.

The direct binary
[cache/coordinator flags](https://github.com/golang/go/blob/go1.27.1/src/testing/fuzz.go)
are internal Go interfaces. Pin and qualify their cache and corpus behavior
before depending on them. The [inert control sources](../../examples/qualification/go/README.md)
prepare this prerequisite. Their recorded exact digest has human source approval
as of 2026-10-01; the sources then received an independent exact-source model
review, a compile-only instrumented build, and on 2026-10-06 a bounded
single-trial control per module executed through `hf-runtime`
(spare-capacity regression passed; the
benign module completed normally; the known-defect module retained a crash
corpus file that replayed identically through the exact compiled binary).
Verified on the pinned Go 1.26.5 image: `-test.fuzz` requires
`-test.fuzzcachedir` (`testing.go` refuses the run otherwise), a failing input
is written to `testdata/fuzz/<FuzzXxx>` relative to the process working
directory through the coordinator's corpus directory, worker count follows
`-test.parallel` (default `GOMAXPROCS`), and `-test.fuzzminimizetime=0`
disables minimization so the crasher is retained immediately. These are
single-host linux/arm64 observations, not five-trial acceptance. The existing
sandbox Go 1.26.5 pin serves Syzkaller and does not qualify Go
native fuzzing. User demand on 2026-10-01 selects Go before Python; the
independent-module fixed-budget acceptance requirement remains.

Go keeps its regression corpus in `testdata/fuzz/<FuzzXxx>` and additional
interesting inputs in the fuzz cache. The service inventories both run-owned
locations, rejects links and oversized files, and imports only exact-format
corpus entries into durable storage. A raw C/libFuzzer corpus file is not a Go
seed until a typed converter has produced and verified Go's corpus format.
Historical replay uses the retained module, generated test, corpus entry,
toolchain/image, and invocation; it never reads a mutable checkout. Stop
cancels the addressed runtime operation, waits for owned process teardown,
then records retained cache/corpus and a terminal result. If teardown is not
verified, the run remains interrupted and requires recovery.

## Progress, coverage, and failures

Parse bounded Go fuzz progress as Go-specific telemetry: elapsed time,
executions, and interesting-input count. Go's interesting-input count is not
comparable to LLVM edges or proof that the selected function was entered.
Missing or changed output is `unavailable`, never zero. Exact selected-function
entry needs a separately qualified run-bound Go coverage measurement; until
then it remains unavailable in shared reports.

A panic or test failure is a candidate finding only after the exact Go corpus
input reproduces in the same sandbox image. Preserve the failure output,
corpus bytes, package/test name, Go version, source and harness digests,
exit status, and stack. Separate target failure from harness/setup failure;
do not call a timeout, OOM, or expected parse error a target bug. Go's own
minimization is bounded and sandboxed, and original input remains retained
when minimization fails. Crash identity and deduplication use `hf-crash` only
after service attribution.

## Verification and order

First write failing tests for disabled/direct admission, offline dependency
failure, exact source/image invalidation, lint/review denial, argv limits,
progress parsing, corpus import, Stop ownership, replay, and crash attribution.
Then qualify two independent pinned Go modules: a benign control and a known
reproducible defect, with five trials per condition under B1's fixed budgets.
Publish the image/toolchain identity, approvals, transcripts, Stop samples,
and missing measurements. No platform support claim follows from a Linux
container test on one host. Prioritize this implementation against Python only
after B1 and user demand identify the more useful path.

Native `go test` fuzzing is selected over a new AFL++ driver because Go already
defines seed, cache, minimization, and failure formats. Mapping Go to the
existing C libFuzzer engine is rejected because it would misstate telemetry and
replay behavior. Online module fetches are rejected because they make a run
depend on mutable remote state and violate the sandbox network policy.

Go's [native fuzzing guide](https://go.dev/doc/security/fuzz/) describes the
`go test -fuzz` lifecycle and limits; the
[testing package](https://pkg.go.dev/testing) documents `FuzzXxx`, corpus
locations, and failure behavior. The [go command reference](https://pkg.go.dev/cmd/go)
documents `go test -c` and the `-test.` prefix for direct binary flags.
Version-specific details must be checked
against the pinned toolchain during implementation.
