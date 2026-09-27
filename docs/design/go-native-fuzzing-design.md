# Go Native Fuzzing Design

Status: **planned, not implemented**. Owners: `hf-service` for admission and
workflow, `hf-harness` for generated test source, `hf-engine` for Go progress
and artifact parsing, and `hf-runtime` for every process. This design does not
change Go's discovery-only entry in the support matrix.

## Goal and admission

Qualify one exported Go function through a generated `FuzzXxx(*testing.F)`
test, then run Go's native coverage-guided fuzzer. The Go engine is a separate
capability, not an alias for C/C++ libFuzzer. Add a disabled-by-default
`go-native-fuzzing` feature in the owning crates and an explicit Go engine kind
only when the implementation and its tests are ready. `hf-service` resolves
the feature, language, allowed-engine policy, saved project input, image, and
budget before provider access or `hf-runtime` dispatch. Direct executor calls
must reject unsupported combinations before side effects.

The first qualified target class is a package-level exported function that
accepts one `[]byte` or `string` input and can be called from an adjacent test
file. Methods, generic type instantiation, unsafe packages, cgo, functions
requiring external services, and multi-parameter targets need separate typed
recipes and evidence. Lexical discovery remains only a suggestion; package
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
`FuzzXxx(f *testing.F)`. It registers bounded deterministic seeds with `f.Add`
and passes each fuzz input to the selected function. Deterministic target
errors have a reviewed failure predicate; a returned error is not
automatically a bug. Lint rejects package/init side effects, subprocesses,
network and filesystem writes, unsafe imports, unbounded allocation, input
replacement with constants, and fuzz cases that do not call the selected
function. Compile diagnostics may drive a bounded repair attempt, but a new
source digest needs a new independent model review.

All compilation, review, smoke, promotion, campaign, replay, and crash
reproduction retain the existing service lifecycle. After a successful
in-sandbox `go test -c -o <run-owned-binary>` compile, independent model review
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
argv.

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
