# Go toolchain control candidates

Status: bounded control executed; qualification and Go support remain pending.
Exact human source approval was received on 2026-10-01 for the digest below,
followed by an independent exact-source model review and a compile-only
instrumented build of both modules through `hf-runtime` on 2026-10-01. On
2026-10-06 the bounded control ran under the same pinned image: the
spare-capacity regression passed, one trial per module terminated within its
five-second cap with at most two workers and minimization disabled, the
known-defect trial retained an actual Go crash corpus file, and that file
replayed identically through the exact compiled binary in a separate
sandboxed operation. Evidence is retained in the private qualification store.
This is the direct-test-binary prerequisite only, not evidence of an
implemented Go service workflow, five-trial acceptance, or held-out
effectiveness.

The benign module uses an exported single-string function and checks its
field-count result. The independent known-defect module uses an exported
single-`[]byte` function with a deliberately absent length check. Its valid
initial seeds must pass; input `[]byte{2, 'A'}` must panic inside `ParseFrame`,
even when its backing array has spare capacity. Direct indexing intentionally
checks logical input length. `TestParseFramePanicsWithSpareCapacity` records
this requirement; it passed in the bounded 2026-10-06 control.
Both modules use only the standard library, have no initialization hooks,
external dependencies, cgo, unsafe code, filesystem/network/subprocess access,
or explicit heap allocations in the selected functions. Fuzz inputs reach
the selected functions unchanged.

## Exact source set

Approve only these six files, in this order:

1. `benign/fields.go`
2. `benign/go.mod`
3. `benign/harness_test.go`
4. `known-defect/frame.go`
5. `known-defect/go.mod`
6. `known-defect/harness_test.go`

Combined SHA-256: `1bb55924e93484f4cdcb81ef2a7ecb9d72f90945207d6e90569787bf247bf314`.

For each listed file, hash its relative path as UTF-8, a NUL byte, the exact
file bytes, and another NUL byte. Concatenate these records in the listed
order before SHA-256. This README is not compiled and is outside the approved
source set. A change to any source or module file requires a new digest,
independent source review, and exact human approval.

## Proposed sandbox scope

The owning [Go design](../../../docs/design/go-native-fuzzing-design.md) defines
the future execution path. No command in this directory authorizes execution.
Before any build, the runner must require the exact source approval and retain
independent model source review. It must stage only the reviewed sources and
bind the captured immutable image and Go version. The repository currently
pins Go 1.26.5 for Syzkaller; that pin is not Go-native-fuzzing acceptance.
A new Go image/toolchain candidate needs its own recorded identity and results.

Compilation must go through `hf-runtime` with networking disabled, 2 CPUs,
4 GiB memory, 512 PIDs, and at most 120 seconds per module. Use
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, and
run-owned cache/output paths. The fixed compile-only argv must select exactly
one package and include both `-c` and `-fuzz=^FuzzCountFields$` or
`-fuzz=^FuzzParseFrame$`; plain `go test -c` does not enable fuzz instrumentation.
Neither compilation nor version inspection may invoke package tests.

After build identity and review checks, run the exact spare-capacity regression
in a separate sandboxed operation capped at five seconds. The bounded
prerequisite will then try one
trial per module capped at five seconds, requesting `-test.fuzztime=100x`,
selecting its exact fuzz test, and skipping unrelated tests. Use no more than
two workers and disable implicit 60-second minimization. The fixed iteration
request may finish before the five-second runtime deadline; there is no hidden
startup or shutdown allowance.
Replay of a retained failure is a separate sandboxed operation capped at
five seconds. Capture argv, source/binary/image digests, Go version, corpus,
stdout/stderr, terminal outcome, and verified owned-container cleanup.

Direct-binary cache/coordinator flags are internal Go interfaces. Verify them
on the pinned version with run-owned writable corpus/cache locations and
immutable source/binary inputs before adding a campaign adapter. A stopped
process, missing corpus, unavailable telemetry, timeout, OOM, setup failure,
or failed cleanup is not successful qualification. Actual Go service
admission, lint/review, promotion, campaign, replay, and five-trial independent
module acceptance remain separate implementation and qualification work.
