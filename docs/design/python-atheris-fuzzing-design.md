# Python Atheris Fuzzing Design

Status: **planned, not implemented**. Owners: `hf-service` for admission and
workflow, `hf-harness` for generated Python source, `hf-engine` for Atheris
telemetry and artifacts, and `hf-runtime` for every process. Python remains
discovery-only in the support matrix.

## Goal and admission

Qualify a selected importable Python callable through an Atheris
`TestOneInput(bytes)` harness. Introduce a disabled-by-default
`python-atheris` feature and a distinct Atheris engine kind only alongside
tested implementation. Do not advertise Python as libFuzzer support merely
because Atheris embeds libFuzzer. `hf-service` resolves the feature, selected
callable, operator engine policy, image, source inputs, and limits before a
provider or sandbox call; direct executor calls must enforce the same checks.

The first supported class is a top-level synchronous function in an importable
pure-Python module accepting bytes. Async functions, methods needing object
construction, C extensions, dynamic imports, native sanitizers, and APIs that
need external services require separate recipes and qualification. Discovery's
lexical name is not proof that an import succeeds or an input reaches it.

## Toolchain and packaging

Pin CPython, Atheris, Linux architecture, and wheel digests in a new versioned
sandbox image. Stage the project and an immutable offline wheelhouse; install
only reviewed, hash-pinned wheels with no package-index or network access.
Reject source distributions and install hooks in the initial path. Capture
Python ABI, dependency lock, staged module tree, generated harness, and exact
image digest. Import paths are service-resolved within `/work`; no writable
host package location or user site is used. Missing or incompatible wheels
fail before review/smoke rather than triggering online installation.

All syntax checks, package imports, harness smoke, fuzzing, replay, and crash
parsing use `hf-runtime`. A syntax-only compile may precede execution approval;
imports execute module top-level code and therefore wait for exact-source
review and human approval. The sandbox has disabled networking, dropped
capabilities, bounded CPU/memory/processes/time, and only run-owned writable
output/cache/corpus. Provider-generated shell text never becomes argv.

## Harness and lifecycle

`hf-harness` emits a fixed-entry script: import Atheris; import the selected
module within `atheris.instrument_imports()`; define
`TestOneInput(data: bytes)` that calls the selected function; then call
`atheris.Setup(...)` and `atheris.Fuzz()`. The initial recipe instruments the
selected module explicitly and retains a smoke check that rejects Atheris's
"no interesting inputs" diagnostic. Lint rejects `subprocess`, socket use,
arbitrary file writes, uncontrolled `eval`/`exec`, hidden imports, replacing
input with constants, and exception handlers that swallow target failures.
A reviewed predicate may classify documented input-rejection exceptions as
nonbugs; broad `except Exception` is not accepted.

Compile and bounded repair retain attempt-specific source/dependency/image
digests. Independent model review examines the exact persisted script after
each repair. Human approval precedes any import or smoke execution; human
promotion of the exact smoke-qualified attempt precedes a full run. Both
smoke and campaigns use fixed, bounded Atheris/libFuzzer arguments; no
operator or model text is passed through a shell. `hf-service` captures the
initial corpus, script, image, Python/Atheris versions, args, and target
module digest into immutable run inputs. Historical replay uses only those
retained inputs. Stop cancels the addressed sandbox process and records
teardown; uncertain teardown stays interrupted, not successful.

## Evidence and failure semantics

Parse bounded libFuzzer-style progress from Atheris separately from the C
engine. Atheris coverage counts instrumented Python bytecode events; they are
not C LLVM source edges. A positive selected-function entry requires an
exact-run Python measurement with the selected module/callable identity;
aggregate feature counts cannot stand in for it. Atheris/coverage.py reports
may be unavailable after a native crash or abrupt Stop. Record that absence
explicitly rather than reporting zero. Run-owned corpus files and artifacts
are read with file-count, byte, regular-file, and containment limits.

An uncaught Python exception is a candidate failure, not automatically a
target vulnerability. Reproduce the exact input in the pinned sandbox,
retain its traceback and module digest, and distinguish target exception,
harness/import failure, expected rejection, native crash, timeout, and OOM.
Native extension targets are excluded initially because they require separate
instrumented builds, sanitizer/library matching, and crash analysis. Retain
the original reproducer even if bounded minimization fails; deduplicate only
after service-owned origin classification.

## Verification and order

Begin with failing tests for disabled/direct admission, offline wheel and ABI
validation, exact input invalidation, lint/review denial, no-instrumentation
smoke failure, progress parsing, absent coverage, Stop ownership, retained
replay, and exception classification. Qualify two independent pinned
pure-Python projects, one benign and one with a known reproducible defect,
under B1's fixed trial budgets. Record approvals, image and wheel identities,
tracebacks, selected-function evidence, and explicit unavailable results.
Native-extension and other-host claims remain separate. Choose implementation
order against Go from B1 results and actual user demand.

Atheris is selected over a custom Python mutator because it supplies
coverage-guided execution and a documented input callback. Mapping it to the
C libFuzzer engine is rejected because Python bytecode instrumentation and
uncaught-exception findings need their own evidence semantics. Online pip
installation and source-distribution builds are excluded from the first path
because they introduce mutable dependencies and package build code during
qualification.

The [Atheris README](https://github.com/google/atheris/blob/master/README.md)
documents Python instrumentation, `TestOneInput`, bundled libFuzzer,
exceptions, and coverage-report limitations. Its
[native-extension guide](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md)
explains why extension fuzzing needs a separate toolchain and sanitizer path.
