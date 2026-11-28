# Python Atheris Fuzzing Design

Status: **first slice implemented, acceptance open** (2026-11-21). Owners:
`hf-service` for admission and workflow, `hf-harness` for generated Python
source, `hf-engine` for Atheris telemetry and artifacts, and `hf-runtime` for
every process. The section "Implemented behaviour" at the end states what the
first slice does and where it differs from the plan below.

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
nonbugs; broad `except Exception` is not accepted. The template derives that
predicate from the target module itself: the exception classes it defines at
top level (tomli's `TOMLDecodeError`), and the `ValueError`,
`RecursionError`, `OverflowError`, `UnicodeError`, `UnicodeDecodeError` or
`EOFError` it raises with an explicit `raise` (tomli's nesting limit). The
directive records the list, the `except` names exactly those, and every
other exception, `TypeError`, `KeyError` and `AssertionError` among them,
stays a finding.

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

## Implemented behaviour (first slice)

Evidence is from Atheris 3.0.0 on CPython 3.12.3 in `oxfuzz/fuzz-sandbox:0.2.3`
(linux/arm64), 2026-11-21, through the live test
`live_atheris_finds_replays_and_classifies_a_planted_exception`.

- **Engine and admission.** `EngineKind::Atheris` (`atheris`) supports Python
  only and stays outside the default enabled set; an operator lists it under
  `[fuzzing] enabled_engines`. The `python-atheris` feature is part of the
  default feature set, following the `go-native-fuzzing` precedent: the
  runtime engine policy, not the build, is what keeps the path off until an
  operator opts in. This differs from the "disabled-by-default feature" the
  plan names. System status carries an `atheris` flag, true only when the
  image's interpreter imports Atheris.
- **Toolchain.** PyPI publishes no Atheris wheel for CPython 3.12 on
  linux/arm64, so the image builds the hash-pinned Atheris source
  distribution at image build time. Nothing is installed at run time and no
  project dependency is installed at all: the supported class is the standard
  library, the project's own modules, and the pure-Python packages the
  project carries under `vendor/python/`, which the script puts on the import
  path after the project root. The `vendor/python/` tree is staged and
  retained whole, data files included, because a package reads the files it
  ships beside its modules; elsewhere only `.py` files are staged. Files
  under `vendor/` are not discovery candidates. The offline wheelhouse of the plan is not
  implemented; a project that imports a package it does not carry fails
  smoke with the import error.
- **Harness.** `hf_harness::python_atheris` renders one fixed script from the
  selected function (import root, dotted module, function, and the type of
  each required parameter: `bytes`, `str`, `int`, `float` or `bool`) and
  records them in an `# oxfuzz:python-target` line. A function of one `bytes`
  or `str` receives the input as it is; any other list is decoded in order
  with `atheris.FuzzedDataProvider`. There is no
  model draft and no repair: lint accepts only the generated text for the
  recorded target, and the service additionally requires the recorded
  function to be the selected one. The lint rules the plan lists
  (`subprocess`, sockets, swallowed exceptions, constant inputs) are therefore
  enforced by equality with the template rather than rule by rule.
- **Build.** One fixed interpreter invocation parses the script and the
  selected module with `ast.parse` and installs the script as an executable
  file. Nothing is imported before the smoke approval.
- **Execution.** The script starts with `#!/usr/bin/python3 -I` and is run
  directly, so smoke, campaign, and replay start it the way they start a
  compiled harness. The argv is fixed libFuzzer flags built in
  `hf_engine::atheris`; fork and job flags are refused. A run is one
  interpreter whatever the CPU allocation.
- **Retained sources.** Project `.py` files are staged at their relative
  paths and captured into each run's `input/source-context`. A staged run's
  script imports from that directory, so the run and its historical replay
  execute the sources captured at run start even when the workspace has
  changed since. Smoke and triage replay run the workspace copy.
- **Findings.** An uncaught exception exits 77 and writes `crash-<sha1>`;
  ingestion collects it like a libFuzzer artifact. Classification names the
  exception line and signs the frames of the code under test with their
  install location removed, so a finding signs the same from a run and from
  a replay. An exit other than 0, 70, or 77 (an import or interpreter
  failure) fails the smoke as such and is never a finding; libFuzzer's "no
  interesting inputs" diagnostic fails the smoke as uninstrumented. Atheris's
  startup notes about missing sanitizer hooks are not read as a crash.
- **Not implemented.** Selected-function entry evidence, coverage.py reports,
  minimization, expected-rejection predicates, CASR, methods, async
  functions, native extensions, third-party packages, and the two-project
  acceptance. A full review/promotion/campaign/Stop cycle through the
  commands has not been exercised.
