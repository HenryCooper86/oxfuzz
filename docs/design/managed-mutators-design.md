# Managed native custom mutators

Status: active implementation. Owners: hf-service workflow, hf-harness native
source/build operations, hf-engine existing fuzzers. Feature: `managed-mutators`.

## Native engine interfaces

Use AFL++'s existing C/C++ shared-library API (`afl_custom_init`, `afl_custom_fuzz`, `afl_custom_deinit`, optional native
trim callbacks) and libFuzzer's `LLVMFuzzerCustomMutator`. honggfuzz, Rust,
syzkaller and Go reject this managed workflow explicitly. No grammar language,
mutation engine, Python module loader or host plugin loader is introduced.
Upstream references: https://aflplus.plus/docs/custom_mutators/ and
https://llvm.org/docs/LibFuzzer.html .

## Reviewed source and revision identity

An engineer imports bounded C/C++ source against an existing harness. Service
composition creates a versioned source envelope containing the complete base
harness, imported mutator and small native-ABI observation wrappers. The ordinary
harness source digest therefore binds every byte shown to the model and human.
AFL++ compiles the same translation unit twice: the target branch normally, and
the mutator branch with `OXFUZZ_MUTATOR_BUILD` into a shared library. libFuzzer
links the custom callback into its ordinary target executable.

Every import compiles a new unpromoted harness revision. Existing review, smoke
and human promotion never transfer to it. `Harness.custom_mutator` retains version,
engine API, imported-source digest, artifact name/digest, exact image, declared
trim mode and bounded self-test evidence. Generic source compilation recognizes
and validates the envelope and cannot silently discard the metadata. Editing an
envelope requires recomposition/rebuild. Disabled-feature executors reject a
managed record or envelope before sandbox dispatch.

## Build and bounded qualification

All builds use hf-runtime with the captured immutable image. AFL++ plugins use
Clang's shared-library mode, not host dynamic loading. The complete source goes
through the existing independent model review (or explicit audited bypass).
Existing RunHarness authorization precedes any execution of the compiled plugin.

Qualification uses the real existing engine's bounded smoke run, not a substitute
fuzzing implementation. Native callback wrappers check returned lengths against
upstream maximums and emit a bounded first-success witness. AFL++ qualification
selects custom-mutation-only mode so ordinary mutations cannot manufacture a
passing observation. Smoke evidence retains whether mutation and declared trim
callbacks actually ran, the engine exit status, and bounded logs; absence is explicit. A mutator without
observed successful mutation and a successful engine exit cannot advance qualification. Trim support is
engine-native or the complete AFL callback trio; partial callback sets reject.
Unobserved custom trimming remains unverified and is shown as such. Throughput
alone does not establish mutator exercise or an effectiveness gain.

## Execution and retained inputs

Before review, promotion and execution, validate the artifact digest and captured
image. AFL++ campaigns stage the exact shared library into immutable run inputs
and configure `AFL_CUSTOM_MUTATOR_LIBRARY` to that staged path. The complete
execution-input manifest retains library bytes alongside the reviewed source,
harness executable, config, image and argv. Replay verifies those retained bytes
and relocates only the run-specific environment path; it never consults a mutable
live plugin. libFuzzer retains its already-linked executable and source through
existing capture. Corpus operations retain the same reviewed executable; AFL
coverage pruning does not perform mutations or load plugins. Engine executors
reject arbitrary/custom plugin environment overrides outside managed staging.

## Product surfaces

A Harness GUI panel imports/pastes source, explains supported native APIs, shows
exact source/artifact/image and self-test status, and links back to existing
review/smoke/promotion controls. Tauri and REST call the same service methods;
CLI offers attach/status for automation. All surfaces state when a new revision
needs requalification. The feature is compiled by default in product crates and
absent-feature calls fail explicitly.

## Verification and effectiveness

Runtime mocks verify both compile commands, immutable image propagation,
unsupported/disabled rejection, source tamper, unobserved callback denial,
artifact tamper, retained replay tamper and native AFL environment wiring.
UI tests cover import arguments and truthful status. No test loads a mutator on
the host. Root's matched-budget benchmark owns empirical coverage comparisons;
this implementation does not claim improved effectiveness without those runs.

Operator workflow and manual sandbox qualification: [Managed mutators guide](../guides/MANAGED_MUTATORS.md).
