# Harness Standard

Status: **active**. Scope: `hf-harness`, `hf-engine`, `hf-service`.

## 1. Harness Requirements

A harness is acceptable only if it satisfies all of:

1. **Engine entry point present** -- e.g. `LLVMFuzzerTestOneInput` for
   libFuzzer/AFL++, `HF_ITER` for honggfuzz, `Fuzz` function for Go.
2. **No host I/O** -- the harness does not read from or write to the host
   filesystem; all input comes from the fuzzer.
3. **Deterministic** -- same input -> same behavior (no time-based or RNG
   branches that break reproducibility).
4. **Compiles** with the selected sanitizer + engine flags in the sandbox.
5. **Smoke fuzz passes** -- 60s run, no crash on empty input, execs/sec > 0.

## 2. Naming

- Source file: `fuzz_<symbol>.<ext>` in `fuzz_workspace/harnesses/<target>/`.
- Build artifact: `fuzz_<symbol>_<engine>` binary.

## 3. Templates

Templates live in `config/prompts/harness_<lang>_<engine>.md`. They contain:

- The engine entry point skeleton.
- Include/import guidance.
- A placeholder for the LLM to fill the target call.
- Safety assertions (no `system()`, no file writes).

## 4. Iteration Policy

- On compile failure: feed compiler diagnostics back to the LLM (max 3 rounds).
- On smoke failure: feed engine log back (max 3 rounds).
- After 3 failed rounds: mark `Failed`, surface to user for guidance.

## 5. Promotion Gate

A harness moves to `Promoted` only after smoke pass. A human must approve
before a full `FuzzRun` starts.