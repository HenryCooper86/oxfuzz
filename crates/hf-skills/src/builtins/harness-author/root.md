# harness-author

Write a fuzzing harness for a target function.

## When to use

- After `target-triage` selects a target.
- When the user asks "write a harness for X".

## Procedure

1. Read the target signature and surrounding types/includes.
2. Select the engine entry point:
   - libFuzzer / AFL++: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
   - honggfuzz: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` with `HF_ITER`
   - Go: `func FuzzX(f *testing.F)`
   - Rust (cargo-fuzz): `fuzz_target!(|data: &[u8]| { ... })`
   - Python (Atheris): `def TestOneInput(data):`
3. Map fuzzer input to the target's expected input.
4. No host I/O. No `system()`. No file writes. Deterministic.
5. Output only the harness source in a fenced code block.

## Iteration policy

- On compile failure: read compiler diagnostics, fix, retry (max 3).
- On smoke failure: read engine log, fix, retry (max 3).
- After 3 failed rounds: mark `Failed`, ask the user.

## Template (C + libFuzzer)

```c
#include <stdint.h>
#include <stddef.h>
#include "target_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Map data -> target input.
    target_function(data, size);
    return 0;
}
```
