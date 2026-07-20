# oxfuzz example targets

A curated suite of small, self-contained C targets that are ready to run the
full `oxfuzz` pipeline (`discover -> harness -> run -> triage`) against. Each
example isolates one bug class and is modeled on a canonical example shipped by
an upstream fuzzing engine (LLVM libFuzzer, AFLplusplus, honggfuzz) or on the
real-world parser pattern that bug class is famous for.

Unlike the heavyweight `examples/` directories in the upstream fuzzer repos
(which are build recipes that fetch and patch large external libraries such as
libpng, openssl, and libtiff), every target here is a dozen-or-so lines of
dependency-free C. They depend only on libc (`stdint.h`, `stddef.h`,
`string.h`, `stdlib.h`), read all input solely from the `(data, len)`
parameters, run offline, and crash deterministically -- so they are reproducible
demo material rather than a moving external build.

Each target exposes exactly one non-`static` `(const uint8_t *data, size_t len)`
entry point so the discovery scanner picks it up and the harness generator can
wrap it. Every helper function is `static`, so the scanner ignores it. All five
targets work across libFuzzer, AFL++, and honggfuzz because the framework
generates a standard `LLVMFuzzerTestOneInput` harness that each engine drives.

## Targets

| Directory | Entry point | Engine style | Bug class | Trigger input |
| --- | --- | --- | --- | --- |
| `libfuzzer_fuzzme/` | `FuzzMe` | libFuzzer | heap-buffer-overflow (read) | 3-byte input `FUZ` |
| `honggfuzz_magic/` | `match_magic` | honggfuzz | reachable `abort()` (SIGABRT) | input begins `ABCD` |
| `aflpp_persistent/` | `parse_packet` | AFL++ persistent | heap-buffer-overflow (write) | declared length byte > payload bytes present |
| `json_number_parser/` | `parse_number` | libFuzzer | stack-buffer-overflow (write) | numeric literal longer than 32 bytes |
| `utf8_decoder/` | `decode_utf8` | libFuzzer | out-of-bounds read | lead byte declares more bytes than remain (e.g. `0xF0`) |

Per-target provenance, the upstream project it models, and the precise faulting
line are documented in each directory's header (`.h`) file, with a `// BUG:`
comment marking the exact faulting statement in the `.c`.

## Running an example

```bash
# Discover the target (offline; uses tree-sitter, no toolchain needed).
oxfuzz discover examples/libfuzzer_fuzzme --lang c

# Generate a harness, then fuzz it (requires a real engine + clang/ASan).
oxfuzz harness examples/libfuzzer_fuzzme --target FuzzMe --engine libfuzzer
oxfuzz run     examples/libfuzzer_fuzzme --target FuzzMe --engine libfuzzer --duration 1m
oxfuzz triage  examples/libfuzzer_fuzzme --target FuzzMe
```

Swap the directory and `--target` for any row in the table above, and swap
`--engine libfuzzer` for `afl++` or `honggfuzz` to drive the same target through
a different engine. Every target crashes within seconds under a coverage-guided
engine with AddressSanitizer.

Corpora and crash artifacts are generated at runtime and are not committed to
this repository -- only the `.c`, `.h`, and this `.md` file live here. The
framework writes generated corpora, harnesses, and crash reproducers into its
own workspace directories when you run the pipeline.

## Automated coverage

`crates/hf-discovery/tests/showcase_examples.rs` runs discovery over every
directory here and asserts the documented entry point is found and classified as
a fuzzable kind. That layer is deterministic and toolchain-free, so it runs in
CI. Reproducing the actual *crash* requires a real fuzzing engine and sanitizer
toolchain and is exercised by the manual / engine-gated runs shown above.

## Attribution

These targets are original, clean-room implementations written for oxfuzz; they
are not copied from upstream sources. They are modeled on the introductory
examples published by the following projects, all under permissive licenses:

- LLVM libFuzzer (part of LLVM, Apache-2.0 with LLVM exceptions).
- AFLplusplus / AFL++ (Apache-2.0).
- honggfuzz (Apache-2.0).
- google/fuzzing tutorial (Apache-2.0).
