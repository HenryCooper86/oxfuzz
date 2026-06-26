# Fuzzing example targets

A curated suite of small, self-contained C targets for exercising the full
`hobot-fuzz` pipeline (`discover -> harness -> run -> triage`). Each example
isolates one bug class and is modeled on a canonical example shipped by the
upstream fuzzers (libFuzzer, honggfuzz, AFL++) or on the real-world parser CVE
pattern that bug class is famous for.

Unlike the heavyweight `examples/` directories in the upstream fuzzer repos
(which are build recipes that fetch and patch large external libraries such as
libpng, openssl, and libtiff), every target here is a few lines of dependency
free C. They build with any C compiler plus AddressSanitizer, run offline, and
crash deterministically, so they are reproducible test material rather than a
moving external build.

Each target exposes a non-`static` `(const uint8_t *data, size_t len)` entry
point so the discovery scanner picks it up and the harness generator can wrap
it. Helper functions that should not be fuzzed directly are `static`.

## Targets

| Directory | Entry point | Bug class | Trigger | Modeled on |
| --- | --- | --- | --- | --- |
| `libfuzzer_fuzzme/` | `FuzzMe` | heap-buffer-overflow (read) | 3-byte input `FUZ` | LLVM libFuzzer docs / google/fuzzing `fuzz_me.cc` |
| `honggfuzz_magic/` | `match_magic` | reachable `abort()` (SIGABRT) | input begins `ABCD` | honggfuzz README / `examples` intro target |
| `heap_overflow/` | `copy_chunk` | heap-buffer-overflow (write) | declared length byte > 16 | "trust the length field" media-codec CVEs |
| `stack_overflow/` | `unpack_frame` | stack-buffer-overflow (write) | declared length byte > 8 | fixed on-stack record buffers |
| `use_after_free/` | `run_session` | heap-use-after-free (read) | input `OU...` | protocol state-machine UAF |
| `integer_overflow/` | `parse_image` | int overflow -> heap overflow | `width*height` overflows u32 | libpng/libjpeg/giflib alloc CVEs |
| `oob_read_png_crc/` | `read_chunk` | heap-buffer-overflow (read) | chunk length > remaining bytes | PNG/TIFF chunk over-read CVEs |
| `null_deref/` | `parse_optional` | NULL deref (SIGSEGV) | first byte `?` | unchecked lookup return value |
| `memory_leak/` | `parse_token` | memory leak (LeakSanitizer) | token length byte > 4 | early-return-without-free |

Per-target provenance and the precise faulting line are documented in each
directory's header (`.h`) file.

## Running an example

```bash
# Discover the target (offline; uses tree-sitter, no toolchain needed).
hobot-fuzz discover tests/fixtures/examples/libfuzzer_fuzzme --lang c

# Generate a harness, then fuzz it (requires a real engine + clang/ASan).
hobot-fuzz harness tests/fixtures/examples/libfuzzer_fuzzme --target FuzzMe --engine libfuzzer
hobot-fuzz run     tests/fixtures/examples/libfuzzer_fuzzme --target FuzzMe --engine libfuzzer --duration 1m
hobot-fuzz triage  tests/fixtures/examples/libfuzzer_fuzzme --target FuzzMe
```

Swap the directory and `--target` for any row in the table above. Every target
crashes within seconds under a coverage-guided engine with AddressSanitizer.

Notes:

- `memory_leak` is caught by LeakSanitizer, which ships with ASan on Linux (the
  sandbox's container runtime) but not on macOS -- run it inside the Linux
  sandbox, or build with `-fsanitize=address` on Linux, to observe the leak.
- The out-of-bounds reads (`libfuzzer_fuzzme`, `oob_read_png_crc`) land in the
  heap region only because a coverage-guided engine hands the target a
  heap-backed input buffer; that is exactly how the harness feeds them.

## Automated coverage

`crates/hf-discovery/tests/examples.rs` runs discovery over every directory here
and asserts the documented entry point is found and classified. That layer is
deterministic and toolchain-free, so it runs in CI. Asserting the *crash* itself
requires a real fuzzing engine and sanitizer toolchain and is intended for the
manual / engine-gated runs shown above.
