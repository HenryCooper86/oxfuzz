# oxfuzz example targets

A curated suite of small, self-contained targets that are ready to run the
full `oxfuzz` pipeline (`discover -> harness -> run -> triage`) against. Each
example isolates one bug class and is modeled on a canonical example shipped by
an upstream fuzzing engine (LLVM libFuzzer, AFLplusplus, honggfuzz) or on the
real-world parser pattern that bug class is famous for.

Unlike the heavyweight `examples/` directories in the upstream fuzzer repos
(which are build recipes that fetch and patch large external libraries such as
libpng, openssl, and libtiff), every target in the first table below is a
dozen-or-so lines of dependency-free C. The
[project-shaped targets](#project-shaped-targets) are slightly larger: a
multi-file CMake C library, a C++17 parser, and a standalone Rust crate. They depend only on libc (`stdint.h`, `stddef.h`,
`string.h`, `stdlib.h`), read all input solely from the `(data, len)`
parameters, run offline, and crash deterministically -- so they are reproducible
demo material rather than a moving external build.

Each target in the first table exposes exactly one non-`static`
`(const uint8_t *data, size_t len)` entry point so the discovery scanner picks
it up and the harness generator can wrap it. Every helper function is
`static`, so the scanner ignores it. All five of those targets work across
libFuzzer, AFL++, and honggfuzz because the framework generates a standard
`LLVMFuzzerTestOneInput` harness that each engine drives.

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

## Project-shaped targets

These look more like code a fuzzing engineer maintains: several source files,
a build system, a public header or crate API, and the bug sitting below the
entry point in an internal function. Each still has exactly one planted bug,
uses only the language's standard library, and reads input solely from its
byte-buffer parameter. Each directory has a `README.md` that documents the
bug, the input class that triggers it, and which engine and sanitizer finds
it; `// BUG:` comments mark the faulting lines.

| Directory | Language | Entry point | Bug class | Trigger input |
| --- | --- | --- | --- | --- |
| `cmake_tlv_lib/` | C (CMake, 3 `.c` files) | `tlv_decode` | heap-buffer-overflow (1-byte write) in internal `decode_string` | `TLV` header, version 1, then a non-empty `STRING` record |
| `cpp_config_parser/` | C++17 (CMake) | `cfgparse::parse_config` | heap-buffer-overflow (1-byte read) in internal `read_quoted` | last line ends inside a quoted value, no trailing newline (e.g. `k="`) |
| `rust_varint/` | Rust (standalone crate) | `decode` | shift overflow panic (`attempt to shift left with overflow`) | 10+ bytes with the continuation bit set, then any byte |

```bash
oxfuzz fuzz examples/cmake_tlv_lib --lang c
oxfuzz fuzz examples/cpp_config_parser --lang cpp
oxfuzz fuzz examples/rust_varint --lang rust
```

Without `--target`, `oxfuzz fuzz` picks the highest-fit candidate, which is
the entry point in the table for each of these. Pass `--target` to pin it.
`oxfuzz fuzz` drafts the harness, smoke-tests it in the sandbox, and stops for
human approval before any campaign. Expected findings:

- `cmake_tlv_lib`: AddressSanitizer `heap-buffer-overflow` WRITE of size 1 in
  `decode_string` (`src/tlv_record.c`), reached through `tlv_decode`.
- `cpp_config_parser`: AddressSanitizer `heap-buffer-overflow` READ of size 1
  in `read_quoted` (`src/config_parser.cpp`), reached through `parse_config`.
- `rust_varint`: a Rust panic, `attempt to shift left with overflow`, in
  `decode`, reported by cargo-fuzz/libFuzzer as a crash. This needs overflow
  checks, which `cargo fuzz` builds have on by default.

No build directories, `compile_commands.json`, `Cargo.lock` or `fuzz/`
harness directories are committed. The C and C++ READMEs show how to generate
`compile_commands.json` with `cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
`rust_varint/Cargo.toml` has an empty `[workspace]` table, so the crate is
not part of the oxfuzz Cargo workspace.

## Running an example

```bash
# Discover the target (offline; uses tree-sitter, no toolchain needed).
oxfuzz discover examples/libfuzzer_fuzzme --lang c

# Export the authoring packet, then write harness.c from its instructions.
oxfuzz work-order export examples/libfuzzer_fuzzme --target FuzzMe \
  --lang c --engine libfuzzer --out work-order.md
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human
oxfuzz work-order qualify --submission <submission UUID>
# Review the retained source, independent review and smoke evidence before promotion.
oxfuzz work-order promote --attempt <attempt UUID>
oxfuzz run examples/libfuzzer_fuzzme --target fuzz_me.c::FuzzMe \
  --engine libfuzzer --duration 1m
oxfuzz triage examples/libfuzzer_fuzzme --target fuzz_me.c::FuzzMe
```

Swap the directory and `--target` for any row in the table above, and swap
`--engine libfuzzer` for `afl++` or `honggfuzz` to drive the same target through
a different engine. Keep the complete file-qualified selector printed by the
Work Order. The fixtures contain known triggers; time to discover them depends
on the engine, qualified harness and seed corpus. See the
[CLI guide](../docs/guides/CLI_REFERENCE.md) for the full review workflow.

The `aflpp_persistent` row fuzzes fine on the stock driver build; for the
harness-owned loop form (`__AFL_INIT` + `__AFL_LOOP` with an explicit
per-iteration reset), draft it with `oxfuzz harness --engine afl++
--persistent` (see "AFL++ persistent mode" in the CLI guide).

`scripts/demo-cve-rediscovery.sh` automates this retained-attempt workflow:
it displays the imported source and qualification result, then asks for human
approval before promoting that exact attempt. Failed qualification, declined
approval, EOF, or stale promotion stops before a campaign starts. A smoke crash
is retained for investigation. Use `--example <directory-name>` to select any
fixture in the first table (the project-shaped targets are not selectable
there); `--yes` is unsupported. `--engine <engine>` picks the userspace engine
(`libfuzzer`, the default, `afl++` or `honggfuzz`) and `--duration <duration>`
bounds the campaign (default `90s`).

`--preflight-only` checks the selected engine, duration policy, sandbox, and
provider configuration before discovery. It does not verify provider credentials,
model connectivity, or live qualification.

Corpora and crash artifacts are generated at runtime and are not committed to
this repository -- only source files, build files, and Markdown live here. The
framework writes generated corpora, harnesses, and crash reproducers into its
own workspace directories when you run the pipeline.

## Automated coverage

`crates/hf-discovery/tests/showcase_examples.rs` runs discovery over every
directory in the first table and asserts the documented entry point is found and classified as
a fuzzable kind. That layer is deterministic and toolchain-free, so it runs in
CI. Reproducing the actual *crash* requires a real fuzzing engine and sanitizer
toolchain and is exercised by the manual / engine-gated runs shown above.

## Upstream honggfuzz examples

`honggfuzz_upstream/` holds unmodified upstream honggfuzz code, under
Apache-2.0 with its `LICENSE` beside it. It contains:

- a file-path target, `badcode1.c`
- the stateful `vulnserver_cov.c` protocol handlers
- the human-written persistent harnesses for libxml2, libpng, libjpeg,
  libmagic and OpenSSL, kept as baselines for comparing LLM-drafted harnesses

See [`honggfuzz_upstream/README.md`](honggfuzz_upstream/README.md).

## Attribution

The targets in the table above are original, clean-room implementations
written for oxfuzz; they are not copied from upstream sources. The exception
is `honggfuzz_upstream/`, which is vendored verbatim (see its README). They are modeled on the introductory
examples published by the following projects, all under permissive licenses:

- LLVM libFuzzer (part of LLVM, Apache-2.0 with LLVM exceptions).
- AFLplusplus / AFL++ (Apache-2.0).
- honggfuzz (Apache-2.0).
- google/fuzzing tutorial (Apache-2.0).
