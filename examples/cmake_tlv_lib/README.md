# cmake_tlv_lib

A small multi-file C library built with CMake. It decodes a
type-length-value message format and has a public header under `include/`,
an internal header, and three translation units under `src/`. It is shaped
like a typical embedded or protocol library, not like a single-file demo.

| | |
| --- | --- |
| Entry point | `tlv_decode(const uint8_t *data, size_t len, tlv_message *msg)` in `src/tlv_decode.c` |
| Cleanup | `tlv_message_free(tlv_message *msg)` |
| Bug class | heap-buffer-overflow (1-byte write) |
| Faulting function | `decode_string` in `src/tlv_record.c` (internal, `static`) |
| Finds it | libFuzzer, AFL++ or honggfuzz with AddressSanitizer |

## Layout

```text
CMakeLists.txt
include/tlv/tlv.h      public API and wire-format description
src/tlv_internal.h     cursor type and internal prototypes
src/tlv_decode.c       tlv_decode / tlv_message_free (header + record loop)
src/tlv_record.c       per-record decoding; contains the bug
src/tlv_reader.c       bounds-checked cursor reads
```

## The bug

`tlv_decode` validates the `TLV` magic and version byte, then calls
`tlv_record_decode` for each record. For a `STRING` record (type `0x02`),
`decode_string` copies the value into a heap block allocated with
`malloc(length)` and then writes the NUL terminator at `copy[length]`. That
is one byte past the allocation. The `// BUG:` comments mark the allocation
and the faulting store.

The cursor reads in `tlv_reader.c` are correctly bounds-checked, so the
library is otherwise memory-safe. The defect is the classic missing `+ 1` for
a string terminator, sitting two calls below the public API.

Trigger input class: a valid header followed by a `STRING` record with at
least one value byte, for example the 8 bytes

```text
54 4C 56 01 02 00 01 41     "TLV", version 1, type 0x02, length 1, "A"
```

AddressSanitizer reports a `heap-buffer-overflow` WRITE of size 1 in
`decode_string`. Without a sanitizer the write usually lands in allocator
padding and the program keeps running, which is why this class of bug needs
ASan to be seen.

A harness needs to stack-allocate a `tlv_message`, call `tlv_decode`, and
call `tlv_message_free` on success so LeakSanitizer stays quiet.

## Building and compile_commands.json

Do not commit a build directory. Configure out of tree:

```bash
cmake -S examples/cmake_tlv_lib -B build/tlv -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/tlv
```

`build/tlv/compile_commands.json` lists the exact flags and include paths for
each translation unit. Pass it to tools that need a compilation database
(for example clang-based analysis) or copy it next to `CMakeLists.txt`.
oxfuzz discovery itself is tree-sitter based and does not require it.

## Running oxfuzz

```bash
oxfuzz discover examples/cmake_tlv_lib --lang c
oxfuzz fuzz examples/cmake_tlv_lib --lang c --target tlv_decode
```

`oxfuzz fuzz` drafts a harness, smoke-tests it in the sandbox, and asks for
human approval before any campaign. The expected finding is a
heap-buffer-overflow WRITE in `decode_string`, reached through `tlv_decode`.
