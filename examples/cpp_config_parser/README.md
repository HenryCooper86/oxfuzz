# cpp_config_parser

A small C++17 INI-style configuration parser that uses `std::string`,
`std::vector`, `std::optional` and `std::string_view`. It has a public header,
one implementation file and a CMake build. To avoid a copy, it parses the
caller's byte range in place with raw `const char *` pointers, as many
zero-copy parsers do.

| | |
| --- | --- |
| Entry point | `cfgparse::parse_config(const std::uint8_t *data, std::size_t size, Config &out)` in `src/config_parser.cpp` |
| Bug class | heap-buffer-overflow (read, 1 byte past the input) |
| Faulting function | `read_quoted` in `src/config_parser.cpp` (anonymous namespace) |
| Finds it | libFuzzer, AFL++ or honggfuzz with AddressSanitizer |

## Layout

```text
CMakeLists.txt
include/cfgparse/config_parser.hpp   public API and accepted syntax
src/config_parser.cpp                line splitter, LineParser, read_quoted
```

## The bug

`parse_config` splits the input into lines and passes each `[begin, end)`
range to `LineParser`. A value that starts with `"` is handed to
`read_quoted`, which loops `while (p <= end)` instead of `while (p < end)`
(marked `// BUG:`). It therefore dereferences `*end` when no closing quote
is found.

For every line but the last, `*end` is the `\n` or trailing whitespace that
ended the line. That byte is inside the buffer, so the parser just reports an
unterminated value and moves on. A unit test with an unterminated quote on a
middle line therefore passes. Only when the unterminated quoted value is on
the last line, and the input has no trailing newline or whitespace, is `end`
one past the end of the caller's buffer.

Trigger input class: the input ends inside a quoted value. The smallest
trigger is the 3 bytes

```text
k="
```

with no trailing newline. AddressSanitizer reports a `heap-buffer-overflow`
READ of size 1 in `read_quoted`. Fuzzers hand the target an exact-size heap
copy of each input, so the over-read reaches the redzone immediately.
Without ASan the stray read usually returns a harmless byte, the parser
reports an unterminated value, and nothing visibly fails.

A harness only needs a `cfgparse::Config` local and a call to
`cfgparse::parse_config(data, size, cfg)`.

## Building and compile_commands.json

```bash
cmake -S examples/cpp_config_parser -B build/cfgparse -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/cfgparse
```

Do not commit the build directory.

## Running oxfuzz

```bash
oxfuzz discover examples/cpp_config_parser --lang cpp
oxfuzz fuzz examples/cpp_config_parser --lang cpp --target parse_config
```

The expected finding is a heap-buffer-overflow READ in `read_quoted`, reached
through `parse_config`, on an input whose last line holds an unterminated
quoted value.
