# Target Taxonomy

Status: **active**. Scope: `hf-discovery`, `hf-core`.

## 1. TargetLanguage

```rust
pub enum TargetLanguage { C, Cpp, Rust, Go, Python }
```

| Language | Scanner | Candidate rule |
| --- | --- | --- |
| C/C++ | Tree-sitter (`hf-discovery`) | Non-static function definitions with at least one parameter. |
| Rust | dependency-free lexical | `pub fn` (incl. `async`/`unsafe`/`const`) with at least one parameter; `main` and `test_*` excluded. |
| Go | dependency-free lexical | Exported (capitalized) package-level functions and methods with at least one parameter; `main`, `init`, and `Test*`/`Benchmark*` excluded, as are `_test.go` files and `vendor/`. Methods are named `Receiver.Method`. |
| Python | dependency-free lexical | Top-level `def` and direct class methods (incl. `async` and decorated definitions) with at least one parameter besides `self`/`cls`; underscore-privates, dunders, `test_*`, and closures nested in another `def` excluded. Methods are named `Class.method`. |

The lexical scanners are intentionally conservative: a missed multi-line
signature is a lost candidate, never a wrong one. They extract no call edges,
so their candidates carry no reachability annotation.

## 2. TargetKind

| Variant | Description | Example |
| --- | --- | --- |
| `Function` | A standalone function taking input. | `parse_value(const char*)` |
| `Parser` | A parser entry point. | `json_parse(const char*, size_t)` |
| `ApiEntry` | A public API entry point of a library. | `SSL_read` |
| `Ffi` | Foreign function interface boundary. | `Java_pkg_foo_nativeBar` |

## 3. InputSurface

| Variant | Description | Harness strategy |
| --- | --- | --- |
| `Bytes` | Raw byte buffer. | `LLVMFuzzerTestOneInput(data, size)` |
| `Structured` | Structured input (protobuf, JSON, custom). | Custom mutator / grammar. |
| `File` | Reads from a file path. | Temp-file harness. |
| `Stdin` | Reads from stdin. | Pipe harness. |

## 4. Sanitizer

```rust
pub enum Sanitizer { None, Address, Undefined, Memory, Thread }
```

## 5. Complexity

A coarse score 0..=100 approximating cyclomatic complexity, derived from
Tree-sitter node counts (branches + loops + operators).

## 6. Fit Score

A 0.0..=1.0 score combining: input surface, complexity, sanitizer
applicability, absence of existing harness, and LLM rationale.

## 7. Automotive Protocol Targets

Automotive protocol work is not represented as a new `TargetLanguage` or
source `TargetKind`. The optional `hf-automotive` contract identifies a
protocol (CAN, CAN FD, ISO-TP, UDS, GMLAN, SOME/IP, SOME/IP-SD, DoIP, OBD, CCP,
XCP, BMW HSFZ, or SecOC), an offline/virtual/physical mode, and opaque staged
artifacts or replay messages.

Its feedback surface is protocol state: canonical transcript hashes and
protocol-scoped state signatures. These values may guide a separate corpus
promotion policy but must never be stored or displayed as source edges, lines,
functions, regions, sanitizer findings, or source-target fit. A workflow that
correlates an automotive state with a source target retains both identities and
evidence types explicitly.
