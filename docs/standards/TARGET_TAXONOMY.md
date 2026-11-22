# Target Taxonomy

Status: **active**. Scope: `hf-discovery`, `hf-core`.

## 1. TargetLanguage

```rust
pub enum TargetLanguage { C, Cpp, Rust, Go, Python, Java, JavaScript }
```

| Language | Scanner | Candidate rule |
| --- | --- | --- |
| C/C++ | Tree-sitter (`hf-discovery`) | Non-static function definitions with at least one parameter; `main`, `LLVMFuzzer*` callbacks, and every function in a unit that is itself a fuzz harness (`hf_core::c_unit::UnitRole::FuzzEntry`, left out of the harness link) excluded (they still contribute call edges). |
| Rust | dependency-free lexical | `pub fn` (incl. `async`/`unsafe`/`const`) with at least one parameter; `main` and `test_*` excluded. |
| Go | dependency-free lexical | Exported (capitalized) package-level functions and methods with at least one parameter; `main`, `init`, and `Test*`/`Benchmark*` excluded, as are `_test.go` files and `vendor/`. Methods are named `Receiver.Method`. |
| Python | dependency-free lexical | Top-level `def` and direct class methods (incl. `async` and decorated definitions) with at least one parameter besides `self`/`cls`; underscore-privates, dunders, `test_*`, and closures nested in another `def` excluded. Methods are named `Class.method`. |
| Java | dependency-free lexical | `public static` methods with at least one parameter, declared directly in the top-level class a file is named after; `main` excluded, as are `module-info.java`, `package-info.java`, and files under a `test` or `tests` directory. Methods are named `Class.method`; the first overload of a name is kept. |
| JavaScript | dependency-free lexical | Functions declared at column zero of a `.js`, `.mjs` or `.cjs` file with at least one parameter and exported under their own name (`export`, `export { name }`, `exports.name`, `module.exports.name`, `module.exports = { name }`); function declarations, function expressions and arrow functions, `async` or not. Generators, default exports, methods and classes excluded, as are `node_modules`, test directories, and `*.test.*`, `*.spec.*`, `*.min.*` and `*.config.*` files. |

The lexical scanners are intentionally conservative: a missed multi-line
signature is a lost candidate, never a wrong one. They extract no call edges,
so their candidates carry no reachability annotation.

The scan inventory deliberately covers more languages than the harness
pipeline can build. `TargetLanguage::harnessable` (hf-core) is the single
predicate for the latter. Every scanned language is harnessable today, each
under the engine that runs it: C and C++ under libFuzzer, AFL++ and honggfuzz,
Rust under libFuzzer, Go under `go-native`, Python under `atheris`, Java
under `jazzer`, and JavaScript under `jazzer-js`
(`docs/design/go-native-fuzzing-design.md`,
`docs/design/python-atheris-fuzzing-design.md`,
`docs/design/jvm-jazzer-fuzzing-design.md`,
`docs/design/javascript-jazzerjs-fuzzing-design.md`). Harness authoring operations
and `oxfuzz fuzz` target auto-selection enforce that predicate directly.

## 2. TargetKind

| Variant | Description | Example |
| --- | --- | --- |
| `Function` | A standalone function taking input. | `parse_value(const char*)` |
| `Parser` | A parser, decoder, or deserializer entry point, recognized by name (`parse`, `decode`, `deserial`, `unmarshal`, `unpack`, `inflate`, `decompress`, `tokeniz`). | `json_parse(const char*, size_t)` |
| `ApiEntry` | A public API entry point of a library. | `SSL_read` |
| `Ffi` | Foreign function interface boundary. | `Java_pkg_foo_nativeBar` |

## 3. InputSurface

| Variant | Description | Harness strategy |
| --- | --- | --- |
| `Bytes` | Raw byte buffer: a pointer, array, reference, slice, or string parameter. | `LLVMFuzzerTestOneInput(data, size)` |
| `Structured` | Structured input (protobuf, JSON, custom), or scalar parameters a harness must carve out of the fuzzer's bytes. | Custom mutator / grammar, or a harness that builds the arguments. |
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

## 7. Persistence Identity

A target's persistence identity is `(project_root, file, symbol)`, where
`file` is the defining file relative to the canonical project root
(`TargetCandidate::relative_file`, absolute-path fallback outside the root).
The scanner derives the deterministic id as a UUIDv5 over that key, and
`hf-storage` enforces it with the unique index
`idx_targets_project_symbol_file`. Two same-named functions in different
files of one project are therefore distinct targets with independent
harness/corpus/crash linkage; rediscovery of one definition re-homes onto its
existing row, keeping the first persisted id.

Wherever a target is named as a string (CLI, REST, GUI), it may carry a
`file::symbol` qualifier (e.g. `src/a.c::parse_opts`). A plain symbol that
matches more than one definition is rejected as ambiguous, with the
file-qualified forms listed.

## 8. Automotive Protocol Targets

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
