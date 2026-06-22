# Target Taxonomy

Status: **active**. Scope: `hf-discovery`, `hf-core`.

## 1. TargetLanguage

```rust
pub enum TargetLanguage { C, Cpp, Rust, Go, Python }
```

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