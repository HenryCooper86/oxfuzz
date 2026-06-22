# Target Discovery Design

Status: **draft**. Owner: `hf-discovery`.

## 1. Goal

Given a project root and a target language, produce a ranked `TargetInventory`
of `TargetCandidate` entries suitable for fuzzing.

## 2. TargetCandidate

```rust
pub struct TargetCandidate {
    pub id: Uuid,
    pub project_root: PathBuf,
    pub language: TargetLanguage,
    pub symbol: String,
    pub kind: TargetKind,         // Function | Parser | API entry | FFI
    pub location: SourceLocation, // file, line, col
    pub signature: Option<String>,
    pub input_surface: InputSurface, // Bytes | Structured | File | Stdin
    pub complexity: Complexity,      // Cyclomatic-ish score
    pub fit_score: f64,              // 0.0 - 1.0
    pub sanitizers: Vec<Sanitizer>,
    pub rationale: String,           // LLM-produced reasoning
}
```

## 3. Pipeline

1. **Index** -- walk project with `ignore` crate; parse with Tree-sitter
   (C/C++, Rust, Go) or AST (Python).
2. **Filter** -- drop symbols that are trivially not fuzzable (pure
   formatting, no input).
3. **Enrich** -- compute complexity, detect input surface, infer sanitizers
   from build flags.
4. **Rank** -- LLM-assisted scoring: the agent receives the candidate list
   with signatures and produces fit scores + rationale.
5. **Emit** -- `TargetInventory` persisted to `hf-storage`; surfaced to user
   for HITL selection.

## 4. Fit Score Heuristics

- Untrusted input entry point: +0.3
- Parser/deserializer: +0.3
- High cyclomatic complexity: +0.2
- No existing harness in project: +0.1
- Uses raw pointers / unsafe / unsafe FFI: +0.1

## 5. Languages

| Language | Parser | Harness template |
| --- | --- | --- |
| C/C++ | Tree-sitter (C/C++ grammar) | `fuzz_*.c` with `LLVMFuzzerTestOneInput` |
| Rust | syn / cargo-metadata | `cargo-fuzz` target |
| Go | go/parser | `go-fuzz` / native fuzz |
| Python | ast | Atheris `FuzzedDataProvider` |

## 6. Open Questions

- Should we integrate `codeql` for richer dataflow on C/C++?
- How to handle projects with multiple build systems (CMake, Meson, Bazel)?

## 7. Tests

- Unit: parse a fixture C project, assert `parse_value` is ranked highest.
- Unit: filter removes `printf` wrappers.
- Integration: discovery on a sample project produces a non-empty inventory.