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

1. **Resolve** -- canonicalize the existing project root so relative paths and
   symlink aliases have one persistence and workspace identity.
2. **Index** -- walk project with `ignore`; parse C/C++ with Tree-sitter and
   conservatively scan public Rust functions lexically. Walk, read, and parse
   failures are surfaced rather than converted into a successful partial scan.
3. **Filter** -- drop symbols that are trivially not fuzzable (pure
   formatting, no input).
4. **Enrich** -- compute complexity, detect input surface, infer sanitizers
   from build flags.
5. **Rank** -- LLM-assisted scoring: the agent receives the candidate list
   with signatures and produces fit scores + rationale.
6. **Emit** -- `TargetInventory` persisted to `hf-storage`; surfaced to user
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
| Rust | conservative lexical scanner | `cargo-fuzz` target |
| Go | planned | planned native fuzz target |
| Python | planned | planned Atheris target |

## 6. Open Questions

- Should we integrate `codeql` for richer dataflow on C/C++?
- How to handle projects with multiple build systems (CMake, Meson, Bazel)?

## 7. Tests

- Unit: parse a fixture C project, assert `parse_value` is ranked highest.
- Unit: filter removes `printf` wrappers.
- Integration: discovery on a sample project produces a non-empty inventory.
