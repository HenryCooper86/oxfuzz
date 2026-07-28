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
    pub location: SourceLocation, // file, start line/col, optional end line/col
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
   conservatively scan public Rust functions and exported Go/Python functions
   lexically. Walk, read, and parse failures are surfaced rather than
   converted into a successful partial scan.
3. **Filter** -- drop symbols that are trivially not fuzzable (pure
   formatting, no input).
4. **Enrich** -- compute complexity, detect input surface, infer sanitizers
   from build flags.
5. **Rank** -- LLM-assisted scoring: the agent receives the candidate list
   with signatures and produces fit scores + rationale.
6. **Emit** -- `TargetInventory` persisted to `hf-storage`; surfaced to user
   for HITL selection.

**Identity:** persistence identity is `(project_root, relative_file, symbol)`
(`deterministic_target_id` in `hf-discovery::scanner`) -- stable across
scans, so rediscovery of one definition keeps its id, while two same-named
functions in different files of one project are distinct persisted targets.
For analysis the scanner still unions same-named functions' call edges and
keeps the maximum complexity (the call graph is name-keyed by design). Target
resolution accepts a `file::symbol` qualifier; a plain symbol matching more
than one definition is rejected as ambiguous with the qualified forms listed.
Migration 0019 backfills `targets.file` from the stored `data_json` and swaps
the unique index for the file-scoped one: historical linkage for a
pre-migration collided symbol stays attached to the surviving legacy row, and
the second definition becomes a distinct new row on the next scan.

### 3.1 Semgrep Target Enrichment

C and C++ discovery records the complete Tree-sitter function-definition span:
the definition start line and column plus optional `end_line` and `end_col`.
The end coordinates are optional so existing serialized inventories remain
readable. Semgrep enrichment requires complete spans; an older C/C++ inventory
without them must be rediscovered before enrichment.

Behind the `semgrep-enrichment` feature, `hf-discovery` owns pure Semgrep JSON
normalization, finding-to-candidate mapping, distinct-rule deduplication,
scoring, deterministic ordering, and the enriched-inventory overlay. The
domain layer accepts bytes and domain values. It does not launch Semgrep,
access the network, stage source, mutate storage, or authorize another action.
Normalized findings are advisory static-analysis signals, not confirmed
vulnerabilities or fuzzing crashes.

A finding maps to a candidate only when its normalized relative path exactly
matches the candidate definition path, the candidate belongs to the scanned
C/C++ inventory revision, and the finding start coordinate is contained by
exactly one complete function span. A finding with zero or multiple containing
spans remains visible but unmatched and contributes no score.

`TargetCandidate.fit_score` is the immutable base score. Scoring deduplicates
by `(candidate_id, rule_id)`, uses the highest severity when one rule reports
multiple severities for the same candidate, and applies these weights:

| Semgrep severity | Per-distinct-rule boost |
| --- | ---: |
| `Error` | `0.10` |
| `Warning` | `0.05` |
| `Info` | `0.01` |

The total Semgrep boost is capped at `0.20`, and the effective score is capped
at `1.0`:

```text
semgrep_boost = min(0.20, sum(distinct matched-rule weights))
effective_score = min(1.0, fit_score + semgrep_boost)
```

Repeated scans recompute the overlay from the current base inventory and never
compound prior boosts. Effective ranking sorts by effective score descending,
base score descending, then relative file, symbol, and target UUID ascending.

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
| Go | conservative lexical scanner | planned native fuzz target |
| Python | conservative lexical scanner | planned Atheris target |

The lexical scanners (Rust, Go, Python) vendor no grammar, so they match
declaration lines and balanced delimiter/indentation blocks instead of
parsing. They are intentionally conservative: a missed multi-line signature
is a lost candidate, never a wrong one. Shared rules: only parameter-bearing,
non-test entry points qualify (a zero-parameter function has no untrusted
input to feed), complexity is the same 1-plus-control-flow-keywords estimate
as the C scanner, and no call edges are extracted, so candidates flow into
ranking without reachability annotation. Language-specific rules:

- **Go** -- only exported (capitalized) package-level functions and methods;
  `main`/`init` (unexported) and `Test*`/`Benchmark*` are skipped, as are
  `_test.go` files and `vendor/` (third-party code is not the project's fuzz
  surface). Methods are named `Receiver.Method` so same-named methods of
  different types do not collide in the name-keyed inventory.
- **Python** -- top-level `def`s and direct class methods, including `async`
  and decorated definitions; `self`/`cls` are excluded from the parameter
  count; underscore-privates, dunders, `test_*`, and closures nested inside
  another `def` are skipped (a nested closure is not importable from a
  harness). Methods are named `Class.method`. Body complexity uses an
  indentation-aware end-of-block instead of balanced braces.

## 6. Open Questions

- Should we integrate `codeql` for richer dataflow on C/C++?
- How to handle projects with multiple build systems (CMake, Meson, Bazel)?

## 7. Tests

- Unit: parse a fixture C project, assert `parse_value` is ranked highest.
- Unit: filter removes `printf` wrappers.
- Integration: discovery on a sample project produces a non-empty inventory.
