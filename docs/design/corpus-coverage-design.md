# Corpus & Coverage Design

Status: **draft**. Owner: `hf-corpus` + `hf-coverage`.

## 1. Goal

Manage seed corpora, grow them during fuzzing, prune redundant entries, and
track coverage deltas to detect stagnation and trigger new harness proposals.

## 2. Corpus

```rust
pub struct Corpus {
    pub id: Uuid,
    pub target_id: Uuid,
    pub root: PathBuf,
    pub entries: Vec<CorpusEntry>,
}

pub struct CorpusEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source: CorpusSource, // Seed | Fuzzer | Minimized | Manual
    pub coverage_hash: Option<String>,
}
```

## 3. Operations

- **Seed** -- initialize from project-supplied seeds or LLM-suggested seeds.
- **Grow** -- pull new coverage-inducing inputs from engine output queue.
- **Prune** -- remove entries that no longer increase coverage.
- **Merge** -- combine corpora across engines for the same target.

## 4. Coverage

```rust
pub struct CoverageReport {
    pub run_id: Uuid,
    pub edges: u64,
    pub blocks: u64,
    pub delta_edges: i64,
    pub stagnation_secs: u64,
    pub new_edges_files: Vec<PathBuf>,
}
```

When `stagnation_secs` exceeds a threshold, `hf-service` may propose a new
harness variant or a custom mutator to the user.

## 5. Tests

- Unit: prune removes a duplicate-coverage entry.
- Unit: stagnation flag triggers when delta_edges == 0 for N seconds.