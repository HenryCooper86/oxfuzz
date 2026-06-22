# hobot_fuzz -- TODO

## Phase 1: Foundation

- [ ] hf-core: define `FuzzEngine`, `TargetCandidate`, `Harness`, `Crash`, `Corpus` traits.
- [ ] hf-provider: port LLM provider pool from y-agent (model-agnostic).
- [ ] hf-storage: SQLite schema for runs, targets, harnesses, crashes, corpora.
- [ ] hf-runtime: Docker sandbox adapter for isolated builds and fuzz runs.
- [ ] hf-cli: `init`, `discover`, `harness`, `run`, `triage` subcommands.

## Phase 2: Discovery & Harness

- [ ] hf-discovery: project scanner for C/C++ (Tree-sitter), Rust, Go, Python.
- [ ] hf-discovery: target ranking (fit score, input surface, complexity).
- [ ] hf-harness: LLM-driven harness generation with compile validation.
- [ ] hf-harness: smoke fuzz step (60s) before promoting a harness.

## Phase 3: Engine Integration

- [ ] hf-engine: AFL++ adapter.
- [ ] hf-engine: honggfuzz adapter.
- [ ] hf-engine: libFuzzer adapter.
- [ ] hf-engine: ClusterFuzzLite / oss-fuzz integration adapter.

## Phase 4: Crash & Corpus

- [ ] hf-crash: crash ingestion, stack-signature dedup.
- [ ] hf-crash: minimization (libFuzzer `minimize` / afl `tmin`).
- [ ] hf-corpus: seed, grow, prune, merge operations.
- [ ] hf-coverage: coverage delta tracking and stagnation alerts.

## Phase 5: Polish

- [ ] hf-web: REST API + SSE for run progress.
- [ ] hf-skills: `target-triage`, `harness-author`, `crash-triage` skills.
- [ ] hf-diagnostics: cost intelligence and run replay.
- [ ] CI: cargo fmt/clippy/test gates, cargo-deny.