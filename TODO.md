# hobot_fuzz -- TODO

Status legend: [x] done - [~] partial - [ ] not started.

## Phase 1: Foundation

- [x] hf-core: `FuzzEngine`, `TargetCandidate`, `Harness`, `Crash`, `Corpus` traits.
- [~] hf-provider: LLM provider pool (OpenAI-compatible). Multi-provider
  (Anthropic/Gemini/Ollama), freeze/health/lease not yet ported.
- [x] hf-storage: SQLite schema for runs, targets, harnesses, crashes, corpora.
- [x] hf-runtime: Docker sandbox adapter for isolated builds and fuzz runs.
- [x] hf-cli: `init`, `discover`, `harness`, `run`, `triage` subcommands (a thin
  layer over the shared `hf-service::ServiceContainer`).

## Phase 2: Discovery & Harness

- [x] hf-discovery: project scanner for C/C++ (Tree-sitter). Rust/Go/Python
  scanners not yet implemented.
- [x] hf-discovery: target ranking (fit score, input surface, complexity).
- [x] hf-harness: LLM-driven harness generation with compile validation.
- [x] hf-harness: smoke fuzz step (60s) before promoting a harness.

## Phase 3: Engine Integration

- [x] hf-engine: AFL++ adapter.
- [x] hf-engine: honggfuzz adapter.
- [x] hf-engine: libFuzzer adapter.
- [x] hf-engine: ClusterFuzzLite + Syzkaller adapters.

## Phase 4: Crash & Corpus

- [x] hf-crash: crash ingestion, stack-signature dedup.
- [x] hf-crash: minimization + LLM bug-report drafting (wired into triage).
- [x] hf-corpus: seed, grow, prune, merge operations.
- [x] hf-coverage: coverage delta tracking and stagnation alerts.

## Phase 5: Orchestration, Safety & Polish

- [x] hf-service: single `ServiceContainer` spine; CLI/web/GUI route through
  `bootstrap()`; persists runs/targets/crashes via hf-storage.
- [x] hf-guardrails: action risk tiers, policy, HITL approval gates; enforced at
  every untrusted-execution point (compile/run/triage).
- [x] hf-agent: autonomous reason/act loop dispatching the fuzzing tools.
- [x] hf-gui: chat wired to the streaming agent (`chat_agent` + `chat:event`).
- [x] hf-web: REST API + SSE for run progress.
- [ ] Run cancellation: cooperative cancel of an in-flight `run_fuzzer`
  (needs cancellation-token support in `hf-runtime`/`EngineRunner`).
- [ ] Interactive HITL dialog in the GUI (emit `chat:permission_request` and
  await a `chat_answer_permission` response; mechanism exists in hf-guardrails).
- [ ] Diagnostics/Observability panels: instrument the provider pool and expose
  `hf-diagnostics::CostTracker` via a command (panels currently mocked).
- [ ] hf-bot, hf-mcp, hf-scheduler, hf-knowledge, hf-skills, hf-hooks,
  hf-journal, hf-session, hf-context: still scaffold crates.

## Cross-cutting

- [~] CI: cargo fmt/clippy gates pass workspace-wide; add cargo-deny + test job.
- [~] Tests: storage, service, guardrails, agent covered; expand crash/triage
  and end-to-end coverage.
