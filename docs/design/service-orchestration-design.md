# Service Orchestration Design

Status: **draft**. Owner: `hf-service`.

## 1. Goal

`hf-service` owns all business logic: it orchestrates the
discover -> harness -> run -> triage -> corpus -> coverage loop, manages
sub-agent delegation, and exposes a clean API to presentation layers.

## 2. Service API (sketch)

```rust
pub trait FuzzService: Send + Sync {
    async fn discover(&self, req: DiscoverRequest) -> Result<TargetInventory>;
    async fn generate_harness(&self, req: HarnessRequest) -> Result<Harness>;
    async fn run_fuzz(&self, req: FuzzRunRequest) -> Result<FuzzRunHandle>;
    async fn triage(&self, req: TriageRequest) -> Result<Vec<Crash>>;
    async fn corpus_ops(&self, req: CorpusOp) -> Result<Corpus>;
    async fn coverage_report(&self, run_id: Uuid) -> Result<CoverageReport>;
}
```

## 3. Workbench Readiness

`hf-service` owns workbench readiness derivation. Presentation layers receive a
dashboard DTO with state, score, blockers, and detail text instead of
re-deriving readiness from raw counts. This keeps REST, Tauri, CLI, and future
surfaces aligned on the same operational status.

## 4. Orchestration Flow

1. `discover` -> `TargetInventory` persisted; HITL selects targets.
2. For each selected target: `generate_harness` -> `Harness` (Promoted).
3. HITL approves harness -> `run_fuzz` -> streaming `FuzzRunHandle`.
4. On crash: `triage` -> `Vec<Crash>` with draft reports.
5. Background: `corpus_ops` + `coverage_report` loop; on stagnation, propose
   new harness.

## 5. Sub-Agents

- `discovery-agent` -- owns target ranking.
- `harness-agent` -- owns harness draft/iterate.
- `triage-agent` -- owns crash classification and bug report drafting.
- `coverage-agent` -- owns stagnation detection and harness proposals.

## 6. Tests

- Integration: end-to-end loop with mocked LLM and mocked engine.
