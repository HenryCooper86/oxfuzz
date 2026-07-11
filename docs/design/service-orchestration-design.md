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
2. For each selected target: `generate_harness` -> compile -> persisted smoke
   evidence (`SmokePassed`).
3. HITL explicitly promotes the exact revision -> `run_fuzz` -> streaming
   `FuzzRunHandle`. Agents and schedules fail closed before this approval.
4. On crash: `triage` -> `Vec<Crash>` with draft reports.
5. Background: `corpus_ops` + `coverage_report` loop; on stagnation, propose
   new harness.

### 4.1 Coverage Regression Rollback

Automatic harness rollback is evidence-gated. A completed run may be compared
only with an earlier successful run for the same target whose engine, requested
duration, memory/CPU limits, sanitizer, corpus location, environment, and engine
arguments match. Cross-engine, cross-budget, failed, cancelled, unattributed,
and legacy runs without configuration are not rollback baselines.

The active source revision is stored separately from language-specific compiler
inputs and is committed only after a successful sandbox build. Failed builds may
leave attempt files for diagnostics, but they do not change the active revision
or the binary/source attribution used by run history and rollback decisions.
Coverage-drop thresholds are finite percentages in `(0, 100]`; invalid global
values fall back to the safe default and invalid per-project writes are rejected.

Run-history presentation receives an opaque service-owned comparison key. This
prevents desktop/web clients from calling adjacent runs a regression when they
belong to another target or use incomparable execution conditions.

## 5. Sub-Agents

`hf-agent` owns only the model reason/act loop and depends on an inward
`AgentBackend` port. `hf-service` implements that port and owns tool dispatch,
knowledge access, diagnostics, guardrails, session locking, checkpoints, and
transcript persistence. Presentation crates depend on `hf-service` only; CI
manifest tests enforce this boundary and prevent a service/agent cycle.

- `discovery-agent` -- owns target ranking.
- `harness-agent` -- owns harness draft/iterate.
- `triage-agent` -- owns crash classification and bug report drafting.
- `coverage-agent` -- owns stagnation detection and harness proposals.

## 6. Tests

- Integration: end-to-end loop with mocked LLM and mocked engine.
- Regression: failed harness builds preserve the active revision.
- Regression: auto-revert baselines reject target, engine, budget, sanitizer,
  corpus, environment, and argument mismatches.
- Regression: target rediscovery preserves the original target id and all
  harness/corpus/crash attribution.
- Contract: presentation manifests contain no direct domain, runtime, or agent
  dependencies.
