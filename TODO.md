# hobot_fuzz -- TODO

Status legend: [x] done - [~] partial - [ ] not started.

## Phase 1: Foundation

- [x] hf-core: `FuzzEngine`, `TargetCandidate`, `Harness`, `Crash`, `Corpus` traits.
- [~] hf-provider: LLM provider pool with multi-provider backends (OpenAI,
  Azure, Anthropic, Gemini, Ollama). Freeze/thaw failover + error classification
  ported from y-agent (rate-limit/auth/5xx no longer kills a campaign). Token
  streaming not yet ported.
- [x] hf-storage: SQLite schema for runs, targets, harnesses, crashes, corpora.
- [x] hf-runtime: Docker sandbox adapter for isolated builds and fuzz runs.
- [x] hf-cli: `init`, `discover`, `harness`, `run`, `triage` subcommands (a thin
  layer over the shared `hf-service::ServiceContainer`).

## Phase 2: Discovery & Harness

- [x] hf-discovery: project scanner for C/C++ (Tree-sitter) + lexical Rust
  scanner. Go/Python scanners not yet implemented.
- [x] hf-harness: Rust cargo-fuzz backend (`cargo_fuzz` module: project
  scaffold + `cargo fuzz build`; language-aware `build_command`; `try_compile`
  Rust branch stages the crate via `copy_project_sources` and produces a
  libFuzzer binary the existing run path drives). Sandbox image gains a
  persistent nightly + cargo-fuzz toolchain. Not yet E2E-verified in-sandbox
  (needs the rebuilt image + a real cargo crate).
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
- [x] hf-corpus: coverage-guided minimization (cmin) + crash-to-corpus
  feedback loop (`absorb`); CLI `corpus --op minimize|absorb`.
- [x] hf-coverage: coverage delta tracking and stagnation alerts.
- [x] hf-coverage: line/region/function coverage summary (`CoverageSummary`
  from `llvm-cov export` totals); CLI `coverage`.
- [x] hf-service: detailed Markdown campaign report (`report::render_markdown`
  + `ServiceContainer::generate_report`) aggregating target, run, coverage,
  corpus, and triaged crashes (CASR severity + bug reports). Surfaced via CLI
  `report --out`, hf-web `POST /report`, and a GUI Triage "Download Report"
  button (native save dialog; browser download in web mode).
- [x] hf-service: AI-composed professional report -- the deterministic
  graph-bearing fact-sheet (Mermaid severity/kind pies + coverage chart +
  Unicode bars) is fed to the LLM, which writes the narrative (exec summary,
  methodology, per-finding impact + remediation, risk, recommendations) with
  strict fact-grounding; falls back to the fact-sheet without a provider.
- [x] hf-gui: report preview pane (react-markdown + mermaid) with rendered
  graphs, Copy/Download; "View Report" in Triage; lazy-loaded chunk.

## Phase 5: Orchestration, Safety & Polish

- [x] hf-service: single `ServiceContainer` spine; CLI/web/GUI route through
  `bootstrap()`; persists runs/targets/crashes via hf-storage.
- [x] hf-guardrails: action risk tiers, policy, HITL approval gates; enforced at
  every untrusted-execution point (compile/run/triage). Safe-by-default
  (`from_env` -> env-gated; `HF_GUARDRAILS=permissive` opts out). 4-pattern
  loop-detection guard (`loop_guard`) ported from y-agent + wired into the agent.
- [x] hf-agent: autonomous reason/act loop dispatching the fuzzing tools.
- [x] hf-gui: chat wired to the streaming agent (`chat_agent` + `chat:event`).
- [x] hf-web: REST API + SSE for run progress.
- [x] hf-engine: real `EngineAdapter` trait + registry (dead `FuzzEngine`
  removed).
- [x] hf-cli `init`: scaffolds config from templates + creates/migrates the DB.
- [x] hf-session + hf-context: persistent conversations + token-budget assembly;
  agent trims history and persists turns server-side (GUI `create_session`).
- [x] Interactive HITL dialog in the GUI (`chat:permission_request` ->
  approve/deny -> `chat_answer_permission`); chat runs under the
  approval-required guardrail policy.
- [ ] Provider token streaming: implement OpenAI SSE in `hf-provider` +
  `ProviderPool::stream` + agent Token events. (Deferred: low value through the
  ReAct JSON tool-protocol loop; would benefit from a native function-calling
  redesign first.)
- [x] Run cancellation: cooperative cancel of an in-flight `run_fuzzer` via a
  `CancellationToken` threaded through `hf-runtime`/`EngineRunner`;
  `ServiceContainer::cancel_run`/`cancel_all_runs`/`active_run_ids`; CLI Ctrl-C;
  `RunStatus::Cancelled`; GUI Stop button (`cancel_run` Tauri command +
  RunView). syzkaller (separate streaming path) not yet cancellable.
- [x] Diagnostics/Observability panels: LLM calls flow through
  `LlmProviderBridge` -> `DiagnosticsRecorder`, aggregated by
  `ServiceContainer::cost_summary` and surfaced via the `diagnostics_cost_summary`
  command; the DiagnosticsPanel renders real per-model cost/usage.
- [ ] Agents/Skills/Knowledge GUI views: back with real data (needs `hf-skills`
  command surface; `hf-knowledge` + sub-agent pools are still scaffolds).
- [ ] Remaining scaffold crates: hf-mcp, hf-scheduler, hf-knowledge,
  hf-skills (thin), hf-hooks, hf-journal, hf-tools (skeleton), hf-test-utils.

## Integrations

- [x] DefectDojo: push triaged crashes as findings via the REST API
  (`hf-service/src/defectdojo.rs`). Generic-findings mapper reusing the SARIF
  CWE/severity logic; reimport-scan dedup by stack signature; secret-env token;
  config section + GUI Settings > Integrations panel with Test connection;
  "Push to DefectDojo" in Triage and Reports; CLI `defectdojo`; web
  `/defectdojo/{push,test,configured}`. See `docs/design/defectdojo-integration.md`.

## Cross-cutting

- [~] CI: cargo fmt/clippy gates pass workspace-wide; add cargo-deny + test job.
- [~] Tests: storage, service, guardrails, agent covered; expand crash/triage
  and end-to-end coverage.

## Audit backlog (refreshed 2026-07-15)

A multi-crate audit fixed ~30 correctness/dead-code/doc issues (see git log).
The following verified findings remain open, ranked by user impact. Each is real
but larger or riskier than a drop-in fix.

### Safety and security (highest impact)
- [ ] Make promoted artifacts immutable at execution time: persist source and
  binary digests, verify them immediately before launch, and split read-only
  harness mounts from writable corpus/output mounts.
- [ ] Bound Docker stdout/stderr capture and represent `Completed`, `TimedOut`,
  and `Cancelled` separately; forced teardown currently synthesizes exit code 0.
- [ ] Stage Syzkaller config and disk inputs into managed storage, use a
  disposable disk overlay, and replace broad writable mounts/network/capability
  exceptions with the minimum documented profile.
- [ ] Default the web server to loopback, reject optional authentication on a
  non-loopback bind, and return redacted provider/config DTOs from REST.
- [x] Constrain Docker primary workspaces and runtime file I/O to the configured
  workspace root, including parent traversal and symlink escapes.
- [x] Reject symlinked crash/corpus roots and entries; validate seed filenames
  and atomically replace corpus destinations instead of following links.
- [x] Write generated and edited config files atomically with owner-only `0600`
  permissions on Unix. Rotate any credentials that predate this migration.
- [x] Reject unsafe transcript session ids before file I/O and require persisted
  session metadata before loading model context or retaining a per-session lock.

### Correctness (highest impact)
- [x] Target-scoped "latest run": reports, exports, triage, regression replay,
  and corpus absorption resolve runs through the persisted harness/target
  relationship and ignore newer runs for another target in the same project.
- [ ] Give every fuzz/smoke execution its own output directory and propagate an
  explicit run id into triage. Same-target overlapping runs still share
  `workspace/out`, so process-level serialization alone would not preserve
  durable attribution after a crash or restart.
- [ ] `persist_corpus` is upsert-only: `corpus_prune`/`corpus_prune_coverage`/
  `corpus_minimize` delete files but never remove persisted rows, so reported
  corpus counts only grow. Reconcile rows against the survivor set.
- [x] `harness_smoke` records the qualified harness id and execution settings,
  keeping smoke findings attributable to the correct target.
- [ ] AFL++ coverage: edge count is parsed from stdout (`count coverage :
  2.55 bits/tuple` -> ~2) instead of `out/default/fuzzer_stats` (`edges_found`),
  so AFL++ coverage/deltas/stagnation are wrong. Parse `fuzzer_stats`.
- [ ] Crash minimization is unwired: `hf-crash::build_minimize_args` has no
  caller and `Crash.minimized` is always false. Wire a minimize step into triage.
- [x] Prompt-protocol agent tool results use provider-compatible user messages;
  strict OpenAI-compatible relays no longer receive an orphan `tool` message.
- [ ] Make chat turns and rollback durable across display transcript, context
  transcript, metadata, and checkpoints. Append/rollback failures are currently
  downgraded to successful responses, and branch/delete cleanup can be partial.
- [ ] Serialize rollback, branch, and delete through the same per-session lock
  as model turns, then render the backend transcript after mutation. The GUI's
  local rollback indexes diverge when non-persisted tool events are present.
- [ ] Rework scheduler restart recovery so more than 256 queued recoveries cannot
  block startup, persisted `last_fire` is restored, and `MissedPolicy::Skip`
  advances the schedule instead of firing it on the first interval tick.
- [ ] Track scheduler campaign task handles through stop/cancel and account
  actual completed iterations and fuzz duration. Current detached tasks outlive
  scheduler stop and budget counters undercount retries while charging failures.

### REST/web parity
- [ ] REST cannot start or observe a fuzz run (`run_fuzzer`/`run_syzkaller`/
  `cancel_all_runs` have no route) and the SSE `RunProgress`/`DockerStatus`
  channel is never fed. Add the routes + wire the SSE producer.
- [ ] Web mode needs a `CorsLayer` and the frontend must send the `Authorization`
  bearer header, or browser + token auth stay mutually exclusive.
- [ ] REST handlers hardcode status codes; map `ClassifiedError` category to
  4xx/5xx instead.
- [ ] Path safety: `discover`/`knowledge_*` REST handlers pass raw user paths to
  the host FS (`knowledge_search` returns file snippets). Canonicalize + bound.

### Config knobs that silently no-op
- [ ] Provider `cost_per_1k_input/output` never reaches `ProviderMetadata`, so
  `CostOptimized` routing degenerates to "first candidate".
- [ ] Per-schedule `concurrency_policy` / `max_executions_per_hour` are persisted
  but never enforced; `SchedulerConfig.history_retention_limit`/others are inert.
- [ ] `KnowledgeConfig.retrieval_strategy`/weights and `SessionConfig` fields are
  deserialized but never mapped into the retriever/session manager.
- [ ] `cmd_ci` composes pipeline logic in the CLI and mutates global env
  (`HF_GUARDRAILS`); move to a `ServiceContainer::run_ci_gate` method.

### Data / schema
- [x] Unified `hf-storage` on `Store::connect` plus forward-only
  `migrations/*.sql`; session and checkpoint tests now exercise the production
  schema path, and the destructive test-only schema initializer was removed.
- [ ] Fix `DATABASE_SCHEMA.md` drift (runs missing statistics columns and
  ancillary persistence tables are undocumented).
- [ ] `list_all_crashes` doc claims newest-first but has no `ORDER BY`.
- [ ] `container.rs` storage reads use `.await.unwrap_or_default()` (14 sites), so
  a DB error renders as "no data" (worst for the crash list). At least log the error.
- [ ] Persist schedules and campaign budget state with atomic replace + fsync;
  corrupt or truncated JSON currently degrades to an empty/default state and can
  silently re-enable previously exhausted work.

### Unwired subsystems (decide: roadmap or remove)
- [ ] `hf-mcp` (3.3k LOC) has zero dependents. Most of `hf-journal` (file_history/
  rollback/middleware/hash) and much of `hf-diagnostics` (subscriber/search/
  replay/langfuse/cost) are dead. Hook execution/blocking path is never
  constructed. Per-tool `RateLimiter`, `PriorityScheduler`, `LeaseManager` unused.
- [ ] Knowledge dedup fingerprints only the first 100 chars and keys on a
  never-written `l1_section_index`, so distinct chunks are dropped from RAG.
- [ ] Cron `timezone` is dropped at evaluation (latent; creation forces UTC).
- [ ] `providers.example.toml` recommends a retired Anthropic model id.
