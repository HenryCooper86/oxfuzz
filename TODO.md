# oxfuzz -- TODO

Status legend: [x] done - [~] partial - [ ] not started.

## Phase 1: Foundation

- [x] hf-core: `EngineKind`, `TargetCandidate`, `Harness`, `Crash`, `Corpus` types.
- [x] hf-provider: LLM provider pool with multi-provider backends (OpenAI,
  Azure, Anthropic, Gemini, Ollama). Freeze/thaw failover + error classification
  ported from y-agent (rate-limit/auth/5xx no longer kills a campaign). Token
  streaming is implemented on all five backends and on `ProviderPool`; only the
  cosmetic agent `Token` event is unwired (see the streaming entry below).
- [x] hf-storage: SQLite schema for runs, targets, harnesses, crashes, corpora.
- [x] hf-runtime: Docker sandbox adapter for isolated builds and fuzz runs.
- [x] hf-cli: `init`, `discover`, `harness`, `run`, `triage` subcommands (a thin
  layer over the shared `hf-service::ServiceContainer`).

## Phase 2: Discovery & Harness

- [x] hf-discovery: project scanner for C/C++ (Tree-sitter) + lexical Rust, Go,
  and Python scanners (`scan_go`/`scan_python`, dispatched from `scan()`; Go
  methods are named `Receiver.name` and Python methods `Class.name`).
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
- [x] hf-engine: syzkaller adapter.

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
- [~] Provider token streaming: OpenAI SSE, `ProviderPool::chat_completion_stream`,
  and the shared SSE parser are implemented and tested (`hf-provider/src/sse.rs`,
  `providers/openai.rs`). Only cosmetic agent `Token` events remain unwired --
  deferred as genuinely low value: the ReAct JSON tool-protocol loop must parse a
  whole response before dispatching a tool call, so nothing benefits until a
  native function-calling redesign.
- [x] Run cancellation: cooperative cancel of an in-flight `run_fuzzer` via a
  `CancellationToken` threaded through `hf-runtime`/`EngineRunner`;
  `ServiceContainer::cancel_run`/`cancel_all_runs`/`active_run_ids`; CLI Ctrl-C;
  `RunStatus::Cancelled`; GUI Stop button (`cancel_run` Tauri command +
  RunView). Syzkaller campaigns register the same active-run cancellation token
  and propagate cancellation through their streaming sandbox path.
- [x] Diagnostics/Observability panels: LLM calls flow through
  `LlmProviderBridge` -> `DiagnosticsRecorder`, aggregated by
  `ServiceContainer::cost_summary` and surfaced via the `diagnostics_cost_summary`
  command; the DiagnosticsPanel renders real per-model cost/usage.
- [x] Agents/Skills/Knowledge GUI views: backed by real data -- skills/agents
  are served from the registries (list/read/save/delete via `hf-service`,
  Tauri commands, and REST twins), and the Knowledge view shows the real
  per-project index status (`knowledge_stats`: size, build time, ingested
  documents, retrieval config). Single-depth specialist delegation (the
  `delegate` tool + 7 builtin specialists) is wired end-to-end and the GUI
  shows a live Agent Pool; concurrent sub-agent "pools" (parallel fan-out) is
  an undefined-scope idea with no design or demand, deliberately not built.
- [x] `hf-skills` reviewed -- complete, not a stub: a functional registry
  (builtins + user override + atomic persistence) wired through `hf-service`
  CRUD, Tauri, and REST, with a live runtime effect (builtin agents inject the
  builtin skill playbooks into their system prompt every turn), covered by
  in-crate and cross-crate tests. `hf-mcp` and `hf-hooks` were removed;
  `hf-test-utils` is consumed by `hf-harness`, `hf-service`, and `hf-session`
  and is doing its job.

## Integrations

- [x] DefectDojo: push triaged crashes as findings via the REST API
  (`hf-service/src/defectdojo.rs`). Generic-findings mapper reusing the SARIF
  CWE/severity logic; reimport-scan dedup by stack signature; secret-env token;
  config section + GUI Settings > Integrations panel with Test connection;
  "Push to DefectDojo" in Triage and Reports; CLI `defectdojo`; web
  `/defectdojo/{push,test,configured}`. See `docs/design/defectdojo-integration.md`.

## Cross-cutting

- [x] CI: all ten `scripts/tests/gates.sh` gates (fmt, clippy, check,
  check-no-default-features, test, doc, deny, script-tests, frontend-test,
  frontend-lint) run on every push/PR via `.github/workflows/ci.yml` (public
  GitHub) and `.gitlab-ci.yml` (OrbStack origin); `release.yml` builds the four
  desktop bundles on tag. See `docs/guides/CI.md`.
- [~] Tests: storage, service, guardrails, agent covered. Crash/triage coverage
  expanded (`hf-service/tests/crash_triage_paths.rs`, `container.rs`): the
  CASR-clustered triage E2E (the default strategy, previously untested), the
  legacy-triage signature-stagnation early break + dedup collapse, the
  bug-report drafting cap with root-cause persistence, and the
  `verify_regressions` regressed/fixed branches. The Semgrep terminal-settlement
  race surfaced by the first Linux CI run (the operation view exposed `failed`
  before staging cleanup, journal abort, and reservation release) is fixed --
  terminal rows now report `persisting` until settled -- and pinned by a
  deterministic pause-point test
  (`terminal_failure_stays_persisting_until_settlement_completes`). Linux CI
  also caught a timestamp-precision assumption: the guardrail round-trip
  fixture is pinned to the column's microsecond contract, the two remaining
  lossy millisecond serializers (chat checkpoint and session `created_at`)
  now store fixed-width nanosecond RFC 3339 with the checkpoint round-trip
  strengthened to full-record equality, and a workspace sweep confirmed no
  other timestamp path truncates. Remaining
  E2E arms: successful minimization through the full loop; UBSan /
  syzkaller classification edges. The
  `lifecycle_and_recovery_events_include_required_structured_fields` race is
  fixed: it asserted a transition-event floor that the workers emit
  independently of the status reads it waited on, so runner contention could
  beat it; it now polls for the transitions with a timeout (0/10 on native
  Linux, 8/8 locally).
- [x] Windows workspace naming: `workspace_dir` embedded the raw target symbol
  in a directory name, so a C++ target (`ns::Class::method`) or the documented
  `file.c::symbol` syntax produced an NTFS-illegal path on a Windows host, and a
  target containing `/` nested one target's workspace inside another's. Fixed by
  routing `sanitize_target` through the same `target_artifact_stem` that already
  named harness binaries: a workspace is now always one `[A-Za-z0-9_-]`
  component, hashed when the target is not that verbatim. Plain identifiers --
  everything the scanners emit -- keep their existing directory name.
- [x] Event schedules whose action is a campaign re-trigger themselves: a
  campaign emits `run.completed` when its run phase ends, so an
  `event: run.completed` schedule fired again while its own execution was still
  in triage, and nothing stopped a fresh firing once the execution finished.
  Resolved by suppressing self-emitted events: `IncomingEvent` carries the
  `source_schedule_id` whose execution produced it (a `DISPATCHING_SCHEDULE`
  task-local scoped over `FuzzCampaignDispatcher::dispatch`), and `EventBridge`
  never fires a schedule on its own event. Chaining between *different*
  schedules is unchanged. Known limitation: two campaign schedules listening on
  the same run event still chain into each other; bounding that needs cascade
  depth carried through the fired trigger, which no configuration reaches
  today.

## Audit backlog (refreshed 2026-07-17)

A second full-workspace audit (see `.claude/plans/2026-07-17-codebase-audit.md`)
fixed the following; open design decisions are listed at the end.

### Safety and security
- [x] Web origin host-match fallback is restricted to loopback hosts, closing a
  DNS-rebinding hole in open local-dev mode; exact allowlist semantics unchanged.
- [x] Pinned image references reject leading-dash values and empty name
  components in `hf-runtime` and the automotive sidecar validator, so a
  validated reference can never be consumed as a `docker run` flag.
- [x] Raw `/config/write` rejects `providers.toml`; the typed endpoint is the
  only write path so the live provider pool always reloads.

### Correctness
- [x] Docker stdin EPIPE no longer discards captured container output; the real
  exit and stderr surface instead of a misleading "write docker stdin" error.
- [x] Status-aware error classification is wired into all five providers:
  context-window 400s classify as request-specific `ContextWindowExceeded` and
  no longer freeze the provider; 404/unknown-400 freeze durations corrected.
- [x] `hf_corpus::minimize` fails closed on an empty survivor set instead of
  deleting the live corpus and returning `Ok` (closes the rollback wipe path).
- [x] ASan reports whose stacks merely mention "timeout" stay `Asan`; timeout
  detection now requires a fuzzer verdict headline.
- [x] Stack signatures strip unresolved-frame hex addresses, so dedup is
  ASLR-stable across processes.
- [x] Batch knowledge indexing upserts per chunk id like the single-item path.
- [x] Engine capabilities no longer advertise honggfuzz or syzkaller crash
  minimization (the minimizer only supports AFL++/libFuzzer).
- [x] Duplicate C symbols merge call-graph edges/complexity in the scanner
  instead of silently overwriting; name-based persistence identity documented
  as intentional (known limitation below).
- [x] Internal smoke/prune/minimize budgets clamp to the operator duration
  ceiling instead of erroring, so a low `max_duration_secs` cannot block
  harness qualification; operator-requested campaigns still hard-fail.
- [x] Web `parse_role` keeps `tool` transcript turns (parity with the GUI);
  `knowledge_index` runs off the async runtime via `spawn_blocking`.
- [x] Diagnostics trace rows persist real token/cost/duration totals; corrupt
  rows propagate decode errors instead of silently shrinking reads, and
  `list_traces_by_session` is newest-first on both backends.
- [x] `SessionManagerError::NotFound` is reachable (was mapped to `Storage`).
- [x] Agent delegation resolves sub-agents from the user registry
  (`config/agents/`) like the driving agent, not only the built-in roster.
- [x] hf-prompt's token estimator uses bytes/4 like hf-context/hf-core, so
  multibyte budgets are enforced consistently.

### Dead code removed
- [x] `TOOL_CATALOG` (hf-agent), `stub.rs` orphan (hf-skills), the unused
  `bollard` dependency, unconstructed `ProviderPoolError` variants, provider
  metrics accessors + the prometheus renderer, `hf-engine`'s duplicate
  `build_tmin_args`, and `RunResult.coverage` (minted a random run id, no
  readers) with `parse_coverage`.

### Docs
- [x] `ENGINE_ADAPTER_STANDARD.md` section 5 documents the real flat crash
  layout ingestion accepts; stale hf-scheduler doc references corrected.

### Open design decisions (status after TODO batches 1-2)
- [x] Guardrail authorization decisions persist to storage (migration 0018) and
  surface through the CLI `policy decisions`, REST `/policy/decisions`, and the
  desktop Policy Audit view.
- [~] Unwired-but-designed subsystems:
  - [x] guardrail authorization of discover/corpus/chat actions (batch 1);
  - [x] knowledge-augmented harness/triage prompts via the live retrieval path
    (batch 2) -- the standalone `InjectKnowledge` middleware, ingestion
    pipeline, and vector indexer remain unwired;
  - [x] hf-context working-memory/pruning pipeline -- resolved by removal: the
    provider pipeline, context guard, store-backed pruning, and
    memory/working-memory subsystems (~7k LOC) were reachable only from the
    crate's own unit tests and required a store/delegator/session-id that never
    reached the agent port. Cut; the live loop keeps the wired flat-message
    trio (simple + IntraTurnPruner + CompactionEngine);
  - [x] hf-scheduler parameter resolution + event triggers -- both fully
    implemented, wired, and tested: `params.rs` resolves a fired schedule into a
    concrete target/engine/duration campaign, and `crash.found`/`run.completed`/
    `run.failed` flow through `emit_event` end-to-end (`scheduler_events.rs`).
- [x] Provider `thaw` operator surface (CLI `providers thaw`, web
  `POST /providers/{id}/thaw`) + `health_check_interval_secs` honored by a
  bootstrap health-check task (batch 1).
- [x] Same-named C functions share one `(project, symbol)` persistence
  identity -- resolved by file-scoped identity `(project_root, file, symbol)`
  (migration 0019, `file::symbol` qualifier in target resolution).
- [x] REST routes kept as supported public API; 8 never-invoked Tauri
  commands pruned (batch 1).
- [x] `CoverageReport` carries the real run id through the coverage feedback
  path (batch 1); delta fields retained after `main` made them real.

## Audit backlog (refreshed 2026-07-15)

A multi-crate audit fixed dozens of correctness, safety, dead-code, and
documentation issues (see git log). Every verified finding in this audit is
resolved below; intentionally deferred roadmap work remains in Phase 5.

### Safety and security (highest impact)
- [x] Persist promoted source and binary digests, verify them immediately before
  execution, and mount promoted harnesses read-only while keeping only
  run-local corpus/output paths writable.
- [x] Bound Docker stdout/stderr capture and preserve typed `Completed`,
  `TimedOut`, and `Cancelled` termination states through forced teardown.
- [x] Stage Syzkaller config and disk inputs under the managed workspace, use a
  disposable rootfs, enforce live write budgets, and apply the documented
  restricted network/device/capability profile.
- [x] Default the web server to loopback, require authentication for non-loopback
  binds, and return redacted provider/config DTOs from REST.
- [x] Constrain Docker primary workspaces and runtime file I/O to the configured
  workspace root, including parent traversal and symlink escapes.
- [x] Reject symlinked crash/corpus roots and entries; validate seed filenames
  and atomically replace corpus destinations instead of following links.
- [x] Write generated and edited config files atomically with owner-only `0600`
  permissions on Unix. Rotate any credentials that predate this migration.
- [x] Reject unsafe transcript session ids before file I/O and require persisted
  session metadata before loading model context or retaining a per-session lock.
- [x] Build the production agent prompt through the bounded canonical
  `hf-prompt` path with the real tool catalog, workspace identity, HITL rules,
  and prompt-injection defenses.

### Correctness (highest impact)
- [x] Target-scoped "latest run": reports, exports, triage, regression replay,
  and corpus absorption resolve runs through the persisted harness/target
  relationship and ignore newer runs for another target in the same project.
- [x] Give every fuzz/smoke execution its own output directory and propagate the
  explicit run id through triage, crash ingestion, and retained evidence.
- [x] Reconcile persisted corpus rows exactly against the target survivor set
  after seed, prune, coverage-prune, minimize, absorb, and run discovery paths.
- [x] `harness_smoke` records the qualified harness id and execution settings,
  keeping smoke findings attributable to the correct target.
- [x] Parse terminal AFL++ coverage and crash metrics from the run-local
  `out/default/fuzzer_stats`; stdout parsing remains live telemetry only.
- [x] Triage minimizes supported AFL++ and libFuzzer crashes through the bounded
  sandbox path, stages minimized artifacts safely, and records the resulting
  `Crash.minimized` evidence without following untrusted symlinks.
- [x] Prompt-protocol agent tool results use provider-compatible user messages;
  strict OpenAI-compatible relays no longer receive an orphan `tool` message.
- [x] Make chat turns and rollback durable across display/context transcripts,
  metadata, and checkpoints; mutation failures now propagate instead of being
  reported as successful responses.
- [x] Serialize rollback, branch, and delete through the same per-session lock
  as model turns and render the canonical backend transcript after mutation.
- [x] Make scheduler restart recovery bounded and non-blocking, restore
  persisted `last_fire`, and make `MissedPolicy::Skip` advance without firing.
- [x] Track scheduler campaign task handles through stop/cancel and account
  completed iterations and actual fuzz duration.
- [x] Make the service-owned run WAL the sole recovery state model, serialize
  writers that share a path, fsync/atomically compact it, and surface sticky
  durability failures before new execution starts.

### REST/web parity
- [x] REST can start, observe, and cancel exact user-space fuzz runs through
  durable run ids, run-scoped status, and fed SSE progress/status events.
  Syzkaller remains intentionally limited to the trusted local desktop workflow
  because its kernel, rootfs, SSH, and VM inputs require a stronger boundary.
- [x] Apply an origin-bounded `CorsLayer` in web mode and send the configured
  bearer token from both frontend HTTP and SSE transports.
- [x] REST maps `ClassifiedError` categories consistently to 4xx/5xx responses,
  including validation, provider, sandbox, timeout, and storage failures.
- [x] Canonicalize and bound REST discovery/knowledge paths to the configured
  workspace before host filesystem access or snippet return.

### Config knobs that silently no-op
- [x] Remove the inert engines/runtime/guardrails/storage/session/tools config
  sections from templates, APIs, and Settings rather than presenting controls
  that do not affect runtime behavior.
- [x] Provider `cost_per_1k_input/output` reaches `ProviderMetadata`, so
  `CostOptimized` routing compares configured costs instead of falling back to
  provider order.
- [x] Scheduler concurrency/hourly policies, recovery, timezone-aware cron, and
  history retention are enforced. CLI, web, and desktop startup and mutations
  use fallible scheduler APIs; missing web schedule ids return 404.
- [x] Effective knowledge strategy, score threshold, weights, and chunk limits
  reach retrieval; unsupported semantic-only retrieval is rejected until an
  embedding pipeline exists. Supported session settings reach the session
  manager, and inert session controls were removed.
- [x] CI-gate orchestration lives in `ServiceContainer::run_ci_gate`; the CLI is
  a thin renderer and no longer mutates `HF_GUARDRAILS` to run the pipeline.

### Data / schema
- [x] Unified `hf-storage` on `Store::connect` plus forward-only
  `migrations/*.sql`; session and checkpoint tests now exercise the production
  schema path, and the destructive test-only schema initializer was removed.
- [x] `DATABASE_SCHEMA.md` documents run statistics and ancillary persistence
  tables and is verified against the production migration path.
- [x] Crash history queries have deterministic newest-first ordering matching
  their API contract.
- [x] Authoritative storage reads propagate typed failures instead of rendering
  database errors as empty data. Bootstrap recovery also logs unrepairable run
  ids and failed interrupted-run status repairs while retaining WAL evidence.
- [x] Persist schedules and campaign budget state with locked atomic replace,
  file and parent-directory fsync, and explicit corrupt-state errors.

### Unwired subsystems (decide: roadmap or remove)
- [x] Remove the unreachable high-risk tool registrar and its shell/file/task/
  loop/workflow prototypes; the live agent catalog now contains only registered
  inspection tools plus service-backed knowledge search.
- [x] Remove the zero-consumer `hf-bot` scaffold and the duplicate `hf-journal`
  state model; the service-owned durable WAL is the sole run-recovery journal.
- [x] Removed the zero-consumer MCP, hook, diagnostics, per-tool rate-limit, and
  provider scheduling/lease prototypes while retaining live observability and
  provider behavior.
- [x] Knowledge dedup uses complete content and chunk identities instead of a
  100-character prefix and an unwritten section index.
- [x] Cron evaluation preserves configured timezones through trigger evaluation
  and calendar/DST-aware restart recovery.
- [x] `providers.example.toml` uses the current supported Anthropic model
  example rather than the retired id.
