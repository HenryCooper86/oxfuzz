# Database Schema

Status: **implemented**. Scope: `hf-storage` and `hf-diagnostics`.

## 1. Storage and migration ownership

SQLite is embedded through `sqlx`. `Store::connect` uses `HF_DB_PATH` when
configured and otherwise opens `data/oxfuzz.db`. It creates the parent
directory and database when needed, then applies the forward-only migrations
in `crates/hf-storage/migrations/`.

The migrations are the schema source of truth. Applied migration files are
immutable because `sqlx` records their checksums. Schema changes therefore use
a new numbered migration rather than editing an existing file.

The fuzzing-domain tables `targets`, `harnesses`, `crashes`, and
`corpus_entries` contain query columns plus `data_json`, which holds the full
serialized `hf-core` model. `runs` is reconstructed from its typed columns and
does not contain `data_json`. Infrastructure tables use the storage strategy
listed in their individual sections below.

## 2. Fuzzing-domain tables

### `runs`

| column | SQLite declaration | notes |
| --- | --- | --- |
| `id` | `TEXT PRIMARY KEY` | UUID |
| `project_root` | `TEXT NOT NULL` | |
| `engine` | `TEXT NOT NULL` | |
| `status` | `TEXT NOT NULL` | pending/running/done/failed/cancelled |
| `started_at` | `TEXT NOT NULL` | RFC 3339 |
| `ended_at` | `TEXT` | nullable |
| `config_json` | `TEXT` | nullable serialized `FuzzRunConfig` |
| `edges` | `INTEGER` | nullable terminal peak edge count |
| `execs` | `REAL` | nullable terminal executions/second |
| `crash_count` | `INTEGER` | nullable terminal crash count |
| `samples_json` | `TEXT` | nullable serialized run samples |
| `harness_rev` | `TEXT` | nullable SHA-256 of approved harness source |
| `harness_source` | `TEXT` | nullable source used by the run |
| `binary_rev` | `TEXT` | nullable SHA-256 of the staged executable |
| `evidence_dir` | `TEXT` | nullable workspace-relative evidence directory |
| `run_kind` | `TEXT NOT NULL DEFAULT 'campaign'` | campaign/smoke |
| `context_rev` | `TEXT` | nullable SHA-256 of source/corpus/runtime context |
| `source_rev` | `TEXT` | nullable SHA-256 of staged target-source inputs |
| `corpus_rev` | `TEXT` | nullable SHA-256 of the starting corpus snapshot |
| `sandbox_rev` | `TEXT` | nullable typed exact identity, `docker-image-id-sha256:<digest>`; legacy untyped values are not proof-bearing |

Indexes: `idx_runs_project(project_root)`, `idx_runs_status(status)`.

### `automotive_operations`

| column | SQLite declaration | notes |
| --- | --- | --- |
| `id` | `TEXT PRIMARY KEY` | service-owned UUID |
| `project_root` | `TEXT NOT NULL` | canonical project root |
| `operation` | `TEXT NOT NULL` | capability/analyze/plan/session/replay/minimize/promotion operation |
| `mode` | `TEXT NOT NULL` | offline_pcap/virtual_can/physical_bench |
| `protocol` | `TEXT` | nullable primary protocol |
| `status` | `TEXT NOT NULL` | running/done/failed/cancelled |
| `started_at` | `TEXT NOT NULL` | RFC 3339 |
| `ended_at` | `TEXT` | nullable terminal timestamp |
| `request_hash` | `TEXT NOT NULL` | canonical request SHA-256 |
| `transcript_hash` | `TEXT` | nullable JSONL transcript SHA-256 |
| `artifact_dir` | `TEXT NOT NULL` | workspace-relative evidence directory |
| `approval_json` | `TEXT` | nullable serialized approval evidence |
| `result_json` | `TEXT` | nullable serialized domain result/state findings |
| `error` | `TEXT` | nullable sanitized failure reason |

Indexes: `idx_automotive_operations_project(project_root, started_at DESC)`,
`idx_automotive_operations_status(status)`.

### `automotive_state_corpus`

This table retains protocol-state novelty evidence separately from source
coverage corpus entries.

| column | SQLite declaration | notes |
| --- | --- | --- |
| `project_root` | `TEXT NOT NULL` | canonical project root |
| `protocol` | `TEXT NOT NULL` | stable automotive protocol id |
| `state_digest` | `TEXT NOT NULL` | validated protocol-state SHA-256 |
| `artifact_sha256` | `TEXT NOT NULL` | digest of retained artifact bytes |
| `source_operation_id` | `TEXT NOT NULL` | completed automotive operation UUID |
| `artifact_path` | `TEXT NOT NULL` | workspace-relative digest-addressed copy |
| `created_at` | `TEXT NOT NULL` | RFC 3339 first-promotion timestamp |

Primary key: `(project_root, protocol, state_digest, artifact_sha256)`.
Foreign key: `source_operation_id -> automotive_operations(id)`.
Indexes: `idx_automotive_state_corpus_project(project_root, created_at DESC)`,
`idx_automotive_state_corpus_state(protocol, state_digest)`.

### `automotive_consumed_approvals`

Single-use ledger for physical-bench approvals. The service claims an approval
by inserting its id here before running the sidecar; the primary key makes a
second claim of the same id fail atomically, so one human approval authorizes at
most one physical transmission even within its freshness window.

| column | SQLite declaration | notes |
| --- | --- | --- |
| `approval_id` | `TEXT PRIMARY KEY` | operator-issued approval id (single-use) |
| `scope_sha256` | `TEXT NOT NULL` | plan/budget scope hash the approval covered |
| `operation_id` | `TEXT NOT NULL` | automotive operation UUID that claimed it |
| `project_root` | `TEXT NOT NULL` | project the operation ran under (retention) |
| `consumed_at` | `TEXT NOT NULL` | RFC 3339 claim timestamp |

Primary key: `approval_id`.
Index: `idx_automotive_consumed_approvals_project(project_root)`.
Cleared for a project by `delete_project` and globally by `clear_knowledge`.

### `targets`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `project_root` | `TEXT NOT NULL` |
| `symbol` | `TEXT NOT NULL` |
| `language` | `TEXT NOT NULL` |
| `fit_score` | `REAL NOT NULL` |
| `rationale` | `TEXT NOT NULL` |
| `discovered_at` | `TEXT NOT NULL` |
| `data_json` | `TEXT NOT NULL` |
| `file` | `TEXT NOT NULL DEFAULT ''` |

Indexes: `idx_targets_project(project_root)`; unique
`idx_targets_project_symbol_file(project_root, symbol, file)`. The `file`
column is the defining file relative to `project_root` (added and backfilled
from `data_json` by migration 0019); the triple is the persistence identity of
a target. Legacy rows whose file could not be backfilled keep `''` and remain
valid.

### `harnesses`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `target_id` | `TEXT NOT NULL` |
| `engine` | `TEXT NOT NULL` |
| `source` | `TEXT NOT NULL` |
| `status` | `TEXT NOT NULL` |
| `smoke_run_json` | `TEXT` |
| `data_json` | `TEXT NOT NULL` |

Index: `idx_harnesses_target(target_id)`. `target_id` is a logical reference;
the migration does not declare a SQL foreign key.

### `harness_approvals`

Durable human-promotion provenance for proof-carrying campaign evidence. The
service writes the approval and promoted harness state in one transaction.

| column | SQLite declaration | notes |
| --- | --- | --- |
| `id` | `TEXT PRIMARY KEY` | service-owned approval UUID |
| `harness_id` | `TEXT NOT NULL` | exact promoted harness |
| `source_sha256` | `TEXT NOT NULL` | smoke-qualified source revision |
| `binary_sha256` | `TEXT NOT NULL` | smoke-qualified binary revision |
| `approval_kind` | `TEXT NOT NULL` | `clean_smoke` or `known_findings` |
| `approved_at` | `TEXT NOT NULL` | RFC 3339 human approval time |

Unique key: `(harness_id, source_sha256, binary_sha256, approval_kind)`.
Index: `idx_harness_approvals_harness(harness_id, approved_at DESC)`. Harness
ids are logical references so historical approval evidence remains readable if
other project data is cleaned independently.

### `crashes`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `run_id` | `TEXT NOT NULL` |
| `target_id` | `TEXT NOT NULL` |
| `stack_signature` | `TEXT NOT NULL` |
| `kind` | `TEXT NOT NULL` |
| `summary` | `TEXT NOT NULL` |
| `minimized` | `INTEGER NOT NULL` |
| `bug_report_json` | `TEXT` |
| `data_json` | `TEXT NOT NULL` |

Indexes: `idx_crashes_run(run_id)`, `idx_crashes_target(target_id)`. `run_id`
and `target_id` are logical references; the migration does not declare SQL
foreign keys. The cross-run list uses SQLite row insertion order because the
model has no creation timestamp.

### `corpus_entries`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `target_id` | `TEXT NOT NULL` |
| `sha256` | `TEXT NOT NULL` |
| `size` | `INTEGER NOT NULL` |
| `source` | `TEXT NOT NULL` |
| `coverage_hash` | `TEXT` |
| `data_json` | `TEXT NOT NULL` |

Indexes: `idx_corpus_target(target_id)` and unique
`idx_corpus_target_sha(target_id, sha256)`. `target_id` is a logical reference;
the migration does not declare a SQL foreign key.

Corpus persistence is reconciled transactionally per target. Rows absent from
the latest on-disk snapshot are deleted, while retained rows preserve known
source and coverage metadata when a filesystem rescan can classify them only
as manual. Single-entry deletion is keyed by both target and hash.

## 3. Conversation and session tables

### `sessions`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `parent_id` | `TEXT` |
| `title` | `TEXT` |
| `created_at` | `TEXT NOT NULL` |

### `messages`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `session_id` | `TEXT NOT NULL` |
| `seq` | `INTEGER NOT NULL` |
| `role` | `TEXT NOT NULL` |
| `content` | `TEXT NOT NULL` |
| `created_at` | `TEXT NOT NULL` |

Index: `idx_messages_session(session_id, seq)`.

### `session_metadata`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `parent_id` | `TEXT REFERENCES session_metadata(id)` |
| `root_id` | `TEXT NOT NULL REFERENCES session_metadata(id)` |
| `depth` | `INTEGER NOT NULL DEFAULT 0` |
| `path` | `TEXT NOT NULL` |
| `session_type` | `TEXT NOT NULL` | checked: main/child/branch/ephemeral/sub_agent/canonical |
| `state` | `TEXT NOT NULL DEFAULT 'active'` | checked: active/paused/archived/merged/tombstone |
| `agent_id` | `TEXT` |
| `title` | `TEXT` |
| `manual_title` | `TEXT` |
| `token_count` | `INTEGER NOT NULL DEFAULT 0` |
| `message_count` | `INTEGER NOT NULL DEFAULT 0` |
| `transcript_path` | `TEXT NOT NULL` |
| `channel` | `TEXT` |
| `label` | `TEXT` |
| `last_compaction` | `TEXT` |
| `compaction_count` | `INTEGER NOT NULL DEFAULT 0` |
| `context_reset_index` | `INTEGER` |
| `custom_system_prompt` | `TEXT` |
| `created_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |
| `updated_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |

Indexes: `idx_session_parent(parent_id)`, `idx_session_root(root_id)`,
`idx_session_state(state)`.

### `chat_checkpoints`

| column | SQLite declaration |
| --- | --- |
| `checkpoint_id` | `TEXT PRIMARY KEY` |
| `session_id` | `TEXT NOT NULL` |
| `turn_number` | `INTEGER NOT NULL` |
| `message_count_before` | `INTEGER NOT NULL` |
| `journal_scope_id` | `TEXT NOT NULL` | retained checkpoint field; not a SQL reference |
| `invalidated` | `INTEGER NOT NULL DEFAULT 0` |
| `created_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |

Constraints/indexes: unique `(session_id, turn_number)` and
`idx_chat_cp_session(session_id, turn_number DESC)`.

## 4. Diagnostics tables

### `diag_traces`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `session_id` | `TEXT NOT NULL` |
| `name` | `TEXT NOT NULL` |
| `status` | `TEXT NOT NULL DEFAULT 'active'` |
| `user_input` | `TEXT` |
| `metadata` | `TEXT NOT NULL DEFAULT 'null'` |
| `tags` | `TEXT NOT NULL DEFAULT '[]'` |
| `replay_context` | `TEXT` |
| `started_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |
| `completed_at` | `TEXT` |
| `total_input_tokens` | `INTEGER NOT NULL DEFAULT 0` |
| `total_output_tokens` | `INTEGER NOT NULL DEFAULT 0` |
| `total_cost_usd` | `REAL NOT NULL DEFAULT 0.0` |
| `llm_duration_ms` | `INTEGER NOT NULL DEFAULT 0` |
| `tool_duration_ms` | `INTEGER NOT NULL DEFAULT 0` |

Index: `idx_diag_traces_session(session_id, started_at DESC)`.

### `diag_observations`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `trace_id` | `TEXT NOT NULL REFERENCES diag_traces(id) ON DELETE CASCADE` |
| `parent_id` | `TEXT` |
| `session_id` | `TEXT` |
| `obs_type` | `TEXT NOT NULL` |
| `name` | `TEXT NOT NULL` |
| `status` | `TEXT NOT NULL DEFAULT 'running'` |
| `model` | `TEXT` |
| `input_tokens` | `INTEGER NOT NULL DEFAULT 0` |
| `output_tokens` | `INTEGER NOT NULL DEFAULT 0` |
| `cost_usd` | `REAL NOT NULL DEFAULT 0.0` |
| `input` | `TEXT NOT NULL DEFAULT 'null'` |
| `output` | `TEXT NOT NULL DEFAULT 'null'` |
| `metadata` | `TEXT NOT NULL DEFAULT 'null'` |
| `sequence` | `INTEGER NOT NULL DEFAULT 0` |
| `depth` | `INTEGER NOT NULL DEFAULT 0` |
| `path` | `TEXT NOT NULL DEFAULT '[]'` |
| `error_message` | `TEXT` |
| `started_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |
| `completed_at` | `TEXT` |

Index: `idx_diag_obs_trace(trace_id, sequence ASC)`.

### `diag_scores`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `trace_id` | `TEXT NOT NULL REFERENCES diag_traces(id) ON DELETE CASCADE` |
| `observation_id` | `TEXT REFERENCES diag_observations(id) ON DELETE CASCADE` |
| `name` | `TEXT NOT NULL` |
| `value` | `REAL NOT NULL DEFAULT 0.0` |
| `data_type` | `TEXT NOT NULL DEFAULT 'numeric'` |
| `string_value` | `TEXT` |
| `comment` | `TEXT` |
| `source` | `TEXT NOT NULL DEFAULT 'system'` |
| `created_at` | `TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))` |

Indexes: `idx_diag_scores_trace(trace_id)`,
`idx_diag_scores_obs(observation_id)`.

## 5. Scheduler and policy tables

### `schedule_executions`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `schedule_id` | `TEXT NOT NULL` |
| `triggered_at` | `TEXT NOT NULL` |
| `status` | `TEXT NOT NULL DEFAULT 'pending'` |
| `data_json` | `TEXT NOT NULL` | serialized schedule execution |

Indexes: `idx_sched_exec_time(triggered_at DESC)`,
`idx_sched_exec_schedule(schedule_id)`. Retention pruning is schedule-scoped
and orders rows by `triggered_at DESC, id DESC` for deterministic ties. It
never removes pending/running records or records whose serialized `started_at`
is still inside the rolling one-hour admission window. Hourly counts likewise
read the serialized `started_at`; trigger time is not a substitute for a real
execution start.

### `project_settings`

| column | SQLite declaration |
| --- | --- |
| `project_root` | `TEXT PRIMARY KEY` |
| `auto_revert_enabled` | `INTEGER NOT NULL` |
| `auto_revert_threshold_pct` | `REAL NOT NULL` |
| `auto_revert_notify_only` | `INTEGER NOT NULL` |

### `auto_revert_events`

| column | SQLite declaration |
| --- | --- |
| `id` | `TEXT PRIMARY KEY` |
| `ts` | `TEXT NOT NULL` |
| `project_root` | `TEXT NOT NULL` |
| `target` | `TEXT NOT NULL` |
| `run_id` | `TEXT NOT NULL` |
| `from_rev` | `TEXT NOT NULL` |
| `to_rev` | `TEXT NOT NULL` |
| `previous_edges` | `INTEGER NOT NULL` |
| `regressed_edges` | `INTEGER NOT NULL` |
| `drop_pct` | `REAL NOT NULL` |
| `reverted` | `INTEGER NOT NULL` |

Indexes: `idx_auto_revert_events_ts(ts DESC)`,
`idx_auto_revert_events_project(project_root)`.

### `guardrail_decisions`

Durable audit trail of guardrail authorization decisions. Every authorizing
service entry point appends one row per authorization: the policy outcome, and
the human approval outcome where the gate was consulted. Recording is
best-effort (a storage failure is logged and never changes the authorization
outcome), and the service prunes the table to a bounded newest window on write.
It is deliberately not cleared by `clear_knowledge`/`delete_project`: an
authorization audit trail must survive project data cleanup.

| column | SQLite declaration | notes |
| --- | --- | --- |
| `id` | `TEXT PRIMARY KEY` | UUID |
| `decided_at` | `TEXT NOT NULL` | RFC 3339 |
| `action` | `TEXT NOT NULL` | action kind: discover/draft_harness/compile_harness/run_harness/run_fuzzer/automotive_offline/automotive_virtual_can/automotive_physical_bench/triage/corpus_op/chat |
| `risk_tier` | `TEXT NOT NULL` | low/medium/high/critical |
| `decision` | `TEXT NOT NULL` | allowed/denied/approved/denied_by_operator |
| `origin` | `TEXT NOT NULL` | service entry point that authorized |
| `project` | `TEXT` | nullable project root |
| `detail` | `TEXT` | nullable policy reason (bounded length) |

Index: `idx_guardrail_decisions_ts(decided_at DESC)`.

## 6. Migration inventory

| migration | schema effect |
| --- | --- |
| `0001_init.sql` | creates runs, targets, harnesses, crashes, corpus entries |
| `0002_sessions.sql` | creates sessions and messages |
| `0003_diagnostics.sql` | creates diagnostic traces, observations, and scores |
| `0004_schedule_executions.sql` | creates schedule execution history |
| `0005_session_metadata.sql` | creates session tree metadata |
| `0006_chat_checkpoints.sql` | creates durable chat checkpoints |
| `0007_run_stats.sql` | adds run edge/throughput/crash totals |
| `0008_run_samples.sql` | adds run sample history |
| `0009_run_harness_rev.sql` | adds approved harness digest |
| `0010_run_harness_source.sql` | adds the run's harness source |
| `0011_project_settings.sql` | creates per-project auto-revert settings |
| `0012_auto_revert_events.sql` | creates the auto-revert audit trail |
| `0013_run_evidence.sql` | adds binary, evidence, run-kind, and context fields |
| `0014_automotive_operations.sql` | creates durable automotive operation evidence |
| `0015_automotive_state_corpus.sql` | creates protocol-state corpus promotion evidence |
| `0016_targets_unique.sql` | collapses duplicate targets and adds `UNIQUE(project_root, symbol)` |
| `0017_automotive_consumed_approvals.sql` | creates the single-use physical-bench approval ledger |
| `0018_guardrail_decisions.sql` | creates the guardrail authorization audit trail |
| `0019_targets_file_scoped_identity.sql` | adds and backfills `targets.file`; replaces the unique index with `UNIQUE(project_root, symbol, file)` |
| `0020_harness_approvals.sql` | creates atomic, digest-bound human harness-promotion provenance |
| `0021_run_provenance_components.sql` | adds independently verifiable source, corpus, and sandbox-reference digests to runs |

## 7. Read failure contract

An unconfigured optional store may produce an explicitly documented empty or
unavailable view. Once a store is configured, a SQL, pool, or deserialization
failure is never converted into a successful empty collection.

Service APIs with a fallible presentation boundary return
`ClassifiedError::Storage`. Composite views abort instead of combining defaults
with partial database state. CLI, REST, and Tauri adapters translate that error
without re-reading storage or inventing substitute data. Best-effort internal
maintenance may continue only when it emits a structured error and its result
cannot be mistaken for an authoritative persisted-data view.

## 8. Write failure contract

Once a store is configured, a required evidence write is part of the service
operation's success condition. Target inventories, harness revisions,
qualification state, runs, crashes, corpus state, and operator-visible audit
records must propagate `ClassifiedError::Storage` when the write fails.

Filesystem state that refers to a database identifier is committed after the
database record, or restored to its prior value if a later step fails. A service
method must not return an authoritative model that the configured store rejected.
Optional stores may remain absent, but a present broken store is never treated as
if persistence were disabled.
