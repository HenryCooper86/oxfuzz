# Database Schema

Status: **implemented**. Scope: `hf-storage`.

## 1. Storage

SQLite (embedded via `sqlx`). Path from `HF_DB_PATH` (default
`data/hobot_fuzz.db`). The `Store` type opens (creating if missing) the
database and applies forward-only migrations on connect.

Every domain table carries the queryable columns listed below **plus a
`data_json TEXT` column** holding the full serialized `hf-core` model. Queries
that reconstruct a model read `data_json`; the dedicated columns exist for
filtering, sorting, and inspection. This keeps the schema stable while
preserving full-fidelity round-trips as the models evolve.

## 2. Tables

### runs
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| project_root | TEXT | |
| engine | TEXT | |
| status | TEXT | pending/running/done/failed/cancelled |
| started_at | TEXT | ISO8601 |
| ended_at | TEXT | nullable |
| config_json | TEXT | FuzzRunConfig |
| run_kind | TEXT | campaign/smoke; defaults to campaign for legacy rows |
| harness_rev | TEXT | nullable full SHA-256 of approved source |
| binary_rev | TEXT | nullable full SHA-256 of staged executable |
| evidence_dir | TEXT | nullable workspace-relative run output directory |
| context_rev | TEXT | nullable SHA-256 of target sources, starting corpus, and runtime image |

### targets
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| project_root | TEXT | |
| symbol | TEXT | |
| language | TEXT | |
| fit_score | REAL | |
| rationale | TEXT | |
| discovered_at | TEXT | |

### harnesses
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| target_id | TEXT | FK |
| engine | TEXT | |
| source | TEXT | |
| status | TEXT | draft/compiled/smoke_passed/promoted/failed |
| smoke_run_json | TEXT | nullable |

### crashes
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| run_id | TEXT | FK |
| target_id | TEXT | FK |
| stack_signature | TEXT | |
| kind | TEXT | |
| summary | TEXT | |
| minimized | INTEGER | 0/1 |
| bug_report_json | TEXT | nullable |

### corpus_entries
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| target_id | TEXT | FK |
| sha256 | TEXT | |
| size | INTEGER | |
| source | TEXT | seed/fuzzer/minimized/manual |
| coverage_hash | TEXT | nullable |

Corpus persistence is reconciled transactionally per target: rows absent from
the latest on-disk snapshot are deleted, while retained rows keep their known
source and coverage metadata when a filesystem rescan can only classify them as
manual. Single-entry deletion is keyed by both `target_id` and `sha256`; a
matching hash owned by another target is never deleted implicitly.

## 3. Migrations

Migrations live in `crates/hf-storage/migrations/`. Forward-only.
