# Database Schema

Status: **draft**. Scope: `hf-storage`.

## 1. Storage

SQLite (embedded via `sqlx`). Path from `HF_DB_PATH` (default
`data/hobot_fuzz.db`).

## 2. Tables

### runs
| column | type | notes |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| project_root | TEXT | |
| engine | TEXT | |
| status | TEXT | pending/running/done/failed |
| started_at | TEXT | ISO8601 |
| ended_at | TEXT | nullable |
| config_json | TEXT | FuzzRunConfig |

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

## 3. Migrations

Migrations live in `crates/hf-storage/migrations/`. Forward-only.