-- Initial schema for hobot_fuzz persistence.
-- See docs/standards/DATABASE_SCHEMA.md. Forward-only.
--
-- Each domain table carries the queryable columns from the schema spec plus a
-- `data_json` blob holding the full serialized `hf-core` model, so records can
-- be reconstructed losslessly without widening the schema for every field.

CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    engine       TEXT NOT NULL,
    status       TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    ended_at     TEXT,
    config_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_project ON runs (project_root);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs (status);

CREATE TABLE IF NOT EXISTS targets (
    id            TEXT PRIMARY KEY,
    project_root  TEXT NOT NULL,
    symbol        TEXT NOT NULL,
    language      TEXT NOT NULL,
    fit_score     REAL NOT NULL,
    rationale     TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    data_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_targets_project ON targets (project_root);

CREATE TABLE IF NOT EXISTS harnesses (
    id             TEXT PRIMARY KEY,
    target_id      TEXT NOT NULL,
    engine         TEXT NOT NULL,
    source         TEXT NOT NULL,
    status         TEXT NOT NULL,
    smoke_run_json TEXT,
    data_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harnesses_target ON harnesses (target_id);

CREATE TABLE IF NOT EXISTS crashes (
    id              TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    stack_signature TEXT NOT NULL,
    kind            TEXT NOT NULL,
    summary         TEXT NOT NULL,
    minimized       INTEGER NOT NULL,
    bug_report_json TEXT,
    data_json       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_crashes_run ON crashes (run_id);
CREATE INDEX IF NOT EXISTS idx_crashes_target ON crashes (target_id);

CREATE TABLE IF NOT EXISTS corpus_entries (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size          INTEGER NOT NULL,
    source        TEXT NOT NULL,
    coverage_hash TEXT,
    data_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corpus_target ON corpus_entries (target_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_corpus_target_sha
    ON corpus_entries (target_id, sha256);
