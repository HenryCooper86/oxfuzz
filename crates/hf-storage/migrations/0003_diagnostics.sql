-- Diagnostics: span-based LLM/tool tracing + cost intelligence.
-- Tables consumed by hf-diagnostics::SqliteTraceStore so cost/usage persists
-- across app restarts. Mirrors the diag_* section of the consolidated schema.

CREATE TABLE IF NOT EXISTS diag_traces (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    user_input  TEXT,
    metadata    TEXT NOT NULL DEFAULT 'null',
    tags        TEXT NOT NULL DEFAULT '[]',
    replay_context TEXT,
    started_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT,
    total_input_tokens  INTEGER NOT NULL DEFAULT 0,
    total_output_tokens INTEGER NOT NULL DEFAULT 0,
    total_cost_usd      REAL NOT NULL DEFAULT 0.0,
    llm_duration_ms     INTEGER NOT NULL DEFAULT 0,
    tool_duration_ms    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_diag_traces_session
    ON diag_traces(session_id, started_at DESC);

CREATE TABLE IF NOT EXISTS diag_observations (
    id          TEXT PRIMARY KEY,
    trace_id    TEXT NOT NULL REFERENCES diag_traces(id) ON DELETE CASCADE,
    parent_id   TEXT,
    session_id  TEXT,
    obs_type    TEXT NOT NULL,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    model       TEXT,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd      REAL NOT NULL DEFAULT 0.0,
    input         TEXT NOT NULL DEFAULT 'null',
    output        TEXT NOT NULL DEFAULT 'null',
    metadata      TEXT NOT NULL DEFAULT 'null',
    sequence      INTEGER NOT NULL DEFAULT 0,
    depth         INTEGER NOT NULL DEFAULT 0,
    path          TEXT NOT NULL DEFAULT '[]',
    error_message TEXT,
    started_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_diag_obs_trace
    ON diag_observations(trace_id, sequence ASC);

CREATE TABLE IF NOT EXISTS diag_scores (
    id              TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL REFERENCES diag_traces(id) ON DELETE CASCADE,
    observation_id  TEXT REFERENCES diag_observations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    value           REAL NOT NULL DEFAULT 0.0,
    data_type       TEXT NOT NULL DEFAULT 'numeric',
    string_value    TEXT,
    comment         TEXT,
    source          TEXT NOT NULL DEFAULT 'system',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_diag_scores_trace
    ON diag_scores(trace_id);

CREATE INDEX IF NOT EXISTS idx_diag_scores_obs
    ON diag_scores(observation_id);
