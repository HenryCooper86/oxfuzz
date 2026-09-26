CREATE TABLE ai_discovery_operations (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    language TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('scanning', 'ranking', 'completed', 'failed', 'cancelled', 'interrupted')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 2),
    scan_json TEXT,
    assessment_json TEXT,
    source TEXT NOT NULL DEFAULT 'pending' CHECK (source IN ('pending', 'ai', 'mixed', 'heuristic')),
    reason_code TEXT,
    total_count INTEGER NOT NULL DEFAULT 0,
    assessed_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    scanned_at TEXT,
    ended_at TEXT
);

CREATE INDEX ai_discovery_project_idx ON ai_discovery_operations(project_root, started_at DESC);

CREATE TABLE ai_rank_batches (
    operation_id TEXT NOT NULL REFERENCES ai_discovery_operations(id) ON DELETE CASCADE,
    batch_index INTEGER NOT NULL,
    prompt TEXT NOT NULL,
    provider_model TEXT NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'pending',
    assessment_json TEXT,
    PRIMARY KEY(operation_id, batch_index)
);
