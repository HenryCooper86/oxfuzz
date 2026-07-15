-- Durable evidence for sandboxed automotive protocol operations. Protocol and
-- result details remain JSON/domain-owned; query and lifecycle fields stay
-- typed so interrupted, failed, and completed work is distinguishable.
CREATE TABLE IF NOT EXISTS automotive_operations (
    id              TEXT PRIMARY KEY,
    project_root    TEXT NOT NULL,
    operation       TEXT NOT NULL,
    mode            TEXT NOT NULL,
    protocol        TEXT,
    status          TEXT NOT NULL CHECK (status IN ('running', 'done', 'failed', 'cancelled')),
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    request_hash    TEXT NOT NULL,
    transcript_hash TEXT,
    artifact_dir    TEXT NOT NULL,
    approval_json   TEXT,
    result_json     TEXT,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_automotive_operations_project
    ON automotive_operations(project_root, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_automotive_operations_status
    ON automotive_operations(status);
