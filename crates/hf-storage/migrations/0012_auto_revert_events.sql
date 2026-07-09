-- Durable audit trail of auto-revert policy firings. The run journal WAL is
-- compacted on startup (only still-open scopes survive), so policy events are
-- persisted here instead, queryable per project and over time. Append-only.
CREATE TABLE IF NOT EXISTS auto_revert_events (
    id              TEXT PRIMARY KEY,
    ts              TEXT    NOT NULL,
    project_root    TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    run_id          TEXT    NOT NULL,
    from_rev        TEXT    NOT NULL,
    to_rev          TEXT    NOT NULL,
    previous_edges  INTEGER NOT NULL,
    regressed_edges INTEGER NOT NULL,
    drop_pct        REAL    NOT NULL,
    -- 1 = the harness was restored (applied); 0 = notify-only (flagged, not restored).
    reverted        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auto_revert_events_ts
    ON auto_revert_events(ts DESC);

CREATE INDEX IF NOT EXISTS idx_auto_revert_events_project
    ON auto_revert_events(project_root);
