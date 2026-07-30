CREATE TABLE schedule_occurrences (
    id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL UNIQUE,
    execution_id TEXT NOT NULL UNIQUE,
    triggered_at TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('reserved', 'running', 'completed', 'failed', 'cancelled')),
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT,
    recovery_detail TEXT
        CHECK (
            recovery_detail IS NULL
            OR length(CAST(recovery_detail AS BLOB)) <= 4096
        ),
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        (state IN ('reserved', 'running') AND lease_expires_at IS NOT NULL)
        OR
        (state IN ('completed', 'failed', 'cancelled') AND lease_expires_at IS NULL)
    )
);

CREATE INDEX idx_schedule_occurrences_state
    ON schedule_occurrences(state, lease_expires_at, updated_at);
