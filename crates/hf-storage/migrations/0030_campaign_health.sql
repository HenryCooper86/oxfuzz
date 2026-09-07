-- Run-scoped campaign telemetry and durable health-event deduplication.

CREATE TABLE run_telemetry (
    run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL CHECK (typeof(observed_at) = 'text'),
    last_progress_at TEXT CHECK (
        last_progress_at IS NULL OR typeof(last_progress_at) = 'text'
    ),
    samples_json TEXT NOT NULL CHECK (
        typeof(samples_json) = 'text'
        AND json_valid(samples_json)
        AND json_type(samples_json) = 'array'
        AND length(CAST(samples_json AS BLOB)) <= 65536
    ),
    current_execs REAL CHECK (current_execs IS NULL OR current_execs >= 0),
    mean_execs REAL CHECK (mean_execs IS NULL OR mean_execs >= 0),
    peak_execs REAL CHECK (peak_execs IS NULL OR peak_execs >= 0),
    edges INTEGER CHECK (edges IS NULL OR edges >= 0),
    throughput_sample_count INTEGER NOT NULL CHECK (throughput_sample_count >= 0),
    throughput_sample_sum REAL NOT NULL CHECK (throughput_sample_sum >= 0),
    managed_invocations_expected INTEGER NOT NULL CHECK (managed_invocations_expected >= 0),
    managed_invocations_alive INTEGER NOT NULL CHECK (managed_invocations_alive >= 0),
    free_disk_bytes INTEGER CHECK (free_disk_bytes IS NULL OR free_disk_bytes >= 0)
);

CREATE TABLE campaign_health_events (
    id TEXT PRIMARY KEY CHECK (
        typeof(id) = 'text'
        AND length(id) = 36
        AND lower(id) = id
        AND id NOT GLOB '*[^0-9a-f-]*'
        AND length(replace(id, '-', '')) = 32
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    dedup_key TEXT NOT NULL CHECK (
        typeof(dedup_key) = 'text'
        AND length(CAST(dedup_key AS BLOB)) BETWEEN 1 AND 512
    ),
    condition TEXT NOT NULL CHECK (
        condition IN (
            'coverage_plateau', 'managed_invocation_missing',
            'worker_stats_stale', 'disk_pressure', 'run_failed'
        )
    ),
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'error')),
    detail TEXT NOT NULL CHECK (
        typeof(detail) = 'text'
        AND length(CAST(detail AS BLOB)) BETWEEN 1 AND 4096
    ),
    evidence_json TEXT NOT NULL CHECK (
        typeof(evidence_json) = 'text'
        AND json_valid(evidence_json)
        AND json_type(evidence_json) = 'object'
        AND length(CAST(evidence_json AS BLOB)) <= 65536
    ),
    observed_at TEXT NOT NULL CHECK (typeof(observed_at) = 'text'),
    UNIQUE (run_id, condition, dedup_key)
);

CREATE INDEX idx_campaign_health_events_run_observed
    ON campaign_health_events (run_id, observed_at DESC, id DESC);
CREATE INDEX idx_campaign_health_events_observed
    ON campaign_health_events (observed_at);

CREATE TRIGGER campaign_health_events_immutable
BEFORE UPDATE ON campaign_health_events
BEGIN
    SELECT RAISE(ABORT, 'campaign health events are immutable');
END;
