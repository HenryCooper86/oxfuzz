-- Persisted scheduler execution history, so the Automation view's "Recent
-- Runs" survive app restarts. The full ScheduleExecution is stored as JSON in
-- data_json; the indexed columns drive ordering and per-schedule lookups.

CREATE TABLE IF NOT EXISTS schedule_executions (
    id           TEXT PRIMARY KEY,
    schedule_id  TEXT NOT NULL,
    triggered_at TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    data_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sched_exec_time
    ON schedule_executions(triggered_at DESC);

CREATE INDEX IF NOT EXISTS idx_sched_exec_schedule
    ON schedule_executions(schedule_id);
