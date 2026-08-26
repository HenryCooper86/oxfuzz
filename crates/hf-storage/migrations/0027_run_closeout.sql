-- Per-run closeout step outcomes, so an interrupted closeout resumes at the
-- first non-terminal step instead of repeating the expensive corpus replay that
-- coverage measurement performs.
--
-- Not stored in the run WAL: that journal is compacted on open to the still-open
-- run events, so notes against a finished run would not survive a restart, and a
-- finished run is exactly what closeout operates on.
--
-- `outcome` is one of 'completed', 'skipped', 'failed'. Completed and skipped
-- are terminal; a failed step is retried by a later closeout. Forward-only.
CREATE TABLE IF NOT EXISTS run_closeout_steps (
    run_id      TEXT NOT NULL,
    step        TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (run_id, step)
);

CREATE INDEX IF NOT EXISTS idx_run_closeout_steps_run
    ON run_closeout_steps (run_id);
