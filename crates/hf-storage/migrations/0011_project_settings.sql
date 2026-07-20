-- Per-project override of the global auto-revert policy. A row here fully
-- specifies the policy for one project (identified by its root path); when no
-- row exists, the project inherits the global policy from oxfuzz.toml.
-- Clearing an override deletes the row (back to inherit). Forward-only.
CREATE TABLE IF NOT EXISTS project_settings (
    project_root              TEXT PRIMARY KEY,
    auto_revert_enabled       INTEGER NOT NULL,
    auto_revert_threshold_pct REAL    NOT NULL,
    auto_revert_notify_only   INTEGER NOT NULL
);
