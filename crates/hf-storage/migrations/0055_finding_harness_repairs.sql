-- Retains each finding-driven harness repair request before provider dispatch,
-- and its response and outcome once it finishes (Engineering Protocol 2.13).
-- The prompt carries the harness source and the crash evidence, so the exact
-- text is kept rather than rebuilt.
--
-- `harness_id` names the compiled proposal revision. It is not a foreign key:
-- a proposal record stays readable after its revision is pruned.
CREATE TABLE finding_harness_repairs (
    id TEXT PRIMARY KEY,
    crash_id TEXT NOT NULL REFERENCES crashes(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    prompt_version INTEGER NOT NULL CHECK (prompt_version >= 1),
    base_source_sha256 TEXT NOT NULL CHECK (length(base_source_sha256) = 64),
    prompt TEXT NOT NULL CHECK (length(CAST(prompt AS BLOB)) <= 65536),
    response TEXT CHECK (response IS NULL OR length(CAST(response AS BLOB)) <= 65536),
    outcome TEXT CHECK (outcome IS NULL OR outcome IN ('proposed', 'unchanged', 'rejected', 'failed')),
    detail TEXT CHECK (detail IS NULL OR length(CAST(detail AS BLOB)) <= 4096),
    harness_id TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK ((outcome IS NULL) = (completed_at IS NULL)),
    CHECK ((outcome IS NULL) = (detail IS NULL)),
    CHECK ((outcome IS 'proposed') = (harness_id IS NOT NULL))
);
CREATE INDEX idx_finding_harness_repairs_crash
    ON finding_harness_repairs(crash_id, created_at DESC, id DESC);
-- The only permitted update records the outcome of a pending repair once.
CREATE TRIGGER finding_harness_repairs_write_once BEFORE UPDATE ON finding_harness_repairs
WHEN OLD.outcome IS NOT NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.crash_id IS NOT OLD.crash_id
    OR NEW.run_id IS NOT OLD.run_id
    OR NEW.project_root IS NOT OLD.project_root
    OR NEW.prompt_version IS NOT OLD.prompt_version
    OR NEW.base_source_sha256 IS NOT OLD.base_source_sha256
    OR NEW.prompt IS NOT OLD.prompt
    OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'finding harness repair is immutable once finished'); END;
