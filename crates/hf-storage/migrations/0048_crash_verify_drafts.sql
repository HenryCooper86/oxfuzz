-- Retains each crash-verification request before provider dispatch, and the
-- model's response once it arrives (Engineering Protocol 2.13). The prompt
-- carries the crash classification evidence, so the exact text is kept rather
-- than rebuilt.
--
-- The crash row exists before verification starts (triage persists the
-- classification first), so the cascading foreign key removes drafts only when
-- the crash itself is deleted.
CREATE TABLE crash_verify_drafts (
    id TEXT PRIMARY KEY,
    crash_id TEXT NOT NULL REFERENCES crashes(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    prompt TEXT NOT NULL CHECK (length(CAST(prompt AS BLOB)) <= 65536),
    response TEXT CHECK (response IS NULL OR length(CAST(response AS BLOB)) <= 65536),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK ((response IS NULL) = (completed_at IS NULL))
);
CREATE INDEX idx_crash_verify_drafts_crash
    ON crash_verify_drafts(crash_id, created_at DESC, id DESC);
-- The only permitted update records the response of a pending draft once.
CREATE TRIGGER crash_verify_drafts_write_once BEFORE UPDATE ON crash_verify_drafts
WHEN OLD.response IS NOT NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.crash_id IS NOT OLD.crash_id
    OR NEW.run_id IS NOT OLD.run_id
    OR NEW.project_root IS NOT OLD.project_root
    OR NEW.prompt IS NOT OLD.prompt
    OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'crash verify draft is immutable once answered'); END;
