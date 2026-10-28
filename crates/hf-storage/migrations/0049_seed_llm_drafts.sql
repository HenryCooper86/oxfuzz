-- Retains each seed-drafting request before provider dispatch, and the
-- model's response once it arrives (Engineering Protocol 2.13). The prompt
-- names the target's own definition, the harness entry gate, the corpus seeds
-- that already exist, the dead seeds being replaced, and the measured
-- coverage frontier, so the exact text is kept rather than rebuilt.
--
-- `purpose` separates first-time seeding from survival-driven regeneration:
-- the two prompts carry different sections and are audited apart. There is no
-- crash or run foreign key because seeding happens outside run records;
-- project deletion and clear_knowledge delete the rows by project_root.
CREATE TABLE seed_llm_drafts (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    target TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('initial', 'regenerate')),
    prompt_version INTEGER NOT NULL CHECK (prompt_version >= 1),
    prompt TEXT NOT NULL CHECK (length(CAST(prompt AS BLOB)) <= 65536),
    response TEXT CHECK (response IS NULL OR length(CAST(response AS BLOB)) <= 65536),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK ((response IS NULL) = (completed_at IS NULL))
);
CREATE INDEX idx_seed_llm_drafts_project
    ON seed_llm_drafts(project_root, target, created_at DESC, id DESC);
-- The only permitted update records the response of a pending draft once.
CREATE TRIGGER seed_llm_drafts_write_once BEFORE UPDATE ON seed_llm_drafts
WHEN OLD.response IS NOT NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.project_root IS NOT OLD.project_root
    OR NEW.target IS NOT OLD.target
    OR NEW.purpose IS NOT OLD.purpose
    OR NEW.prompt_version IS NOT OLD.prompt_version
    OR NEW.prompt IS NOT OLD.prompt
    OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'seed draft is immutable once answered'); END;
