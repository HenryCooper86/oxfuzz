-- Retains each dictionary-augmentation request before provider dispatch, and
-- the model's response once it arrives (Engineering Protocol 2.13). The prompt
-- names the target's own definition and the tokens the static dictionary
-- already contains, so the exact text is kept rather than rebuilt.
--
-- Rows are keyed by (project_root, target, static_dict_sha256): the latest
-- completed draft for that triple is reused without a provider call, so each
-- static dictionary version is proposed at most once. There is no crash or
-- run foreign key because augmentation happens during pre-run staging;
-- project deletion and clear_knowledge delete the rows by project_root.
CREATE TABLE dictionary_llm_drafts (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    target TEXT NOT NULL,
    static_dict_sha256 TEXT NOT NULL CHECK (length(static_dict_sha256) = 64),
    prompt TEXT NOT NULL CHECK (length(CAST(prompt AS BLOB)) <= 65536),
    response TEXT CHECK (response IS NULL OR length(CAST(response AS BLOB)) <= 65536),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK ((response IS NULL) = (completed_at IS NULL))
);
CREATE INDEX idx_dictionary_llm_drafts_reuse
    ON dictionary_llm_drafts(project_root, target, static_dict_sha256, created_at DESC, id DESC);
-- The only permitted update records the response of a pending draft once.
CREATE TRIGGER dictionary_llm_drafts_write_once BEFORE UPDATE ON dictionary_llm_drafts
WHEN OLD.response IS NOT NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.project_root IS NOT OLD.project_root
    OR NEW.target IS NOT OLD.target
    OR NEW.static_dict_sha256 IS NOT OLD.static_dict_sha256
    OR NEW.prompt IS NOT OLD.prompt
    OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'dictionary draft is immutable once answered'); END;
