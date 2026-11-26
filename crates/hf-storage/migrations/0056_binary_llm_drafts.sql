-- Retains each binary-only-fuzzing model prompt (seed drafting, dictionary
-- drafting, crash explanation) before provider dispatch, and the model's
-- response once it arrives (Engineering Protocol 2.13). The prompt carries
-- disassembly, strings, and crash evidence of an untrusted binary, so the
-- exact text is kept rather than rebuilt.
--
-- `purpose = 'explain'` rows are keyed by (project_root, session,
-- finding_sha256) so the latest completed explanation of a finding is shown
-- without another provider call; the other purposes carry neither. There is
-- no run or crash foreign key: a binary session and its findings are file
-- based, and the rows are keyed by the binary's own SHA-256.
CREATE TABLE binary_llm_drafts (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    binary_sha256 TEXT NOT NULL CHECK (length(binary_sha256) = 64),
    purpose TEXT NOT NULL CHECK (purpose IN ('seeds', 'dictionary', 'explain')),
    session TEXT,
    finding_sha256 TEXT CHECK (finding_sha256 IS NULL OR length(finding_sha256) = 64),
    prompt_version INTEGER NOT NULL CHECK (prompt_version >= 1),
    prompt TEXT NOT NULL CHECK (length(CAST(prompt AS BLOB)) <= 65536),
    response TEXT CHECK (response IS NULL OR length(CAST(response AS BLOB)) <= 65536),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK ((response IS NULL) = (completed_at IS NULL)),
    CHECK ((purpose = 'explain' AND session IS NOT NULL AND finding_sha256 IS NOT NULL)
        OR (purpose <> 'explain' AND session IS NULL AND finding_sha256 IS NULL))
);
CREATE INDEX idx_binary_llm_drafts_explain
    ON binary_llm_drafts(project_root, session, finding_sha256, created_at DESC, id DESC);
-- The only permitted update records the response of a pending draft once.
CREATE TRIGGER binary_llm_drafts_write_once BEFORE UPDATE ON binary_llm_drafts
WHEN OLD.response IS NOT NULL
    OR NEW.id IS NOT OLD.id
    OR NEW.project_root IS NOT OLD.project_root
    OR NEW.binary_sha256 IS NOT OLD.binary_sha256
    OR NEW.purpose IS NOT OLD.purpose
    OR NEW.session IS NOT OLD.session
    OR NEW.finding_sha256 IS NOT OLD.finding_sha256
    OR NEW.prompt_version IS NOT OLD.prompt_version
    OR NEW.prompt IS NOT OLD.prompt
    OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'binary draft is immutable once answered'); END;
