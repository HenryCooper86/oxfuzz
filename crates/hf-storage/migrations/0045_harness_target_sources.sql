-- Retains the target-definition section rendered into a harness draft prompt
-- before provider dispatch (Engineering Protocol 2.13). The section is read
-- from the project at draft time, and the project can change later, so the
-- exact model-visible text is kept here rather than re-read.
--
-- `source_sha256` is the digest of the complete source file the excerpt was
-- cut from. There is no harness foreign key: drafting precedes compilation and
-- may fail, as for `harness_build_contexts`.
CREATE TABLE harness_target_sources (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
    rendered TEXT NOT NULL CHECK (length(CAST(rendered AS BLOB)) <= 16384),
    created_at TEXT NOT NULL
);
CREATE INDEX idx_harness_target_sources_project
    ON harness_target_sources(project_root, created_at DESC, id DESC);
CREATE TRIGGER harness_target_sources_immutable BEFORE UPDATE ON harness_target_sources
BEGIN SELECT RAISE(ABORT, 'harness target source is immutable'); END;
CREATE TRIGGER harness_target_sources_no_replace BEFORE INSERT ON harness_target_sources
WHEN EXISTS (SELECT 1 FROM harness_target_sources WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'harness target source already exists'); END;
