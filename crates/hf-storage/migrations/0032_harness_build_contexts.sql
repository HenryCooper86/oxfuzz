CREATE TABLE harness_build_contexts (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    compile_database_sha256 TEXT NOT NULL,
    context_json TEXT NOT NULL CHECK (json_valid(context_json) AND length(CAST(context_json AS BLOB)) <= 65536),
    created_at TEXT NOT NULL
);
CREATE INDEX idx_harness_build_contexts_project ON harness_build_contexts(project_root, created_at DESC, id DESC);
CREATE TRIGGER harness_build_contexts_immutable BEFORE UPDATE ON harness_build_contexts
BEGIN SELECT RAISE(ABORT, 'harness build context is immutable'); END;
CREATE TRIGGER harness_build_contexts_no_replace BEFORE INSERT ON harness_build_contexts
WHEN EXISTS (SELECT 1 FROM harness_build_contexts WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'harness build context already exists'); END;
