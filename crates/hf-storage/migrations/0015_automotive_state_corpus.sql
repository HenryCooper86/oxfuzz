-- Retained automotive protocol-state corpus entries are deliberately separate
-- from source-coverage corpus rows. Their uniqueness is protocol/state/artifact
-- based and every row attributes the evidence to its completed source operation.
CREATE TABLE IF NOT EXISTS automotive_state_corpus (
    project_root        TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    state_digest        TEXT NOT NULL,
    artifact_sha256     TEXT NOT NULL,
    source_operation_id TEXT NOT NULL,
    artifact_path       TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    PRIMARY KEY (project_root, protocol, state_digest, artifact_sha256),
    FOREIGN KEY (source_operation_id) REFERENCES automotive_operations(id)
);

CREATE INDEX IF NOT EXISTS idx_automotive_state_corpus_project
    ON automotive_state_corpus(project_root, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_automotive_state_corpus_state
    ON automotive_state_corpus(protocol, state_digest);
