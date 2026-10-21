-- Compact advanced rendering introduces renderer version 2 alongside the
-- version-1 full ClangTargetContext JSON (docs/design/clang-symbolic-harness-design.md).
-- SQLite cannot alter a CHECK constraint in place, so the context table is
-- rebuilt with the widened constraint; existing rows keep their identities,
-- rendered bytes, and operation links.
CREATE TABLE harness_clang_contexts_v2 (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES clang_analysis_results(operation_id) ON DELETE CASCADE,
    project_root TEXT NOT NULL,
    target_id TEXT NOT NULL,
    renderer_version INTEGER NOT NULL CHECK (renderer_version IN (1, 2)),
    rendered TEXT NOT NULL CHECK(length(CAST(rendered AS BLOB)) <= 65536),
    created_at TEXT NOT NULL
);

INSERT INTO harness_clang_contexts_v2
    SELECT id, operation_id, project_root, target_id, renderer_version, rendered, created_at
    FROM harness_clang_contexts;

DROP TABLE harness_clang_contexts;
ALTER TABLE harness_clang_contexts_v2 RENAME TO harness_clang_contexts;
