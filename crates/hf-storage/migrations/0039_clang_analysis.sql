CREATE TABLE clang_analysis_operations (
 id TEXT PRIMARY KEY,
 project_root TEXT NOT NULL,
 language TEXT NOT NULL CHECK(language IN ('c','cpp')),
 state TEXT NOT NULL CHECK(state IN ('staging','analyzing','validating','done','failed','cancelled','interrupted')),
 request_json TEXT NOT NULL CHECK(json_valid(request_json) AND length(CAST(request_json AS BLOB)) <= 67108864),
 started_at TEXT NOT NULL,
 ended_at TEXT,
 failure TEXT,
 CHECK ((state IN ('staging','analyzing','validating') AND ended_at IS NULL)
     OR (state IN ('done','failed','cancelled','interrupted') AND ended_at IS NOT NULL))
);
CREATE INDEX clang_analysis_project ON clang_analysis_operations(project_root, started_at);
CREATE TABLE clang_analysis_results (
 operation_id TEXT PRIMARY KEY REFERENCES clang_analysis_operations(id) ON DELETE CASCADE,
 project_root TEXT NOT NULL,
 input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
 image_id TEXT NOT NULL,
 inputs_json TEXT NOT NULL CHECK(json_valid(inputs_json) AND length(CAST(inputs_json AS BLOB)) <= 67108864),
 index_json TEXT NOT NULL CHECK(json_valid(index_json) AND length(CAST(index_json AS BLOB)) <= 67108864)
);
CREATE TABLE harness_clang_contexts (
 id TEXT PRIMARY KEY,
 operation_id TEXT NOT NULL REFERENCES clang_analysis_results(operation_id) ON DELETE CASCADE,
 project_root TEXT NOT NULL,
 target_id TEXT NOT NULL,
 renderer_version INTEGER NOT NULL CHECK(renderer_version=1),
 rendered TEXT NOT NULL CHECK(length(CAST(rendered AS BLOB)) <= 65536),
 created_at TEXT NOT NULL
);
