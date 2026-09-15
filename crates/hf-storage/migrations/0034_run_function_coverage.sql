CREATE TABLE run_function_coverage (
    run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    binary_sha256 TEXT NOT NULL,
    sandbox_rev TEXT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    export_sha256 TEXT NOT NULL,
    export_json TEXT NOT NULL CHECK (json_valid(export_json) AND length(CAST(export_json AS BLOB)) <= 8388608),
    collected_at TEXT NOT NULL
);
