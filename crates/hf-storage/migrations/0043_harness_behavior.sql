CREATE TABLE harness_behavior (
    run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    source_sha256 TEXT NOT NULL,
    binary_sha256 TEXT NOT NULL,
    sandbox_rev TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    report_json TEXT NOT NULL CHECK (json_valid(report_json) AND length(CAST(report_json AS BLOB)) <= 1048576)
);
