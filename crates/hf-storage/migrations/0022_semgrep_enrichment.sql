CREATE TABLE semgrep_enrichment_runs (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    language TEXT NOT NULL CHECK (language IN ('c', 'cpp')),
    source_sha256 TEXT,
    sandbox_image TEXT NOT NULL,
    sandbox_image_sha256 TEXT NOT NULL,
    semgrep_version TEXT NOT NULL,
    rules_commit TEXT NOT NULL,
    rules_tree_sha256 TEXT NOT NULL,
    command_schema_version INTEGER NOT NULL CHECK (command_schema_version = 1),
    status TEXT NOT NULL CHECK (
        status IN ('staging','scanning','validating','persisting','done','failed','cancelled')
    ),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    output_sha256 TEXT,
    finding_count INTEGER,
    matched_candidate_count INTEGER,
    duration_ms INTEGER,
    failure_code TEXT,
    failure_message TEXT,
    CHECK (
        status <> 'done' OR (
            source_sha256 IS NOT NULL AND ended_at IS NOT NULL AND
            output_sha256 IS NOT NULL AND finding_count IS NOT NULL AND
            matched_candidate_count IS NOT NULL AND duration_ms IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX idx_semgrep_one_active_project
ON semgrep_enrichment_runs(project_root)
WHERE status IN ('staging','scanning','validating','persisting');

CREATE INDEX idx_semgrep_latest_project_language
ON semgrep_enrichment_runs(project_root, language, ended_at DESC)
WHERE status = 'done';

CREATE TABLE semgrep_findings (
    scan_id TEXT NOT NULL REFERENCES semgrep_enrichment_runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('error','warning','info')),
    message TEXT NOT NULL,
    relative_file TEXT NOT NULL,
    start_line INTEGER NOT NULL CHECK (start_line > 0),
    start_col INTEGER NOT NULL CHECK (start_col > 0),
    end_line INTEGER NOT NULL CHECK (end_line > 0),
    end_col INTEGER NOT NULL CHECK (end_col > 0),
    target_id TEXT,
    nominal_weight REAL NOT NULL CHECK (nominal_weight IN (0.10, 0.05, 0.01)),
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE TABLE semgrep_target_scores (
    scan_id TEXT NOT NULL REFERENCES semgrep_enrichment_runs(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL,
    base_score REAL NOT NULL CHECK (base_score >= 0.0 AND base_score <= 1.0),
    boost REAL NOT NULL CHECK (boost >= 0.0 AND boost <= 0.20),
    effective_score REAL NOT NULL CHECK (effective_score >= 0.0 AND effective_score <= 1.0),
    matched_rule_count INTEGER NOT NULL CHECK (matched_rule_count >= 0),
    PRIMARY KEY (scan_id, target_id)
);
