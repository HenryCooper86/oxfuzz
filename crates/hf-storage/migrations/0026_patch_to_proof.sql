CREATE TABLE remediation_operations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES crashes(id) ON DELETE CASCADE,
    project_root TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('draft','approved','running','verified','rejected','inconclusive')
    ),
    current_stage TEXT NOT NULL CHECK (
        current_stage IN (
            'review','original_replay','patch_build','patched_replay',
            'regression','follow_up','complete'
        )
    ),
    binding_json TEXT NOT NULL CHECK (
        json_valid(binding_json) AND length(CAST(binding_json AS BLOB)) <= 2097152
    ),
    approval_json TEXT CHECK (
        approval_json IS NULL OR (
            json_valid(approval_json) AND length(CAST(approval_json AS BLOB)) <= 16384
        )
    ),
    verification_json TEXT CHECK (
        verification_json IS NULL OR (
            json_valid(verification_json) AND length(CAST(verification_json AS BLOB)) <= 1048576
        )
    ),
    artifact_dir TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    failure_code TEXT CHECK (
        failure_code IS NULL OR length(CAST(failure_code AS BLOB)) BETWEEN 1 AND 128
    ),
    failure_message TEXT CHECK (
        failure_message IS NULL OR length(CAST(failure_message AS BLOB)) BETWEEN 1 AND 4096
    ),
    CHECK (
        (status = 'draft' AND current_stage = 'review' AND approval_json IS NULL
            AND verification_json IS NULL AND ended_at IS NULL
            AND failure_code IS NULL AND failure_message IS NULL)
        OR
        (status = 'approved' AND current_stage = 'review' AND approval_json IS NOT NULL
            AND verification_json IS NULL AND ended_at IS NULL
            AND failure_code IS NULL AND failure_message IS NULL)
        OR
        (status = 'running' AND current_stage IN (
                'original_replay','patch_build','patched_replay','regression','follow_up'
            ) AND approval_json IS NOT NULL AND verification_json IS NULL
            AND ended_at IS NULL AND failure_code IS NULL AND failure_message IS NULL)
        OR
        (status IN ('verified','rejected') AND current_stage = 'complete'
            AND approval_json IS NOT NULL AND verification_json IS NOT NULL
            AND ended_at IS NOT NULL AND failure_code IS NULL AND failure_message IS NULL)
        OR
        (status = 'inconclusive' AND current_stage = 'complete'
            AND approval_json IS NOT NULL AND ended_at IS NOT NULL
            AND (verification_json IS NOT NULL
                OR (failure_code IS NOT NULL AND failure_message IS NOT NULL)))
    )
);

CREATE INDEX idx_remediation_finding
ON remediation_operations(finding_id, created_at DESC);

CREATE INDEX idx_remediation_status
ON remediation_operations(status, updated_at);

CREATE TRIGGER remediation_operations_identity_immutable
BEFORE UPDATE ON remediation_operations
WHEN NEW.id <> OLD.id
    OR NEW.run_id <> OLD.run_id
    OR NEW.finding_id <> OLD.finding_id
    OR NEW.project_root <> OLD.project_root
    OR NEW.target <> OLD.target
    OR NEW.binding_json <> OLD.binding_json
    OR NEW.artifact_dir <> OLD.artifact_dir
    OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'remediation operation identity and binding are immutable');
END;

CREATE TRIGGER remediation_operations_approval_immutable
BEFORE UPDATE ON remediation_operations
WHEN OLD.approval_json IS NOT NULL
    AND (NEW.approval_json IS NULL OR NEW.approval_json <> OLD.approval_json)
BEGIN
    SELECT RAISE(ABORT, 'remediation operation approval is immutable');
END;
