CREATE TABLE harness_work_orders (
    id TEXT PRIMARY KEY CHECK (
        typeof(id) = 'text'
        AND length(id) = 64
        AND lower(id) = id
        AND id NOT GLOB '*[^0-9a-f]*'
    ),
    target_id TEXT NOT NULL CHECK (
        typeof(target_id) = 'text'
        AND length(target_id) = 36
        AND lower(target_id) = target_id
        AND target_id NOT GLOB '*[^0-9a-f-]*'
        AND length(replace(target_id, '-', '')) = 32
        AND substr(target_id, 9, 1) = '-'
        AND substr(target_id, 14, 1) = '-'
        AND substr(target_id, 19, 1) = '-'
        AND substr(target_id, 24, 1) = '-'
    ),
    project_root TEXT NOT NULL CHECK (
        typeof(project_root) = 'text'
        AND length(CAST(project_root AS BLOB)) > 0
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    packet_json TEXT NOT NULL CHECK (
        typeof(packet_json) = 'text'
        AND json_valid(packet_json)
        AND length(CAST(packet_json AS BLOB)) <= 262144
    ),
    created_at TEXT NOT NULL CHECK (typeof(created_at) = 'text')
);

CREATE TABLE harness_work_order_submissions (
    id TEXT PRIMARY KEY CHECK (
        typeof(id) = 'text'
        AND length(id) = 36
        AND lower(id) = id
        AND id NOT GLOB '*[^0-9a-f-]*'
        AND length(replace(id, '-', '')) = 32
        AND substr(id, 9, 1) = '-'
        AND substr(id, 14, 1) = '-'
        AND substr(id, 19, 1) = '-'
        AND substr(id, 24, 1) = '-'
    ),
    work_order_id TEXT NOT NULL REFERENCES harness_work_orders(id) CHECK (
        typeof(work_order_id) = 'text'
        AND length(work_order_id) = 64
        AND lower(work_order_id) = work_order_id
        AND work_order_id NOT GLOB '*[^0-9a-f]*'
    ),
    source TEXT NOT NULL CHECK (
        typeof(source) = 'text'
        AND length(CAST(source AS BLOB)) BETWEEN 1 AND 65536
    ),
    source_sha256 TEXT NOT NULL CHECK (
        typeof(source_sha256) = 'text'
        AND length(source_sha256) = 64
        AND lower(source_sha256) = source_sha256
        AND source_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    origin_json TEXT NOT NULL CHECK (
        typeof(origin_json) = 'text'
        AND json_valid(origin_json)
        AND length(CAST(origin_json AS BLOB)) <= 4096
    ),
    parent_submission_id TEXT REFERENCES harness_work_order_submissions(id) CHECK (
        parent_submission_id IS NULL OR (
            typeof(parent_submission_id) = 'text'
            AND length(parent_submission_id) = 36
            AND lower(parent_submission_id) = parent_submission_id
            AND parent_submission_id NOT GLOB '*[^0-9a-f-]*'
            AND length(replace(parent_submission_id, '-', '')) = 32
            AND substr(parent_submission_id, 9, 1) = '-'
            AND substr(parent_submission_id, 14, 1) = '-'
            AND substr(parent_submission_id, 19, 1) = '-'
            AND substr(parent_submission_id, 24, 1) = '-'
        )
    ),
    lint_json TEXT NOT NULL CHECK (
        typeof(lint_json) = 'text'
        AND json_valid(lint_json)
        AND length(CAST(lint_json AS BLOB)) <= 65536
    ),
    submitted_at TEXT NOT NULL CHECK (typeof(submitted_at) = 'text')
);

CREATE TABLE harness_work_order_attempts (
    id TEXT PRIMARY KEY CHECK (
        typeof(id) = 'text'
        AND length(id) = 36
        AND lower(id) = id
        AND id NOT GLOB '*[^0-9a-f-]*'
        AND length(replace(id, '-', '')) = 32
        AND substr(id, 9, 1) = '-'
        AND substr(id, 14, 1) = '-'
        AND substr(id, 19, 1) = '-'
        AND substr(id, 24, 1) = '-'
    ),
    submission_id TEXT NOT NULL REFERENCES harness_work_order_submissions(id) CHECK (
        typeof(submission_id) = 'text'
        AND length(submission_id) = 36
        AND lower(submission_id) = submission_id
        AND submission_id NOT GLOB '*[^0-9a-f-]*'
        AND length(replace(submission_id, '-', '')) = 32
        AND substr(submission_id, 9, 1) = '-'
        AND substr(submission_id, 14, 1) = '-'
        AND substr(submission_id, 19, 1) = '-'
        AND substr(submission_id, 24, 1) = '-'
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'running', 'compile_failed', 'review_failed', 'smoke_failed',
            'smoke_passed', 'interrupted'
        )
    ),
    current_stage TEXT NOT NULL CHECK (
        current_stage IN ('compile', 'review', 'smoke', 'complete')
    ),
    harness_id TEXT CHECK (
        harness_id IS NULL OR (
            typeof(harness_id) = 'text'
            AND length(harness_id) = 36
            AND lower(harness_id) = harness_id
            AND harness_id NOT GLOB '*[^0-9a-f-]*'
            AND length(replace(harness_id, '-', '')) = 32
            AND substr(harness_id, 9, 1) = '-'
            AND substr(harness_id, 14, 1) = '-'
            AND substr(harness_id, 19, 1) = '-'
            AND substr(harness_id, 24, 1) = '-'
        )
    ),
    smoke_run_id TEXT CHECK (
        smoke_run_id IS NULL OR (
            typeof(smoke_run_id) = 'text'
            AND length(smoke_run_id) = 36
            AND lower(smoke_run_id) = smoke_run_id
            AND smoke_run_id NOT GLOB '*[^0-9a-f-]*'
            AND length(replace(smoke_run_id, '-', '')) = 32
            AND substr(smoke_run_id, 9, 1) = '-'
            AND substr(smoke_run_id, 14, 1) = '-'
            AND substr(smoke_run_id, 19, 1) = '-'
            AND substr(smoke_run_id, 24, 1) = '-'
        )
    ),
    result_json TEXT CHECK (
        result_json IS NULL OR (
            typeof(result_json) = 'text'
            AND json_valid(result_json)
            AND length(CAST(result_json AS BLOB)) <= 65536
        )
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL OR length(CAST(failure_code AS BLOB)) BETWEEN 1 AND 128
    ),
    failure_message TEXT CHECK (
        failure_message IS NULL OR length(CAST(failure_message AS BLOB)) BETWEEN 1 AND 4096
    ),
    started_at TEXT NOT NULL CHECK (typeof(started_at) = 'text'),
    updated_at TEXT NOT NULL CHECK (typeof(updated_at) = 'text'),
    ended_at TEXT CHECK (ended_at IS NULL OR typeof(ended_at) = 'text'),
    CHECK (
        (status = 'running' AND current_stage IN ('compile', 'review', 'smoke')
            AND ended_at IS NULL)
        OR
        (status IN (
                'compile_failed', 'review_failed', 'smoke_failed', 'smoke_passed',
                'interrupted'
            ) AND current_stage = 'complete' AND ended_at IS NOT NULL)
    )
);

CREATE TRIGGER harness_work_orders_validate_created_at
BEFORE INSERT ON harness_work_orders
WHEN NOT (
    length(CAST(NEW.created_at AS BLOB)) = length(NEW.created_at)
    AND length(NEW.created_at) >= 20
    AND substr(NEW.created_at, 5, 1) = '-'
    AND substr(NEW.created_at, 8, 1) = '-'
    AND substr(NEW.created_at, 11, 1) = 'T'
    AND substr(NEW.created_at, 14, 1) = ':'
    AND substr(NEW.created_at, 17, 1) = ':'
    AND substr(NEW.created_at, -1, 1) = 'Z'
    AND substr(NEW.created_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.created_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.created_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.created_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.created_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.created_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.created_at) = 20 OR (
        length(NEW.created_at) >= 22
        AND substr(NEW.created_at, 20, 1) = '.'
        AND substr(NEW.created_at, 21, length(NEW.created_at) - 21) NOT GLOB '*[^0-9]*'
    ))
    AND CAST(substr(NEW.created_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.created_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE
        CAST(substr(NEW.created_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE
            WHEN CAST(substr(NEW.created_at, 1, 4) AS INTEGER) % 4 = 0
                AND (CAST(substr(NEW.created_at, 1, 4) AS INTEGER) % 100 <> 0
                    OR CAST(substr(NEW.created_at, 1, 4) AS INTEGER) % 400 = 0)
            THEN 29 ELSE 28
        END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30
        ELSE 31
    END
    AND CAST(substr(NEW.created_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.created_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.created_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
)
BEGIN
    SELECT RAISE(ABORT, 'work order created_at must be a valid UTC RFC 3339 timestamp');
END;

CREATE TRIGGER harness_work_order_submissions_validate_submitted_at
BEFORE INSERT ON harness_work_order_submissions
WHEN NOT (
    length(CAST(NEW.submitted_at AS BLOB)) = length(NEW.submitted_at)
    AND length(NEW.submitted_at) >= 20
    AND substr(NEW.submitted_at, 5, 1) = '-'
    AND substr(NEW.submitted_at, 8, 1) = '-'
    AND substr(NEW.submitted_at, 11, 1) = 'T'
    AND substr(NEW.submitted_at, 14, 1) = ':'
    AND substr(NEW.submitted_at, 17, 1) = ':'
    AND substr(NEW.submitted_at, -1, 1) = 'Z'
    AND substr(NEW.submitted_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.submitted_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.submitted_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.submitted_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.submitted_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.submitted_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.submitted_at) = 20 OR (
        length(NEW.submitted_at) >= 22
        AND substr(NEW.submitted_at, 20, 1) = '.'
        AND substr(NEW.submitted_at, 21, length(NEW.submitted_at) - 21) NOT GLOB '*[^0-9]*'
    ))
    AND CAST(substr(NEW.submitted_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.submitted_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE
        CAST(substr(NEW.submitted_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE
            WHEN CAST(substr(NEW.submitted_at, 1, 4) AS INTEGER) % 4 = 0
                AND (CAST(substr(NEW.submitted_at, 1, 4) AS INTEGER) % 100 <> 0
                    OR CAST(substr(NEW.submitted_at, 1, 4) AS INTEGER) % 400 = 0)
            THEN 29 ELSE 28
        END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30
        ELSE 31
    END
    AND CAST(substr(NEW.submitted_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.submitted_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.submitted_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
)
BEGIN
    SELECT RAISE(ABORT, 'work order submitted_at must be a valid UTC RFC 3339 timestamp');
END;

CREATE TRIGGER harness_work_order_attempts_validate_timestamps_insert
BEFORE INSERT ON harness_work_order_attempts
WHEN NOT (
    length(CAST(NEW.started_at AS BLOB)) = length(NEW.started_at)
    AND length(NEW.started_at) >= 20
    AND substr(NEW.started_at, 5, 1) = '-' AND substr(NEW.started_at, 8, 1) = '-'
    AND substr(NEW.started_at, 11, 1) = 'T' AND substr(NEW.started_at, 14, 1) = ':'
    AND substr(NEW.started_at, 17, 1) = ':' AND substr(NEW.started_at, -1, 1) = 'Z'
    AND substr(NEW.started_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.started_at) = 20 OR (length(NEW.started_at) >= 22
        AND substr(NEW.started_at, 20, 1) = '.'
        AND substr(NEW.started_at, 21, length(NEW.started_at) - 21) NOT GLOB '*[^0-9]*'))
    AND CAST(substr(NEW.started_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.started_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.started_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 4 = 0
            AND (CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 100 <> 0
                OR CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
    AND CAST(substr(NEW.started_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.started_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.started_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    AND length(CAST(NEW.updated_at AS BLOB)) = length(NEW.updated_at)
    AND length(NEW.updated_at) >= 20
    AND substr(NEW.updated_at, 5, 1) = '-' AND substr(NEW.updated_at, 8, 1) = '-'
    AND substr(NEW.updated_at, 11, 1) = 'T' AND substr(NEW.updated_at, 14, 1) = ':'
    AND substr(NEW.updated_at, 17, 1) = ':' AND substr(NEW.updated_at, -1, 1) = 'Z'
    AND substr(NEW.updated_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.updated_at) = 20 OR (length(NEW.updated_at) >= 22
        AND substr(NEW.updated_at, 20, 1) = '.'
        AND substr(NEW.updated_at, 21, length(NEW.updated_at) - 21) NOT GLOB '*[^0-9]*'))
    AND CAST(substr(NEW.updated_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.updated_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.updated_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 4 = 0
            AND (CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 100 <> 0
                OR CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
    AND CAST(substr(NEW.updated_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.updated_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.updated_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    AND (NEW.ended_at IS NULL OR (
        length(CAST(NEW.ended_at AS BLOB)) = length(NEW.ended_at)
        AND length(NEW.ended_at) >= 20
        AND substr(NEW.ended_at, 5, 1) = '-' AND substr(NEW.ended_at, 8, 1) = '-'
        AND substr(NEW.ended_at, 11, 1) = 'T' AND substr(NEW.ended_at, 14, 1) = ':'
        AND substr(NEW.ended_at, 17, 1) = ':' AND substr(NEW.ended_at, -1, 1) = 'Z'
        AND substr(NEW.ended_at, 1, 4) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 6, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 9, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 12, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 15, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 18, 2) NOT GLOB '*[^0-9]*'
        AND (length(NEW.ended_at) = 20 OR (length(NEW.ended_at) >= 22
            AND substr(NEW.ended_at, 20, 1) = '.'
            AND substr(NEW.ended_at, 21, length(NEW.ended_at) - 21) NOT GLOB '*[^0-9]*'))
        AND CAST(substr(NEW.ended_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(NEW.ended_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.ended_at, 6, 2) AS INTEGER)
            WHEN 2 THEN CASE WHEN CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 4 = 0
                AND (CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 100 <> 0
                    OR CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
            WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
        AND CAST(substr(NEW.ended_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(NEW.ended_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(NEW.ended_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'work order attempt timestamps must be valid UTC RFC 3339 values');
END;

CREATE TRIGGER harness_work_order_attempts_validate_timestamps_update
BEFORE UPDATE ON harness_work_order_attempts
WHEN NOT (
    length(CAST(NEW.started_at AS BLOB)) = length(NEW.started_at)
    AND length(NEW.started_at) >= 20
    AND substr(NEW.started_at, 5, 1) = '-' AND substr(NEW.started_at, 8, 1) = '-'
    AND substr(NEW.started_at, 11, 1) = 'T' AND substr(NEW.started_at, 14, 1) = ':'
    AND substr(NEW.started_at, 17, 1) = ':' AND substr(NEW.started_at, -1, 1) = 'Z'
    AND substr(NEW.started_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.started_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.started_at) = 20 OR (length(NEW.started_at) >= 22
        AND substr(NEW.started_at, 20, 1) = '.'
        AND substr(NEW.started_at, 21, length(NEW.started_at) - 21) NOT GLOB '*[^0-9]*'))
    AND CAST(substr(NEW.started_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.started_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.started_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 4 = 0
            AND (CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 100 <> 0
                OR CAST(substr(NEW.started_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
    AND CAST(substr(NEW.started_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.started_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.started_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    AND length(CAST(NEW.updated_at AS BLOB)) = length(NEW.updated_at)
    AND length(NEW.updated_at) >= 20
    AND substr(NEW.updated_at, 5, 1) = '-' AND substr(NEW.updated_at, 8, 1) = '-'
    AND substr(NEW.updated_at, 11, 1) = 'T' AND substr(NEW.updated_at, 14, 1) = ':'
    AND substr(NEW.updated_at, 17, 1) = ':' AND substr(NEW.updated_at, -1, 1) = 'Z'
    AND substr(NEW.updated_at, 1, 4) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 6, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 9, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 12, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 15, 2) NOT GLOB '*[^0-9]*'
    AND substr(NEW.updated_at, 18, 2) NOT GLOB '*[^0-9]*'
    AND (length(NEW.updated_at) = 20 OR (length(NEW.updated_at) >= 22
        AND substr(NEW.updated_at, 20, 1) = '.'
        AND substr(NEW.updated_at, 21, length(NEW.updated_at) - 21) NOT GLOB '*[^0-9]*'))
    AND CAST(substr(NEW.updated_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    AND CAST(substr(NEW.updated_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.updated_at, 6, 2) AS INTEGER)
        WHEN 2 THEN CASE WHEN CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 4 = 0
            AND (CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 100 <> 0
                OR CAST(substr(NEW.updated_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
        WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
    AND CAST(substr(NEW.updated_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
    AND CAST(substr(NEW.updated_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
    AND CAST(substr(NEW.updated_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    AND (NEW.ended_at IS NULL OR (
        length(CAST(NEW.ended_at AS BLOB)) = length(NEW.ended_at)
        AND length(NEW.ended_at) >= 20
        AND substr(NEW.ended_at, 5, 1) = '-' AND substr(NEW.ended_at, 8, 1) = '-'
        AND substr(NEW.ended_at, 11, 1) = 'T' AND substr(NEW.ended_at, 14, 1) = ':'
        AND substr(NEW.ended_at, 17, 1) = ':' AND substr(NEW.ended_at, -1, 1) = 'Z'
        AND substr(NEW.ended_at, 1, 4) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 6, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 9, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 12, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 15, 2) NOT GLOB '*[^0-9]*'
        AND substr(NEW.ended_at, 18, 2) NOT GLOB '*[^0-9]*'
        AND (length(NEW.ended_at) = 20 OR (length(NEW.ended_at) >= 22
            AND substr(NEW.ended_at, 20, 1) = '.'
            AND substr(NEW.ended_at, 21, length(NEW.ended_at) - 21) NOT GLOB '*[^0-9]*'))
        AND CAST(substr(NEW.ended_at, 6, 2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(NEW.ended_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(NEW.ended_at, 6, 2) AS INTEGER)
            WHEN 2 THEN CASE WHEN CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 4 = 0
                AND (CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 100 <> 0
                    OR CAST(substr(NEW.ended_at, 1, 4) AS INTEGER) % 400 = 0) THEN 29 ELSE 28 END
            WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
        AND CAST(substr(NEW.ended_at, 12, 2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(NEW.ended_at, 15, 2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(NEW.ended_at, 18, 2) AS INTEGER) BETWEEN 0 AND 60
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'work order attempt timestamps must be valid UTC RFC 3339 values');
END;

CREATE UNIQUE INDEX harness_work_order_submissions_identity
ON harness_work_order_submissions (
    work_order_id,
    source_sha256,
    origin_json,
    COALESCE(parent_submission_id, '')
);

CREATE INDEX idx_harness_work_orders_target_project
ON harness_work_orders (target_id, project_root, created_at DESC);

CREATE INDEX idx_harness_work_order_submissions_work_order
ON harness_work_order_submissions (work_order_id, submitted_at DESC, id DESC);

CREATE INDEX idx_harness_work_order_attempts_submission
ON harness_work_order_attempts (submission_id, started_at DESC, id DESC);

CREATE INDEX idx_harness_work_order_attempts_status
ON harness_work_order_attempts (status, updated_at DESC);

CREATE TRIGGER harness_work_orders_immutable
BEFORE UPDATE ON harness_work_orders
BEGIN
    SELECT RAISE(ABORT, 'harness work order is immutable');
END;

CREATE TRIGGER harness_work_order_submissions_immutable
BEFORE UPDATE ON harness_work_order_submissions
BEGIN
    SELECT RAISE(ABORT, 'harness work order submission is immutable');
END;

CREATE TRIGGER harness_work_order_attempts_identity_immutable
BEFORE UPDATE ON harness_work_order_attempts
WHEN NEW.id <> OLD.id
    OR NEW.submission_id <> OLD.submission_id
    OR NEW.started_at <> OLD.started_at
BEGIN
    SELECT RAISE(ABORT, 'harness work order attempt identity is immutable');
END;

CREATE TRIGGER harness_work_order_attempts_terminal_immutable
BEFORE UPDATE ON harness_work_order_attempts
WHEN OLD.status <> 'running'
BEGIN
    SELECT RAISE(ABORT, 'terminal harness work order attempt is immutable');
END;
