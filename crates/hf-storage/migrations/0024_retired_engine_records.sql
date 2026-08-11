CREATE TABLE IF NOT EXISTS retired_engine_records (
    record_kind TEXT NOT NULL
        CHECK (record_kind IN (
            'run', 'harness', 'harness_approval', 'crash',
            'schedule_execution', 'schedule_occurrence'
        )),
    record_id TEXT NOT NULL,
    retired_engine TEXT NOT NULL CHECK (retired_engine = 'clusterfuzzlite'),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    migration_version INTEGER NOT NULL CHECK (migration_version = 24),
    archived_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (record_kind, record_id)
);

CREATE INDEX idx_retired_engine_records_archived_at
    ON retired_engine_records(archived_at DESC, record_kind, record_id);

CREATE TRIGGER retired_engine_records_no_update
BEFORE UPDATE ON retired_engine_records
BEGIN
    SELECT RAISE(ABORT, 'retired engine evidence is immutable');
END;

CREATE TRIGGER retired_engine_records_no_delete
BEFORE DELETE ON retired_engine_records
BEGIN
    SELECT RAISE(ABORT, 'retired engine evidence is immutable');
END;

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'run',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'project_root', project_root,
        'engine', engine,
        'status', status,
        'started_at', started_at,
        'ended_at', ended_at,
        'config_json', config_json,
        'edges', edges,
        'execs', execs,
        'crash_count', crash_count,
        'samples_json', samples_json,
        'harness_rev', harness_rev,
        'harness_source', harness_source,
        'binary_rev', binary_rev,
        'evidence_dir', evidence_dir,
        'run_kind', run_kind,
        'context_rev', context_rev,
        'source_rev', source_rev,
        'corpus_rev', corpus_rev,
        'sandbox_rev', sandbox_rev
    ),
    24
FROM runs
WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
   OR CASE WHEN json_valid(config_json) THEN
        json_type(config_json, '$.engine') = 'text'
        AND lower(trim(json_extract(config_json, '$.engine')))
            IN ('clusterfuzzlite', 'cfl', 'cflite')
      ELSE 0 END;

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'harness',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'target_id', target_id,
        'engine', engine,
        'source', source,
        'status', status,
        'smoke_run_json', smoke_run_json,
        'data_json', data_json
    ),
    24
FROM harnesses
WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
   OR CASE WHEN json_valid(data_json) THEN
        json_type(data_json, '$.engine') = 'text'
        AND lower(trim(json_extract(data_json, '$.engine')))
            IN ('clusterfuzzlite', 'cfl', 'cflite')
      ELSE 0 END;

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'harness_approval',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'harness_id', harness_id,
        'source_sha256', source_sha256,
        'binary_sha256', binary_sha256,
        'approval_kind', approval_kind,
        'approved_at', approved_at
    ),
    24
FROM harness_approvals
WHERE harness_id IN (
    SELECT id
    FROM harnesses
    WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
       OR CASE WHEN json_valid(data_json) THEN
            json_type(data_json, '$.engine') = 'text'
            AND lower(trim(json_extract(data_json, '$.engine')))
                IN ('clusterfuzzlite', 'cfl', 'cflite')
          ELSE 0 END
);

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'crash',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'run_id', run_id,
        'target_id', target_id,
        'stack_signature', stack_signature,
        'kind', kind,
        'summary', summary,
        'minimized', minimized,
        'bug_report_json', bug_report_json,
        'data_json', data_json
    ),
    24
FROM crashes
WHERE run_id IN (
    SELECT id
    FROM runs
    WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
       OR CASE WHEN json_valid(config_json) THEN
            json_type(config_json, '$.engine') = 'text'
            AND lower(trim(json_extract(config_json, '$.engine')))
                IN ('clusterfuzzlite', 'cfl', 'cflite')
          ELSE 0 END
);

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'schedule_execution',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'schedule_id', schedule_id,
        'triggered_at', triggered_at,
        'status', status,
        'data_json', data_json
    ),
    24
FROM schedule_executions
WHERE CASE WHEN json_valid(data_json) THEN
    json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
    AND lower(trim(json_extract(
        data_json,
        '$.request_summary.parameter_values.engine'
    ))) IN ('clusterfuzzlite', 'cfl', 'cflite')
ELSE 0 END;

INSERT INTO retired_engine_records
    (record_kind, record_id, retired_engine, payload_json, migration_version)
SELECT
    'schedule_occurrence',
    id,
    'clusterfuzzlite',
    json_object(
        'id', id,
        'schedule_id', schedule_id,
        'execution_id', execution_id,
        'triggered_at', triggered_at,
        'state', state,
        'owner_id', owner_id,
        'lease_expires_at', lease_expires_at,
        'recovery_detail', recovery_detail,
        'created_at', created_at,
        'updated_at', updated_at
    ),
    24
FROM schedule_occurrences
WHERE execution_id IN (
    SELECT id
    FROM schedule_executions
    WHERE CASE WHEN json_valid(data_json) THEN
        json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
        AND lower(trim(json_extract(
            data_json,
            '$.request_summary.parameter_values.engine'
        ))) IN ('clusterfuzzlite', 'cfl', 'cflite')
    ELSE 0 END
);

DELETE FROM schedule_occurrences
WHERE execution_id IN (
    SELECT id
    FROM schedule_executions
    WHERE CASE WHEN json_valid(data_json) THEN
        json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
        AND lower(trim(json_extract(
            data_json,
            '$.request_summary.parameter_values.engine'
        ))) IN ('clusterfuzzlite', 'cfl', 'cflite')
    ELSE 0 END
);

DELETE FROM schedule_executions
WHERE CASE WHEN json_valid(data_json) THEN
    json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
    AND lower(trim(json_extract(
        data_json,
        '$.request_summary.parameter_values.engine'
    ))) IN ('clusterfuzzlite', 'cfl', 'cflite')
ELSE 0 END;

DELETE FROM harness_approvals
WHERE harness_id IN (
    SELECT id
    FROM harnesses
    WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
       OR CASE WHEN json_valid(data_json) THEN
            json_type(data_json, '$.engine') = 'text'
            AND lower(trim(json_extract(data_json, '$.engine')))
                IN ('clusterfuzzlite', 'cfl', 'cflite')
          ELSE 0 END
);

DELETE FROM crashes
WHERE run_id IN (
    SELECT id
    FROM runs
    WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
       OR CASE WHEN json_valid(config_json) THEN
            json_type(config_json, '$.engine') = 'text'
            AND lower(trim(json_extract(config_json, '$.engine')))
                IN ('clusterfuzzlite', 'cfl', 'cflite')
          ELSE 0 END
);

DELETE FROM harnesses
WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
   OR CASE WHEN json_valid(data_json) THEN
        json_type(data_json, '$.engine') = 'text'
        AND lower(trim(json_extract(data_json, '$.engine')))
            IN ('clusterfuzzlite', 'cfl', 'cflite')
      ELSE 0 END;

DELETE FROM runs
WHERE lower(trim(engine)) IN ('clusterfuzzlite', 'cfl', 'cflite')
   OR CASE WHEN json_valid(config_json) THEN
        json_type(config_json, '$.engine') = 'text'
        AND lower(trim(json_extract(config_json, '$.engine')))
            IN ('clusterfuzzlite', 'cfl', 'cflite')
      ELSE 0 END;
