-- This migration and receipt version 2 ship as one unreleased migration unit.
-- There is no supported version-1 receipt/proof upgrade path.
CREATE TABLE schedule_retirement_operations (
    operation_id TEXT NOT NULL PRIMARY KEY
        CHECK (
            length(operation_id) = 36
            AND lower(operation_id) = operation_id
            AND operation_id NOT GLOB '*[^0-9a-f-]*'
            AND substr(operation_id, 9, 1) = '-'
            AND substr(operation_id, 14, 1) = '-'
            AND substr(operation_id, 15, 1) GLOB '[1-5]'
            AND substr(operation_id, 19, 1) = '-'
            AND substr(operation_id, 20, 1) GLOB '[89ab]'
            AND substr(operation_id, 24, 1) = '-'
        ),
    plan_digest TEXT NOT NULL
        CHECK (
            length(plan_digest) = 64
            AND lower(plan_digest) = plan_digest
            AND plan_digest NOT GLOB '*[^0-9a-f]*'
        ),
    schedule_ids_json TEXT NOT NULL
        CHECK (
            json_valid(schedule_ids_json)
            AND json_type(schedule_ids_json) = 'array'
            AND json_array_length(schedule_ids_json) <= 4096
            AND length(CAST(schedule_ids_json AS BLOB)) <= 2097152
        ),
    completed_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        CHECK (
            length(CAST(completed_at AS BLOB)) BETWEEN 20 AND 32
            AND completed_at GLOB '????-??-??T??:??:??*Z'
        )
);

CREATE TABLE schedule_retirement_schedule_ids (
    schedule_id TEXT NOT NULL PRIMARY KEY
        CHECK (
            length(CAST(schedule_id AS BLOB)) BETWEEN 1 AND 512
            AND instr(schedule_id, char(0)) = 0
        ),
    operation_id TEXT NOT NULL
        REFERENCES schedule_retirement_operations(operation_id),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    UNIQUE (operation_id, ordinal)
);

CREATE TRIGGER schedule_retirement_operations_validate_ids
BEFORE INSERT ON schedule_retirement_operations
WHEN EXISTS (
    SELECT 1
    FROM json_each(NEW.schedule_ids_json) AS current
    WHERE current.type <> 'text'
       OR length(CAST(current.value AS BLOB)) NOT BETWEEN 1 AND 512
       OR EXISTS (
           SELECT 1
           FROM json_each(NEW.schedule_ids_json) AS prior
           WHERE CAST(prior.key AS INTEGER) < CAST(current.key AS INTEGER)
             AND CAST(prior.value AS TEXT) >= CAST(current.value AS TEXT)
       )
)
BEGIN
    SELECT RAISE(ABORT, 'schedule retirement proof IDs must be bounded sorted unique strings');
END;

CREATE TRIGGER schedule_retirement_operations_no_insert_when_existing
BEFORE INSERT ON schedule_retirement_operations
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_operations
    WHERE operation_id = NEW.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'schedule retirement proof is immutable');
END;

CREATE TRIGGER schedule_retirement_operations_no_update
BEFORE UPDATE ON schedule_retirement_operations
BEGIN
    SELECT RAISE(ABORT, 'schedule retirement proof is immutable');
END;

CREATE TRIGGER schedule_retirement_operations_no_delete
BEFORE DELETE ON schedule_retirement_operations
BEGIN
    SELECT RAISE(ABORT, 'schedule retirement proof is immutable');
END;

CREATE TRIGGER schedule_retirement_schedule_ids_no_insert_when_existing
BEFORE INSERT ON schedule_retirement_schedule_ids
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_schedule_ids
    WHERE schedule_id = NEW.schedule_id
)
BEGIN
    SELECT RAISE(ABORT, 'retired schedule tombstone is immutable');
END;

CREATE TRIGGER schedule_retirement_schedule_ids_no_update
BEFORE UPDATE ON schedule_retirement_schedule_ids
BEGIN
    SELECT RAISE(ABORT, 'retired schedule tombstone is immutable');
END;

CREATE TRIGGER schedule_retirement_schedule_ids_no_delete
BEFORE DELETE ON schedule_retirement_schedule_ids
BEGIN
    SELECT RAISE(ABORT, 'retired schedule tombstone is immutable');
END;

CREATE TRIGGER schedule_executions_reject_retired_schedule_insert
BEFORE INSERT ON schedule_executions
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_schedule_ids
    WHERE schedule_id = NEW.schedule_id
)
BEGIN
    SELECT RAISE(ABORT, 'schedule execution belongs to a proven-retired schedule');
END;

CREATE TRIGGER schedule_executions_reject_retired_schedule_update
BEFORE UPDATE OF schedule_id ON schedule_executions
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_schedule_ids
    WHERE schedule_id = NEW.schedule_id
)
BEGIN
    SELECT RAISE(ABORT, 'schedule execution belongs to a proven-retired schedule');
END;

CREATE TRIGGER schedule_occurrences_reject_retired_schedule_insert
BEFORE INSERT ON schedule_occurrences
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_schedule_ids
    WHERE schedule_id = NEW.schedule_id
)
BEGIN
    SELECT RAISE(ABORT, 'schedule occurrence belongs to a proven-retired schedule');
END;

CREATE TRIGGER schedule_occurrences_reject_retired_schedule_update
BEFORE UPDATE OF schedule_id ON schedule_occurrences
WHEN EXISTS (
    SELECT 1 FROM schedule_retirement_schedule_ids
    WHERE schedule_id = NEW.schedule_id
)
BEGIN
    SELECT RAISE(ABORT, 'schedule occurrence belongs to a proven-retired schedule');
END;
