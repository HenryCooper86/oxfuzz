CREATE TABLE schedule_retirement_operations (
    operation_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL,
    schedule_ids_json TEXT NOT NULL CHECK (json_valid(schedule_ids_json)),
    completed_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

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
