-- A proposal owns at most one execution, even after cancellation or restart.
CREATE TABLE coverage_experiment_executions (
    experiment_id TEXT PRIMARY KEY REFERENCES coverage_experiments(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
    review_json TEXT NOT NULL CHECK(length(CAST(review_json AS BLOB)) BETWEEN 2 AND 16384)
);
CREATE TRIGGER coverage_experiment_execution_immutable
BEFORE UPDATE ON coverage_experiment_executions BEGIN
    SELECT RAISE(ABORT, 'coverage experiment execution is immutable');
END;
CREATE TRIGGER coverage_experiment_execution_result
BEFORE UPDATE OF result_run_id ON coverage_experiments
WHEN NEW.result_run_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM coverage_experiment_executions
    WHERE experiment_id = NEW.id AND run_id <> NEW.result_run_id
) BEGIN
    SELECT RAISE(ABORT, 'coverage experiment result must match execution');
END;
