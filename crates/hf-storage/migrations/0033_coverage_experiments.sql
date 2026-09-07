-- Retained experiment metadata is unconditional; no execution is authorized.
CREATE TABLE coverage_experiments (
    id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(id) = 'text'
        AND length(CAST(id AS BLOB)) BETWEEN 36 AND 36
        AND instr(id, char(0)) = 0
        AND substr(id, 9, 1) = '-'
        AND substr(id, 14, 1) = '-'
        AND substr(id, 19, 1) = '-'
        AND substr(id, 24, 1) = '-'
        AND length(replace(id, '-', '')) = 32
        AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(id, '-', '') <> '00000000000000000000000000000000'
        AND substr(id, 15, 1) = '4'
        AND substr(id, 20, 1) IN ('8','9','a','b')),
    schema_version INTEGER NOT NULL CHECK (typeof(schema_version) = 'integer' AND schema_version = 1),
    project_root TEXT NOT NULL CHECK (typeof(project_root) = 'text' AND length(CAST(project_root AS BLOB)) BETWEEN 1 AND 4096 AND instr(project_root, char(0)) = 0),
    target_id TEXT NOT NULL CHECK (
        typeof(target_id) = 'text'
        AND length(CAST(target_id AS BLOB)) BETWEEN 36 AND 36
        AND instr(target_id, char(0)) = 0
        AND substr(target_id, 9, 1) = '-'
        AND substr(target_id, 14, 1) = '-'
        AND substr(target_id, 19, 1) = '-'
        AND substr(target_id, 24, 1) = '-'
        AND length(replace(target_id, '-', '')) = 32
        AND replace(target_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(target_id, '-', '') <> '00000000000000000000000000000000'),
    target_symbol TEXT NOT NULL CHECK (
        typeof(target_symbol) = 'text'
        AND length(CAST(target_symbol AS BLOB)) BETWEEN 1 AND 1024
        AND instr(target_symbol, char(0)) = 0
        AND length(trim(target_symbol, char(9) || char(10) || char(13) || ' ')) > 0),
    baseline_run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT CHECK (
        typeof(baseline_run_id) = 'text'
        AND length(CAST(baseline_run_id AS BLOB)) BETWEEN 36 AND 36
        AND instr(baseline_run_id, char(0)) = 0
        AND substr(baseline_run_id, 9, 1) = '-'
        AND substr(baseline_run_id, 14, 1) = '-'
        AND substr(baseline_run_id, 19, 1) = '-'
        AND substr(baseline_run_id, 24, 1) = '-'
        AND length(replace(baseline_run_id, '-', '')) = 32
        AND replace(baseline_run_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(baseline_run_id, '-', '') <> '00000000000000000000000000000000'),
    kind TEXT NOT NULL CHECK (typeof(kind) = 'text' AND length(CAST(kind AS BLOB)) BETWEEN 1 AND 32 AND instr(kind, char(0)) = 0 AND kind IN ('grow_corpus','refine_harness')),
    goal_function TEXT NOT NULL CHECK (
        typeof(goal_function) = 'text'
        AND length(CAST(goal_function AS BLOB)) BETWEEN 1 AND 1024
        AND instr(goal_function, char(0)) = 0
        AND length(trim(goal_function, char(9) || char(10) || char(13) || ' ')) > 0),
    hypothesis TEXT NOT NULL CHECK (
        typeof(hypothesis) = 'text'
        AND length(CAST(hypothesis AS BLOB)) BETWEEN 1 AND 4096
        AND instr(hypothesis, char(0)) = 0
        AND length(trim(hypothesis, char(9) || char(10) || char(13) || ' ')) > 0),
    duration_secs INTEGER NOT NULL CHECK (typeof(duration_secs) = 'integer' AND duration_secs BETWEEN 1 AND 604800),
    baseline_evidence_json TEXT NOT NULL CHECK (
        typeof(baseline_evidence_json) = 'text'
        AND length(CAST(baseline_evidence_json AS BLOB)) BETWEEN 1 AND 65536
        AND instr(baseline_evidence_json, char(0)) = 0
        AND json_valid(baseline_evidence_json)
        AND json_type(baseline_evidence_json, '$') IS 'object'
        AND json_type(baseline_evidence_json, '$.schema_version') IS 'integer'
        AND json_extract(baseline_evidence_json, '$.schema_version') = 1
        AND json_type(baseline_evidence_json, '$.run_id') IS 'text'
        AND json_extract(baseline_evidence_json, '$.run_id') = baseline_run_id
        AND json_type(baseline_evidence_json, '$.project_root') IS 'text'
        AND json_extract(baseline_evidence_json, '$.project_root') = project_root
        AND json_type(baseline_evidence_json, '$.target_id') IS 'text'
        AND json_extract(baseline_evidence_json, '$.target_id') = target_id
        AND json_type(baseline_evidence_json, '$.target_symbol') IS 'text'
        AND json_extract(baseline_evidence_json, '$.target_symbol') = target_symbol
        AND json_type(baseline_evidence_json, '$.duration_secs') IS 'integer'
        AND json_extract(baseline_evidence_json, '$.duration_secs') = duration_secs),
    status TEXT NOT NULL CHECK (typeof(status) = 'text' AND length(CAST(status AS BLOB)) BETWEEN 1 AND 32 AND instr(status, char(0)) = 0 AND status IN ('prepared','completed','cancelled')),
    result_run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT CHECK (
        result_run_id IS NULL OR (typeof(result_run_id) = 'text'
        AND length(CAST(result_run_id AS BLOB)) BETWEEN 36 AND 36
        AND instr(result_run_id, char(0)) = 0
        AND substr(result_run_id, 9, 1) = '-'
        AND substr(result_run_id, 14, 1) = '-'
        AND substr(result_run_id, 19, 1) = '-'
        AND substr(result_run_id, 24, 1) = '-'
        AND length(replace(result_run_id, '-', '')) = 32
        AND replace(result_run_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(result_run_id, '-', '') <> '00000000000000000000000000000000')),
    result_evidence_json TEXT CHECK (
        result_evidence_json IS NULL OR (typeof(result_evidence_json) = 'text'
        AND length(CAST(result_evidence_json AS BLOB)) BETWEEN 1 AND 65536
        AND instr(result_evidence_json, char(0)) = 0
        AND json_valid(result_evidence_json)
        AND json_type(result_evidence_json, '$') IS 'object'
        AND json_type(result_evidence_json, '$.schema_version') IS 'integer'
        AND json_extract(result_evidence_json, '$.schema_version') = 1
        AND json_type(result_evidence_json, '$.run.schema_version') IS 'integer'
        AND json_extract(result_evidence_json, '$.run.schema_version') = 1
        AND json_type(result_evidence_json, '$.run') IS 'object'
        AND json_type(result_evidence_json, '$.input_change') IS 'text'
        AND json_type(result_evidence_json, '$.build_comparison') IS 'text'
        AND json_type(result_evidence_json, '$.edge_comparison') IS 'object'
        AND json_type(result_evidence_json, '$.target_entry') IS 'object'
        AND json_type(result_evidence_json, '$.limitations') IS 'array'
        AND json_type(result_evidence_json, '$.run.run_id') IS 'text'
        AND json_extract(result_evidence_json, '$.run.run_id') = result_run_id
        AND json_type(result_evidence_json, '$.run.project_root') IS 'text'
        AND json_extract(result_evidence_json, '$.run.project_root') = project_root
        AND json_type(result_evidence_json, '$.run.target_id') IS 'text'
        AND json_extract(result_evidence_json, '$.run.target_id') = target_id)),
    cancellation_reason TEXT CHECK (
        cancellation_reason IS NULL OR (typeof(cancellation_reason) = 'text'
        AND length(CAST(cancellation_reason AS BLOB)) BETWEEN 1 AND 4096
        AND instr(cancellation_reason, char(0)) = 0
        AND length(trim(cancellation_reason, char(9) || char(10) || char(13) || ' ')) > 0)),
    created_at TEXT NOT NULL CHECK (
        typeof(created_at) = 'text'
        AND length(CAST(created_at AS BLOB)) BETWEEN 30 AND 30
        AND instr(created_at, char(0)) = 0
        AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND substr(created_at, 1, 4) BETWEEN '0001' AND '9999'
        AND substr(created_at, 6, 2) BETWEEN '01' AND '12'
        AND CAST(substr(created_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(created_at, 6, 2) AS INTEGER) WHEN 2 THEN CASE WHEN CAST(substr(created_at, 1, 4) AS INTEGER) % 400 = 0 OR (CAST(substr(created_at, 1, 4) AS INTEGER) % 4 = 0
        AND CAST(substr(created_at, 1, 4) AS INTEGER) % 100 <> 0) THEN 29 ELSE 28 END WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
        AND substr(created_at, 12, 2) BETWEEN '00' AND '23'
        AND substr(created_at, 15, 2) BETWEEN '00' AND '59'
        AND substr(created_at, 18, 2) BETWEEN '00' AND '59'),
    updated_at TEXT NOT NULL CHECK (
        typeof(updated_at) = 'text'
        AND length(CAST(updated_at AS BLOB)) BETWEEN 30 AND 30
        AND instr(updated_at, char(0)) = 0
        AND updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND substr(updated_at, 1, 4) BETWEEN '0001' AND '9999'
        AND substr(updated_at, 6, 2) BETWEEN '01' AND '12'
        AND CAST(substr(updated_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(updated_at, 6, 2) AS INTEGER) WHEN 2 THEN CASE WHEN CAST(substr(updated_at, 1, 4) AS INTEGER) % 400 = 0 OR (CAST(substr(updated_at, 1, 4) AS INTEGER) % 4 = 0
        AND CAST(substr(updated_at, 1, 4) AS INTEGER) % 100 <> 0) THEN 29 ELSE 28 END WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
        AND substr(updated_at, 12, 2) BETWEEN '00' AND '23'
        AND substr(updated_at, 15, 2) BETWEEN '00' AND '59'
        AND substr(updated_at, 18, 2) BETWEEN '00' AND '59'),
    ended_at TEXT CHECK (
        ended_at IS NULL OR (typeof(ended_at) = 'text'
        AND length(CAST(ended_at AS BLOB)) BETWEEN 30 AND 30
        AND instr(ended_at, char(0)) = 0
        AND ended_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND substr(ended_at, 1, 4) BETWEEN '0001' AND '9999'
        AND substr(ended_at, 6, 2) BETWEEN '01' AND '12'
        AND CAST(substr(ended_at, 9, 2) AS INTEGER) BETWEEN 1 AND CASE CAST(substr(ended_at, 6, 2) AS INTEGER) WHEN 2 THEN CASE WHEN CAST(substr(ended_at, 1, 4) AS INTEGER) % 400 = 0 OR (CAST(substr(ended_at, 1, 4) AS INTEGER) % 4 = 0
        AND CAST(substr(ended_at, 1, 4) AS INTEGER) % 100 <> 0) THEN 29 ELSE 28 END WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END
        AND substr(ended_at, 12, 2) BETWEEN '00' AND '23'
        AND substr(ended_at, 15, 2) BETWEEN '00' AND '59'
        AND substr(ended_at, 18, 2) BETWEEN '00' AND '59')),
    CHECK (updated_at >= created_at),
    CHECK (
      (status = 'prepared' AND result_run_id IS NULL AND result_evidence_json IS NULL
       AND cancellation_reason IS NULL AND ended_at IS NULL AND updated_at = created_at)
      OR (status = 'completed' AND result_run_id IS NOT NULL AND result_run_id <> baseline_run_id
       AND result_evidence_json IS NOT NULL AND cancellation_reason IS NULL
       AND ended_at IS NOT NULL AND updated_at = ended_at)
      OR (status = 'cancelled' AND result_run_id IS NULL AND result_evidence_json IS NULL
       AND cancellation_reason IS NOT NULL AND ended_at IS NOT NULL AND updated_at = ended_at)
    )
);
CREATE INDEX idx_coverage_experiments_project ON coverage_experiments(project_root, created_at DESC, id DESC);
CREATE INDEX idx_coverage_experiments_target ON coverage_experiments(project_root, target_id, created_at DESC, id DESC);
CREATE INDEX idx_coverage_experiments_baseline ON coverage_experiments(baseline_run_id);
CREATE INDEX idx_coverage_experiments_result ON coverage_experiments(result_run_id) WHERE result_run_id IS NOT NULL;
CREATE TRIGGER coverage_experiments_no_replace BEFORE INSERT ON coverage_experiments
WHEN EXISTS (SELECT 1 FROM coverage_experiments WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'coverage experiment already exists'); END;
CREATE TRIGGER coverage_experiments_immutable_proposal BEFORE UPDATE ON coverage_experiments
WHEN OLD.id IS NOT NEW.id OR
     OLD.schema_version IS NOT NEW.schema_version OR
     OLD.project_root IS NOT NEW.project_root OR
     OLD.target_id IS NOT NEW.target_id OR
     OLD.target_symbol IS NOT NEW.target_symbol OR
     OLD.baseline_run_id IS NOT NEW.baseline_run_id OR
     OLD.kind IS NOT NEW.kind OR
     OLD.goal_function IS NOT NEW.goal_function OR
     OLD.hypothesis IS NOT NEW.hypothesis OR
     OLD.duration_secs IS NOT NEW.duration_secs OR
     OLD.baseline_evidence_json IS NOT NEW.baseline_evidence_json OR
     OLD.created_at IS NOT NEW.created_at
BEGIN SELECT RAISE(ABORT, 'coverage experiment proposal is immutable'); END;
CREATE TRIGGER coverage_experiments_terminal_immutable BEFORE UPDATE ON coverage_experiments
WHEN OLD.status IN ('completed', 'cancelled') OR NEW.status NOT IN ('completed', 'cancelled')
BEGIN SELECT RAISE(ABORT, 'coverage experiment terminal state is immutable'); END;
