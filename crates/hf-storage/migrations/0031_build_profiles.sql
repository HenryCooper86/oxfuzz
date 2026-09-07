CREATE TABLE project_build_profiles (
    project_root TEXT PRIMARY KEY,
    component_root TEXT NOT NULL,
    build_system TEXT NOT NULL CHECK (build_system IN ('cmake', 'make')),
    compile_database_path TEXT NOT NULL,
    cmake_definitions_json TEXT NOT NULL CHECK (json_valid(cmake_definitions_json) AND length(CAST(cmake_definitions_json AS BLOB)) <= 65536),
    dependencies_json TEXT NOT NULL CHECK (json_valid(dependencies_json) AND length(CAST(dependencies_json AS BLOB)) <= 65536),
    sandbox_image_tag TEXT NOT NULL,
    sandbox_image_id TEXT NOT NULL,
    marker_path TEXT NOT NULL,
    marker_sha256 TEXT NOT NULL,
    profile_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE build_diagnosis_runs (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    profile_sha256 TEXT,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'cancelled')),
    diagnosis_json TEXT NOT NULL CHECK (json_valid(diagnosis_json) AND length(CAST(diagnosis_json AS BLOB)) <= 65536),
    created_at TEXT NOT NULL
);
CREATE INDEX idx_build_diagnosis_runs_project
    ON build_diagnosis_runs(project_root, created_at DESC, id DESC);

CREATE TABLE harness_build_inputs (
    harness_id TEXT PRIMARY KEY REFERENCES harnesses(id) ON DELETE CASCADE,
    project_root TEXT NOT NULL,
    profile_sha256 TEXT,
    compile_database_sha256 TEXT,
    compile_flags_sha256 TEXT NOT NULL,
    sandbox_image_id TEXT NOT NULL,
    build_input_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (profile_sha256 IS NULL OR compile_database_sha256 IS NOT NULL)
);
CREATE INDEX idx_harness_build_inputs_project ON harness_build_inputs(project_root);

CREATE TRIGGER harness_build_inputs_immutable
BEFORE UPDATE ON harness_build_inputs
BEGIN
    SELECT RAISE(ABORT, 'harness build inputs are immutable');
END;

CREATE TRIGGER harness_build_inputs_no_replace
BEFORE INSERT ON harness_build_inputs
WHEN EXISTS (SELECT 1 FROM harness_build_inputs WHERE harness_id = NEW.harness_id)
BEGIN
    SELECT RAISE(ABORT, 'harness build inputs already exist');
END;

CREATE TRIGGER build_diagnosis_runs_immutable
BEFORE UPDATE ON build_diagnosis_runs
BEGIN
    SELECT RAISE(ABORT, 'build diagnosis evidence is immutable');
END;

CREATE TRIGGER build_diagnosis_runs_no_replace
BEFORE INSERT ON build_diagnosis_runs
WHEN EXISTS (SELECT 1 FROM build_diagnosis_runs WHERE id = NEW.id)
BEGIN
    SELECT RAISE(ABORT, 'build diagnosis evidence already exists');
END;
