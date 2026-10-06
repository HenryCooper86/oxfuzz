-- Meson and Autotools join CMake and plain Make as accepted saved build
-- systems (docs/design/build-doctor-design.md). SQLite cannot alter a CHECK
-- constraint in place, so the profile table is rebuilt with the widened
-- constraint; existing rows keep their identities and digests.
CREATE TABLE project_build_profiles_widened (
    project_root TEXT PRIMARY KEY,
    component_root TEXT NOT NULL,
    build_system TEXT NOT NULL CHECK (build_system IN ('cmake', 'make', 'meson', 'autotools')),
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

INSERT INTO project_build_profiles_widened
    SELECT project_root, component_root, build_system, compile_database_path,
           cmake_definitions_json, dependencies_json, sandbox_image_tag,
           sandbox_image_id, marker_path, marker_sha256, profile_sha256,
           created_at, updated_at
    FROM project_build_profiles;

DROP TABLE project_build_profiles;
ALTER TABLE project_build_profiles_widened
    RENAME TO project_build_profiles;
