-- File-scoped target identity: two same-named functions in different files of
-- one project previously shared one persistence identity (project_root,
-- symbol), so one row shadowed the other for harness/corpus/crash linkage.
-- The identity is now (project_root, file, symbol); upsert_target re-homes
-- onto the existing row whose backfilled file matches, so a rescan keeps the
-- legacy id for the surviving row and creates a distinct row for the second
-- definition.
--
-- Backfill `file` from the candidate's location.file inside data_json,
-- relativized by stripping the canonical project_root prefix (canonical roots
-- carry no trailing slash). Files outside the root -- or already relative --
-- keep their stored path, mirroring TargetCandidate::relative_file. Rows
-- whose data_json yields no usable file keep '' and remain valid; new scans
-- upsert against the file-scoped key.
ALTER TABLE targets ADD COLUMN file TEXT NOT NULL DEFAULT '';

UPDATE targets
SET file = CASE
    WHEN instr(json_extract(data_json, '$.location.file'), project_root || '/') = 1
    THEN substr(json_extract(data_json, '$.location.file'), length(project_root) + 2)
    ELSE json_extract(data_json, '$.location.file')
END
WHERE json_valid(data_json)
  AND json_extract(data_json, '$.location.file') IS NOT NULL;

DROP INDEX idx_targets_project_symbol;

CREATE UNIQUE INDEX idx_targets_project_symbol_file
    ON targets (project_root, symbol, file);
