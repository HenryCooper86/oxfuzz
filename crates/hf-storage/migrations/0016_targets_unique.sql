-- Enforce the (project_root, symbol) identity invariant for targets.
--
-- upsert_target previously used a racy read-then-write with no unique
-- constraint, so two concurrent discover/save_inventory operations on the same
-- project could each mint a fresh UUID and insert a second row for the same
-- symbol, breaking the invariant that harness/corpus/crash rows reference a
-- single stable target id.
--
-- Collapse any pre-existing duplicates onto the earliest-inserted row (lowest
-- rowid == the stable id that child rows already reference, so no child is
-- orphaned), then add a unique index so duplicates can no longer be created.
DELETE FROM targets
WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM targets GROUP BY project_root, symbol
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_project_symbol
    ON targets (project_root, symbol);
