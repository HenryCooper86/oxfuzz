-- Store the harness source a run used, so run history can show the diff between
-- harness revisions (jump from a coverage change to exactly what changed in the
-- harness). Nullable; forward-only. Read on demand, never in the run list.
ALTER TABLE runs ADD COLUMN harness_source TEXT;
