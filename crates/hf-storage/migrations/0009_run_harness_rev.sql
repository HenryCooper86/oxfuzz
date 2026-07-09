-- Record which harness revision a run used, as a short content hash of the
-- harness source. Lets run history tie a coverage jump to the harness change
-- that produced it. Nullable; forward-only.
ALTER TABLE runs ADD COLUMN harness_rev TEXT;
