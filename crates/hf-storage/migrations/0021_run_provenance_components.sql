-- Split the comparison context into independently verifiable source, starting
-- corpus, and pinned sandbox-reference digests. Nullable columns preserve
-- legacy rows, which remain explicitly incomplete proof manifests.
ALTER TABLE runs ADD COLUMN source_rev TEXT;
ALTER TABLE runs ADD COLUMN corpus_rev TEXT;
ALTER TABLE runs ADD COLUMN sandbox_rev TEXT;
