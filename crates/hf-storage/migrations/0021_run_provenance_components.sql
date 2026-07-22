-- Split the comparison context into independently verifiable source, starting
-- corpus, and sandbox provenance. Exact Docker identities use the typed
-- `docker-image-id-sha256:<digest>` representation; older untyped hashes remain
-- explicitly incomplete proof manifests. Nullable columns preserve legacy rows.
ALTER TABLE runs ADD COLUMN source_rev TEXT;
ALTER TABLE runs ADD COLUMN corpus_rev TEXT;
ALTER TABLE runs ADD COLUMN sandbox_rev TEXT;
