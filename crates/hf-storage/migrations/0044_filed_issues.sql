-- Durable dedup ledger for issue-tracker filings.
--
-- Filing an issue used to dedup with a best-effort remote search between two
-- racing callers: both searches miss, both create, and one crash opens two
-- tracker issues. This table is the server-side constraint that removes the
-- race window: the filing path claims its dedup key (crash UUID, or the
-- comparison signature) with an atomic insert BEFORE creating the remote
-- issue, records the created issue, and every retry returns the recorded
-- issue instead of creating again. `issue_json` is NULL only for the instant
-- a claim is held while the remote create is in flight; a claim whose create
-- failed is released so the filing can be retried.
CREATE TABLE IF NOT EXISTS filed_issues (
    dedup_key   TEXT PRIMARY KEY,
    issue_json  TEXT CHECK (issue_json IS NULL OR (json_valid(issue_json) AND length(CAST(issue_json AS BLOB)) <= 4096)),
    created_at  TEXT NOT NULL
);
