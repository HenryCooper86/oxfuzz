-- Durable dedup ledger for issue-tracker filings.
--
-- Filing an issue used to dedup with a best-effort remote search between two
-- racing callers: both searches miss, both create, and one crash opens two
-- tracker issues. This table is the server-side constraint that removes the
-- race window: the filing path claims its dedup key (crash UUID, or the
-- comparison signature) with an atomic insert BEFORE creating the remote
-- issue, records the created issue, and every retry returns the recorded
-- issue instead of creating again.
--
-- `attempt_id` is the ownership token: a claim can be completed or released
-- only by the attempt that holds it, so a delayed claimant cannot complete or
-- free a row a newer claimant now owns. `issue_json` is NULL only while a
-- claim is held and its remote create is in flight; a failed create releases
-- the claim so the filing can be retried. A stale claim (process died before
-- completion) is reclaimed by a later claimant only after that claimant has
-- reconciled against the remote tracker and found no issue, so recovery
-- cannot silently re-create an issue the dead process already opened.
CREATE TABLE IF NOT EXISTS filed_issues (
    dedup_key   TEXT PRIMARY KEY,
    attempt_id  TEXT NOT NULL,
    issue_json  TEXT CHECK (issue_json IS NULL OR (json_valid(issue_json) AND length(CAST(issue_json AS BLOB)) <= 4096)),
    created_at  TEXT NOT NULL
);