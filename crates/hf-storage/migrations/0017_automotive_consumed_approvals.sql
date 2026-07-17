-- Single-use ledger for physical-bench approvals.
--
-- A physical automotive replay authorizes real transmissions on a vehicle bench.
-- The approval is scope-hashed and time-boxed (15 min), but nothing recorded
-- that an approval id had already been used, so one human approval could
-- authorize repeated scripted transmissions within its freshness window. This
-- table makes each approval single-use: the service claims an approval by
-- inserting its id here before running the sidecar, and the PRIMARY KEY makes a
-- second claim of the same id fail atomically -- the race-free primitive that a
-- read-then-write check cannot provide.
CREATE TABLE IF NOT EXISTS automotive_consumed_approvals (
    approval_id   TEXT PRIMARY KEY,
    scope_sha256  TEXT NOT NULL,
    operation_id  TEXT NOT NULL,
    project_root  TEXT NOT NULL,
    consumed_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_automotive_consumed_approvals_project
    ON automotive_consumed_approvals(project_root);
