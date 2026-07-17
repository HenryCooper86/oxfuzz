-- Durable audit trail of guardrail authorization decisions. Every authorizing
-- service entry point records the policy decision and, when the approval gate
-- was consulted, its outcome (approved / denied_by_operator). Append-only;
-- the service prunes it to a bounded newest window on write. Forward-only.
CREATE TABLE IF NOT EXISTS guardrail_decisions (
    id          TEXT PRIMARY KEY,
    decided_at  TEXT NOT NULL,
    action      TEXT NOT NULL,
    risk_tier   TEXT NOT NULL,
    decision    TEXT NOT NULL,
    origin      TEXT NOT NULL,
    project     TEXT,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_guardrail_decisions_ts
    ON guardrail_decisions(decided_at DESC);
