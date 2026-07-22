-- Digest-bound provenance for the explicit human harness-promotion boundary.
-- The storage API writes this row and the promoted harness in one transaction,
-- so evidence can never claim approval while the harness remains unpromoted (or
-- vice versa).
CREATE TABLE harness_approvals (
    id              TEXT PRIMARY KEY,
    harness_id      TEXT NOT NULL,
    source_sha256   TEXT NOT NULL,
    binary_sha256   TEXT NOT NULL,
    approval_kind   TEXT NOT NULL CHECK (approval_kind IN ('clean_smoke', 'known_findings')),
    approved_at     TEXT NOT NULL,
    UNIQUE (harness_id, source_sha256, binary_sha256, approval_kind)
);

CREATE INDEX idx_harness_approvals_harness
    ON harness_approvals (harness_id, approved_at DESC);
