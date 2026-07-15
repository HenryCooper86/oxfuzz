-- Bind each run to its immutable binary digest and service-owned evidence
-- directory. `harness_rev` already stores the source digest; these nullable
-- fields keep pre-migration run history readable.
ALTER TABLE runs ADD COLUMN binary_rev TEXT;
ALTER TABLE runs ADD COLUMN evidence_dir TEXT;
ALTER TABLE runs ADD COLUMN run_kind TEXT NOT NULL DEFAULT 'campaign';
ALTER TABLE runs ADD COLUMN context_rev TEXT;
