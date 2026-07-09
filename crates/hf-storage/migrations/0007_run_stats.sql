-- Persist a completed run's peak coverage (edges) and throughput (execs/sec)
-- so run history can show real coverage / exec trends over time. Nullable:
-- unset while a run is pending, filled in when it finishes. Forward-only.
ALTER TABLE runs ADD COLUMN edges INTEGER;
ALTER TABLE runs ADD COLUMN execs REAL;
ALTER TABLE runs ADD COLUMN crash_count INTEGER;
