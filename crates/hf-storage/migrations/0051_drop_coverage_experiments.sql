-- Coverage experiments were removed from oxfuzz (2026-11-04 UI audit): the
-- feature recorded proposals around work the operator performed by hand and ran
-- nothing itself. Its tables reference runs with ON DELETE RESTRICT, which
-- would otherwise block deleting those runs once the feature's own guards are
-- gone. Dropping a table also drops its indexes and triggers. Retained
-- experiment records are deleted with them. Forward-only.
DROP TABLE IF EXISTS coverage_experiment_executions;
DROP TABLE IF EXISTS coverage_experiments;
