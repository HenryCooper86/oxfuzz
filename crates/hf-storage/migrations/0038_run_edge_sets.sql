-- Per-run covered edge set: the union of AFL coverage-map offsets the run's
-- retained corpus exercises, replayed through afl-showmap against the run's
-- exact staged binary at closeout (or on demand). Edge id presence only --
-- hit-count buckets are folded away. This turns run-to-run comparison from an
-- edge-count delta into an exact set diff ("which edges did run B lose that
-- run A had").
--
-- The bitmap is fixed at 64 KiB (524288 addressable map offsets; AFL's
-- default instrumented map is 65536 entries), so one row is bounded
-- regardless of target size. Immutable: re-measuring a run never rewrites its
-- evidence, and the row is bound at insert to the run's retained executable
-- and sandbox image digests. Forward-only.
CREATE TABLE run_edge_sets (
    run_id        TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    binary_sha256 TEXT NOT NULL,
    sandbox_rev   TEXT NOT NULL,
    inputs        INTEGER NOT NULL,
    edge_count    INTEGER NOT NULL,
    edge_map      BLOB NOT NULL CHECK (length(edge_map) = 65536),
    collected_at  TEXT NOT NULL
);
