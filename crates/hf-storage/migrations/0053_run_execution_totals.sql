-- Total executions get their own column. Until now syzkaller kept its
-- cumulative executed count in `execs`, which every other engine uses for
-- executions per second, so history trends mixed a count with a rate.
ALTER TABLE runs ADD COLUMN execs_total INTEGER;

UPDATE runs
SET execs_total = CAST(execs AS INTEGER), execs = NULL
WHERE engine = 'syzkaller' AND execs IS NOT NULL;

-- libFuzzer prints `exec/s: 0` through a run's whole first second, so a run
-- that crashed early was stored at 0 exec/s although it covered edges or
-- crashed. Any such run executed inputs; its rate was never measured.
UPDATE runs
SET execs = NULL
WHERE execs = 0 AND (COALESCE(edges, 0) > 0 OR COALESCE(crash_count, 0) > 0);
