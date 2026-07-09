-- Persist a run's intra-run coverage/throughput samples (a downsampled time
-- series captured live as the fuzzer ran) so a run's coverage curve can be
-- charted after the fact. Stored as a JSON array blob; nullable. Forward-only.
ALTER TABLE runs ADD COLUMN samples_json TEXT;
