-- Retire the Coverage and Blockers run-closeout steps. Both were always
-- recorded as Skipped: exact run-bound source coverage is not available at
-- closeout, and current-workspace measurements are a separate analysis.
--
-- A trust verdict recorded while those steps existed may have audited
-- workspace evidence (a completed legacy Coverage step) or be blocked by one of
-- them. Delete such TrustReport rows so the next closeout recomputes the verdict
-- from the current ladder instead of showing a stale one. Forward-only.
DELETE FROM run_closeout_steps
WHERE step = 'TrustReport'
  AND (
    (outcome = 'blocked' AND detail IN ('Coverage', 'Blockers'))
    OR run_id IN (
      SELECT run_id FROM run_closeout_steps
      WHERE step = 'Coverage' AND outcome = 'completed'
    )
  );

DELETE FROM run_closeout_steps WHERE step IN ('Coverage', 'Blockers');
