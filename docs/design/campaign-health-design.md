# Campaign Health

Status: **planned**. Owner: `hf-service`, emitting through the existing session
event log and scheduler event bridge.

## 1. Goal

A long campaign fails quietly. Workers die, the disk fills, or the fuzzer keeps
executing at full rate while learning nothing new. This subsystem names those
conditions from retained run state, once each, with the evidence behind them.

It reports. It does not stop, restart, or resize a campaign.

## 2. Feature and Ownership

Enabled by the `campaign-health` feature in `hf-service`. Conditions are emitted
into the **existing** session event log and scheduler event bridge. No new
notification transport is added: a second delivery path would need its own
secret handling, retry policy, and dedup state, all of which already exist.

## 3. Conditions

Each carries a stable code, a severity, cited evidence, and one next action.

- **`CoveragePlateau`** -- the retained coverage series for the run shows no
  increase across the last N measurements while execution continued.
- **`WorkersMissing`** -- fewer live engine processes than the run record
  expects.
- **`WorkerStatsStale`** -- an engine's progress record has not advanced within
  its expected reporting interval, while the run is still active.
- **`DiskPressure`** -- free space in the fuzz workspace is below the configured
  floor.
- **`RunFailed`** -- the run reached a terminal failure state.

`DiskPressure` is assessed but not yet supplied by the service gathering step.
Reading free space needs a cross-platform call the workspace has no dependency
for -- `statvfs` on Unix and `GetDiskFreeSpaceExW` on Windows -- and adding
platform-specific `unsafe` is its own change rather than a rider on this one.
Until then the gatherer passes no figure, which yields no condition; a caller
that has the figure gets the condition. Reporting an unknown free-space value as
"below the floor" would be exactly the unavailable-as-failure substitution this
subsystem exists to avoid.

## 4. Stalling Is A Coverage Question, Not An Exec-Count Question

fuzzctl declares a campaign stalled when `execs_done` and `paths_total` are
unchanged for three intervals. That misses the failure mode that matters: a
fuzzer executing millions of inputs per second against a harness that rejects
all of them has a rising exec count, a static corpus, and is learning nothing.
Its counters move, so fuzzctl calls it healthy.

`CoveragePlateau` keys on the retained coverage series (`run_coverage_series`),
which already records coverage per measurement for a run. Flat coverage under
continued execution is the condition worth an operator's attention, and it is
the one the exec counter cannot express.

Execution counters are still evidence: a plateau is only reported while
execution is progressing. A run whose execs are also flat is not plateaued, it
is stopped, and `WorkersMissing` or `WorkerStatsStale` names that instead.

## 5. Deduplication

Every condition carries a dedup key derived from the run, the condition code,
and the specific state that triggered it. A condition already emitted for a key
is not emitted again. The key includes the triggering state so that a condition
which worsens -- three workers missing after one was already reported -- emits
once more rather than being suppressed as a repeat.

Dedup state is retained with the run, so a restarted service does not re-emit
the backlog.

## 6. Thresholds Are Configuration

The plateau window, the stale-progress interval, and the disk floor are
validated configuration fields, not constants (AGENTS.md 2.15). A deployment
fuzzing a slow target and one fuzzing a fast parser do not share a plateau
window, and a `DEFAULT_*` constant would make that a code change.

## 7. Rejected Alternatives

- **Exec-counter stall detection** -- section 4.
- **A dedicated webhook poster** -- duplicates transport, secret handling, and
  retry policy that the scheduler event bridge already owns.
- **Auto-restarting missing workers** -- run control has an approval path; a
  health reporter that restarts things is a supervisor, and a supervisor that
  silently restarts a crashing harness hides the harness defect.
- **Emitting an all-clear condition** -- alerting on the absence of a problem
  trains operators to ignore the channel. Health is queryable; only conditions
  are emitted.
- **Severity derived from crash counts** -- crash volume is a triage input, not
  a health signal; `triage-disposition-design.md` already orders crashes.

## 8. Verification Criteria

- A run with rising execs and flat coverage across the configured window emits
  `CoveragePlateau` exactly once.
- A run with flat execs emits no `CoveragePlateau`.
- A condition emitted twice for identical state produces one event.
- A condition whose triggering state worsens produces a second event.
- Retained dedup state survives a service restart.
- No condition is emitted for a run with no retained coverage measurement; the
  plateau check reports unavailable instead.
- An unknown worker count or free-space figure yields no condition, rather than
  a condition asserting the worst case.
