# Campaign Health

Status: **active implementation**. Owner: `hf-service`, with durable evidence in
`hf-storage` and live delivery through the existing scheduler and presentation
event paths.

## 1. Goal

Campaign Health records enough bounded evidence to explain whether a running or
recent campaign is progressing, stalled, under disk pressure, or failed. It
reports conditions and a morning summary. It never stops, restarts, or resizes a
run.

## 2. Ownership and scope

The `campaign-health` feature enables service monitoring, assessment, queries,
and delivery. `hf-service` owns all calculations and lifecycle decisions.
`hf-storage` owns strict durable records and atomic duplicate admission. REST,
Tauri, SSE, and React carry or render service results without reassessing them.

Monitoring applies only to `RunKind::Campaign`. Smoke qualification and
maintenance runs remain visible in ordinary run history but never acquire a
campaign monitor or enter morning-summary categories.

Userspace campaigns and admitted syzkaller campaigns each expose one managed
invocation: the single awaited call that owns `EngineRunner` or `syz-manager`.
This is not a process, worker, VM, or Docker liveness probe. Current runtime
APIs cannot prove those independently.

## 3. Retained observation

`RunTelemetryObservation` identifies the run and records:

- observation time and optional last structured-progress time;
- a bounded oldest-first deque of edge/throughput samples;
- current, whole-run arithmetic sample mean, and peak executions per second;
- the latest edge count;
- managed invocations expected and alive; and
- optional available bytes on the configured fuzz-workspace filesystem.

Only finite structured throughput samples contribute to current, mean, and
peak. A valid structured edge or throughput observation refreshes progress
time. The mean is `sum(valid reported throughput samples) / count(valid
reported throughput samples)` over the whole observed run. The accumulator
remains independent of bounded deque eviction. Log lines and raw crash signals
do not refresh metric time. Unknown disk or progress evidence is `None`, never
zero.

On Unix the service reads capacity with safe `rustix::fs::statvfs`, using
available blocks times fragment size with checked arithmetic. Windows uses a
safe crate API. Failure is logged and retained as unknown.

## 4. Conditions

Each condition carries a stable code, severity, exact assessment evidence,
deduplication key, observation time, and one next action.

- **`CoveragePlateau`**: the configured tail of live samples has flat edges
  while at least one valid positive throughput sample shows continued
  execution. A steady positive rate is sufficient; the rate need not rise.
- **`ManagedInvocationMissing`**: explicit service evidence says an awaited
  managed invocation was expected but its guard is absent. Normal invocation
  entry and exit update expected/alive together and must not manufacture this
  state. No independent process-liveness claim is made.
- **`WorkerStatsStale`**: structured progress has not advanced within the
  configured interval while the managed invocation is active.
- **`DiskPressure`**: known available workspace bytes are below the configured
  floor.
- **`RunFailed`**: a campaign reached durable `Failed` status.

All-zero or unknown throughput alone cannot establish a coverage plateau.
Missing evidence yields an unavailable assessment with a reason. A completed
run's stopped metrics are not stale.

## 5. Configuration

The `[campaign_health]` section in both shipped global configuration templates
defines and validates:

- `plateau_window` (at least two samples);
- `stale_progress_secs` (greater than zero);
- `disk_floor_bytes` (greater than zero);
- `assessment_interval_secs` (greater than zero);
- `max_live_samples` (at least two);
- `event_retention_days` (greater than zero); and
- `morning_summary_lookback_hours` (greater than zero).

The monitor resolves one validated settings value when the run is admitted.
Edits apply to later monitors and explicit queries, not unpredictably within an
existing monitor.

`max_live_samples` must be at least `plateau_window`, and a plateau becomes
evaluable when exactly `plateau_window` valid samples are present. Configuration
cannot make every live plateau assessment permanently unavailable.

## 6. Durable events and duplicate admission

`run_telemetry` retains the latest bounded observation for each run.
`campaign_health_events` retains a version 2 envelope containing a service UUID,
run UUID, condition, severity, detail, deduplication key, observation time, and
the exact assessment evidence. Unknown or malformed durable versions fail the
read. The earlier version 1 report was computed on demand and was never stored,
so this pre-1.0 change updates its wire consumers coherently and adds no
compatibility decoder for a durable format that did not exist.

The read-only current assessment is a candidate view and has `id: null`; it does
not claim that a GET created a durable alert. Only SQLite-admitted events and
retained event hydration carry a non-null stable UUID.

Retained hydration returns `{ events, next_cursor }` in deterministic
newest-first `(observed_at, id)` order. `limit` must be between 1 and 100. The
cursor is the last event UUID from the prior page and must belong to the same
run; missing and foreign-run cursors fail validation. The next page selects
strictly older keys, so a live event inserted while paging cannot skip an older
retained event. Clients merge pages and live delivery by event UUID.

SQLite admits an event with `INSERT ... ON CONFLICT(run_id, condition,
dedup_key) DO NOTHING`.
Only a newly inserted event is delivered live. The key covers run, condition,
and triggering state, so identical assessments deduplicate across concurrent
ticks and service restarts while worsened evidence produces a new event.

Pruning uses the configured retention period and excludes supplied teardown
IDs plus every durable `Pending` or `Running` campaign, including campaigns
owned by another process.
Active-run telemetry and every key required to suppress its repeated events are
retained. One bounded telemetry row may remain with a retained run after it
becomes terminal.

Telemetry upserts admit only observations newer than the retained row. A
delayed assessment cannot replace newer accumulators or publish an event as if
its rejected snapshot were current. Event uniqueness is scoped by run,
condition, and state key, so one run or condition cannot suppress another.
The configured live-sample limit is capped at 256, which keeps the complete
strict sample and event-evidence encodings within the durable 64 KiB limits.

## 7. Monitor lifecycle

After a campaign has a durable and cancellable run ID, the service prepares its
registry entry and starts one immediately ticking periodic monitor. A small
owner holds the cancellation token and join handle. Normal completion closes
progress, cancels and awaits the task, assesses already-persisted terminal
state, then removes registry state. `Drop` closes and removes the entry, cancels,
and aborts an unfinished task so a cancelled caller cannot detach monitoring or
allow a late callback to recreate closed state. Drop cannot await and therefore
does not promise a final assessment; `PersistedRunGuard` repairs durable run
status asynchronously on abnormal caller cancellation.

`register_invocation` atomically moves expected/alive from `0/0` to `1/1`
immediately around the runtime await. Its guard atomically returns both to
`0/0`. Registry locks are never held over storage, filesystem, delivery, or
runtime awaits.

Userspace and syzkaller ordinary-error paths persist terminal failure and finish
the monitor explicitly. `PersistedRunGuard` remains the abnormal caller-drop
repair. Syzkaller becomes durable/cancellable and emits its service-owned UUID
before scoped progress; pre-admission guidance has no run UUID and remains
request-scoped.

Desktop launch commands may also receive an optional request-scoped Tauri
channel. Their existing service `on_started` callback sends the admitted UUID
through that channel before the command waits for termination. The HTTP
transport reports the validated UUID from `POST /runs/start` through the same
local callback interface before its terminal wait. Global UUID-scoped progress
and status events remain observation streams; they do not identify which
foreground request admitted a run. A missing channel preserves direct native
callers, and channel delivery failure does not change successful admission.

## 8. Delivery and authorization

The existing scheduler bridge receives `campaign.health` only after durable
insertion. The existing SSE stream carries `campaign:health`; reconnect and
lag recovery hydrate retained events through REST and merge them by event UUID.
No second transport or delivery acknowledgement is introduced.

Owner-authorized `GET /runs/{id}/telemetry` returns the service snapshot time,
bounded coverage series, latest edge count, and cumulative throughput
count/sum/current/mean/peak. A browser joining midway or recovering from SSE
lag replaces its session subset with this authoritative cumulative snapshot;
it never labels callback-only arithmetic as a whole-run mean. Structured
progress received while a telemetry request is in flight marks the run dirty
and coalesces one refresh after that read settles. The client never replays an
unsequenced throughput callback into the returned count/sum because the response
may already include it. Raw logs and crash signals may render immediately;
whole-run population and mean remain service-owned.

Owner-authorized `GET /runs/{id}/health/events?cursor=<uuid>&limit=<n>` and the
matching native `campaign_health_events(run_id, cursor, limit)` command expose
the retained page. Both default to 100 events and preserve validation errors
from the service.

Every retained read resolves the durable run owner and applies the server's
approved-project policy. SSE applies the same policy before publishing events,
including scheduled and unsolicited campaigns. A selected GUI project never
supplies ownership for an event. Native and HTTP progress carry the service run
UUID; owner metadata is resolved from the service and run buckets remain
separate while that lookup is pending.

Raw crash notifications remain signals. The terminal retained artifact count is
the unique crash total and is labelled separately.

## 9. Morning summary

The configured lookback produces run-ID sets for:

- `failed`: campaign runs durably `Failed` in the window;
- `stalled`: campaigns with retained plateau, stale-stats, or explicit
  managed-invocation evidence;
- `interrupted`: campaign IDs recovered by the run journal; and
- `unprocessed`: terminal campaigns whose strict closeout view has pending or
  failed work.

IDs deduplicate within a category and may appear in several categories. The
pure strict closeout decoder is shared with `campaign-health`; the closeout
executor is not. Unknown closeout rows remain errors. A standalone
`campaign-health` build compiles without enabling run-closeout execution.

## 10. Rejected alternatives

- An execution-count-only stall rule misses active fuzzers with flat coverage.
- Docker/PID/VM inspection would claim worker evidence the runtime API does not
  provide.
- A dedicated webhook duplicates the scheduler bridge's routing and secrets.
- Automatic restart or cancellation changes run control without approval.
- Detached monitor tasks can write after teardown and retain the container.
- Assigning callbacks to the currently selected GUI project misattributes
  scheduled and concurrent runs.

## 11. Verification criteria

- Flat live edges plus steady positive throughput emits a plateau before
  terminal `runs.samples_json`; all-zero or unknown throughput does not.
- Samples `100` then `25` report current `25`, whole-run arithmetic mean `62.5`,
  and peak `100`, even after deque eviction.
- Identical concurrent and restarted assessments insert and deliver once;
  worsened evidence inserts again.
- Unknown/nonfinite evidence remains unavailable and log noise does not refresh
  metric time.
- Normal, error, and cancellation paths leave no monitor or registry state
  after final assessment. Dropped callers close and remove live state while the
  persisted-run repair records failure asynchronously.
- Userspace and admitted syzkaller progress uses the exact durable run UUID.
- Cross-project REST and SSE reads/delivery are denied from the durable owner.
- Interleaved and scheduled GUI runs retain separate metrics and owner-correct
  project indexes.
- Morning summary excludes smoke and maintenance runs and strictly reports
  malformed closeout evidence.
