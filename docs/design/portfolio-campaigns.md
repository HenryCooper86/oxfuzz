# Portfolio Campaigns -- Design

## Goal

Fuzz a whole project on autopilot. A scheduled campaign points at a project
*folder* (independent of any "active project" in the GUI) and rotates through
every promoted target in it, under a global concurrency cap and a per-campaign
budget, auto-reporting and notifying when it finds crashes.

## The one constraint everything bends around

A scheduled campaign only ever runs a **human-promoted** harness. `run_campaign`
(`hf-service/src/container.rs`) refuses anything else -- generation, smoke, and
promotion are deliberately human steps (AGENTS.md 2.5/2.12). Portfolio campaigns
do not weaken this: they only ever select from `schedulable_targets`, which
returns promoted harnesses. "Choose the folder and target and run" means *choose
among what a human already approved*, not generate-and-run.

## Model

`CampaignParams` (`scheduler.rs`) is backward-compatible; old `schedules.json`
loads unchanged:

| field | meaning |
|-------|---------|
| `project` | absolute path (canonicalised at creation -- a relative path hashes to the wrong workspace) |
| `target: Option<String>` | `None` = portfolio (rotate all promoted targets); `Some` = one target. An old bare-string `target` deserialises to `Some`. |
| `duration_secs` | one target's fuzz-run length |
| `max_runs` / `max_total_secs` | budget (either, both, or neither) |
| `schedule_id` | injected at creation so the headless dispatcher -- handed only the constant workflow kind -- can key per-campaign state |

## Runtime state -- JSON sidecar, not a DB table

Rotation cursor and budget consumption live in `campaign_state.json` beside
`schedules.json`, via `campaign_state::CampaignStateStore`. **This is deliberate.**
The state is private to the scheduler and is updated atomically with its
schedule definitions, so storing it alongside those definitions keeps one
durability boundary. Shared application data remains in `hf-storage`, whose
single `Store::connect` initializer applies forward-only SQL migrations without
archiving a user's database.

`record_success` advances the target cursor once after a successful campaign
outcome, adds every completed fuzz iteration to `runs_done`, and adds measured
wall-clock campaign work to `secs_done`. Failed attempts and skipped fires do not
consume the success budget. A per-schedule dispatch permit covers reading this
state, executing the campaign, and persisting its result; overlapping fires for
that schedule skip rather than reuse an uncharged allowance. Different schedules
still run concurrently under the global cap.

Each fire passes at most the remaining run count to the campaign operation.
When a time budget is configured, the operation checks the remaining elapsed
allowance before every iteration and caps that fuzzer's requested duration to
the remaining whole-second budget. Elapsed time is measured in completed seconds,
matching the persisted counter and engine duration setting; a one-second budget
therefore permits a one-second run despite fractional setup time. Zero remaining
seconds ends the loop. Qualification,
triage, cancellation, and teardown may finish beyond the time allowance; this
success budget is not a hard process deadline. Refinement is skipped once time
is spent. Interrupted/failed work is not charged under the existing success
accounting; a strict resource-spend budget would require durable reservations
and separate attempt accounting.

Both `campaign_state.json` and `schedules.json` use same-directory temporary
files, file `fsync`, atomic replacement, and parent-directory `fsync`. A missing
file is an empty initial state; an unreadable or corrupt existing file is a
startup error and is preserved for recovery instead of silently resetting
budgets or schedules.

## Each fire (`FuzzCampaignDispatcher::dispatch`)

1. **Budget.** Spent -> record one skip, pause the schedule (via a `Weak<SchedulerManager>`, fire-and-forget so it cannot re-enter the store lock), return.
2. **Concurrency.** `ConcurrencyGate::try_enter` (a resizable CAS-guarded counter). Full -> skip this fire. Skipped, never queued: a short interval over long runs would otherwise pile up unbounded background work.
3. **Rotate.** `schedulable_targets(project)` -> `priority_order` (highest `fit_score` first) -> `rotate(cursor)` picks this fire's target. A single-target campaign narrows to its one target first.
4. **Run** one promoted target through `run_campaign` (engine + language from the harness, never a guess), then atomically record the successful outcome's actual iterations and measured duration. A failed outcome leaves budget state unchanged.
5. **On crashes:** best-effort auto-report (a "Needs Review" report draft), DefectDojo push if configured, and a `CampaignNotice` to the notifier. Failures here are logged, never fatal.

The pure pieces -- `priority_order`, `rotate`, `budget_skip_reason`, the state
store, the gate -- are unit-tested; `schedulable_targets` and the scheduler
surface are integration-tested.

## Concurrency setting + notifier

- The **active fuzz-campaign limit** is persisted in the sidecar and applied
  live to the campaign gate; `CampaignScheduler::{max_concurrent,
  set_max_concurrent}` expose it. A fire that cannot enter this gate is skipped
  instead of queued.
- The **scheduler workflow-dispatch limit** comes from
  `SchedulerConfig.max_concurrent_executions` at scheduler startup. It bounds
  manager-owned workflow tasks and is intentionally separate from the live
  campaign gate.
- Every active fuzz run holds one workflow-dispatch slot and one campaign-gate
  slot, so the effective maximum number of concurrent fuzz runs is the minimum
  of those two limits. `CampaignScheduler::concurrency_limits` returns the
  read-only `CampaignConcurrencyLimits` DTO with
  `active_fuzz_campaign_limit`, `scheduler_workflow_dispatch_limit`, and
  `effective_max_concurrent_fuzz_runs`. Presentation layers must show the two
  controls with these distinct meanings rather than presenting either one as
  the sole global cap.
- The crash notifier is a late-bound slot (`Arc<Mutex<Option<..>>>`): the desktop
  shell only has an `AppHandle` to emit with *after* the scheduler is built, so
  it calls `set_notifier` in Tauri `setup()` to emit `campaign:crash`. CLI/web
  pass `None`. Mirrors the DefectDojo autostart `on_status` pattern.

## Restart and shutdown durability

Every changed `Schedule`, including `last_fire`, is written back to
`schedules.json`. Existing recurring schedule definitions whose cursor predates
this persistence are repaired once from persisted execution history before
recovery is planned. One-time recovery instead loads and validates occurrence
receipts before planning, then reconciles a stale JSON cursor from the durable
receipt timestamp; terminal execution history may have been cleared.

Only one-time triggers use permanent SQLite occurrence receipts. Their admission
first checks global and schedule-specific journal health before any hourly or
other preflight that can mutate the cursor or execution history. Its durable
admission order is receipt+pending transaction -> JSON `last_fire` -> tracked
task -> running transaction -> dispatcher -> terminal transaction. A 60-second
owner lease renews every 15 seconds. Expired non-terminal receipts require
acknowledgement as cancelled and never retry automatically. Recurring schedules
do not use occurrence APIs. SQLite unique constraints, not process-local
scheduler locks or the JSON write mutex, are the cross-process admission
authority. Retrying work requires a newly created one-time schedule with a new
schedule identifier. Acknowledgement cursor reconciliation shares the
service-local mutation-admission boundary with remove and enable/disable,
re-reads the current definition under that boundary, and advances only its
cursor; a removed definition stays absent and a current enabled state is
preserved. An exact terminal transition remains receipt-idempotent after
terminal history clearing only when all permanent receipt metadata matches; the
replay never recreates cleared execution history.

Recovery creates compact batches rather than filling the trigger channel before
its receiver exists. `Skip` advances to the latest due occurrence without
dispatching, `CatchUp` queues one occurrence, and `Backfill` lazily submits every
missed occurrence through the bounded channel. Backfills serialize per schedule;
the scheduler-wide semaphore bounds active workflow execution.

The scheduler retains every spawned workflow task. `stop` first stops trigger
production and queue consumption, then aborts and joins active campaign tasks and
reconciles recurring execution records from `Running` to `Cancelled`. For
one-time tasks, cancellation uses the paired terminal receipt-and-execution
transaction; a failed terminal transition leaves the receipt non-terminal for
acknowledgement after its lease expires. The service-level `CampaignScheduler::stop`
exposes this lifecycle boundary.

## Schedule policy enforcement

`SchedulerConfig` is resolved by `hf-service` at scheduler startup. Its global
workflow-dispatch cap bounds active scheduler tasks, its history limit applies
per schedule (zero means unlimited), and its missed-fire/concurrency defaults
are materialized when a schedule omits an override. Per-schedule policies are
enforced before a workflow starts:

- `allow` permits overlapping executions;
- `skip_if_running` records a visible skipped execution;
- `queue` preserves trigger order and serializes the schedule;
- `cancel_previous` cancels and records the displaced execution before starting
  the newer one;
- `max_executions_per_hour` is a rolling one-hour admission limit over started
  executions; policy skips do not consume it.

Queued work remains `Pending` until it owns both its per-schedule queue position
and a global execution slot. Pending/running rows and started rows still needed
by the rolling-hour limit are protected from history pruning; the configured
display-history cap is restored as those rows finish or age out.

A newly created cron schedule waits for the first calendar occurrence strictly
after its creation time. Recovery uses that same starting point and applies the
configured missed-fire policy only to occurrences that were actually due.
Re-enabling a cron schedule advances its cursor to activation time; disabled
periods are not implicitly replayed. Interval schedules retain their immediate
first-fire behavior. Operator and persisted intervals must be positive and
representable as a Chrono duration; next-date calculation is checked and an
unrepresentable future occurrence is never dispatched.

Cron values may be created as `CRON_TZ=<IANA zone> <five-field expression>`.
The zone is validated at creation, persisted in `TriggerConfig`, and used by
normal evaluation and recovery. Recovery advances through actual cron calendar
occurrences, so month boundaries and daylight-saving transitions are not
approximated as fixed UTC intervals. Legacy unknown zones remain fail-safe UTC
with an operator warning.

## Parameter resolution and event triggers

Before every dispatch the manager resolves the schedule's `parameter_values`
through `hf-scheduler::params`: schema defaults (none today -- an empty object)
-> static schedule overrides -> trigger-time expressions. Supported
expressions: `{{ trigger.time }}`, `{{ trigger.type }}`,
`{{ execution.sequence }}`, and `{{ event.payload.<field> }}`. An expression
that cannot resolve (unknown name, missing event field) **fails the dispatch**:
a `Failed` execution is recorded with the reason and the fire cursor advances,
so a broken template is loud once per fire instead of silently leaking a raw
`{{ ... }}` string into a campaign.

Event-driven schedules (`TriggerConfig::Event`) fire when the service emits a
matching event, not on the evaluation tick. The events the service genuinely
has today:

| event type | emitted at | payload fields |
|------------|-----------|----------------|
| `crash.found` | triage completion with classified crashes (`triage_run_record_inner`) | `project`, `target`, `run_id`, `crashes` |
| `run.completed` | fuzz-run termination, success or cancellation (`run_fuzzer_with_started`) | `project`, `target`, `run_id`, `engine`, `edges`, `execs`, `crashes`, `termination` |
| `run.failed` | a *started* fuzz run terminating with a failure | `project`, `target`, `run_id`, `engine`, `error` |

`ServiceContainer` holds a late-bound, clone-shared `Weak<SchedulerManager>`
slot that `CampaignScheduler::try_start` binds; every surface built from that
container (scheduled or interactive) emits through `SchedulerManager::
emit_event` -> `EventBridge` -> the normal trigger queue, so event fires get
`last_fire`, history, and policy enforcement exactly like cron fires. Errors
before a run becomes durable are rejections and emit nothing. An optional
payload `filter` (glob on a payload field, e.g. `payload.target` = `parse_*`)
and `debounce_secs` narrow and collapse fires. Creation goes through
`parse_trigger("event", "<type>")`; unknown event types are rejected so a typo
can never arm a schedule that can never fire.

## Layering (AGENTS.md 2.9 -- all logic in hf-service)

| Layer | Location |
|-------|----------|
| State + gate | `hf-service/src/campaign_state.rs` |
| Campaign logic | `hf-service/src/scheduler.rs` (`CampaignParams`, dispatcher, `CampaignScheduler`) |
| Target set | `container.rs::schedulable_targets` (`SchedulableTarget` gains `fit_score`) |
| CLI | `hf-cli`: `schedule create --target ""` (empty = portfolio), `--max-runs`, `--max-total-secs` |
| Web | `hf-web`: `POST /schedule` (target optional + budget), `GET/POST /schedule/concurrency`, `GET /schedule/concurrency/limits` |
| Tauri | `commands.rs`: `schedule_create` (target `Option`, budget), `schedule_concurrency_get/set/limits`; notifier bound in `lib.rs` setup |
| GUI | Automation view: folder picker, scope toggle (all/single), budget inputs, editable active-campaign cap plus read-only dispatch/effective limits, per-campaign progress; `campaign:crash` toaster in `App.tsx` |

## Non-goals

- No autonomous harness generation/promotion -- the safety gate is the point.
- No queuing of blocked fires -- skip and record why, so it stays visible and bounded.
