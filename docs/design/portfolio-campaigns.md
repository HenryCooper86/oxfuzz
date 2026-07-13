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
`hf-storage`'s migration gate archives-and-recreates the whole database when a
`REQUIRED_TABLES` entry is missing (`migration.rs::schema_shape_matches`), so
adding a `campaign_state` table would wipe every existing user's
targets/harnesses/runs/crashes on the next launch. State only the scheduler owns
has no business forcing that risk on everything else.

`record_run` advances the cursor + budget; it is called **only on a real fuzz
attempt**, never on a skipped fire, so both stay honest across restarts.

## Each fire (`FuzzCampaignDispatcher::dispatch`)

1. **Budget.** Spent -> record one skip, pause the schedule (via a `Weak<SchedulerManager>`, fire-and-forget so it cannot re-enter the store lock), return.
2. **Concurrency.** `ConcurrencyGate::try_enter` (a resizable CAS-guarded counter). Full -> skip this fire. Skipped, never queued: a short interval over long runs would otherwise pile up unbounded background work.
3. **Rotate.** `schedulable_targets(project)` -> `priority_order` (highest `fit_score` first) -> `rotate(cursor)` picks this fire's target. A single-target campaign narrows to its one target first.
4. **Run** one promoted target through `run_campaign` (engine + language from the harness, never a guess), then `record_run` advances state on any real attempt.
5. **On crashes:** best-effort auto-report (a "Needs Review" report draft), DefectDojo push if configured, and a `CampaignNotice` to the notifier. Failures here are logged, never fatal.

The pure pieces -- `priority_order`, `rotate`, `budget_skip_reason`, the state
store, the gate -- are unit-tested; `schedulable_targets` and the scheduler
surface are integration-tested.

## Concurrency setting + notifier

- The global cap is persisted in the sidecar and applied live to the gate;
  `CampaignScheduler::{max_concurrent,set_max_concurrent}` expose it.
- The crash notifier is a late-bound slot (`Arc<Mutex<Option<..>>>`): the desktop
  shell only has an `AppHandle` to emit with *after* the scheduler is built, so
  it calls `set_notifier` in Tauri `setup()` to emit `campaign:crash`. CLI/web
  pass `None`. Mirrors the DefectDojo autostart `on_status` pattern.

## Layering (AGENTS.md 2.9 -- all logic in hf-service)

| Layer | Location |
|-------|----------|
| State + gate | `hf-service/src/campaign_state.rs` |
| Campaign logic | `hf-service/src/scheduler.rs` (`CampaignParams`, dispatcher, `CampaignScheduler`) |
| Target set | `container.rs::schedulable_targets` (`SchedulableTarget` gains `fit_score`) |
| CLI | `hf-cli`: `schedule create --target ""` (empty = portfolio), `--max-runs`, `--max-total-secs` |
| Web | `hf-web`: `POST /schedule` (target optional + budget), `GET/POST /schedule/concurrency` |
| Tauri | `commands.rs`: `schedule_create` (target `Option`, budget), `schedule_concurrency_get/set`; notifier bound in `lib.rs` setup |
| GUI | Automation view: folder picker, scope toggle (all/single), budget inputs, header concurrency control, per-campaign progress; `campaign:crash` toaster in `App.tsx` |

## Non-goals

- No autonomous harness generation/promotion -- the safety gate is the point.
- No queuing of blocked fires -- skip and record why, so it stays visible and bounded.
