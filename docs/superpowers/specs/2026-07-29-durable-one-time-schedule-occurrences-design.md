# Durable One-Time Schedule Occurrences Design

Status: **approved design**. Owner: `hf-scheduler`, `hf-storage`, and
`hf-service`.

## 1. Goal

Make scheduled one-time fuzz campaigns fail closed and dispatch at most once
across process races, persistence failures, and service restarts.

The first increment is intentionally narrow:

- only `TriggerConfig::OneTime` schedules are covered;
- cron, interval, and event scheduling semantics remain unchanged;
- schedule definitions remain in the existing atomically replaced JSON file;
- SQLite stores durable occurrence receipts and execution history;
- an expired non-terminal receipt requires explicit operator acknowledgement;
- acknowledgement consumes the schedule as cancelled and never retries it; and
- retrying requires a newly created schedule with a new schedule identifier.

This design adopts the durable one-shot occurrence-journal lesson introduced
after the first oxfuzz study of `xai-org/grok-build`. It is a clean-room
oxfuzz design; no upstream implementation code is copied.

## 2. Approved Product Decisions

1. SQLite occurrence receipts are added alongside the existing JSON schedule
   definitions.
2. Reserving an occurrence and creating its pending execution record is one
   SQLite transaction.
3. A one-time campaign cannot enter `WorkflowDispatcher` until its receipt is
   reserved, its pending execution exists, and its JSON fire cursor is durable.
4. A unique schedule identifier can own only one occurrence receipt.
5. Any expired or explicitly released `reserved` or `running` receipt
   quarantines the affected schedule.
6. Structurally corrupt or internally inconsistent occurrence data blocks all
   one-time triggers while leaving cron, interval, and event triggers
   available.
7. A one-time schedule cannot be created or started without configured,
   readable SQLite storage.
8. The only recovery action in this increment is acknowledgement as cancelled.
   It is idempotent and permanently consumes the schedule.
9. Presentation clients render service-owned state and invoke service
   operations. They do not infer journal state or modify storage directly.

## 3. Motivation and Local Gap

`hf-scheduler` currently performs these operations separately:

1. build an in-memory pending `ScheduleExecution`;
2. update the schedule's in-memory `last_fire`;
3. best-effort persist the JSON schedule cursor;
4. best-effort persist the pending execution row; and
5. spawn the asynchronous workflow dispatch.

The persistence helpers log failures and continue. A process can therefore
enter `WorkflowDispatcher` without durable evidence that the occurrence was
consumed. A second process or a restart can observe `last_fire = None` and
dispatch the same one-time fuzz campaign again. Reversing the writes would
trade duplication for a lost campaign rather than closing the gap.

The July 22, 2026 `grok-build` sync added a durable one-shot occurrence journal
and scheduler lifecycle versioning:

<https://github.com/xai-org/grok-build/commit/a5727c5960452e7527a154b25cb5bf00cda0545e>

The applicable lesson is the durable reservation boundary, not
`grok-build`'s scheduler types or agent-specific notification protocol.

## 4. Architectural Ownership

### 4.1 `hf-scheduler`

`hf-scheduler` owns:

- occurrence identifiers, states, and transition validation;
- the storage-agnostic persistence contract;
- ordering reservation, cursor persistence, start, dispatch, and finish;
- the in-memory quarantine set used after a live persistence failure;
- suppression of consumed or quarantined one-time schedules; and
- exact-once entry into `WorkflowDispatcher` after durable admission.

It does not import SQLx, know table names, mutate the schedule JSON file
directly, or expose presentation DTOs.

### 4.2 `hf-storage`

`hf-storage` owns:

- migration `0023_schedule_occurrences.sql`;
- atomic occurrence/execution reservation;
- atomic occurrence/execution state transitions;
- receipt lookup and journal-integrity validation;
- idempotent cancellation acknowledgement; and
- history retention rules that preserve non-terminal execution rows and every
  occurrence receipt.

### 4.3 `hf-service`

`hf-service` owns:

- the production `SchedulerPersistence` implementation;
- requiring SQLite durability for one-time schedule creation and startup;
- reconciling receipts with JSON schedule definitions before ticking;
- operator-facing recovery and campaign-state DTOs;
- presentation-safe error classification; and
- keeping the Automation view consistent across CLI, REST, and desktop modes.

### 4.4 Presentation

`hf-cli`, `hf-web`, and `hf-gui` only:

- list service-owned campaign and recovery DTOs;
- request cancellation acknowledgement by occurrence identifier;
- render durable states and errors; and
- refresh the list returned by the service.

No presentation crate parses receipts, decides whether a schedule is safe,
constructs SQL, or clears a quarantine locally.

### 4.5 `hf-runtime`

This increment grants no new execution authority and does not change runtime
profiles. A reserved campaign still reaches fuzzing only through the existing
`hf-service` dispatcher, harness-approval gate, and `hf-runtime` sandbox.

## 5. Domain Model

`hf-scheduler` adds storage-neutral types equivalent to:

```rust
pub struct OneTimeOccurrence {
    pub id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub triggered_at: DateTime<Utc>,
    pub state: OneTimeOccurrenceState,
    pub owner_id: String,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub recovery_detail: Option<String>,
}

pub enum OneTimeOccurrenceState {
    Reserved,
    Running,
    Completed,
    Failed,
    Cancelled,
}

pub enum OneTimeReservation {
    Reserved(OneTimeOccurrence),
    Existing(OneTimeOccurrence),
}
```

`Reserved` and `Running` are non-terminal. They become recovery-required only
after their ownership lease expires or the owning scheduler explicitly
releases it. `Completed`, `Failed`, and `Cancelled` are terminal. Unknown
strings never degrade to a default state.

`owner_id` is a random scheduler-instance UUID. A non-terminal receipt carries
a renewable `lease_expires_at`; terminal transitions clear the lease. The
lease distinguishes an active campaign in another oxfuzz process from an
orphaned receipt. It is not permission to retry work and does not claim that an
expired owner's sandbox process has stopped.

`recovery_detail` is capped at 4,096 UTF-8 bytes before persistence. It may
contain a bounded operational reason such as a cursor-write failure or
operator acknowledgement. It must not contain project source, prompt content,
captured process output, credentials, or absolute host paths.

The existing `ScheduleExecution` remains the execution-history record.
Occurrence and execution states are updated together, with this mapping:

| Occurrence | Execution |
| --- | --- |
| `reserved` | `pending` |
| `running` | `running` |
| `completed` | `completed` |
| `failed` | `failed` |
| `cancelled` | `cancelled` |

## 6. SQLite Schema

Migration `0023_schedule_occurrences.sql` creates:

```sql
CREATE TABLE schedule_occurrences (
    id              TEXT PRIMARY KEY,
    schedule_id     TEXT NOT NULL UNIQUE,
    execution_id    TEXT NOT NULL UNIQUE,
    triggered_at    TEXT NOT NULL,
    state           TEXT NOT NULL
                    CHECK (state IN (
                        'reserved',
                        'running',
                        'completed',
                        'failed',
                        'cancelled'
                    )),
    owner_id        TEXT NOT NULL,
    lease_expires_at TEXT,
    recovery_detail TEXT
                    CHECK (
                        recovery_detail IS NULL
                        OR length(CAST(recovery_detail AS BLOB)) <= 4096
                    ),
    created_at      TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        (
            state IN ('reserved', 'running')
            AND lease_expires_at IS NOT NULL
        )
        OR (
            state IN ('completed', 'failed', 'cancelled')
            AND lease_expires_at IS NULL
        )
    )
);

CREATE INDEX idx_schedule_occurrences_state
    ON schedule_occurrences(state, lease_expires_at, updated_at);
```

`execution_id` is an intentional soft reference to `schedule_executions`.
There is no foreign key because terminal execution history may be explicitly
cleared while the compact receipt must remain permanently. Unresolved
execution rows are protected from history clearing and pruning.

Receipts are not automatically pruned. Their cardinality is bounded to one per
one-time schedule identifier, and they are the durable at-most-once evidence.
Deleting a schedule definition does not delete its receipt.

## 7. Persistence Contract

`SchedulerPersistence` gains one-time occurrence operations for:

- reserving a receipt and pending execution atomically;
- transitioning a receipt and execution atomically;
- renewing or explicitly releasing a non-terminal ownership lease;
- loading all receipts needed for startup reconciliation;
- looking up a receipt after an ambiguous live error; and
- acknowledging a recovery-eligible receipt as cancelled.

The production adapter treats these operations as required for one-time
schedules. Generic scheduler tests use a deterministic in-memory adapter.
Absence of an adapter never falls back to unsafe one-time dispatch.

### 7.1 Reservation transaction

The reservation transaction:

1. attempts to insert the receipt using its stable occurrence, schedule, and
   execution identifiers;
2. if `schedule_id` already exists, returns the existing receipt without
   inserting a new execution;
3. if the receipt was inserted, inserts the serialized pending execution; and
4. commits both writes together.

The implementation must not use `INSERT OR REPLACE`. A duplicate cannot
overwrite an earlier receipt or execution.

SQLite's unique constraint serializes competing process reservations. At most
one caller receives `OneTimeReservation::Reserved`; every other caller receives
the durable existing receipt or a fail-closed storage error.

The reservation records a 60-second lease owned by the scheduler instance.
While a reserved or running task is live, the scheduler renews that lease every
15 seconds. A renewal uses an owner-and-state compare-and-update; it cannot
revive a terminal receipt or take ownership from another instance.

### 7.2 Transition transaction

Each transition validates the stored source state, the occurrence identifier,
the schedule identifier, and the execution identifier. It then updates the
receipt and serialized execution in one transaction.

Allowed transitions are:

```text
reserved -> running
reserved -> cancelled
running  -> completed
running  -> failed
running  -> cancelled
```

Repeating the exact same transition with the same terminal execution is
idempotent. After explicit history clearing removes that terminal execution,
the replay is receipt-idempotent only when the permanent occurrence,
schedule, execution, owner, destination-state, lease, and recovery-detail
fields all match. The incoming serialized execution cannot be verified after
clearing, is not treated as durable evidence, and is never recreated by this
receipt-only replay. Any permanent receipt mismatch or a different transition
from a terminal state is a conflict and does not modify either row.

Terminal transitions clear `lease_expires_at`. A scheduler that stops before a
terminal transition explicitly releases the lease when possible; if storage is
unavailable, the lease expires naturally.

## 8. Dispatch Protocol

The one-time branch in `SchedulerManager::handle_fired_trigger` uses this
ordering:

1. Load and validate the schedule.
2. Check the global and schedule-specific one-time journal health before any
   preflight that can mutate the cursor or execution history.
3. Apply rate, concurrency, and parameter preflight. If reading persisted
   hourly history fails, latch the global one-time journal block and leave the
   cursor and execution history unchanged; recurring hourly-policy behavior is
   unaffected.
4. Construct stable occurrence and execution identifiers and a pending
   execution record.
5. Reserve the receipt and pending execution transactionally.
6. If an existing receipt is returned, suppress dispatch, align the in-memory
   cursor to the receipt timestamp, and request durable JSON reconciliation.
7. If a new receipt is returned, update the in-memory `last_fire`.
8. Persist the JSON schedule cursor and await success.
9. Spawn and synchronously register the tracked asynchronous task without an
   intervening cancellation point.
10. After the task acquires its serialization and global execution permits,
   transition the receipt and execution to `running`.
11. Only after the running transaction commits, call `WorkflowDispatcher`.
12. Atomically persist the terminal receipt and execution state.

There is no cancellation point between spawning the task and registering its
tracked handle. Existing graceful scheduler shutdown continues to cancel and
join tracked tasks. A cancellation before dispatch transitions a reserved
receipt to `cancelled`; cancellation after the running transition records
`cancelled`.

The lease-renewal task is owned by the same tracked occurrence lifecycle and is
cancelled and joined with it. Losing lease renewal does not stop an already
running sandbox campaign, but it emits a high-severity durability event and
prevents the scheduler from claiming a known terminal transition until storage
is available.

Preflight outcomes that never enter `WorkflowDispatcher` do not create an
occurrence receipt. They retain their existing visible execution outcome.
The at-most-once guarantee applies to entry into the campaign dispatcher, not
to repeated evaluation of an invalid or temporarily policy-blocked schedule.

## 9. Failure Semantics

### Reservation failure

The scheduler does not update `last_fire` and does not dispatch. It quarantines
the schedule in memory. If the receipt can subsequently be read, the scheduler
uses the durable state. If storage remains unreadable, the schedule stays
quarantined.

### JSON cursor failure after reservation

The scheduler does not spawn dispatch. The durable `reserved` receipt remains
non-terminal. The scheduler releases its lease, making the receipt eligible for
operator acknowledgement. Startup reconciliation uses the receipt to suppress
redispatch even though the JSON cursor is stale.

### Running-transition failure

The task does not call `WorkflowDispatcher`. The receipt remains non-terminal,
the schedule is quarantined, and the scheduler releases its lease.

### Terminal-transition failure

The dispatcher result is not rewritten as success. The receipt remains
`running`; the scheduler stops renewing its lease, and recovery reports that
its terminal outcome is unknown after expiry. No automatic redispatch occurs.

### Duplicate reservation

The caller never dispatches. The existing receipt is authoritative even when
the local JSON schedule has no fire cursor.

### Corrupt journal

An invalid state, invalid timestamp, empty identity, contradictory receipt and
execution state, impossible lease shape, or missing non-terminal execution row
makes journal health corrupt. The service starts cron, interval, and event
scheduling but blocks all one-time evaluation and creation. It exposes a
bounded health error and does not delete, rewrite, or guess at damaged
evidence. Startup inspects rows individually and preserves a safely decoded,
non-empty text `schedule_id` before strict receipt conversion. Every identifiable
malformed row quarantines that schedule definition before cursor/history
reconciliation or any schedule-file write. If the schedule identity itself
cannot be decoded, the service quarantines the complete startup definition
snapshot. Later full-snapshot writes restore those captured definitions.
Recurring schedules remain registered and executable in memory, but a
quarantined definition's cursor or direct mutations are not persisted until
the journal is repaired.

## 10. Startup Reconciliation

`CampaignScheduler::try_start` loads and validates occurrence receipts before
the scheduler tick loop begins.

For every receipt whose schedule definition still exists:

- the service confirms that the definition is a one-time trigger;
- it sets a missing or older `last_fire` to `triggered_at`;
- it marks expired or explicitly released `reserved` and `running` receipts as
  recovery-required;
- it treats a non-terminal receipt with an unexpired lease as consumed and
  currently owned by another scheduler instance; and
- it marks terminal receipts as consumed.

The corrected schedule list is atomically written before ticking. Failure to
write the reconciled JSON state prevents one-time ticking; it does not erase
the receipt.

A receipt without a current schedule definition remains queryable recovery
evidence. It does not recreate the schedule. A terminal execution row may be
absent after explicit history clearing; a non-terminal execution row may not.

Receipt loading is performed before recovery planning so missed-fire recovery
cannot synthesize a second one-time occurrence.

## 11. Operator Recovery

`hf-service` exposes:

```rust
pub async fn list_one_time_recoveries(
    &self,
) -> Result<Vec<OneTimeRecoveryView>, CampaignSchedulerError>;

pub async fn acknowledge_one_time_recovery(
    &self,
    occurrence_id: &str,
) -> Result<OneTimeRecoveryView, CampaignSchedulerError>;
```

The recovery DTO contains only:

- occurrence identifier;
- schedule identifier and retained schedule name when available;
- execution identifier;
- trigger timestamp;
- last durable state;
- bounded recovery detail; and
- whether the schedule definition still exists.

Acknowledgement:

1. accepts only `reserved` or `running` with an expired or explicitly released
   lease;
2. atomically sets both receipt and execution to `cancelled`;
3. records a bounded operator-acknowledgement reason;
4. acquires the same schedule-mutation admission guard used by remove and
   enable/disable;
5. re-reads the current schedule definition after acquiring that guard;
6. when the definition still exists, advances only its consumed cursor while
   preserving every current field, including `enabled`, and persists it;
7. when a concurrent remove won admission first, leaves the definition absent;
8. clears only the manager's recovery-required presentation state; and
9. returns the terminal DTO.

Acknowledging an already cancelled receipt returns the same result. Attempting
to acknowledge a completed or failed receipt returns a conflict. The operation
never launches, resumes, or adopts a sandbox process.

The service also rejects acknowledgement when the current manager still owns a
tracked task for the occurrence. The storage transaction repeats the
lease-expiry predicate so an acknowledgement cannot race a heartbeat from
another process. The confirmation text states that acknowledgement records an
unknown prior outcome as cancelled; it does not prove or force termination of
an orphaned sandbox process.

To try the work again, the operator creates a new one-time schedule. The
service generates a new schedule identifier and subjects it to the normal
approval, policy, reservation, and sandbox boundaries.

## 12. Service and Presentation Contract

`CampaignView` gains a service-owned durability status:

```text
ready
consumed
recovery_required
```

Only one-time schedules use `consumed` or `recovery_required`; other trigger
types report `ready`.

CLI adds:

```text
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>
```

REST adds:

```text
GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```

Tauri adds matching `schedule_recovery_list` and
`schedule_recovery_acknowledge` commands.

The Automation view:

- shows a recovery-required warning above scheduled campaigns;
- lists schedule, trigger time, last durable state, and bounded detail;
- requires an explicit confirmation before acknowledgement;
- labels the action "Acknowledge as cancelled"; and
- refreshes campaign, recovery, and history lists after success.

HTTP and Tauri transports preserve the same service DTOs. Missing schedulers
return the existing explicit unavailable behavior for recovery mutation; they
do not return a fabricated empty success.

## 13. History Retention

Schedule-scoped retention continues to protect `pending` and `running`
executions. It also excludes every execution referenced by a non-terminal
receipt.

Explicit history clearing:

- never deletes occurrence receipts;
- never deletes execution rows referenced by `reserved` or `running` receipts;
- may delete terminal execution rows; and
- reports only the number of execution-history rows actually deleted.

This preserves recovery evidence without making ordinary terminal history
undeletable. Exact terminal transition replay remains idempotent from matching
permanent receipt fields and never recreates a cleared execution row.

## 14. Concurrency

The SQLite unique constraint is the cross-process admission authority.
Process-local scheduler locks and the JSON write mutex are not treated as
cross-process coordination.

Two schedulers may evaluate the same stale JSON definition concurrently. They
may both construct candidate identifiers, but only one reservation commits.
Only the winner may persist the cursor and enter `WorkflowDispatcher`. The
loser reads the winning receipt and suppresses its task.

Within one service process, acknowledgement cursor reconciliation, remove, and
enable/disable share one mutation-admission boundary. Whichever operation wins
the boundary first completes its current-definition read and JSON persistence
before the other proceeds. Acknowledgement never re-registers a pre-admission
schedule clone.

An unexpired receipt lease is the cross-process liveness signal for recovery
presentation. Only the owning instance may renew it. Lease expiry makes
acknowledgement possible but never authorizes automatic retry.

Existing JSON schedule mutations remain last-writer-wins across independent
processes. This increment does not claim to solve general cross-process
schedule-definition editing. Reconciliation writes the same receipt timestamp
for the same schedule and therefore does not introduce a competing cursor
value.

## 15. Observability

Structured scheduler events include:

- `occurrence_id`;
- `schedule_id`;
- `execution_id`;
- source and destination state;
- reservation outcome;
- recovery-required reason category; and
- transition duration.

Metrics count reservation wins, duplicate suppressions, transition failures,
lease-renewal failures, expired non-terminal receipts, acknowledgements, and
corrupt-journal blocks.

Logs and metrics exclude project paths, prompts, target source, harness source,
sandbox output, environment values, and credentials.

## 16. Compatibility and Documentation

Migration is additive. Existing `schedule_executions` rows and schedule JSON
remain readable.

Before ticking, one-time definitions created by older versions require SQLite
and receive normal reservation on their first eligible dispatch. Historical
execution rows do not fabricate receipts. If an old one-time definition
already has `last_fire`, it is treated as consumed without backfilling a
receipt.

This is mandatory hardening of the existing scheduler persistence path, not a
new optional subsystem. It therefore has no feature flag and no unsafe fallback
mode. Builds or service containers without SQLite may still use recurring
schedules, but they reject one-time creation and execution.

The implementation updates:

- `docs/design/DESIGN_OVERVIEW.md`;
- `docs/design/portfolio-campaigns.md`;
- `docs/design/service-orchestration-design.md`;
- `docs/standards/DATABASE_SCHEMA.md`;
- CLI and REST documentation where schedule commands are listed; and
- the July 19 grok-build lessons report with a dated follow-up rather than
  rewriting the original research baseline.

## 17. Security and Safety

- No receipt state grants harness approval or fuzzing authority.
- Every actual campaign continues through `hf-service` and `hf-runtime`.
- No generated harness, engine, or crash artifact runs on the host.
- Recovery acknowledgement is terminal bookkeeping, not sandbox adoption or
  execution.
- Untrusted stored strings are bounded and rendered as data.
- Corrupt or unavailable durability evidence fails closed.
- A presentation client cannot clear quarantine by editing its local state.
- Automatic retry is deliberately absent because the prior sandbox outcome may
  be unknown.

## 18. Testing Strategy

### `hf-scheduler` unit tests

- Reservation precedes cursor mutation and task spawn.
- Existing receipts suppress dispatcher entry.
- Reservation failure, cursor failure, and running-transition failure yield
  zero dispatcher calls.
- Terminal-transition failure yields one dispatcher call and an expired
  non-terminal receipt.
- Exact repeated terminal transitions are idempotent.
- Conflicting terminal transitions fail without mutation.
- Heartbeats renew only receipts owned by the current scheduler instance.
- Expired leases never trigger automatic retry.
- Cron, interval, and event paths do not call occurrence APIs.
- Scheduler shutdown cancels and joins a reserved or running one-time task.

### `hf-storage` integration tests

- Receipt and pending execution commit together.
- Forced failure of either insert rolls back both.
- Two concurrent reservations for one schedule produce one winner and one
  existing receipt.
- A competing acknowledgement cannot overtake a valid owner lease.
- State and execution updates commit together.
- Invalid transitions roll back both rows.
- Acknowledgement is idempotent.
- Receipt state, timestamps, identities, and detail limits reject malformed
  data.
- Retention and history clearing preserve non-terminal execution rows and all
  receipts.

### `hf-service` integration tests

- Startup reconciles a stale JSON cursor from a receipt before ticking.
- Restarts at reserved, running, and every terminal state never redispatch.
- Unresolved receipts appear in recovery and campaign DTOs.
- Live receipts with unexpired leases do not appear acknowledgeable.
- Acknowledgement consumes the schedule and survives restart.
- A missing schedule definition does not hide its recovery-eligible receipt.
- A corrupt receipt blocks all one-time schedules while a recurring fixture
  still dispatches.
- Creating or loading a one-time schedule without SQLite fails closed.
- Two service schedulers sharing one database enter the dispatcher at most
  once.

### Presentation tests

- CLI list and acknowledge commands call only the service API.
- REST routes preserve DTOs and return missing/conflict/storage errors.
- Tauri commands contain no recovery decisions.
- HTTP transport maps both recovery commands exactly.
- The Automation view displays recovery state, confirms acknowledgement, and
  refreshes all affected lists.

### Regression and quality gates

Targeted Rust tests use the repository's required filtered `cargo test`
command. Frontend unit tests and the production frontend build run when GUI
files change. The final Rust gates run in this exact order:

1. `cargo fmt --all`
2. `cargo clippy --fix --allow-dirty --workspace -- -D warnings`
3. `cargo clippy --workspace -- -D warnings`
4. `cargo check --workspace`
5. `cargo doc --workspace --no-deps`

## 19. Success Criteria

1. Two processes racing the same one-time schedule produce exactly one
   committed receipt and at most one `WorkflowDispatcher` call.
2. No tested failure point after reservation causes automatic redispatch.
3. Receipt and execution state never commit partially.
4. Every expired non-terminal receipt is visible and requires explicit
   acknowledgement.
5. Acknowledgement is idempotent, survives restart, cannot overtake a valid
   owner lease, and cannot launch work.
6. Recurring schedules continue when a one-time receipt requires recovery.
7. Corrupt journal evidence blocks all one-time execution without blocking
   recurring execution.
8. No code path executes a scheduled fuzz campaign outside `hf-runtime`.
9. CLI, REST, Tauri, and GUI expose one service-owned recovery contract.
10. Targeted tests, frontend verification, and all mandated Rust gates pass.

## 20. Rejected Alternatives

### Store receipts only in `schedules.json`

Rejected because the receipt and execution history cannot commit atomically,
and the process-local JSON mutex does not arbitrate multiple oxfuzz processes.

### Move all schedules into SQLite

Rejected for this increment because it would migrate every trigger type,
rewrite existing schedule CRUD, and combine a broad storage migration with the
at-most-once fix.

### Automatically retry non-terminal receipts

Rejected because a `running` receipt may represent a campaign whose terminal
outcome was lost. Retrying can duplicate expensive or still-active fuzzing.

### Delete the receipt after terminal history is recorded

Rejected because clearing history or losing the JSON cursor would remove the
only durable at-most-once evidence.

### Treat the execution-history row as the receipt

Rejected because current history writes are general-purpose, replaceable,
prunable, and clearable. They do not provide a permanent unique reservation by
schedule identifier.

### Stop the whole scheduler for one recovery-required receipt

Rejected because the failure is isolated to one one-time schedule. Cron,
interval, and event campaigns remain useful and can continue safely.
