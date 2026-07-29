# Durable One-Time Schedule Occurrences Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one-time fuzz-campaign scheduling fail closed and admit at most one workflow dispatch across concurrent processes, persistence failures, and restarts.

**Architecture:** `hf-scheduler` owns a storage-neutral occurrence state machine, admission order, lease lifecycle, quarantine, and observability; `hf-storage` supplies the SQLite transaction boundary that writes occurrence receipts and execution history together. `hf-service` adapts the two layers, reconciles durable receipts before ticking, and owns recovery DTOs and acknowledgement, while CLI, REST, Tauri, and React remain thin presentations.

**Tech Stack:** Rust 2021, Tokio, async-trait, chrono, serde/serde_json, UUID, SQLx/SQLite, tracing, Axum, Clap, Tauri 2, React 19, TypeScript, Vitest.

## Global Constraints

- The approved design is `docs/superpowers/specs/2026-07-29-durable-one-time-schedule-occurrences-design.md`; update it before implementation if any requirement proves impractical.
- This increment applies only to `TriggerConfig::OneTime`; cron, interval, and event behavior must remain unchanged.
- A schedule identifier permanently owns at most one occurrence receipt. Retrying requires a newly created schedule with a new identifier.
- Reserving the receipt and inserting its pending `schedule_executions` row is one SQLite transaction; do not use `INSERT OR REPLACE`.
- Use a 60-second ownership lease and renew it every 15 seconds while reserved or running.
- Cap `recovery_detail` at 4,096 UTF-8 bytes before persistence. Never include source, prompts, process output, credentials, environment values, or absolute host paths.
- Dispatch order is reserve -> durable JSON cursor -> tracked task -> running transaction -> `WorkflowDispatcher` -> terminal transaction.
- Any ambiguous non-terminal receipt fails closed. Lease expiry allows acknowledgement but never automatic retry.
- Recovery acknowledgement records the unknown outcome as cancelled; it does not stop, resume, adopt, or prove termination of an orphaned sandbox process.
- SQLite unique constraints are the cross-process admission authority. In-memory locks and the JSON write mutex are not cross-process coordination.
- Journal absence, corruption, or unavailability blocks one-time creation and execution but must not stop cron, interval, or event schedules.
- This is mandatory hardening, not an optional feature; add no feature flag and no unsafe fallback.
- All fuzz execution continues through `hf-service`, human-approved harness policy, and `hf-runtime`; tests use stub or recording dispatchers and never run a generated harness on the host.
- All business and recovery decisions live in `hf-service`; CLI, REST, Tauri, and React only render DTOs and invoke service methods.
- All Rust production changes follow Red -> Green -> Refactor and contain no inline lint suppression.
- Every `cargo test` command uses the repository-mandated output filter with `set -o pipefail`; the wrapped `grep` may return no lines without hiding Cargo failures.
- Each implementation task ends in one English commit containing only that task's concern.

## File and Interface Map

| Area | Files | Responsibility |
| --- | --- | --- |
| Canonical design | `docs/design/DESIGN_OVERVIEW.md`, `docs/design/portfolio-campaigns.md`, `docs/design/service-orchestration-design.md`, `docs/standards/DATABASE_SCHEMA.md` | Establish ownership, dispatch ordering, recovery semantics, and schema before code changes. |
| Scheduler domain | `crates/hf-scheduler/src/occurrence.rs`, `crates/hf-scheduler/src/lib.rs`, `crates/hf-scheduler/src/manager.rs` | Occurrence types, transition validation, lease constants, runtime quarantine, metrics, persistence contract, and durable dispatch lifecycle. |
| SQLite persistence | `crates/hf-storage/migrations/0023_schedule_occurrences.sql`, `crates/hf-storage/src/schedule_occurrence_store.rs`, `crates/hf-storage/src/lib.rs`, `crates/hf-storage/src/store.rs`, `crates/hf-storage/tests/store.rs` | Receipt schema, atomic reservation/transition/acknowledgement, row loading, and retention protection. |
| Service | `crates/hf-service/src/scheduler.rs` | Production adapter, startup reconciliation, durability status, recovery DTOs, acknowledgement, and shared-database race tests. |
| CLI | `crates/hf-cli/src/main.rs` | Nested recovery list/acknowledge commands and presentation-only formatting. |
| REST | `crates/hf-web/Cargo.toml`, `crates/hf-web/src/router.rs`, `crates/hf-web/tests/api.rs` | Recovery routes, stable HTTP status mapping, and test-only scheduler/storage fixtures. |
| Tauri | `crates/hf-gui/src-tauri/src/commands.rs`, `crates/hf-gui/src-tauri/src/lib.rs` | Thin recovery commands and handler registration. |
| React | `crates/hf-gui/src/lib/httpTransport.ts`, `crates/hf-gui/src/lib/scheduleRecovery.ts`, `crates/hf-gui/src/views/FeatureViews.tsx`, `crates/hf-gui/src/components/ScheduleRecoveryPanel.tsx`, `crates/hf-gui/src/i18n.extra.ts`, `crates/hf-gui/src/__tests__/transport.test.ts`, `crates/hf-gui/src/__tests__/scheduleRecovery.test.ts`, `crates/hf-gui/src/__tests__/scheduleRecoveryPanel.test.tsx` | Shared HTTP/Tauri contract, warning panel, explicit confirmation, refresh, and translations. |
| Operator docs and research | `README.md`, `docs/guides/GETTING_STARTED.md`, `docs/design/grok-build-lessons-20260719.md` | Document recovery commands and record the dated clean-room upstream lesson. |

---

### Task 1: Align the Canonical Scheduler and Database Designs

**Files:**
- Modify: `docs/design/DESIGN_OVERVIEW.md`
- Modify: `docs/design/portfolio-campaigns.md`
- Modify: `docs/design/service-orchestration-design.md`
- Modify: `docs/standards/DATABASE_SCHEMA.md`

**Interfaces:**
- Consumes: the approved specification named in Global Constraints.
- Produces: canonical architecture text and the `schedule_occurrences` schema contract that Tasks 2-6 implement.

- [ ] **Step 1: Run a failing documentation-contract check**

```bash
for file in \
  docs/design/DESIGN_OVERVIEW.md \
  docs/design/portfolio-campaigns.md \
  docs/design/service-orchestration-design.md \
  docs/standards/DATABASE_SCHEMA.md
do
  rg -q 'schedule_occurrences|occurrence receipt' "$file" || {
    echo "missing durable one-time occurrence contract: $file"
    exit 1
  }
done
```

Expected: FAIL on the first canonical document that does not yet describe occurrence receipts.

- [ ] **Step 2: Add the exact ownership and flow contract**

Add this alignment row to `DESIGN_OVERVIEW.md`:

```markdown
| Durable one-time schedule occurrences | hf-scheduler + hf-storage + hf-service | `OneTimeOccurrence`, `OneTimeRecoveryView` | portfolio-campaigns.md + service-orchestration-design.md + DATABASE_SCHEMA.md |
```

Add these exact architectural facts to the owning documents:

```text
portfolio-campaigns.md:
  Only one-time triggers use permanent SQLite occurrence receipts.
  Admission order is receipt+pending transaction -> JSON last_fire -> tracked
  task -> running transaction -> dispatcher -> terminal transaction.
  A 60-second owner lease renews every 15 seconds.
  Expired non-terminal receipts require acknowledgement as cancelled and never
  retry automatically. Recurring schedules do not use occurrence APIs.

service-orchestration-design.md:
  hf-service requires readable SQLite for one-time creation/execution, loads
  and validates receipts before recovery planning, reconciles stale JSON
  cursors before ticking, and owns recovery DTOs plus acknowledgement.
  Corrupt or unavailable receipt evidence blocks one-time work only.

DATABASE_SCHEMA.md:
  Migration 0023 creates permanent schedule_occurrences receipts, one receipt
  per schedule_id and execution_id, non-terminal lease requirements, terminal
  lease clearing, a 4,096-byte recovery_detail check, soft execution references,
  atomic paired transitions, and retention protection.
```

- [ ] **Step 3: Re-run the documentation-contract check**

Run the command from Step 1.

Expected: PASS with no output.

- [ ] **Step 4: Verify the canonical documents do not promise unsafe retry**

```bash
if rg -n -i 'will automatic(ally)? retry|automatic(ally)? retries|retry the same one-time schedule' \
  docs/design/DESIGN_OVERVIEW.md \
  docs/design/portfolio-campaigns.md \
  docs/design/service-orchestration-design.md
then
  exit 1
fi
```

Expected: PASS with no matches.

- [ ] **Step 5: Commit**

```bash
git add docs/design/DESIGN_OVERVIEW.md docs/design/portfolio-campaigns.md \
  docs/design/service-orchestration-design.md docs/standards/DATABASE_SCHEMA.md
git commit -m "docs: align durable one-time scheduling design"
```

---

### Task 2: Add the Storage-Neutral Occurrence State Machine

**Files:**
- Create: `crates/hf-scheduler/src/occurrence.rs`
- Modify: `crates/hf-scheduler/src/lib.rs`
- Modify: `crates/hf-scheduler/src/manager.rs`
- Test: `crates/hf-scheduler/src/occurrence.rs`
- Test: `crates/hf-scheduler/src/manager.rs`

**Interfaces:**
- Consumes: `chrono::DateTime<Utc>`, existing `ScheduleExecution`, and existing `PersistenceError`.
- Produces:

```rust
pub const ONE_TIME_LEASE: Duration = Duration::from_secs(60);
pub const ONE_TIME_HEARTBEAT: Duration = Duration::from_secs(15);
pub const MAX_RECOVERY_DETAIL_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OneTimeOccurrenceState {
    Reserved,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeReservation {
    Reserved(OneTimeOccurrence),
    Existing(OneTimeOccurrence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeOccurrenceTransition {
    pub occurrence_id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub owner_id: String,
    pub from: OneTimeOccurrenceState,
    pub to: OneTimeOccurrenceState,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub recovery_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeTransitionResult {
    Applied(OneTimeOccurrence),
    Idempotent(OneTimeOccurrence),
    Conflict(OneTimeOccurrence),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeAcknowledgement {
    Acknowledged(OneTimeOccurrence),
    AlreadyCancelled(OneTimeOccurrence),
    Conflict(OneTimeOccurrence),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneTimeRuntimeStatus {
    Ready,
    Consumed,
    RecoveryRequired { detail: String },
}
```

`SchedulerPersistence` gains default fail-closed occurrence methods with these signatures, so existing recurring-only test adapters remain source-compatible:

```rust
async fn reserve_one_time_occurrence(
    &self,
    occurrence: &OneTimeOccurrence,
    execution: &ScheduleExecution,
) -> Result<OneTimeReservation, PersistenceError>;

async fn transition_one_time_occurrence(
    &self,
    transition: &OneTimeOccurrenceTransition,
    execution: &ScheduleExecution,
) -> Result<OneTimeTransitionResult, PersistenceError>;

async fn renew_one_time_lease(
    &self,
    occurrence_id: &str,
    owner_id: &str,
    lease_expires_at: DateTime<Utc>,
) -> Result<bool, PersistenceError>;

async fn release_one_time_lease(
    &self,
    occurrence_id: &str,
    owner_id: &str,
    released_at: DateTime<Utc>,
    recovery_detail: &str,
) -> Result<bool, PersistenceError>;

async fn load_one_time_occurrences(
    &self,
) -> Result<Vec<OneTimeOccurrence>, PersistenceError>;

async fn get_one_time_occurrence(
    &self,
    occurrence_id: &str,
) -> Result<Option<OneTimeOccurrence>, PersistenceError>;

async fn get_one_time_execution(
    &self,
    occurrence_id: &str,
) -> Result<Option<ScheduleExecution>, PersistenceError>;

async fn acknowledge_one_time_occurrence(
    &self,
    occurrence_id: &str,
    acknowledged_at: DateTime<Utc>,
    recovery_detail: &str,
    execution: &ScheduleExecution,
) -> Result<OneTimeAcknowledgement, PersistenceError>;
```

- [ ] **Step 1: Write the failing state, lease, and detail tests**

Add tests in `occurrence.rs`:

```rust
fn fixture_occurrence(state: OneTimeOccurrenceState) -> OneTimeOccurrence {
    let terminal = matches!(
        state,
        OneTimeOccurrenceState::Completed
            | OneTimeOccurrenceState::Failed
            | OneTimeOccurrenceState::Cancelled
    );
    OneTimeOccurrence {
        id: "occ-1".to_owned(),
        schedule_id: "schedule-1".to_owned(),
        execution_id: "exec-1".to_owned(),
        triggered_at: Utc::now(),
        state,
        owner_id: "owner-1".to_owned(),
        lease_expires_at: (!terminal)
            .then(|| Utc::now() + chrono::Duration::seconds(60)),
        recovery_detail: None,
    }
}

#[test]
fn transition_table_allows_only_the_approved_edges() {
    use OneTimeOccurrenceState::{Cancelled, Completed, Failed, Reserved, Running};
    assert!(transition_allowed(Reserved, Running));
    assert!(transition_allowed(Reserved, Cancelled));
    assert!(transition_allowed(Running, Completed));
    assert!(transition_allowed(Running, Failed));
    assert!(transition_allowed(Running, Cancelled));
    assert!(!transition_allowed(Reserved, Completed));
    assert!(!transition_allowed(Completed, Running));
    assert!(!transition_allowed(Cancelled, Running));
}

#[test]
fn recovery_requires_an_expired_non_terminal_lease() {
    let now = Utc::now();
    let mut occurrence = fixture_occurrence(OneTimeOccurrenceState::Running);
    occurrence.lease_expires_at = Some(now + chrono::Duration::seconds(1));
    assert!(!occurrence.recovery_eligible(now));
    occurrence.lease_expires_at = Some(now);
    assert!(occurrence.recovery_eligible(now));
    occurrence.state = OneTimeOccurrenceState::Completed;
    occurrence.lease_expires_at = None;
    assert!(!occurrence.recovery_eligible(now));
}

#[test]
fn recovery_detail_is_bounded_by_utf8_bytes() {
    assert_eq!(bounded_recovery_detail("a".repeat(4_096)).unwrap().len(), 4_096);
    assert!(bounded_recovery_detail("界".repeat(1_366)).is_err());
}
```

- [ ] **Step 2: Run the focused tests and verify red**

```bash
set -o pipefail
cargo test -p hf-scheduler occurrence::tests 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because `occurrence` and its state helpers do not exist.

- [ ] **Step 3: Implement the domain model and validation**

Create `occurrence.rs` with the interfaces above and these exact rules:

```rust
pub fn transition_allowed(
    from: OneTimeOccurrenceState,
    to: OneTimeOccurrenceState,
) -> bool {
    matches!(
        (from, to),
        (OneTimeOccurrenceState::Reserved, OneTimeOccurrenceState::Running)
            | (OneTimeOccurrenceState::Reserved, OneTimeOccurrenceState::Cancelled)
            | (OneTimeOccurrenceState::Running, OneTimeOccurrenceState::Completed)
            | (OneTimeOccurrenceState::Running, OneTimeOccurrenceState::Failed)
            | (OneTimeOccurrenceState::Running, OneTimeOccurrenceState::Cancelled)
    )
}

impl OneTimeOccurrence {
    #[must_use]
    pub fn terminal(&self) -> bool {
        matches!(
            self.state,
            OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
                | OneTimeOccurrenceState::Cancelled
        )
    }

    #[must_use]
    pub fn recovery_eligible(&self, now: DateTime<Utc>) -> bool {
        !self.terminal()
            && self
                .lease_expires_at
                .is_some_and(|lease_expires_at| lease_expires_at <= now)
    }

    pub fn validate(&self) -> Result<(), OccurrenceValidationError> {
        if self.id.is_empty()
            || self.schedule_id.is_empty()
            || self.execution_id.is_empty()
            || self.owner_id.is_empty()
        {
            return Err(OccurrenceValidationError::EmptyIdentity);
        }
        if self.terminal() != self.lease_expires_at.is_none() {
            return Err(OccurrenceValidationError::InvalidLeaseShape);
        }
        if let Some(detail) = &self.recovery_detail {
            bounded_recovery_detail(detail.clone())?;
        }
        Ok(())
    }
}

pub fn bounded_recovery_detail(
    detail: impl Into<String>,
) -> Result<String, OccurrenceValidationError> {
    let detail = detail.into();
    if detail.len() > MAX_RECOVERY_DETAIL_BYTES {
        return Err(OccurrenceValidationError::RecoveryDetailTooLarge);
    }
    Ok(detail)
}
```

Use `Display`/`FromStr` for exact lowercase state strings and return an error for every unknown string. Export the new module and public types from `lib.rs`.

- [ ] **Step 4: Add fail-closed default persistence methods**

In `SchedulerPersistence`, add the signatures from **Interfaces**. Each default body must return:

```rust
Err(PersistenceError::new(
    "durable one-time occurrence persistence is unavailable",
))
```

- [ ] **Step 5: Write failing runtime-status and metrics tests**

Add:

```rust
#[tokio::test]
async fn global_one_time_block_overrides_schedule_status() {
    let manager = SchedulerManager::with_defaults();
    manager.mark_one_time_consumed("once").await;
    manager.block_one_time("journal is corrupt").await;
    assert_eq!(
        manager.one_time_block_reason().await.as_deref(),
        Some("journal is corrupt")
    );
    assert!(matches!(
        manager.one_time_runtime_status("once").await,
        OneTimeRuntimeStatus::RecoveryRequired { .. }
    ));
    assert!(matches!(
        manager.one_time_runtime_status("another").await,
        OneTimeRuntimeStatus::RecoveryRequired { .. }
    ));
}

#[test]
fn occurrence_metrics_snapshot_reports_each_counter() {
    let manager = SchedulerManager::with_defaults();
    manager.record_expired_one_time_occurrence();
    manager.record_one_time_acknowledgement();
    manager.record_corrupt_one_time_journal();
    let snapshot = manager.occurrence_metrics();
    assert_eq!(snapshot.expired_non_terminal, 1);
    assert_eq!(snapshot.acknowledgements, 1);
    assert_eq!(snapshot.corrupt_journal_blocks, 1);
}
```

- [ ] **Step 6: Run the runtime-status tests and verify red**

```bash
set -o pipefail
cargo test -p hf-scheduler global_one_time_block_overrides_schedule_status 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because manager-level one-time status and counters do not exist.

- [ ] **Step 7: Add runtime status and occurrence metrics**

Add process-local state to `SchedulerManager`:

```rust
owner_id: String,
one_time_status: Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
one_time_global_block: Arc<Mutex<Option<String>>>,
occurrence_metrics: Arc<OccurrenceMetrics>,
```

Extend tracked tasks at the same time and set both new fields to `None` in the
existing recurring constructor:

```rust
struct TrackedDispatch {
    execution_id: String,
    schedule_id: String,
    occurrence_id: Option<String>,
    owner_id: Option<String>,
    handle: JoinHandle<()>,
}
```

Expose:

```rust
pub fn owner_id(&self) -> &str;
pub async fn block_one_time(&self, detail: impl Into<String>);
pub async fn mark_one_time_consumed(&self, schedule_id: &str);
pub async fn mark_one_time_recovery_required(
    &self,
    schedule_id: &str,
    detail: impl Into<String>,
);
pub async fn clear_one_time_status(&self, schedule_id: &str);
pub async fn one_time_block_reason(&self) -> Option<String>;
pub async fn one_time_runtime_status(&self, schedule_id: &str)
    -> OneTimeRuntimeStatus;
pub fn has_active_occurrence(&self, occurrence_id: &str) -> bool;
pub fn record_expired_one_time_occurrence(&self);
pub fn record_one_time_acknowledgement(&self);
pub fn record_corrupt_one_time_journal(&self);
pub fn occurrence_metrics(&self) -> OccurrenceMetricsSnapshot;
```

`OccurrenceMetricsSnapshot` contains `reservation_wins`, `duplicate_suppressions`, `transition_failures`, `lease_renewal_failures`, `expired_non_terminal`, `acknowledgements`, and `corrupt_journal_blocks`, all `u64`. Implement the collector with `AtomicU64` and `Ordering::Relaxed`.

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OccurrenceMetricsSnapshot {
    pub reservation_wins: u64,
    pub duplicate_suppressions: u64,
    pub transition_failures: u64,
    pub lease_renewal_failures: u64,
    pub expired_non_terminal: u64,
    pub acknowledgements: u64,
    pub corrupt_journal_blocks: u64,
}
```

`OccurrenceMetrics` supplies
`record_reservation_win`, `record_duplicate_suppression`,
`record_transition_failure`, `record_lease_renewal_failure`,
`record_expired_non_terminal`, `record_acknowledgement`,
`record_corrupt_journal_block`, and `snapshot`; every record method performs
one `fetch_add(1, Ordering::Relaxed)`, matching the existing lightweight
provider-metrics style.

Initialize `owner_id` with `Uuid::new_v4().to_string()` in
`SchedulerManager::new`. `one_time_runtime_status` checks
`one_time_global_block` first and returns `RecoveryRequired` for every schedule
when it is set; otherwise it returns the schedule entry or `Ready`.
`clear_one_time_status` removes only a schedule entry and never clears the
global journal block. `has_active_occurrence` prunes finished tracked handles
and compares the optional `TrackedDispatch.occurrence_id`.

- [ ] **Step 8: Run scheduler tests**

```bash
set -o pipefail
cargo test -p hf-scheduler 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/hf-scheduler/src/occurrence.rs \
  crates/hf-scheduler/src/lib.rs crates/hf-scheduler/src/manager.rs
git commit -m "feat: define one-time occurrence state machine"
```

---

### Task 3: Add the SQLite Receipt Repository and Atomic Transactions

**Files:**
- Create: `crates/hf-storage/migrations/0023_schedule_occurrences.sql`
- Create: `crates/hf-storage/src/schedule_occurrence_store.rs`
- Modify: `crates/hf-storage/src/lib.rs`
- Modify: `crates/hf-storage/src/store.rs`
- Modify: `crates/hf-storage/tests/store.rs`

**Interfaces:**
- Consumes: string/JSON projections from the `hf-service` adapter; `hf-storage` must not depend on `hf-scheduler`.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleOccurrenceRecord {
    pub id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub triggered_at: String,
    pub state: String,
    pub owner_id: String,
    pub lease_expires_at: Option<String>,
    pub recovery_detail: Option<String>,
    pub execution_status: Option<String>,
    pub execution_data_json: Option<String>,
}

pub struct NewScheduleOccurrence {
    pub id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub triggered_at: String,
    pub owner_id: String,
    pub lease_expires_at: String,
    pub execution_status: String,
    pub execution_data_json: String,
}

pub enum ScheduleOccurrenceReservation {
    Reserved(ScheduleOccurrenceRecord),
    Existing(ScheduleOccurrenceRecord),
}

pub struct ScheduleOccurrenceTransition {
    pub occurrence_id: String,
    pub schedule_id: String,
    pub execution_id: String,
    pub owner_id: String,
    pub from_state: String,
    pub to_state: String,
    pub lease_expires_at: Option<String>,
    pub recovery_detail: Option<String>,
    pub execution_status: String,
    pub execution_data_json: String,
}

pub enum ScheduleOccurrenceTransitionResult {
    Applied(ScheduleOccurrenceRecord),
    Idempotent(ScheduleOccurrenceRecord),
    Conflict(ScheduleOccurrenceRecord),
    Missing,
}

pub enum ScheduleOccurrenceAcknowledgement {
    Acknowledged(ScheduleOccurrenceRecord),
    AlreadyCancelled(ScheduleOccurrenceRecord),
    Conflict(ScheduleOccurrenceRecord),
    Missing,
}
```

`Store` adds:

```rust
pub async fn reserve_schedule_occurrence(
    &self,
    new: &NewScheduleOccurrence,
) -> Result<ScheduleOccurrenceReservation, StorageError>;

pub async fn transition_schedule_occurrence(
    &self,
    transition: &ScheduleOccurrenceTransition,
) -> Result<ScheduleOccurrenceTransitionResult, StorageError>;

pub async fn renew_schedule_occurrence_lease(
    &self,
    occurrence_id: &str,
    owner_id: &str,
    lease_expires_at: &str,
) -> Result<bool, StorageError>;

pub async fn release_schedule_occurrence_lease(
    &self,
    occurrence_id: &str,
    owner_id: &str,
    released_at: &str,
    recovery_detail: &str,
) -> Result<bool, StorageError>;

pub async fn schedule_occurrence(
    &self,
    occurrence_id: &str,
) -> Result<Option<ScheduleOccurrenceRecord>, StorageError>;

pub async fn list_schedule_occurrences(
    &self,
) -> Result<Vec<ScheduleOccurrenceRecord>, StorageError>;

pub async fn acknowledge_schedule_occurrence(
    &self,
    occurrence_id: &str,
    acknowledged_at: &str,
    recovery_detail: &str,
    execution_status: &str,
    execution_data_json: &str,
) -> Result<ScheduleOccurrenceAcknowledgement, StorageError>;
```

- [ ] **Step 1: Write failing migration and reservation tests**

In `crates/hf-storage/tests/store.rs`, add:

```rust
#[tokio::test]
async fn occurrence_reservation_commits_receipt_and_pending_execution_together() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    let result = store.reserve_schedule_occurrence(&new).await.unwrap();
    assert!(matches!(result, ScheduleOccurrenceReservation::Reserved(_)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-1' AND status = 'pending'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn duplicate_schedule_reservation_returns_existing_without_second_execution() {
    let (store, _dir) = temp_store().await;
    store
        .reserve_schedule_occurrence(&new_occurrence("occ-1", "schedule-1", "exec-1"))
        .await
        .unwrap();
    let duplicate = store
        .reserve_schedule_occurrence(&new_occurrence("occ-2", "schedule-1", "exec-2"))
        .await
        .unwrap();
    assert!(matches!(duplicate, ScheduleOccurrenceReservation::Existing(_)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn occurrence_constraints_reject_unknown_state_and_oversized_detail() {
    let (store, _dir) = temp_store().await;
    let unknown = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES ('bad-state', 'schedule-a', 'exec-a', ?1, 'invented', 'owner', ?2)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind((Utc::now() + Duration::seconds(60)).to_rfc3339())
    .execute(store.pool())
    .await;
    assert!(unknown.is_err());

    let oversized = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id,
             lease_expires_at, recovery_detail)
         VALUES ('bad-detail', 'schedule-b', 'exec-b', ?1, 'reserved',
                 'owner', ?2, ?3)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind((Utc::now() + Duration::seconds(60)).to_rfc3339())
    .bind("x".repeat(4_097))
    .execute(store.pool())
    .await;
    assert!(oversized.is_err());
}
```

Use these storage-only helpers; the infrastructure crate does not import scheduler types:

```rust
fn execution_json(
    execution_id: &str,
    schedule_id: &str,
    triggered_at: &str,
    status: &str,
) -> String {
    serde_json::json!({
        "execution_id": execution_id,
        "schedule_id": schedule_id,
        "triggered_at": triggered_at,
        "started_at": if status == "running" {
            Some(triggered_at)
        } else {
            None::<&str>
        },
        "completed_at": None::<&str>,
        "status": status,
        "workflow_execution_id": null,
        "request_summary": {},
        "response_summary": {},
        "error_message": null,
    })
    .to_string()
}

fn new_occurrence(
    id: &str,
    schedule_id: &str,
    execution_id: &str,
) -> NewScheduleOccurrence {
    let triggered_at = Utc::now().to_rfc3339();
    NewScheduleOccurrence {
        id: id.to_owned(),
        schedule_id: schedule_id.to_owned(),
        execution_id: execution_id.to_owned(),
        triggered_at: triggered_at.clone(),
        owner_id: "owner-1".to_owned(),
        lease_expires_at: (Utc::now() + Duration::seconds(60)).to_rfc3339(),
        execution_status: "pending".to_owned(),
        execution_data_json: execution_json(
            execution_id,
            schedule_id,
            &triggered_at,
            "pending",
        ),
    }
}

fn transition(
    new: &NewScheduleOccurrence,
    from_state: &str,
    to_state: &str,
    execution_status: &str,
) -> ScheduleOccurrenceTransition {
    ScheduleOccurrenceTransition {
        occurrence_id: new.id.clone(),
        schedule_id: new.schedule_id.clone(),
        execution_id: new.execution_id.clone(),
        owner_id: new.owner_id.clone(),
        from_state: from_state.to_owned(),
        to_state: to_state.to_owned(),
        lease_expires_at: (to_state == "running")
            .then(|| (Utc::now() + Duration::seconds(60)).to_rfc3339()),
        recovery_detail: None,
        execution_status: execution_status.to_owned(),
        execution_data_json: execution_json(
            &new.execution_id,
            &new.schedule_id,
            &new.triggered_at,
            execution_status,
        ),
    }
}
```

- [ ] **Step 2: Run the focused storage tests and verify red**

```bash
set -o pipefail
cargo test -p hf-storage occurrence_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because migration `0023` and the repository API do not exist.

- [ ] **Step 3: Add migration `0023_schedule_occurrences.sql`**

Use:

```sql
CREATE TABLE schedule_occurrences (
    id TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL UNIQUE,
    execution_id TEXT NOT NULL UNIQUE,
    triggered_at TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('reserved', 'running', 'completed', 'failed', 'cancelled')),
    owner_id TEXT NOT NULL,
    lease_expires_at TEXT,
    recovery_detail TEXT
        CHECK (
            recovery_detail IS NULL
            OR length(CAST(recovery_detail AS BLOB)) <= 4096
        ),
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (
        (state IN ('reserved', 'running') AND lease_expires_at IS NOT NULL)
        OR
        (state IN ('completed', 'failed', 'cancelled') AND lease_expires_at IS NULL)
    )
);

CREATE INDEX idx_schedule_occurrences_state
    ON schedule_occurrences(state, lease_expires_at, updated_at);
```

Do not add a foreign key from `execution_id`; terminal history is intentionally clearable.

- [ ] **Step 4: Implement atomic reservation**

Create `schedule_occurrence_store.rs`, export its types from `lib.rs`, and implement the repository as inherent `Store` methods. Reservation must use:

```rust
if new.id.is_empty()
    || new.schedule_id.is_empty()
    || new.execution_id.is_empty()
    || new.owner_id.is_empty()
    || new.execution_status != "pending"
{
    return Err(StorageError::InvalidData(
        "invalid one-time occurrence reservation".to_owned(),
    ));
}

let mut transaction = self.pool().begin().await?;
let inserted = sqlx::query(
    "INSERT INTO schedule_occurrences
        (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
     VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?6)
     ON CONFLICT(schedule_id) DO NOTHING",
)
.bind(&new.id)
.bind(&new.schedule_id)
.bind(&new.execution_id)
.bind(&new.triggered_at)
.bind(&new.owner_id)
.bind(&new.lease_expires_at)
.execute(&mut *transaction)
.await?;

if inserted.rows_affected() == 0 {
    let existing = load_by_schedule(&mut transaction, &new.schedule_id).await?;
    transaction.commit().await?;
    return Ok(ScheduleOccurrenceReservation::Existing(existing));
}

sqlx::query(
    "INSERT INTO schedule_executions
        (id, schedule_id, triggered_at, status, data_json)
     VALUES (?1, ?2, ?3, ?4, ?5)",
)
.bind(&new.execution_id)
.bind(&new.schedule_id)
.bind(&new.triggered_at)
.bind(&new.execution_status)
.bind(&new.execution_data_json)
.execute(&mut *transaction)
.await?;
transaction.commit().await?;
```

Read methods use a `LEFT JOIN schedule_executions` so a terminal receipt remains readable after history clearing.

- [ ] **Step 5: Re-run reservation tests and verify green**

```bash
set -o pipefail
cargo test -p hf-storage occurrence_reservation_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-storage duplicate_schedule_reservation_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 6: Add failing transition, lease, acknowledgement, and race tests**

Add these separate tests:

```rust
#[tokio::test]
async fn transition_updates_receipt_and_execution_in_one_transaction() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .transition_schedule_occurrence(&transition(
            &new,
            "reserved",
            "running",
            "running",
        ))
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceTransitionResult::Applied(_)
    ));
    let states: (String, String) = sqlx::query_as(
        "SELECT o.state, e.status
         FROM schedule_occurrences o
         JOIN schedule_executions e ON e.id = o.execution_id
         WHERE o.id = 'occ-1'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(states, ("running".to_owned(), "running".to_owned()));
}

#[tokio::test]
async fn invalid_transition_changes_neither_row() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .transition_schedule_occurrence(&transition(
            &new,
            "reserved",
            "completed",
            "completed",
        ))
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceTransitionResult::Conflict(_)
    ));
    let states: (String, String) = sqlx::query_as(
        "SELECT o.state, e.status
         FROM schedule_occurrences o
         JOIN schedule_executions e ON e.id = o.execution_id
         WHERE o.id = 'occ-1'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(states, ("reserved".to_owned(), "pending".to_owned()));
}

#[tokio::test]
async fn exact_terminal_repeat_is_idempotent_but_different_terminal_is_a_conflict() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(
            &new,
            "reserved",
            "running",
            "running",
        ))
        .await
        .unwrap();
    let completed = transition(&new, "running", "completed", "completed");
    store
        .transition_schedule_occurrence(&completed)
        .await
        .unwrap();
    assert!(matches!(
        store
            .transition_schedule_occurrence(&completed)
            .await
            .unwrap(),
        ScheduleOccurrenceTransitionResult::Idempotent(_)
    ));
    assert!(matches!(
        store
            .transition_schedule_occurrence(&transition(
                &new,
                "running",
                "failed",
                "failed",
            ))
            .await
            .unwrap(),
        ScheduleOccurrenceTransitionResult::Conflict(_)
    ));
}

#[tokio::test]
async fn acknowledgement_cannot_overtake_an_unexpired_lease() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &Utc::now().to_rfc3339(),
            "operator acknowledgement",
            "cancelled",
            &execution_json(
                &new.execution_id,
                &new.schedule_id,
                &new.triggered_at,
                "cancelled",
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceAcknowledgement::Conflict(_)
    ));
}

#[tokio::test]
async fn lease_renewal_requires_the_current_owner() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let original = store
        .schedule_occurrence(&new.id)
        .await
        .unwrap()
        .unwrap()
        .lease_expires_at;
    assert!(
        !store
            .renew_schedule_occurrence_lease(
                &new.id,
                "different-owner",
                &(Utc::now() + Duration::seconds(120)).to_rfc3339(),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .schedule_occurrence(&new.id)
            .await
            .unwrap()
            .unwrap()
            .lease_expires_at,
        original
    );
}

#[tokio::test]
async fn acknowledgement_is_idempotent_after_expiry() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let now = Utc::now().to_rfc3339();
    assert!(
        store
            .release_schedule_occurrence_lease(
                &new.id,
                &new.owner_id,
                &now,
                "released for recovery",
            )
            .await
            .unwrap()
    );
    let cancelled = execution_json(
        &new.execution_id,
        &new.schedule_id,
        &new.triggered_at,
        "cancelled",
    );
    let first = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &now,
            "operator acknowledgement",
            "cancelled",
            &cancelled,
        )
        .await
        .unwrap();
    let second = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &now,
            "operator acknowledgement",
            "cancelled",
            &cancelled,
        )
        .await
        .unwrap();
    assert!(matches!(
        first,
        ScheduleOccurrenceAcknowledgement::Acknowledged(_)
    ));
    assert!(matches!(
        second,
        ScheduleOccurrenceAcknowledgement::AlreadyCancelled(_)
    ));
}

#[tokio::test]
async fn concurrent_reservations_have_one_winner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("race.db");
    let first = Store::connect(&path).await.unwrap();
    let second = Store::connect(&path).await.unwrap();
    let candidate_a = new_occurrence("occ-a", "schedule-1", "exec-a");
    let candidate_b = new_occurrence("occ-b", "schedule-1", "exec-b");
    let (a, b) = tokio::join!(
        first.reserve_schedule_occurrence(&candidate_a),
        second.reserve_schedule_occurrence(&candidate_b),
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ScheduleOccurrenceReservation::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ScheduleOccurrenceReservation::Existing(_)))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(first.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(first.pool())
        .await
        .unwrap(),
        1
    );
}
```

Add the rollback test:

```rust
#[tokio::test]
async fn execution_insert_failure_rolls_back_receipt() {
    let (store, _dir) = temp_store().await;
    store
        .upsert_schedule_execution(
            "exec-conflict",
            "other-schedule",
            &Utc::now().to_rfc3339(),
            "completed",
            "{}",
        )
        .await
        .unwrap();
    let new = new_occurrence("occ-rollback", "schedule-1", "exec-conflict");
    assert!(store.reserve_schedule_occurrence(&new).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE id = 'occ-rollback'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn receipt_insert_failure_never_creates_an_execution() {
    let (store, _dir) = temp_store().await;
    store
        .reserve_schedule_occurrence(&new_occurrence(
            "occ-conflict",
            "schedule-a",
            "exec-a",
        ))
        .await
        .unwrap();
    let conflicting = new_occurrence("occ-conflict", "schedule-b", "exec-b");
    assert!(
        store
            .reserve_schedule_occurrence(&conflicting)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-b'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}
```

- [ ] **Step 7: Run transition and acknowledgement tests and verify red**

```bash
set -o pipefail
cargo test -p hf-storage transition_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-storage acknowledgement_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because transition, lease, and acknowledgement methods are
absent.

- [ ] **Step 8: Implement atomic transition, renewal, release, and acknowledgement**

Before opening the write transaction, accept only these exact string pairs:

```rust
let allowed = matches!(
    (
        transition.from_state.as_str(),
        transition.to_state.as_str(),
    ),
    ("reserved", "running")
        | ("reserved", "cancelled")
        | ("running", "completed")
        | ("running", "failed")
        | ("running", "cancelled")
);
if !allowed {
    let current = self
        .schedule_occurrence(&transition.occurrence_id)
        .await?;
    return Ok(current.map_or(
        ScheduleOccurrenceTransitionResult::Missing,
        ScheduleOccurrenceTransitionResult::Conflict,
    ));
}
if transition.occurrence_id.is_empty()
    || transition.schedule_id.is_empty()
    || transition.execution_id.is_empty()
    || transition.owner_id.is_empty()
    || transition.execution_status != transition.to_state
{
    return Err(StorageError::InvalidData(
        "invalid one-time occurrence transition".to_owned(),
    ));
}
```

Transition uses an `UPDATE` predicate over every identity and the expected owner/state:

```sql
UPDATE schedule_occurrences
SET state = ?1,
    lease_expires_at = ?2,
    recovery_detail = ?3,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?4
  AND schedule_id = ?5
  AND execution_id = ?6
  AND owner_id = ?7
  AND state = ?8
```

Only after that update affects one row, update the existing execution with plain `UPDATE`. Require that execution update to affect exactly one row; otherwise return `StorageError::InvalidData("occurrence execution is missing".to_owned())` without committing so the receipt update rolls back. Then commit. If the receipt predicate affects zero rows, load the current row. Return `Idempotent` only when every occurrence identity, owner, destination state, lease, recovery detail, execution status, and serialized execution exactly match the requested terminal write; return `Conflict` for every other existing row and `Missing` when absent. Never modify execution history on the zero-row path.

Renewal uses:

```sql
UPDATE schedule_occurrences
SET lease_expires_at = ?1,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?2
  AND owner_id = ?3
  AND state IN ('reserved', 'running')
```

Release uses the same owner/state predicate and sets `lease_expires_at` to `released_at`, not `NULL`, preserving the migration's non-terminal lease invariant.

Acknowledgement must repeat the expiry predicate in its write:

```sql
UPDATE schedule_occurrences
SET state = 'cancelled',
    lease_expires_at = NULL,
    recovery_detail = ?1,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE id = ?2
  AND state IN ('reserved', 'running')
  AND julianday(lease_expires_at) <= julianday(?3)
```

Reject an acknowledgement input unless `execution_status == "cancelled"` and
the bounded detail is at most 4,096 bytes. On an applied acknowledgement,
update the referenced execution to `cancelled` in the same transaction and
require exactly one affected execution row before commit. A missing execution
rolls back the receipt cancellation as corrupt non-terminal evidence. An
existing `cancelled` row returns `AlreadyCancelled`; `completed`, `failed`, an
unexpired lease, or a failed repeated predicate returns `Conflict`.

- [ ] **Step 9: Write the unresolved-history retention test**

First add:

```rust
#[tokio::test]
async fn history_deletion_preserves_non_terminal_receipt_executions_and_all_receipts() {
    let (store, _dir) = temp_store().await;
    let protected = new_occurrence("occ-live", "schedule-live", "exec-live");
    store
        .reserve_schedule_occurrence(&protected)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE schedule_executions
         SET status = 'completed', triggered_at = '2020-01-01T00:00:00Z'
         WHERE id = 'exec-live'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store
        .upsert_schedule_execution(
            "old-history",
            "schedule-live",
            "2020-01-01T00:00:00Z",
            "completed",
            "{}",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .prune_schedule_executions("schedule-live", 0)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-live'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );

    let terminal = new_occurrence("occ-done", "schedule-done", "exec-done");
    store
        .reserve_schedule_occurrence(&terminal)
        .await
        .unwrap();
    store
        .transition_schedule_occurrence(&transition(
            &terminal,
            "reserved",
            "running",
            "running",
        ))
        .await
        .unwrap();
    store
        .transition_schedule_occurrence(&transition(
            &terminal,
            "running",
            "completed",
            "completed",
        ))
        .await
        .unwrap();

    assert_eq!(store.clear_schedule_executions().await.unwrap(), 1);
    let remaining: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM schedule_executions ORDER BY id",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(remaining, ["exec-live"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schedule_occurrences")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        2
    );
}
```

- [ ] **Step 10: Run the retention test and verify red**

```bash
set -o pipefail
cargo test -p hf-storage \
  history_deletion_preserves_non_terminal_receipt_executions_and_all_receipts 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because the deliberately terminal-looking `exec-live` row is
deleted despite its non-terminal receipt.

- [ ] **Step 11: Protect unresolved history in both deletion paths**

Add this predicate to both delete statements:

```sql
AND id NOT IN (
    SELECT execution_id
    FROM schedule_occurrences
    WHERE state IN ('reserved', 'running')
)
```

Keep the existing pending/running and rolling-hour protections.

- [ ] **Step 12: Run all storage tests**

```bash
set -o pipefail
cargo test -p hf-storage 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add crates/hf-storage/migrations/0023_schedule_occurrences.sql \
  crates/hf-storage/src/schedule_occurrence_store.rs crates/hf-storage/src/lib.rs \
  crates/hf-storage/src/store.rs crates/hf-storage/tests/store.rs
git commit -m "feat: persist one-time occurrence receipts atomically"
```

---

### Task 4: Enforce Durable One-Time Admission Before Dispatch

**Files:**
- Modify: `crates/hf-scheduler/src/manager.rs`
- Test: `crates/hf-scheduler/src/manager.rs`

**Interfaces:**
- Consumes: Task 2 occurrence types and `SchedulerPersistence` methods.
- Produces: a dedicated one-time branch in `SchedulerManager::handle_fired_trigger` that returns before the unchanged recurring branch; one-time execution can reach `WorkflowDispatcher` only after a winning receipt reservation and durable JSON cursor.

- [ ] **Step 1: Extend the recording persistence adapter for deterministic occurrence failures**

Add these test helpers beside `RecordingPersistence`:

```rust
#[derive(Default)]
struct CountingDispatcher {
    workflows: AsyncMutex<Vec<String>>,
}

impl CountingDispatcher {
    async fn calls_for(&self, workflow_id: &str) -> usize {
        self.workflows
            .lock()
            .await
            .iter()
            .filter(|seen| seen.as_str() == workflow_id)
            .count()
    }

    async fn total_calls(&self) -> usize {
        self.workflows.lock().await.len()
    }
}

#[async_trait::async_trait]
impl WorkflowDispatcher for CountingDispatcher {
    async fn dispatch(
        &self,
        workflow_id: &str,
        _parameter_values: serde_json::Value,
    ) -> Result<DispatchResult, DispatchError> {
        self.workflows.lock().await.push(workflow_id.to_owned());
        Ok(DispatchResult {
            success: true,
            summary: "ok".to_owned(),
            output: serde_json::Value::Null,
            duration_ms: 1,
            error: None,
        })
    }
}

fn due_one_time(id: &str) -> Schedule {
    Schedule::new(
        id,
        id,
        TriggerConfig::OneTime {
            at: Utc::now() - chrono::Duration::seconds(1),
        },
        id,
    )
}

fn interval_schedule(id: &str) -> Schedule {
    Schedule::new(
        id,
        id,
        TriggerConfig::Interval { interval_secs: 3_600 },
        id,
    )
}

async fn wait_for_dispatches(dispatcher: &CountingDispatcher, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while dispatcher.total_calls().await < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dispatcher did not receive expected calls");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OccurrenceFailure {
    None,
    Reserve,
    Cursor,
    Running,
    Terminal,
    Renew,
}

struct OccurrenceRecordingPersistence {
    failure: OccurrenceFailure,
    occurrence: AsyncMutex<Option<OneTimeOccurrence>>,
    execution: AsyncMutex<Option<ScheduleExecution>>,
    transitions: AsyncMutex<Vec<(OneTimeOccurrenceState, OneTimeOccurrenceState)>>,
    renewals: AsyncMutex<Vec<(String, String)>>,
    occurrence_calls: AtomicUsize,
}

impl OccurrenceRecordingPersistence {
    fn new(failure: OccurrenceFailure) -> Self {
        Self {
            failure,
            occurrence: AsyncMutex::new(None),
            execution: AsyncMutex::new(None),
            transitions: AsyncMutex::new(Vec::new()),
            renewals: AsyncMutex::new(Vec::new()),
            occurrence_calls: AtomicUsize::new(0),
        }
    }
}
```

Use this behavior in its `SchedulerPersistence` implementation:

```rust
#[async_trait::async_trait]
impl SchedulerPersistence for OccurrenceRecordingPersistence {
    async fn record_execution(
        &self,
        _execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        Ok(())
    }

    async fn update_execution(
        &self,
        _execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        Ok(())
    }

    async fn update_schedule(&self, _schedule: &Schedule) -> Result<(), PersistenceError> {
        if self.failure == OccurrenceFailure::Cursor {
            Err(PersistenceError::new("injected cursor failure"))
        } else {
            Ok(())
        }
    }

    async fn reserve_one_time_occurrence(
        &self,
        candidate: &OneTimeOccurrence,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeReservation, PersistenceError> {
        self.occurrence_calls.fetch_add(1, Ordering::SeqCst);
        if self.failure == OccurrenceFailure::Reserve {
            return Err(PersistenceError::new("injected reserve failure"));
        }
        let mut stored = self.occurrence.lock().await;
        if let Some(existing) = stored.as_ref() {
            return Ok(OneTimeReservation::Existing(existing.clone()));
        }
        *stored = Some(candidate.clone());
        *self.execution.lock().await = Some(execution.clone());
        Ok(OneTimeReservation::Reserved(candidate.clone()))
    }

    async fn transition_one_time_occurrence(
        &self,
        transition: &OneTimeOccurrenceTransition,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeTransitionResult, PersistenceError> {
        if (transition.to == OneTimeOccurrenceState::Running
            && self.failure == OccurrenceFailure::Running)
            || (transition.to != OneTimeOccurrenceState::Running
                && self.failure == OccurrenceFailure::Terminal)
        {
            return Err(PersistenceError::new("injected transition failure"));
        }
        let mut stored = self.occurrence.lock().await;
        let Some(current) = stored.as_mut() else {
            return Ok(OneTimeTransitionResult::Missing);
        };
        if current.state == transition.to {
            return Ok(OneTimeTransitionResult::Idempotent(current.clone()));
        }
        if current.state != transition.from
            || current.id != transition.occurrence_id
            || current.schedule_id != transition.schedule_id
            || current.execution_id != transition.execution_id
            || current.owner_id != transition.owner_id
        {
            return Ok(OneTimeTransitionResult::Conflict(current.clone()));
        }
        self.transitions
            .lock()
            .await
            .push((transition.from, transition.to));
        current.state = transition.to;
        current.lease_expires_at = transition.lease_expires_at;
        current.recovery_detail.clone_from(&transition.recovery_detail);
        *self.execution.lock().await = Some(execution.clone());
        Ok(OneTimeTransitionResult::Applied(current.clone()))
    }

    async fn renew_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, PersistenceError> {
        self.renewals
            .lock()
            .await
            .push((occurrence_id.to_owned(), owner_id.to_owned()));
        if self.failure == OccurrenceFailure::Renew {
            return Err(PersistenceError::new("injected renew failure"));
        }
        let mut stored = self.occurrence.lock().await;
        let updated = stored.as_mut().is_some_and(|current| {
            if current.id == occurrence_id
                && current.owner_id == owner_id
                && !current.terminal()
            {
                current.lease_expires_at = Some(lease_expires_at);
                true
            } else {
                false
            }
        });
        Ok(updated)
    }

    async fn release_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        released_at: DateTime<Utc>,
        recovery_detail: &str,
    ) -> Result<bool, PersistenceError> {
        let mut stored = self.occurrence.lock().await;
        let updated = stored.as_mut().is_some_and(|current| {
            if current.id == occurrence_id
                && current.owner_id == owner_id
                && !current.terminal()
            {
                current.lease_expires_at = Some(released_at);
                current.recovery_detail = Some(recovery_detail.to_owned());
                true
            } else {
                false
            }
        });
        Ok(updated)
    }

    async fn get_one_time_occurrence(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<OneTimeOccurrence>, PersistenceError> {
        Ok(self
            .occurrence
            .lock()
            .await
            .clone()
            .filter(|occurrence| occurrence.id == occurrence_id))
    }
}

fn fixture_occurrence(state: OneTimeOccurrenceState) -> OneTimeOccurrence {
    OneTimeOccurrence {
        id: "occ-existing".to_owned(),
        schedule_id: "once-existing".to_owned(),
        execution_id: "exec-existing".to_owned(),
        triggered_at: Utc::now() - chrono::Duration::seconds(1),
        state,
        owner_id: "owner-existing".to_owned(),
        lease_expires_at: (!matches!(
            state,
            OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
                | OneTimeOccurrenceState::Cancelled
        ))
        .then(|| Utc::now() + chrono::Duration::seconds(60)),
        recovery_detail: None,
    }
}

async fn manager_and_persistence(
    failure: OccurrenceFailure,
) -> (SchedulerManager, Arc<OccurrenceRecordingPersistence>) {
    let manager = SchedulerManager::with_defaults();
    let persistence = Arc::new(OccurrenceRecordingPersistence::new(failure));
    manager.set_persistence(persistence.clone()).await;
    (manager, persistence)
}

async fn manager_with_occurrence_failure(
    failure: OccurrenceFailure,
) -> SchedulerManager {
    manager_and_persistence(failure).await.0
}

async fn attached_counting_dispatcher(
    manager: &SchedulerManager,
) -> Arc<CountingDispatcher> {
    let dispatcher = Arc::new(CountingDispatcher::default());
    manager.set_dispatcher(dispatcher.clone()).await;
    dispatcher
}

async fn wait_for_occurrence(persistence: &OccurrenceRecordingPersistence) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while persistence.occurrence.lock().await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("occurrence was not reserved");
}

async fn wait_for_state(
    persistence: &OccurrenceRecordingPersistence,
    expected: OneTimeOccurrenceState,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while persistence
            .occurrence
            .lock()
            .await
            .as_ref()
            .map(|occurrence| occurrence.state)
            != Some(expected)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("occurrence did not reach expected state");
}

async fn send_one_time_now(manager: &SchedulerManager, schedule_id: &str) {
    manager
        .trigger_sender()
        .expect("scheduler is running")
        .send(FiredTrigger {
            schedule_id: schedule_id.to_owned(),
            fired_at: Utc::now(),
            trigger_type: TriggerType::OneTime,
            is_recovery: false,
            event_payload: None,
        })
        .await
        .expect("trigger queue accepts one-time occurrence");
}
```

- [ ] **Step 2: Write failing admission-order tests**

Add:

```rust
#[tokio::test]
async fn missing_occurrence_persistence_blocks_only_one_time_dispatch() {
    let manager = SchedulerManager::with_defaults();
    let dispatcher = Arc::new(CountingDispatcher::default());
    manager.set_dispatcher(dispatcher.clone()).await;
    manager.register(due_one_time("once")).await;
    manager.register(interval_schedule("recurring")).await;
    manager.start(Duration::from_millis(10)).await;
    wait_for_dispatches(&dispatcher, 1).await;
    manager.stop().await;
    assert_eq!(dispatcher.calls_for("once").await, 0);
    assert!(dispatcher.calls_for("recurring").await >= 1);
}

#[tokio::test]
async fn existing_receipt_suppresses_dispatch_and_consumes_cursor() {
    let manager = SchedulerManager::with_defaults();
    let persistence = Arc::new(OccurrenceRecordingPersistence::new(
        OccurrenceFailure::None,
    ));
    let stored = fixture_occurrence(OneTimeOccurrenceState::Completed);
    *persistence.occurrence.lock().await = Some(stored.clone());
    manager.set_persistence(persistence).await;
    let dispatcher = Arc::new(CountingDispatcher::default());
    manager.set_dispatcher(dispatcher.clone()).await;
    manager.register(due_one_time(&stored.schedule_id)).await;
    manager.start(Duration::from_millis(10)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    manager.stop().await;

    assert_eq!(dispatcher.total_calls().await, 0);
    assert_eq!(
        manager
            .get_schedule(&stored.schedule_id)
            .await
            .unwrap()
            .last_fire,
        Some(stored.triggered_at)
    );
}

#[tokio::test]
async fn reservation_failure_never_advances_cursor_or_dispatches() {
    let manager = manager_with_occurrence_failure(OccurrenceFailure::Reserve).await;
    let dispatcher = attached_counting_dispatcher(&manager).await;
    manager.register(due_one_time("reserve-fails")).await;
    manager.start(Duration::from_millis(10)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    manager.stop().await;

    assert_eq!(dispatcher.total_calls().await, 0);
    assert_eq!(
        manager.get_schedule("reserve-fails").await.unwrap().last_fire,
        None
    );
    assert!(matches!(
        manager.one_time_runtime_status("reserve-fails").await,
        OneTimeRuntimeStatus::RecoveryRequired { .. }
    ));
}

#[tokio::test]
async fn cursor_failure_after_reservation_releases_lease_without_dispatch() {
    let (manager, persistence) =
        manager_and_persistence(OccurrenceFailure::Cursor).await;
    let dispatcher = attached_counting_dispatcher(&manager).await;
    manager.register(due_one_time("cursor-fails")).await;
    manager.start(Duration::from_millis(10)).await;
    wait_for_occurrence(&persistence).await;
    manager.stop().await;

    assert_eq!(dispatcher.total_calls().await, 0);
    let receipt = persistence.occurrence.lock().await.clone().unwrap();
    assert_eq!(receipt.state, OneTimeOccurrenceState::Reserved);
    assert!(receipt.lease_expires_at.is_some_and(|lease| lease <= Utc::now()));
}
```

The production change that makes these tests pass is the early, dedicated one-time path. Altering the recurring path alone cannot satisfy them.

- [ ] **Step 3: Run the new tests and verify red**

```bash
set -o pipefail
cargo test -p hf-scheduler \
  missing_occurrence_persistence_blocks_only_one_time_dispatch 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-scheduler \
  existing_receipt_suppresses_dispatch_and_consumes_cursor 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-scheduler \
  reservation_failure_never_advances_cursor_or_dispatches 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-scheduler \
  cursor_failure_after_reservation_releases_lease_without_dispatch 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because current code advances the cursor and persists execution history through separate best-effort calls.

- [ ] **Step 4: Route one-time triggers through a dedicated handler**

After loading the schedule and applying the shared hourly-rate check, branch:

```rust
if matches!(schedule.trigger, crate::store::TriggerConfig::OneTime { .. }) {
    Self::handle_one_time_trigger(
        fired,
        schedule,
        store,
        executor,
        execution_store,
        dispatcher,
        persistence,
        serial_locks,
        dispatch_tasks,
        execution_slots,
        one_time_status,
        occurrence_metrics,
        owner_id,
    )
    .await;
    return;
}
```

Thread `owner_id`, `one_time_status`, `one_time_global_block`, and `occurrence_metrics` from `SchedulerManager` through `executor_loop`. `handle_one_time_trigger` first checks the global/schedule block, then applies the existing concurrency policy and parameter-resolution code. Policy skips and parameter failures use the existing visible preflight records and create no receipt. If durability is blocked, emit a structured warning and return without cursor mutation, receipt creation, or dispatch.

The parameter preflight is:

```rust
let sequence = executor.lock().await.next_sequence_for(&schedule.id);
let context = crate::params::ResolutionContext {
    trigger_time: fired.fired_at,
    trigger_type: fired.trigger_type,
    execution_sequence: sequence,
    event_payload: fired.event_payload.clone(),
};
let parameter_values = match crate::params::resolve_parameters(
    &serde_json::json!({}),
    &schedule.parameter_values,
    &context,
) {
    Ok(values) => values,
    Err(error) => {
        Self::record_dispatch_failure(
            &fired,
            &schedule,
            format!("parameter resolution failed: {error}"),
            store,
            execution_store,
            persistence.as_ref(),
        )
        .await;
        return;
    }
};
```

Use this match before parameter resolution:

```rust
let concurrency_policy = schedule.policies.effective_concurrency_policy();
match concurrency_policy {
    ConcurrencyPolicy::SkipIfRunning
        if Self::schedule_has_active_dispatch(dispatch_tasks, &schedule.id) =>
    {
        Self::record_policy_skip(
            &fired,
            &schedule,
            "previous execution is still running".to_owned(),
            store,
            execution_store,
            persistence.as_ref(),
        )
        .await;
        return;
    }
    ConcurrencyPolicy::CancelPrevious => {
        Self::cancel_previous_dispatches(
            dispatch_tasks,
            execution_store,
            persistence.as_ref(),
            &schedule.id,
        )
        .await;
    }
    ConcurrencyPolicy::Allow
    | ConcurrencyPolicy::Queue
    | ConcurrencyPolicy::SkipIfRunning => {}
}
```

Use `concurrency_policy == ConcurrencyPolicy::Queue` to select the same
per-schedule serial lock before the spawned task acquires the global permit.

The existing cron/interval/event body remains the fallback after this return and must not call an occurrence method.

Use these private helpers from static loop/dispatch functions:

```rust
async fn mark_consumed(statuses: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>, id: &str) {
    statuses
        .lock()
        .await
        .insert(id.to_owned(), OneTimeRuntimeStatus::Consumed);
}

async fn mark_recovery_required(
    statuses: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
    id: &str,
    detail: impl Into<String>,
) {
    statuses.lock().await.insert(
        id.to_owned(),
        OneTimeRuntimeStatus::RecoveryRequired {
            detail: detail.into(),
        },
    );
}
```

- [ ] **Step 5: Reserve receipt and pending execution before cursor mutation**

Inside `handle_one_time_trigger`, reject a missing dispatcher or persistence adapter before creating a receipt. Construct stable candidate identifiers and the pending execution once:

```rust
let occurrence_id = format!("occ-{}-{}", schedule.id, uuid::Uuid::new_v4());
let execution_id = format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4());
let lease_expires_at = now
    + chrono::Duration::from_std(ONE_TIME_LEASE)
        .expect("one-time lease duration fits chrono");
let occurrence = OneTimeOccurrence {
    id: occurrence_id.clone(),
    schedule_id: schedule.id.clone(),
    execution_id: execution_id.clone(),
    triggered_at: fired.fired_at,
    state: OneTimeOccurrenceState::Reserved,
    owner_id: owner_id.to_owned(),
    lease_expires_at: Some(lease_expires_at),
    recovery_detail: None,
};
let pending = ScheduleExecution {
    execution_id: execution_id.clone(),
    schedule_id: schedule.id.clone(),
    triggered_at: fired.fired_at,
    started_at: None,
    completed_at: None,
    status: ExecutionStatus::Pending,
    workflow_execution_id: None,
    request_summary,
    response_summary: serde_json::json!({}),
    error_message: None,
};
```

Call `reserve_one_time_occurrence(&occurrence, &pending).await` before adding to the in-memory execution store or changing `last_fire`.

Handle outcomes exactly:

```rust
match persistence
    .reserve_one_time_occurrence(&occurrence, &pending)
    .await
{
    Ok(OneTimeReservation::Reserved(reserved)) => {
        occurrence_metrics.record_reservation_win();
        execution_store.lock().await.record(pending.clone());
        // Continue with cursor persistence.
    }
    Ok(OneTimeReservation::Existing(existing)) => {
        occurrence_metrics.record_duplicate_suppression();
        let updated = {
            let mut schedules = store.lock().await;
            schedules.update_last_fire(&schedule.id, existing.triggered_at);
            schedules.get(&schedule.id).cloned()
        };
        if let Some(updated) = updated {
            if persistence.update_schedule(&updated).await.is_err() {
                mark_recovery_required(
                    one_time_status,
                    &schedule.id,
                    "receipt exists but the JSON cursor could not be reconciled",
                )
                .await;
            } else {
                mark_consumed(one_time_status, &schedule.id).await;
            }
        }
        return;
    }
    Err(error) => {
        let recovered = persistence
            .get_one_time_occurrence(&occurrence.id)
            .await
            .ok()
            .flatten();
        if let Some(existing) = recovered {
            let updated = {
                let mut schedules = store.lock().await;
                schedules.update_last_fire(&schedule.id, existing.triggered_at);
                schedules.get(&schedule.id).cloned()
            };
            let cursor_durable = match updated {
                Some(updated) => persistence.update_schedule(&updated).await.is_ok(),
                None => false,
            };
            if !existing.terminal() {
                let _released = persistence
                    .release_one_time_lease(
                        &existing.id,
                        &existing.owner_id,
                        Utc::now(),
                        "reservation result was ambiguous",
                    )
                    .await;
            }
            if existing.terminal() && cursor_durable {
                mark_consumed(one_time_status, &schedule.id).await;
            } else {
                mark_recovery_required(
                    one_time_status,
                    &schedule.id,
                    "reservation committed but dispatch admission is ambiguous",
                )
                .await;
            }
        } else {
            mark_recovery_required(
                one_time_status,
                &schedule.id,
                "one-time occurrence reservation is unavailable",
            )
            .await;
        }
        warn!(
            occurrence_id = %occurrence.id,
            schedule_id = %schedule.id,
            execution_id = %occurrence.execution_id,
            error = %error,
            "One-time occurrence reservation failed closed"
        );
        return;
    }
}
```

- [ ] **Step 6: Require durable cursor persistence before task creation**

After a winning reservation, update the in-memory cursor to `max(fired_at, now)`, clone the resulting schedule, and await `persistence.update_schedule`.

When that write succeeds, call:

```rust
mark_consumed(one_time_status, &schedule.id).await;
```

The status means the one-time fire is durably owned/consumed; it does not claim
that the workflow has completed.

On failure:

```rust
let detail = "schedule cursor persistence failed after durable reservation";
let released_at = Utc::now();
let _released = persistence
    .release_one_time_lease(
        &occurrence.id,
        owner_id,
        released_at,
        detail,
    )
    .await;
mark_recovery_required(one_time_status, &schedule.id, detail).await;
warn!(
    occurrence_id = %occurrence.id,
    schedule_id = %schedule.id,
    execution_id = %occurrence.execution_id,
    "Reserved one-time occurrence quarantined before dispatch"
);
return;
```

Do not call the generic best-effort `persist_schedule` or `persist_record` helpers in this branch.

- [ ] **Step 7: Spawn and synchronously register the durable task**

Spawn the one-time task only after cursor persistence returns `Ok(())`, then insert the handle into `dispatch_tasks` using the existing synchronous mutex without an `.await` between `tokio::spawn` and `push`.

- [ ] **Step 8: Add the recurring-path regression test**

Reset `occurrence_calls` before triggering one interval, one cron, and one event schedule. Assert each dispatches and:

```rust
assert_eq!(
    persistence.occurrence_calls.load(Ordering::SeqCst),
    0,
    "recurring and event triggers must not enter one-time persistence"
);
```

- [ ] **Step 9: Run scheduler tests**

```bash
set -o pipefail
cargo test -p hf-scheduler 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/hf-scheduler/src/manager.rs
git commit -m "feat: reserve one-time occurrences before dispatch"
```

---

### Task 5: Add Running, Heartbeat, Terminal, and Shutdown Semantics

**Files:**
- Modify: `crates/hf-scheduler/src/manager.rs`
- Test: `crates/hf-scheduler/src/manager.rs`

**Interfaces:**
- Consumes: the winning occurrence task created in Task 4.
- Produces: owner-checked `reserved -> running`, renewable leases while waiting/running, atomic terminal state, fail-closed terminal ambiguity, and cancellation reconciliation for tracked occurrences.

- [ ] **Step 1: Write failing running-transition and terminal tests**

Add:

```rust
#[tokio::test]
async fn running_transition_failure_makes_zero_dispatch_calls() {
    let (manager, persistence) =
        manager_and_persistence(OccurrenceFailure::Running).await;
    let dispatcher = attached_counting_dispatcher(&manager).await;
    manager.register(due_one_time("running-fails")).await;
    manager.start(Duration::from_millis(10)).await;
    wait_for_occurrence(&persistence).await;
    manager.stop().await;

    assert_eq!(dispatcher.total_calls().await, 0);
    assert_eq!(
        persistence.occurrence.lock().await.as_ref().unwrap().state,
        OneTimeOccurrenceState::Reserved
    );
}

#[tokio::test]
async fn terminal_transition_failure_dispatches_once_and_never_retries() {
    let (manager, persistence) =
        manager_and_persistence(OccurrenceFailure::Terminal).await;
    let dispatcher = attached_counting_dispatcher(&manager).await;
    manager.register(due_one_time("terminal-fails")).await;
    manager.start(Duration::from_millis(10)).await;
    wait_for_dispatches(&dispatcher, 1).await;
    wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(dispatcher.total_calls().await, 1);

    send_one_time_now(&manager, "terminal-fails").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    manager.stop().await;
    assert_eq!(dispatcher.total_calls().await, 1);
}
```

- [ ] **Step 2: Write failing owner heartbeat test**

Add this constructor to the existing test `BlockingDispatcher`:

```rust
impl BlockingDispatcher {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}
```

Use Tokio's paused clock:

```rust
#[tokio::test(start_paused = true)]
async fn heartbeat_renews_only_the_current_owner_lease() {
    let (manager, persistence) =
        manager_and_persistence(OccurrenceFailure::None).await;
    let dispatcher = Arc::new(BlockingDispatcher::new());
    manager.set_dispatcher(dispatcher).await;
    manager.register(due_one_time("heartbeat")).await;
    manager.start(Duration::from_millis(10)).await;
    tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    let renewals = persistence.renewals.lock().await.clone();
    assert!(!renewals.is_empty());
    assert!(renewals
        .iter()
        .all(|(_, owner)| owner == manager.owner_id()));
    manager.stop().await;
}

#[tokio::test(start_paused = true)]
async fn reserved_occurrence_renews_while_waiting_for_dispatch_capacity() {
    let manager = SchedulerManager::new(SchedulerConfig {
        max_concurrent_executions: 1,
        ..SchedulerConfig::default()
    });
    let persistence = Arc::new(OccurrenceRecordingPersistence::new(
        OccurrenceFailure::None,
    ));
    manager.set_persistence(persistence.clone()).await;
    let dispatcher = Arc::new(BlockingDispatcher::new());
    manager.set_dispatcher(dispatcher.clone()).await;
    manager
        .register(policy_schedule("capacity-blocker", ConcurrencyPolicy::Allow, 0))
        .await;
    manager.register(due_one_time("waiting-on-capacity")).await;
    manager.start(Duration::from_secs(60)).await;
    send_now(&manager, "capacity-blocker").await;
    tokio::task::yield_now().await;
    send_one_time_now(&manager, "waiting-on-capacity").await;
    wait_for_occurrence(&persistence).await;

    tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        persistence.occurrence.lock().await.as_ref().unwrap().state,
        OneTimeOccurrenceState::Reserved
    );
    assert!(!persistence.renewals.lock().await.is_empty());
    manager.stop().await;
}
```

- [ ] **Step 3: Run the focused lifecycle tests and verify red**

```bash
set -o pipefail
cargo test -p hf-scheduler \
  running_transition_failure_makes_zero_dispatch_calls 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-scheduler \
  terminal_transition_failure_dispatches_once_and_never_retries 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-scheduler \
  heartbeat_renews_only_the_current_owner_lease 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because the current spawned task writes generic execution history and has no occurrence transition or lease loop.

- [ ] **Step 4: Renew the reserved lease while waiting for task admission**

Start the heartbeat inside the spawned/tracked task, before waiting on the
optional serial lock or global semaphore. Pin the admission future:

```rust
let admission = async {
    let serial_guard = match serial_lock {
        Some(lock) => Some(lock.lock_owned().await),
        None => None,
    };
    let execution_permit = execution_slots
        .acquire_owned()
        .await
        .expect("scheduler execution semaphore is never closed");
    (serial_guard, execution_permit)
};
tokio::pin!(admission);
let mut heartbeat = tokio::time::interval(ONE_TIME_HEARTBEAT);
heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
heartbeat.tick().await;
let (_serial_guard, _execution_permit) = loop {
    tokio::select! {
        guards = &mut admission => break guards,
        _ = heartbeat.tick() => {
            let next_expiry = Utc::now()
                + chrono::Duration::from_std(ONE_TIME_LEASE)
                    .expect("one-time lease duration fits chrono");
            let renewed = persistence
                .renew_one_time_lease(
                    &occurrence.id,
                    &occurrence.owner_id,
                    next_expiry,
                )
                .await;
            if !matches!(renewed, Ok(true)) {
                occurrence_metrics.record_lease_renewal_failure();
                mark_recovery_required(
                    &one_time_status,
                    &occurrence.schedule_id,
                    "one-time ownership lease renewal failed before dispatch",
                )
                .await;
                let _released = persistence
                    .release_one_time_lease(
                        &occurrence.id,
                        &occurrence.owner_id,
                        Utc::now(),
                        "lease renewal failed before dispatcher entry",
                    )
                    .await;
                return;
            }
        }
    }
};
```

Dropping `admission` on failure cancels lock/semaphore waiting and guarantees
zero dispatcher calls.

- [ ] **Step 5: Transition to running before dispatcher entry**

After the task owns its optional serial lock and global semaphore permit, mutate a clone of `pending` to `Running` with `started_at = Some(Utc::now())`, then call:

```rust
let transition = OneTimeOccurrenceTransition {
    occurrence_id: occurrence.id.clone(),
    schedule_id: occurrence.schedule_id.clone(),
    execution_id: occurrence.execution_id.clone(),
    owner_id: occurrence.owner_id.clone(),
    from: OneTimeOccurrenceState::Reserved,
    to: OneTimeOccurrenceState::Running,
    lease_expires_at: Some(
        Utc::now()
            + chrono::Duration::from_std(ONE_TIME_LEASE)
                .expect("one-time lease duration fits chrono"),
    ),
    recovery_detail: None,
};
```

Proceed only for `Applied` or an exact `Idempotent` result. For `Conflict`, `Missing`, or `Err`, update in-memory status to `RecoveryRequired`, increment `transition_failures`, release the lease when possible, and return before calling `disp.dispatch`.

After an applied/idempotent running transition, update the already-recorded
in-memory row rather than inserting a duplicate:

```rust
execution_store
    .lock()
    .await
    .update(&running.execution_id, |record| *record = running.clone());
```

- [ ] **Step 6: Renew the lease while dispatch is pending**

Pin the dispatcher future and select it against a 15-second interval:

```rust
let dispatch = disp.dispatch(&workflow_id, parameter_values);
tokio::pin!(dispatch);
let mut heartbeat = tokio::time::interval(ONE_TIME_HEARTBEAT);
heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
heartbeat.tick().await;
let mut lease_healthy = true;

let dispatch_result = loop {
    tokio::select! {
        result = &mut dispatch => break result,
        _ = heartbeat.tick(), if lease_healthy => {
            let next_expiry = Utc::now()
                + chrono::Duration::from_std(ONE_TIME_LEASE)
                    .expect("one-time lease duration fits chrono");
            match persistence
                .renew_one_time_lease(
                    &occurrence.id,
                    &occurrence.owner_id,
                    next_expiry,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    lease_healthy = false;
                    occurrence_metrics.record_lease_renewal_failure();
                    mark_recovery_required(
                        &one_time_status,
                        &occurrence.schedule_id,
                        "one-time ownership lease renewal failed",
                    )
                    .await;
                    error!(
                        occurrence_id = %occurrence.id,
                        schedule_id = %occurrence.schedule_id,
                        execution_id = %occurrence.execution_id,
                        "Lost durable one-time occurrence lease"
                    );
                }
            }
        }
    }
};
```

Continue awaiting an already-entered dispatcher after renewal failure, but skip the terminal transition because durable ownership is ambiguous.

- [ ] **Step 7: Persist the exact terminal state**

Convert `dispatch_result` to the existing completed/failed `ScheduleExecution`. If `lease_healthy`, transition `Running` to `Completed` or `Failed` with `lease_expires_at: None` and the same execution in one persistence call.

Handle results:

```rust
match persistence
    .transition_one_time_occurrence(&transition, &terminal_execution)
    .await
{
    Ok(OneTimeTransitionResult::Applied(_))
    | Ok(OneTimeTransitionResult::Idempotent(_)) => {
        execution_store
            .lock()
            .await
            .update(&terminal_execution.execution_id, |record| {
                *record = terminal_execution.clone();
            });
        mark_consumed(&one_time_status, &schedule_id).await;
    }
    Ok(OneTimeTransitionResult::Conflict(_))
    | Ok(OneTimeTransitionResult::Missing)
    | Err(_) => {
        occurrence_metrics.record_transition_failure();
        mark_recovery_required(
            &one_time_status,
            &schedule_id,
            "dispatcher finished but terminal occurrence persistence is unknown",
        )
        .await;
    }
}
```

Do not overwrite the durable receipt or execution with a generic best-effort update after a conflict.

- [ ] **Step 8: Reconcile tracked occurrence cancellation on stop**

When `stop` aborts and joins a tracked one-time task, load the current in-memory execution and build a cancelled record. Call `transition_one_time_occurrence` from `Reserved` when still pending or `Running` when started. If cancellation transition fails, call `release_one_time_lease` with:

```text
scheduler stopped before a durable terminal transition
```

For recurring tasks, retain the existing generic cancellation path. `has_active_occurrence` must prune finished handles before testing membership.

- [ ] **Step 9: Add and pass the shutdown test**

```rust
#[tokio::test]
async fn stop_joins_one_time_task_and_records_cancelled_receipt() {
    let (manager, persistence) =
        manager_and_persistence(OccurrenceFailure::None).await;
    manager
        .set_dispatcher(Arc::new(BlockingDispatcher::new()))
        .await;
    manager.register(due_one_time("cancel-on-stop")).await;
    manager.start(Duration::from_millis(10)).await;
    wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;
    manager.stop().await;

    let receipt = persistence.occurrence.lock().await.clone().unwrap();
    assert_eq!(receipt.state, OneTimeOccurrenceState::Cancelled);
    assert!(receipt.lease_expires_at.is_none());
    assert!(!manager.has_active_occurrence(&receipt.id));
}
```

- [ ] **Step 10: Add structured event assertions and metric assertions**

All reservation, transition, renewal-failure, and recovery logs must include `occurrence_id`, `schedule_id`, and `execution_id`; transition logs also include source/destination state and elapsed milliseconds. Extend lifecycle tests to assert metric snapshots, for example:

```rust
let transition_started = std::time::Instant::now();
let result = persistence
    .transition_one_time_occurrence(&transition, &execution)
    .await;
debug!(
    occurrence_id = %transition.occurrence_id,
    schedule_id = %transition.schedule_id,
    execution_id = %transition.execution_id,
    from = %transition.from,
    to = %transition.to,
    duration_ms = u64::try_from(transition_started.elapsed().as_millis())
        .unwrap_or(u64::MAX),
    "Persisted one-time occurrence transition"
);

let metrics = manager.occurrence_metrics();
assert_eq!(metrics.reservation_wins, 1);
assert_eq!(metrics.duplicate_suppressions, 0);
assert_eq!(metrics.transition_failures, 0);
```

Add a fixed `recovery_reason` field such as `reservation_unavailable`,
`cursor_persistence`, `running_transition`, `lease_renewal`, or
`terminal_transition` to every quarantine/recovery event. Do not log request
summaries or parameter values.

- [ ] **Step 11: Run scheduler tests**

```bash
set -o pipefail
cargo test -p hf-scheduler 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add crates/hf-scheduler/src/manager.rs
git commit -m "feat: track one-time occurrence lifecycle"
```

---

### Task 6: Adapt SQLite and Reconcile Receipts in `hf-service`

**Files:**
- Modify: `crates/hf-service/src/scheduler.rs`
- Test: `crates/hf-service/src/scheduler.rs`

**Interfaces:**
- Consumes: Task 2 scheduler persistence contract and Task 3 storage repository.
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignDurabilityStatus {
    Ready,
    Consumed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize)]
pub struct OneTimeRecoveryView {
    pub occurrence_id: String,
    pub schedule_id: String,
    pub schedule_name: Option<String>,
    pub execution_id: String,
    pub triggered_at: String,
    pub state: String,
    pub recovery_detail: Option<String>,
    pub schedule_exists: bool,
}

pub async fn list_one_time_recoveries(
    &self,
) -> Result<Vec<OneTimeRecoveryView>, CampaignSchedulerError>;

pub async fn acknowledge_one_time_recovery(
    &self,
    occurrence_id: &str,
) -> Result<OneTimeRecoveryView, CampaignSchedulerError>;
```

`CampaignView` gains:

```rust
pub durability_status: CampaignDurabilityStatus,
```

`CampaignSchedulerError` gains:

```rust
#[error("durable one-time scheduling is unavailable: {0}")]
DurabilityUnavailable(String),
#[error("one-time occurrence journal error: {0}")]
OccurrenceJournal(String),
#[error("one-time occurrence not found: {0}")]
OccurrenceNotFound(String),
#[error("one-time occurrence conflict: {0}")]
OccurrenceConflict(String),
```

- [ ] **Step 1: Write failing adapter validation tests**

Add:

```rust
fn schedule_execution(
    execution_id: &str,
    schedule_id: &str,
    triggered_at: DateTime<Utc>,
    status: ExecutionStatus,
) -> ScheduleExecution {
    let started = !matches!(status, ExecutionStatus::Pending);
    let completed = matches!(
        status,
        ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
    );
    ScheduleExecution {
        execution_id: execution_id.to_owned(),
        schedule_id: schedule_id.to_owned(),
        triggered_at,
        started_at: started.then_some(triggered_at),
        completed_at: completed.then_some(triggered_at),
        status,
        workflow_execution_id: None,
        request_summary: serde_json::json!({}),
        response_summary: serde_json::json!({}),
        error_message: None,
    }
}

fn occurrence_row(state: &str, execution_status: &str) -> ScheduleOccurrenceRecord {
    let triggered_at = Utc::now();
    let status = match execution_status {
        "pending" => ExecutionStatus::Pending,
        "running" => ExecutionStatus::Running,
        "completed" => ExecutionStatus::Completed,
        "failed" => ExecutionStatus::Failed,
        "cancelled" => ExecutionStatus::Cancelled,
        other => panic!("unsupported fixture execution status: {other}"),
    };
    let execution = schedule_execution("exec-1", "schedule-1", triggered_at, status);
    ScheduleOccurrenceRecord {
        id: "occ-1".to_owned(),
        schedule_id: "schedule-1".to_owned(),
        execution_id: "exec-1".to_owned(),
        triggered_at: triggered_at.to_rfc3339(),
        state: state.to_owned(),
        owner_id: "owner-1".to_owned(),
        lease_expires_at: matches!(state, "reserved" | "running")
            .then(|| (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()),
        recovery_detail: None,
        execution_status: Some(execution_status.to_owned()),
        execution_data_json: Some(serde_json::to_string(&execution).unwrap()),
    }
}
```

Add tests for a valid row and each corrupt shape:

```rust
#[test]
fn occurrence_row_rejects_unknown_state_and_invalid_timestamp() {
    let mut row = occurrence_row("reserved", "pending");
    row.state = "invented".to_owned();
    assert!(row_to_occurrence(&row).is_err());

    let mut row = occurrence_row("reserved", "pending");
    row.triggered_at = "not-a-timestamp".to_owned();
    assert!(row_to_occurrence(&row).is_err());
}

#[test]
fn occurrence_row_requires_matching_non_terminal_execution() {
    let mut missing = occurrence_row("running", "running");
    missing.execution_status = None;
    missing.execution_data_json = None;
    assert!(row_to_occurrence(&missing).is_err());

    let mismatched = occurrence_row("running", "completed");
    assert!(row_to_occurrence(&mismatched).is_err());
}

#[test]
fn terminal_receipt_remains_valid_after_history_clear() {
    let mut row = occurrence_row("completed", "completed");
    row.execution_status = None;
    row.execution_data_json = None;
    assert_eq!(
        row_to_occurrence(&row).unwrap().state,
        OneTimeOccurrenceState::Completed
    );
}
```

- [ ] **Step 2: Run the adapter tests and verify red**

```bash
set -o pipefail
cargo test -p hf-service occurrence_row_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because the storage adapter and validation mapping do not exist.

- [ ] **Step 3: Implement strict row conversion**

Add:

```rust
fn row_to_occurrence(
    row: &hf_storage::ScheduleOccurrenceRecord,
) -> Result<OneTimeOccurrence, PersistenceError> {
    let state = row
        .state
        .parse::<OneTimeOccurrenceState>()
        .map_err(|error| PersistenceError::new(error.to_string()))?;
    let occurrence = OneTimeOccurrence {
        id: row.id.clone(),
        schedule_id: row.schedule_id.clone(),
        execution_id: row.execution_id.clone(),
        triggered_at: row
            .triggered_at
            .parse()
            .map_err(|_| PersistenceError::new("invalid occurrence trigger timestamp"))?,
        state,
        owner_id: row.owner_id.clone(),
        lease_expires_at: row
            .lease_expires_at
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| PersistenceError::new("invalid occurrence lease timestamp"))?,
        recovery_detail: row.recovery_detail.clone(),
    };
    occurrence
        .validate()
        .map_err(|error| PersistenceError::new(error.to_string()))?;

    let expected_status = match occurrence.state {
        OneTimeOccurrenceState::Reserved => "pending",
        OneTimeOccurrenceState::Running => "running",
        OneTimeOccurrenceState::Completed => "completed",
        OneTimeOccurrenceState::Failed => "failed",
        OneTimeOccurrenceState::Cancelled => "cancelled",
    };
    match (&row.execution_status, occurrence.terminal()) {
        (Some(actual), _) if actual != expected_status => {
            return Err(PersistenceError::new(
                "occurrence and execution states do not match",
            ));
        }
        (None, false) => {
            return Err(PersistenceError::new(
                "non-terminal occurrence is missing its execution",
            ));
        }
        _ => {}
    }
    Ok(occurrence)
}
```

When `execution_data_json` exists, deserialize `ScheduleExecution` and verify its `execution_id`, `schedule_id`, `triggered_at`, and status against the row. Never default malformed JSON.

- [ ] **Step 4: Implement every production persistence method**

Keep `CampaignSchedulerPersistence::upsert` for recurring history. Implement the Task 2 occurrence methods by converting scheduler types into the Task 3 storage input structs and mapping every storage result variant one-for-one.

Implement this Task 2 read method in the production adapter:

```rust
async fn get_one_time_execution(
    &self,
    occurrence_id: &str,
) -> Result<Option<ScheduleExecution>, PersistenceError>;
```

It reads the joined `execution_data_json`, returns `Ok(None)` only when the receipt or terminal history is absent, and returns an error for malformed JSON or identity mismatch.

When `store` is `None`, every occurrence method returns:

```rust
Err(PersistenceError::new(
    "SQLite storage is required for durable one-time scheduling",
))
```

Keep an `Arc<CampaignSchedulerPersistence>` in `CampaignScheduler` as `occurrences` and pass the same `Arc` to `manager.set_persistence`.

- [ ] **Step 5: Re-run adapter validation tests and verify green**

```bash
set -o pipefail
cargo test -p hf-service occurrence_row_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 6: Write failing startup reconciliation tests**

Add this test fixture in the existing `scheduler.rs` test module:

```rust
struct SchedulerFixture {
    _directory: tempfile::TempDir,
    schedules_path: PathBuf,
    store: Option<Arc<Store>>,
}

impl SchedulerFixture {
    fn params(&self) -> CampaignParams {
        CampaignParams {
            project: self._directory.path().display().to_string(),
            target: Some("parser".to_owned()),
            engine: "libfuzzer".to_owned(),
            lang: "c".to_owned(),
            duration_secs: 1,
            max_runs: Some(1),
            max_total_secs: None,
            schedule_id: String::new(),
        }
    }

    fn push_schedule(&self, schedule: Schedule) {
        let mut schedules = load_schedules(&self.schedules_path).unwrap();
        schedules.retain(|existing| existing.id != schedule.id);
        schedules.push(schedule);
        atomic_write_schedules(&self.schedules_path, &schedules).unwrap();
    }

    fn write_due_one_time(&self, id: &str) {
        self.push_schedule(
            Schedule::new(
                id,
                id,
                TriggerConfig::OneTime {
                    at: Utc::now() - chrono::Duration::seconds(1),
                },
                CAMPAIGN_KIND,
            )
            .with_params(serde_json::to_value(self.params()).unwrap()),
        );
    }

    fn write_interval(&self, id: &str) {
        let mut schedule = Schedule::new(
            id,
            id,
            TriggerConfig::Interval { interval_secs: 1 },
            CAMPAIGN_KIND,
        )
        .with_params(serde_json::to_value(self.params()).unwrap());
        schedule.last_fire = Some(Utc::now() - chrono::Duration::seconds(2));
        self.push_schedule(schedule);
    }

    async fn start(&self) -> Result<CampaignScheduler, CampaignSchedulerError> {
        let mut container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
        if let Some(store) = &self.store {
            container = container.with_store(Arc::clone(store));
        }
        CampaignScheduler::try_start(container, self.schedules_path.clone(), None).await
    }

    async fn seed_receipt(
        &self,
        schedule_id: &str,
        occurrence_id: &str,
        execution_id: &str,
        state: OneTimeOccurrenceState,
        expired: bool,
    ) {
        let store = self.store.as_ref().expect("fixture has SQLite");
        let triggered_at = Utc::now() - chrono::Duration::seconds(1);
        let owner_id = "fixture-owner";
        let pending = schedule_execution(
            execution_id,
            schedule_id,
            triggered_at,
            ExecutionStatus::Pending,
        );
        let new = hf_storage::NewScheduleOccurrence {
            id: occurrence_id.to_owned(),
            schedule_id: schedule_id.to_owned(),
            execution_id: execution_id.to_owned(),
            triggered_at: triggered_at.to_rfc3339(),
            owner_id: owner_id.to_owned(),
            lease_expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            execution_status: "pending".to_owned(),
            execution_data_json: serde_json::to_string(&pending).unwrap(),
        };
        store.reserve_schedule_occurrence(&new).await.unwrap();

        let apply = |from: &str,
                     to: &str,
                     status: ExecutionStatus,
                     lease: Option<DateTime<Utc>>| {
            let execution =
                schedule_execution(execution_id, schedule_id, triggered_at, status);
            hf_storage::ScheduleOccurrenceTransition {
                occurrence_id: occurrence_id.to_owned(),
                schedule_id: schedule_id.to_owned(),
                execution_id: execution_id.to_owned(),
                owner_id: owner_id.to_owned(),
                from_state: from.to_owned(),
                to_state: to.to_owned(),
                lease_expires_at: lease.map(|value| value.to_rfc3339()),
                recovery_detail: None,
                execution_status: status.to_string(),
                execution_data_json: serde_json::to_string(&execution).unwrap(),
            }
        };

        if matches!(
            state,
            OneTimeOccurrenceState::Running
                | OneTimeOccurrenceState::Completed
                | OneTimeOccurrenceState::Failed
        ) {
            store
                .transition_schedule_occurrence(&apply(
                    "reserved",
                    "running",
                    ExecutionStatus::Running,
                    Some(Utc::now() + chrono::Duration::seconds(60)),
                ))
                .await
                .unwrap();
        }
        match state {
            OneTimeOccurrenceState::Completed => {
                store
                    .transition_schedule_occurrence(&apply(
                        "running",
                        "completed",
                        ExecutionStatus::Completed,
                        None,
                    ))
                    .await
                    .unwrap();
            }
            OneTimeOccurrenceState::Failed => {
                store
                    .transition_schedule_occurrence(&apply(
                        "running",
                        "failed",
                        ExecutionStatus::Failed,
                        None,
                    ))
                    .await
                    .unwrap();
            }
            OneTimeOccurrenceState::Cancelled => {
                store
                    .transition_schedule_occurrence(&apply(
                        "reserved",
                        "cancelled",
                        ExecutionStatus::Cancelled,
                        None,
                    ))
                    .await
                    .unwrap();
            }
            OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running => {}
        }
        if expired && matches!(
            state,
            OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running
        ) {
            store
                .release_schedule_occurrence_lease(
                    occurrence_id,
                    owner_id,
                    &Utc::now().to_rfc3339(),
                    "fixture lease released",
                )
                .await
                .unwrap();
        }
    }

    async fn reserve_receipt(
        &self,
        schedule_id: &str,
        occurrence_id: &str,
        execution_id: &str,
        state: OneTimeOccurrenceState,
    ) {
        self.seed_receipt(
            schedule_id,
            occurrence_id,
            execution_id,
            state,
            false,
        )
        .await;
    }

    async fn reserve_expired_receipt(
        &self,
        schedule_id: &str,
        occurrence_id: &str,
        execution_id: &str,
        state: OneTimeOccurrenceState,
    ) {
        self.seed_receipt(
            schedule_id,
            occurrence_id,
            execution_id,
            state,
            true,
        )
        .await;
    }

    async fn reserve_live_receipt(
        &self,
        schedule_id: &str,
        occurrence_id: &str,
        execution_id: &str,
    ) {
        self.seed_receipt(
            schedule_id,
            occurrence_id,
            execution_id,
            OneTimeOccurrenceState::Reserved,
            false,
        )
        .await;
    }
}

async fn scheduler_fixture_with_store() -> SchedulerFixture {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("scheduler.db"))
            .await
            .unwrap(),
    );
    SchedulerFixture {
        schedules_path: directory.path().join("schedules.json"),
        store: Some(store),
        _directory: directory,
    }
}

async fn scheduler_fixture_without_store() -> SchedulerFixture {
    let directory = tempfile::tempdir().unwrap();
    SchedulerFixture {
        schedules_path: directory.path().join("schedules.json"),
        store: None,
        _directory: directory,
    }
}

fn due_trigger() -> TriggerConfig {
    TriggerConfig::OneTime {
        at: Utc::now() - chrono::Duration::seconds(1),
    }
}
```

Add:

```rust
#[tokio::test]
async fn startup_reconciles_receipt_before_a_stale_one_time_cursor_can_fire() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("once");
    fixture
        .reserve_receipt(
            "once",
            "occ-1",
            "exec-1",
            OneTimeOccurrenceState::Completed,
        )
        .await;

    let scheduler = fixture.start().await.unwrap();
    let schedule = scheduler
        .list()
        .await
        .into_iter()
        .find(|schedule| schedule.id == "once")
        .unwrap();
    assert!(schedule.last_fire.is_some());
    assert_eq!(
        scheduler.list_views().await.unwrap()[0].durability_status,
        CampaignDurabilityStatus::Consumed
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn expired_running_receipt_is_recovery_required_and_never_redispatched() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("once");
    fixture
        .reserve_expired_receipt(
            "once",
            "occ-1",
            "exec-1",
            OneTimeOccurrenceState::Running,
        )
        .await;

    let scheduler = fixture.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let recoveries = scheduler.list_one_time_recoveries().await.unwrap();
    assert_eq!(recoveries.len(), 1);
    assert_eq!(recoveries[0].occurrence_id, "occ-1");
    assert_eq!(
        scheduler.list_views().await.unwrap()[0].durability_status,
        CampaignDurabilityStatus::RecoveryRequired
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn unavailable_journal_blocks_one_time_but_keeps_recurring_scheduler_live() {
    let fixture = scheduler_fixture_without_store().await;
    fixture.write_due_one_time("once");
    fixture.write_interval("recurring");
    let scheduler = fixture.start().await.unwrap();

    assert!(scheduler.manager.is_running());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !scheduler
            .manager
            .execution_history("recurring")
            .await
            .is_empty(),
        "recurring schedule must continue while one-time durability is blocked"
    );
    assert!(matches!(
        scheduler
            .try_create("new once", &fixture.params(), due_trigger())
            .await,
        Err(CampaignSchedulerError::DurabilityUnavailable(_))
    ));
    let views = scheduler.list_views().await.unwrap();
    assert_eq!(
        views
            .iter()
            .find(|view| view.id == "once")
            .unwrap()
            .durability_status,
        CampaignDurabilityStatus::RecoveryRequired
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn legacy_one_time_cursor_without_receipt_remains_consumed() {
    let fixture = scheduler_fixture_with_store().await;
    let mut legacy = Schedule::new(
        "legacy-once",
        "legacy-once",
        due_trigger(),
        CAMPAIGN_KIND,
    )
    .with_params(serde_json::to_value(fixture.params()).unwrap());
    legacy.last_fire = Some(Utc::now() - chrono::Duration::seconds(1));
    fixture.push_schedule(legacy);
    let scheduler = fixture.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        scheduler.list_views().await.unwrap()[0].durability_status,
        CampaignDurabilityStatus::Consumed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schedule_occurrences")
            .fetch_one(fixture.store.as_ref().unwrap().pool())
            .await
            .unwrap(),
        0
    );
    scheduler.stop().await;
}
```

- [ ] **Step 7: Run reconciliation tests and verify red**

```bash
set -o pipefail
cargo test -p hf-service startup_reconciles_receipt 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-service expired_running_receipt 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because startup currently restores only from generic execution history.

- [ ] **Step 8: Reconcile receipts before recovery planning and ticking**

In `try_start`, construct and install `CampaignSchedulerPersistence`, load `schedules.json`, then load/validate all receipts before registering schedules or calling `manager.start`.

Use this decision table:

```rust
match receipt {
    Some(receipt) if receipt.recovery_eligible(now) => {
        manager.record_expired_one_time_occurrence();
        schedule.last_fire = Some(
            schedule
                .last_fire
                .map_or(receipt.triggered_at, |last| last.max(receipt.triggered_at)),
        );
        manager
            .mark_one_time_recovery_required(
                &schedule.id,
                receipt
                    .recovery_detail
                    .clone()
                    .unwrap_or_else(|| "expired non-terminal occurrence".to_owned()),
            )
            .await;
    }
    Some(receipt) => {
        schedule.last_fire = Some(
            schedule
                .last_fire
                .map_or(receipt.triggered_at, |last| last.max(receipt.triggered_at)),
        );
        manager.mark_one_time_consumed(&schedule.id).await;
    }
    None if schedule.last_fire.is_some() => {
        manager.mark_one_time_consumed(&schedule.id).await;
    }
    None => {}
}
```

If a receipt points to an existing non-one-time schedule, or any row fails strict validation, call `manager.record_corrupt_one_time_journal()` and `manager.block_one_time` with a bounded generic reason. Do not rewrite the affected JSON or receipt. Continue registering and ticking recurring schedules.

If corrected cursors cannot be atomically written, globally block one-time schedules and continue recurring scheduling. Receipt loading must complete before the existing `recovery::plan` can run.

- [ ] **Step 9: Add durability status and one-time creation admission**

Initialize `view_of` with `CampaignDurabilityStatus::Ready`. In `list_views`, map one-time manager status:

```rust
view.durability_status = match self
    .manager
    .one_time_runtime_status(&schedule.id)
    .await
{
    OneTimeRuntimeStatus::Ready if schedule.last_fire.is_some() => {
        CampaignDurabilityStatus::Consumed
    }
    OneTimeRuntimeStatus::Ready => CampaignDurabilityStatus::Ready,
    OneTimeRuntimeStatus::Consumed => CampaignDurabilityStatus::Consumed,
    OneTimeRuntimeStatus::RecoveryRequired { .. } => {
        CampaignDurabilityStatus::RecoveryRequired
    }
};
```

All non-one-time views remain `Ready`.

At the beginning of `try_create`, reject `TriggerConfig::OneTime` when `one_time_runtime_status` is globally blocked or `self.store.is_none()`. Do this before registering or writing JSON.

```rust
if matches!(trigger, TriggerConfig::OneTime { .. }) {
    if self.store.is_none() {
        return Err(CampaignSchedulerError::DurabilityUnavailable(
            "SQLite storage is not configured".to_owned(),
        ));
    }
    if let Some(reason) = self.manager.one_time_block_reason().await {
        return Err(CampaignSchedulerError::DurabilityUnavailable(reason));
    }
}
```

- [ ] **Step 10: Re-run reconciliation tests and verify green**

```bash
set -o pipefail
cargo test -p hf-service startup_reconciles_receipt 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-service expired_running_receipt 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 11: Write failing recovery acknowledgement tests**

Add:

```rust
#[tokio::test]
async fn acknowledgement_cancels_expired_receipt_and_survives_restart() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("once");
    fixture
        .reserve_expired_receipt(
            "once",
            "occ-1",
            "exec-1",
            OneTimeOccurrenceState::Running,
        )
        .await;
    let scheduler = fixture.start().await.unwrap();

    let acknowledged = scheduler
        .acknowledge_one_time_recovery("occ-1")
        .await
        .unwrap();
    assert_eq!(acknowledged.state, "cancelled");
    assert!(scheduler.list_one_time_recoveries().await.unwrap().is_empty());
    scheduler.stop().await;

    let restarted = fixture.start().await.unwrap();
    assert!(restarted.list_one_time_recoveries().await.unwrap().is_empty());
    assert_eq!(
        restarted.list_views().await.unwrap()[0].durability_status,
        CampaignDurabilityStatus::Consumed
    );
    restarted.stop().await;
}

#[tokio::test]
async fn acknowledgement_rejects_live_or_terminal_non_cancelled_receipts() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("once");
    fixture.reserve_live_receipt("once", "occ-live", "exec-live").await;
    let scheduler = fixture.start().await.unwrap();
    assert!(matches!(
        scheduler
            .acknowledge_one_time_recovery("occ-live")
            .await,
        Err(CampaignSchedulerError::OccurrenceConflict(_))
    ));
    scheduler.stop().await;
}

#[tokio::test]
async fn deleted_schedule_does_not_hide_recovery_receipt() {
    let fixture = scheduler_fixture_with_store().await;
    fixture
        .reserve_expired_receipt(
            "deleted",
            "occ-deleted",
            "exec-deleted",
            OneTimeOccurrenceState::Reserved,
        )
        .await;
    let scheduler = fixture.start().await.unwrap();
    let recovery = scheduler.list_one_time_recoveries().await.unwrap().pop().unwrap();
    assert_eq!(recovery.schedule_name, None);
    assert!(!recovery.schedule_exists);
    scheduler.stop().await;
}
```

- [ ] **Step 12: Run recovery acknowledgement tests and verify red**

```bash
set -o pipefail
cargo test -p hf-service acknowledgement_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because service-owned acknowledgement is absent.

- [ ] **Step 13: Implement service-owned recovery operations**

`list_one_time_recoveries` loads and validates receipts on every call, filters only `receipt.recovery_eligible(Utc::now())`, joins schedule names in memory, and sorts by `(triggered_at, occurrence_id)`.

`acknowledge_one_time_recovery` performs:

```rust
let occurrence = self
    .occurrences
    .get_one_time_occurrence(occurrence_id)
    .await
    .map_err(occurrence_journal_error)?
    .ok_or_else(|| CampaignSchedulerError::OccurrenceNotFound(occurrence_id.to_owned()))?;

if occurrence.state == OneTimeOccurrenceState::Cancelled {
    return Ok(self.recovery_view(&occurrence).await);
}
if self.manager.has_active_occurrence(occurrence_id)
    || !occurrence.recovery_eligible(Utc::now())
{
    return Err(CampaignSchedulerError::OccurrenceConflict(
        "the occurrence is terminal or still owns a live lease".to_owned(),
    ));
}

let mut execution = self
    .occurrences
    .get_one_time_execution(occurrence_id)
    .await
    .map_err(occurrence_journal_error)?
    .ok_or_else(|| {
        CampaignSchedulerError::OccurrenceJournal(
            "non-terminal occurrence is missing its execution".to_owned(),
        )
    })?;
execution.status = hf_scheduler::ExecutionStatus::Cancelled;
execution.completed_at = Some(Utc::now());
execution.error_message =
    Some("operator acknowledged unknown prior outcome as cancelled".to_owned());
execution.response_summary = serde_json::json!({
    "status": "cancelled",
    "reason": "operator acknowledged unknown prior outcome as cancelled",
});
```

Pass a bounded version of that reason to `acknowledge_one_time_occurrence`. Map `Acknowledged` and `AlreadyCancelled` to a DTO, `Conflict` to `OccurrenceConflict`, and `Missing` to `OccurrenceNotFound`. On a newly applied acknowledgement, call `manager.record_one_time_acknowledgement()`. On either success result, mark the schedule consumed, preserve/reconcile its cursor, and persist JSON.

- [ ] **Step 14: Add restart matrix, corrupt-journal, and two-service race tests**

Add the restart matrix:

```rust
#[tokio::test]
async fn every_durable_occurrence_state_suppresses_restart_redispatch() {
    for state in [
        OneTimeOccurrenceState::Reserved,
        OneTimeOccurrenceState::Running,
        OneTimeOccurrenceState::Completed,
        OneTimeOccurrenceState::Failed,
        OneTimeOccurrenceState::Cancelled,
    ] {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("restart-once");
        if matches!(
            state,
            OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running
        ) {
            fixture
                .reserve_expired_receipt(
                    "restart-once",
                    "occ-restart",
                    "exec-restart",
                    state,
                )
                .await;
        } else {
            fixture
                .reserve_receipt(
                    "restart-once",
                    "occ-restart",
                    "exec-restart",
                    state,
                )
                .await;
        }
        let first = fixture.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.stop().await;
        let restarted = fixture.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        restarted.stop().await;

        let store = fixture.store.as_ref().unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM schedule_executions
                 WHERE schedule_id = 'restart-once'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
            1,
            "state {state:?} must remain consumed across restart"
        );
    }
}
```

Add the corruption isolation test:

```rust
#[tokio::test]
async fn corrupt_receipt_blocks_one_time_and_allows_recurring_recovery() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("corrupt-once");
    fixture.write_interval("healthy-interval");
    let store = fixture.store.as_ref().unwrap();
    sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES
            ('occ-corrupt', 'corrupt-once', 'exec-corrupt', 'not-rfc3339',
             'reserved', 'old-owner', '2099-01-01T00:00:00Z')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO schedule_executions
            (id, schedule_id, triggered_at, status, data_json)
         VALUES
            ('exec-corrupt', 'corrupt-once', 'not-rfc3339', 'pending', '{}')",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let scheduler = fixture.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(matches!(
        scheduler
            .manager
            .one_time_runtime_status("corrupt-once")
            .await,
        OneTimeRuntimeStatus::RecoveryRequired { .. }
    ));
    assert!(
        !scheduler
            .manager
            .execution_history("healthy-interval")
            .await
            .is_empty()
    );
    scheduler.stop().await;
}
```

Add the shared-database service race:

```rust
#[tokio::test]
async fn two_service_schedulers_dispatch_one_time_at_most_once() {
    let fixture = scheduler_fixture_with_store().await;
    fixture.write_due_one_time("raced-once");
    let database_path = fixture._directory.path().join("scheduler.db");
    let first_store = Arc::new(Store::connect(&database_path).await.unwrap());
    let second_store = Arc::new(Store::connect(&database_path).await.unwrap());
    let first_container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&first_store));
    let second_container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&second_store));
    let (first, second) = tokio::join!(
        CampaignScheduler::try_start(
            first_container,
            fixture.schedules_path.clone(),
            None,
        ),
        CampaignScheduler::try_start(
            second_container,
            fixture.schedules_path.clone(),
            None,
        ),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

assert_eq!(
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'raced-once'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap(),
    1
);
assert_eq!(
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'raced-once'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap(),
    1
);
    first.stop().await;
    second.stop().await;
}
```

- [ ] **Step 15: Run service scheduler tests**

```bash
set -o pipefail
cargo test -p hf-service scheduler:: 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 16: Commit**

```bash
git add crates/hf-service/src/scheduler.rs
git commit -m "feat: reconcile and recover one-time occurrences"
```

---

### Task 7: Expose the Recovery Contract Through CLI and REST

**Files:**
- Modify: `crates/hf-cli/src/main.rs`
- Modify: `crates/hf-web/Cargo.toml`
- Modify: `crates/hf-web/src/router.rs`
- Modify: `crates/hf-web/tests/api.rs`

**Interfaces:**
- Consumes:

```rust
CampaignScheduler::list_one_time_recoveries()
CampaignScheduler::acknowledge_one_time_recovery(occurrence_id)
```

- Produces:

```text
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>

GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```

- [ ] **Step 1: Write failing CLI parser tests**

Add a `schedule_cli_tests` module:

```rust
#[test]
fn schedule_recovery_commands_parse() {
    let list = Cli::try_parse_from(["oxfuzz", "schedule", "recovery", "list"]).unwrap();
    assert!(matches!(
        list.command,
        Commands::Schedule {
            op: ScheduleOp::Recovery {
                op: ScheduleRecoveryOp::List
            }
        }
    ));

    let acknowledge = Cli::try_parse_from([
        "oxfuzz",
        "schedule",
        "recovery",
        "acknowledge",
        "occ-123",
    ])
    .unwrap();
    let Commands::Schedule {
        op:
            ScheduleOp::Recovery {
                op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
            },
    } = acknowledge.command
    else {
        panic!("expected recovery acknowledgement");
    };
    assert_eq!(occurrence_id, "occ-123");
}
```

- [ ] **Step 2: Run the CLI parser test and verify red**

```bash
set -o pipefail
cargo test -p hf-cli schedule_recovery_commands_parse 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL because `ScheduleRecoveryOp` does not exist.

- [ ] **Step 3: Add thin CLI recovery commands**

Add:

```rust
#[derive(Subcommand)]
enum ScheduleRecoveryOp {
    /// List one-time occurrences requiring operator acknowledgement.
    List,
    /// Record an unknown prior outcome as cancelled. This does not terminate a process.
    Acknowledge { occurrence_id: String },
}
```

Add to `ScheduleOp`:

```rust
/// Inspect or acknowledge ambiguous one-time occurrences.
Recovery {
    #[command(subcommand)]
    op: ScheduleRecoveryOp,
},
```

Add match arms:

```rust
ScheduleOp::Recovery {
    op: ScheduleRecoveryOp::List,
} => {
    for recovery in scheduler.list_one_time_recoveries().await? {
        println!(
            "{}  {}  {}  {}  {}",
            recovery.occurrence_id,
            recovery.schedule_name.as_deref().unwrap_or("<deleted schedule>"),
            recovery.triggered_at,
            recovery.state,
            recovery.recovery_detail.as_deref().unwrap_or("unknown outcome"),
        );
    }
}
ScheduleOp::Recovery {
    op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
} => {
    let recovery = scheduler
        .acknowledge_one_time_recovery(&occurrence_id)
        .await?;
    println!(
        "{} recorded as {}. This did not terminate or adopt an orphaned sandbox process.",
        recovery.occurrence_id,
        recovery.state,
    );
}
```

Do not read SQLite or inspect receipt state in the CLI.

- [ ] **Step 4: Re-run the CLI parser test and verify green**

```bash
set -o pipefail
cargo test -p hf-cli schedule_recovery_commands_parse 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 5: Write failing REST route tests**

Add test-only direct dependencies:

```toml
[dev-dependencies]
hf-scheduler = { workspace = true }
hf-storage = { workspace = true }
```

These dependencies seed durable evidence only in integration tests; production
REST handlers still depend solely on `hf-service`.

Add this fixture to `crates/hf-web/tests/api.rs`:

```rust
struct WebRecoveryFixture {
    _directory: tempfile::TempDir,
    scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
    app: axum::Router,
}

impl WebRecoveryFixture {
    fn app(&self) -> axum::Router {
        self.app.clone()
    }
}

async fn web_scheduler_with_occurrence(expired: bool) -> WebRecoveryFixture {
    use hf_scheduler::{ExecutionStatus, Schedule, ScheduleExecution, TriggerConfig};
    use hf_storage::{
        NewScheduleOccurrence, ScheduleOccurrenceTransition, Store,
    };

    let directory = tempfile::tempdir().unwrap();
    let schedules_path = directory.path().join("schedules.json");
    let database_path = directory.path().join("scheduler.db");
    let store = Arc::new(Store::connect(&database_path).await.unwrap());
    let triggered_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let params = hf_service::scheduler::CampaignParams {
        project: directory.path().display().to_string(),
        target: Some("parser".to_owned()),
        engine: "libfuzzer".to_owned(),
        lang: "c".to_owned(),
        duration_secs: 1,
        max_runs: Some(1),
        max_total_secs: None,
        schedule_id: "schedule-web".to_owned(),
    };
    let schedule = Schedule::new(
        "schedule-web",
        "web recovery",
        TriggerConfig::OneTime { at: triggered_at },
        "fuzz-campaign",
    )
    .with_params(serde_json::to_value(params).unwrap());
    std::fs::write(
        &schedules_path,
        serde_json::to_vec_pretty(&vec![schedule]).unwrap(),
    )
    .unwrap();

    let pending = ScheduleExecution {
        execution_id: "exec-web".to_owned(),
        schedule_id: "schedule-web".to_owned(),
        triggered_at,
        started_at: None,
        completed_at: None,
        status: ExecutionStatus::Pending,
        workflow_execution_id: None,
        request_summary: serde_json::json!({}),
        response_summary: serde_json::json!({}),
        error_message: None,
    };
    store
        .reserve_schedule_occurrence(&NewScheduleOccurrence {
            id: "occ-web".to_owned(),
            schedule_id: "schedule-web".to_owned(),
            execution_id: "exec-web".to_owned(),
            triggered_at: triggered_at.to_rfc3339(),
            owner_id: "web-fixture".to_owned(),
            lease_expires_at: (
                chrono::Utc::now() + chrono::Duration::seconds(60)
            )
            .to_rfc3339(),
            execution_status: "pending".to_owned(),
            execution_data_json: serde_json::to_string(&pending).unwrap(),
        })
        .await
        .unwrap();
    let mut running = pending.clone();
    running.status = ExecutionStatus::Running;
    running.started_at = Some(triggered_at);
    store
        .transition_schedule_occurrence(&ScheduleOccurrenceTransition {
            occurrence_id: "occ-web".to_owned(),
            schedule_id: "schedule-web".to_owned(),
            execution_id: "exec-web".to_owned(),
            owner_id: "web-fixture".to_owned(),
            from_state: "reserved".to_owned(),
            to_state: "running".to_owned(),
            lease_expires_at: Some(
                (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            ),
            recovery_detail: None,
            execution_status: "running".to_owned(),
            execution_data_json: serde_json::to_string(&running).unwrap(),
        })
        .await
        .unwrap();
    if expired {
        store
            .release_schedule_occurrence_lease(
                "occ-web",
                "web-fixture",
                &chrono::Utc::now().to_rfc3339(),
                "terminal outcome is unknown",
            )
            .await
            .unwrap();
    }

    let container = hf_service::ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let scheduler = Arc::new(
        hf_service::scheduler::CampaignScheduler::try_start(
            container.clone(),
            schedules_path,
            None,
        )
        .await
        .unwrap(),
    );
    let app = hf_web::router::build_with_state(
        hf_web::router::AppState::new(container).with_scheduler(Arc::clone(&scheduler)),
    );
    WebRecoveryFixture {
        _directory: directory,
        scheduler,
        app,
    }
}
```

Add tests:

```rust
#[tokio::test]
async fn schedule_recovery_list_and_acknowledge_preserve_service_dto() {
    allow_open_dev_mode();
    let fixture = web_scheduler_with_occurrence(true).await;
    let app = fixture.app();

    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/schedule/recovery")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(listed.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body[0]["occurrence_id"], "occ-web");
    assert_eq!(body[0]["state"], "running");

    let acknowledged = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/schedule/recovery/occ-web/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(acknowledged.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["state"], "cancelled");
    fixture.scheduler.stop().await;
}

#[tokio::test]
async fn recovery_mutation_without_scheduler_is_unavailable() {
    allow_open_dev_mode();
    let response = hf_web::router::build()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/schedule/recovery/occ-1/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
```

Add:

```rust
#[tokio::test]
async fn schedule_recovery_acknowledge_maps_missing_and_live_conflicts() {
    allow_open_dev_mode();
    let fixture = web_scheduler_with_occurrence(false).await;
    let app = fixture.app();
    let live = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/schedule/recovery/occ-web/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::CONFLICT);

    let missing = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/schedule/recovery/missing/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    fixture.scheduler.stop().await;
}
```

- [ ] **Step 6: Run the REST tests and verify red**

```bash
set -o pipefail
cargo test -p hf-web schedule_recovery_ 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: FAIL with `404 Not Found` because the recovery routes are absent.

- [ ] **Step 7: Add route-specific error mapping**

Update `scheduler_api_error`:

```rust
fn scheduler_api_error(error: CampaignSchedulerError) -> ApiError {
    match error {
        CampaignSchedulerError::OccurrenceNotFound(message) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: message }),
        ),
        CampaignSchedulerError::OccurrenceConflict(message) => (
            StatusCode::CONFLICT,
            Json(ErrorResponse { error: message }),
        ),
        CampaignSchedulerError::DurabilityUnavailable(message) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse { error: message }),
        ),
        other => classified_api_error(other),
    }
}
```

Keep `OccurrenceJournal` classified as a storage/internal failure; do not expose raw SQL or malformed stored JSON.

- [ ] **Step 8: Add static recovery routes before dynamic schedule routes**

Register:

```rust
.route("/schedule/recovery", get(schedule_recovery_list))
.route(
    "/schedule/recovery/{occurrence_id}/acknowledge",
    post(schedule_recovery_acknowledge),
)
```

Handlers:

```rust
async fn schedule_recovery_list(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let recoveries = match &state.scheduler {
        Some(scheduler) => scheduler
            .list_one_time_recoveries()
            .await
            .map_err(scheduler_api_error)?,
        None => Vec::new(),
    };
    Ok(Json(public_value(recoveries)))
}

async fn schedule_recovery_acknowledge(
    State(state): State<AppState>,
    Path(occurrence_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let scheduler = state.scheduler.as_ref().ok_or_else(|| {
        map_err(StatusCode::SERVICE_UNAVAILABLE)(
            "campaign scheduler is unavailable".to_owned(),
        )
    })?;
    let recovery = scheduler
        .acknowledge_one_time_recovery(&occurrence_id)
        .await
        .map_err(scheduler_api_error)?;
    Ok(Json(public_value(recovery)))
}
```

- [ ] **Step 9: Run CLI and web tests**

```bash
set -o pipefail
cargo test -p hf-cli 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-web 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/hf-cli/src/main.rs crates/hf-web/Cargo.toml crates/hf-web/src/router.rs \
  crates/hf-web/tests/api.rs
git commit -m "feat: expose one-time recovery in CLI and REST"
```

---

### Task 8: Expose Recovery in Tauri and the Automation View

**Files:**
- Create: `crates/hf-gui/src/components/ScheduleRecoveryPanel.tsx`
- Create: `crates/hf-gui/src/lib/scheduleRecovery.ts`
- Create: `crates/hf-gui/src/__tests__/scheduleRecovery.test.ts`
- Create: `crates/hf-gui/src/__tests__/scheduleRecoveryPanel.test.tsx`
- Modify: `crates/hf-gui/src-tauri/src/commands.rs`
- Modify: `crates/hf-gui/src-tauri/src/lib.rs`
- Modify: `crates/hf-gui/src/lib/httpTransport.ts`
- Modify: `crates/hf-gui/src/views/FeatureViews.tsx`
- Modify: `crates/hf-gui/src/i18n.extra.ts`
- Modify: `crates/hf-gui/src/__tests__/transport.test.ts`

**Interfaces:**
- Consumes: Task 6 `OneTimeRecoveryView`/`CampaignDurabilityStatus` and Task 7 REST routes.
- Produces: Tauri commands `schedule_recovery_list` and `schedule_recovery_acknowledge`; matching HTTP transport entries; a warning panel above campaign cards; explicit acknowledgement confirmation; and refresh of campaign, recovery, and history lists.

- [ ] **Step 1: Write the failing HTTP transport test**

Extend the existing placeholder test:

```typescript
await transport.invoke("schedule_recovery_list");
await transport.invoke("schedule_recovery_acknowledge", {
  occurrenceId: "occ/a b",
});

expect(calls.slice(-2).map((call) => call.url)).toEqual([
  "http://localhost:8081/schedule/recovery",
  "http://localhost:8081/schedule/recovery/occ%2Fa%20b/acknowledge",
]);
expect(calls.at(-2)?.init.method).toBe("GET");
expect(calls.at(-1)?.init.method).toBe("POST");
expect(JSON.parse(String(calls.at(-1)?.init.body))).toEqual({});
```

- [ ] **Step 2: Run the transport test and verify red**

```bash
cd crates/hf-gui
npm test -- src/__tests__/transport.test.ts
```

Expected: FAIL because both transport operations are unknown.

- [ ] **Step 3: Add HTTP transport entries**

Add:

```typescript
schedule_recovery_list: {
  method: "GET",
  path: "/schedule/recovery",
},
schedule_recovery_acknowledge: {
  method: "POST",
  path: "/schedule/recovery/{occurrenceId}/acknowledge",
},
```

The existing placeholder extraction removes `occurrenceId` from the JSON body and URL-encodes it.

- [ ] **Step 4: Re-run the transport test and verify green**

```bash
cd crates/hf-gui
npm test -- src/__tests__/transport.test.ts
```

Expected: PASS.

- [ ] **Step 5: Run a failing Tauri wiring check**

```bash
for symbol in schedule_recovery_list schedule_recovery_acknowledge
do
  rg -q "fn $symbol" crates/hf-gui/src-tauri/src/commands.rs || exit 1
  rg -q "$symbol" crates/hf-gui/src-tauri/src/lib.rs || exit 1
done
```

Expected: FAIL on `schedule_recovery_list`.

- [ ] **Step 6: Add thin Tauri commands**

In `commands.rs`:

```rust
#[tauri::command]
pub async fn schedule_recovery_list(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<hf_service::scheduler::OneTimeRecoveryView>, String> {
    state
        .scheduler
        .list_one_time_recoveries()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn schedule_recovery_acknowledge(
    state: tauri::State<'_, crate::state::AppState>,
    occurrence_id: String,
) -> Result<hf_service::scheduler::OneTimeRecoveryView, String> {
    state
        .scheduler
        .acknowledge_one_time_recovery(&occurrence_id)
        .await
        .map_err(|error| error.to_string())
}
```

Import and register both in `src-tauri/src/lib.rs`. Do not inspect state or decide eligibility in Tauri.

- [ ] **Step 7: Re-run the Tauri wiring check**

Run the command from Step 5.

Expected: PASS with both functions defined and registered.

- [ ] **Step 8: Write a failing recovery-panel rendering test**

Create `scheduleRecoveryPanel.test.tsx` using `react-dom/server`:

```typescript
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ScheduleRecoveryPanel } from "../components/ScheduleRecoveryPanel";

describe("ScheduleRecoveryPanel", () => {
  it("renders durable evidence and the acknowledgement action", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[
          {
            occurrence_id: "occ-1",
            schedule_id: "schedule-1",
            schedule_name: "nightly parser",
            execution_id: "exec-1",
            triggered_at: "2026-07-29T01:00:00Z",
            state: "running",
            recovery_detail: "terminal outcome is unknown",
            schedule_exists: true,
          },
        ]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        onAcknowledge={() => undefined}
      />,
    );

    expect(html).toContain("nightly parser");
    expect(html).toContain("running");
    expect(html).toContain("terminal outcome is unknown");
    expect(html).toContain("Acknowledge as cancelled");
  });

  it("renders nothing when no recovery is required", () => {
    const html = renderToStaticMarkup(
      <ScheduleRecoveryPanel
        recoveries={[]}
        title="Recovery required"
        actionLabel="Acknowledge as cancelled"
        unknownScheduleLabel="Deleted schedule"
        onAcknowledge={() => undefined}
      />,
    );
    expect(html).toBe("");
  });
});
```

- [ ] **Step 9: Run the panel test and verify red**

```bash
cd crates/hf-gui
npm test -- src/__tests__/scheduleRecoveryPanel.test.tsx
```

Expected: FAIL because `ScheduleRecoveryPanel` does not exist.

- [ ] **Step 10: Implement the presentation-only panel**

Create:

```typescript
import { Button } from "./ui";

export interface OneTimeRecoveryView {
  occurrence_id: string;
  schedule_id: string;
  schedule_name: string | null;
  execution_id: string;
  triggered_at: string;
  state: string;
  recovery_detail: string | null;
  schedule_exists: boolean;
}

interface ScheduleRecoveryPanelProps {
  recoveries: OneTimeRecoveryView[];
  title: string;
  actionLabel: string;
  unknownScheduleLabel: string;
  onAcknowledge: (occurrenceId: string) => void;
}

export function ScheduleRecoveryPanel({
  recoveries,
  title,
  actionLabel,
  unknownScheduleLabel,
  onAcknowledge,
}: ScheduleRecoveryPanelProps) {
  if (recoveries.length === 0) return null;
  return (
    <section
      role="alert"
      className="surface-card flex flex-col gap-2"
      style={{ borderLeft: "3px solid var(--error)", padding: "var(--space-md)" }}
    >
      <strong className="text-sm">{title}</strong>
      {recoveries.map((recovery) => (
        <div key={recovery.occurrence_id} className="flex items-center gap-3">
          <div className="flex flex-col min-w-0 flex-1 text-xs">
            <span className="font-medium">
              {recovery.schedule_name ?? unknownScheduleLabel}
            </span>
            <span className="font-mono text-text-muted">
              {recovery.state} · {new Date(recovery.triggered_at).toLocaleString()}
            </span>
            {recovery.recovery_detail && (
              <span className="text-text-secondary">{recovery.recovery_detail}</span>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onAcknowledge(recovery.occurrence_id)}
          >
            {actionLabel}
          </Button>
        </div>
      ))}
    </section>
  );
}
```

Do not derive eligibility in this component.

- [ ] **Step 11: Re-run the panel test and verify green**

```bash
cd crates/hf-gui
npm test -- src/__tests__/scheduleRecoveryPanel.test.tsx
```

Expected: PASS.

- [ ] **Step 12: Write failing confirmation-and-refresh tests**

Create `scheduleRecovery.test.ts`:

```typescript
import { describe, expect, it } from "vitest";
import { acknowledgeRecoveryWithRefresh } from "../lib/scheduleRecovery";

describe("acknowledgeRecoveryWithRefresh", () => {
  it("does nothing when confirmation is declined", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => false,
      acknowledge: async () => calls.push("acknowledge"),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(false);
    expect(calls).toEqual([]);
  });

  it("acknowledges before refreshing all automation state", async () => {
    const calls: string[] = [];
    const applied = await acknowledgeRecoveryWithRefresh({
      occurrenceId: "occ-1",
      confirm: async () => true,
      acknowledge: async (occurrenceId) =>
        calls.push(`acknowledge:${occurrenceId}`),
      refresh: async () => calls.push("refresh"),
    });
    expect(applied).toBe(true);
    expect(calls).toEqual(["acknowledge:occ-1", "refresh"]);
  });
});
```

- [ ] **Step 13: Run the recovery action tests and verify red**

```bash
cd crates/hf-gui
npm test -- src/__tests__/scheduleRecovery.test.ts
```

Expected: FAIL because `acknowledgeRecoveryWithRefresh` does not exist.

- [ ] **Step 14: Implement confirmation ordering**

Create `src/lib/scheduleRecovery.ts`:

```typescript
interface RecoveryAction {
  occurrenceId: string;
  confirm: () => Promise<boolean>;
  acknowledge: (occurrenceId: string) => Promise<unknown>;
  refresh: () => Promise<unknown>;
}

export async function acknowledgeRecoveryWithRefresh({
  occurrenceId,
  confirm,
  acknowledge,
  refresh,
}: RecoveryAction): Promise<boolean> {
  if (!(await confirm())) return false;
  await acknowledge(occurrenceId);
  await refresh();
  return true;
}
```

- [ ] **Step 15: Run the recovery action tests and verify green**

```bash
cd crates/hf-gui
npm test -- src/__tests__/scheduleRecovery.test.ts
```

Expected: PASS.

- [ ] **Step 16: Wire polling, confirmation, and full refresh**

Import:

```typescript
import {
  ScheduleRecoveryPanel,
  type OneTimeRecoveryView,
} from "../components/ScheduleRecoveryPanel";
import { acknowledgeRecoveryWithRefresh } from "../lib/scheduleRecovery";
```

Extend the local `CampaignView` with:

```typescript
durability_status: "ready" | "consumed" | "recovery_required";
```

Import `useCallback`, add `recoveries` state, and replace the polling body with:

```typescript
const refreshAutomation = useCallback(async () => {
  const [nextCampaigns, nextHistory, nextRecoveries] = await Promise.all([
    getTransport().invoke<CampaignView[]>("schedule_list"),
    getTransport().invoke<ExecutionView[]>("schedule_history", { limit: 20 }),
    getTransport().invoke<OneTimeRecoveryView[]>("schedule_recovery_list"),
  ]);
  setCampaigns(nextCampaigns);
  setHistory(nextHistory);
  setRecoveries(nextRecoveries);
}, []);
```

Use:

```typescript
useEffect(() => {
  void refreshAutomation().catch((cause: unknown) => setError(String(cause)));
  const intervalId = window.setInterval(() => {
    void refreshAutomation().catch((cause: unknown) => setError(String(cause)));
  }, 10_000);
  return () => window.clearInterval(intervalId);
}, [refreshAutomation]);
```

Add:

```typescript
async function acknowledgeRecovery(occurrenceId: string) {
  setError(null);
  try {
    await acknowledgeRecoveryWithRefresh({
      occurrenceId,
      confirm: () =>
        confirm({
          title: t("automation.recoveryAcknowledgeTitle"),
          message: t("automation.recoveryAcknowledgeMessage"),
          danger: true,
          confirmLabel: t("automation.recoveryAcknowledgeAction"),
        }),
      acknowledge: (id) =>
        getTransport().invoke<OneTimeRecoveryView>(
          "schedule_recovery_acknowledge",
          { occurrenceId: id },
        ),
      refresh: refreshAutomation,
    });
  } catch (cause) {
    setError(String(cause));
  }
}
```

Render after the header/fuzzing-policy notice and before the new-campaign form:

```typescript
<ScheduleRecoveryPanel
  recoveries={recoveries}
  title={t("automation.recoveryTitle")}
  actionLabel={t("automation.recoveryAcknowledgeAction")}
  unknownScheduleLabel={t("automation.recoveryUnknownSchedule")}
  onAcknowledge={(occurrenceId) => void acknowledgeRecovery(occurrenceId)}
/>
```

Campaign cards may render `durability_status`, but must not infer recovery from
`last_fire`.

- [ ] **Step 17: Add English and Chinese recovery copy**

Add these keys in both locale maps:

```text
automation.recoveryTitle
  EN: One-time campaign recovery required
  ZH: 需要恢复单次测试活动

automation.recoveryAcknowledgeAction
  EN: Acknowledge as cancelled
  ZH: 确认为已取消

automation.recoveryAcknowledgeTitle
  EN: Record unknown outcome as cancelled?
  ZH: 将未知结果记录为已取消？

automation.recoveryAcknowledgeMessage
  EN: This permanently consumes the one-time campaign. It does not prove or force termination of an orphaned sandbox process. Retry by creating a new one-time campaign.
  ZH: 此操作会永久消耗该单次测试活动。它不会证明或强制终止孤立的沙箱进程。若要重试，请创建新的单次测试活动。

automation.recoveryUnknownSchedule
  EN: Deleted schedule
  ZH: 已删除的计划
```

- [ ] **Step 18: Run frontend tests, lint, and production build**

```bash
cd crates/hf-gui
npm test -- src/__tests__/transport.test.ts \
  src/__tests__/scheduleRecovery.test.ts \
  src/__tests__/scheduleRecoveryPanel.test.tsx
npm run lint
npm run build
```

Expected: all commands exit `0`.

- [ ] **Step 19: Run the Tauri crate tests**

```bash
set -o pipefail
cargo test -p hf-gui 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 20: Commit**

```bash
git add crates/hf-gui/src-tauri/src/commands.rs \
  crates/hf-gui/src-tauri/src/lib.rs \
  crates/hf-gui/src/lib/httpTransport.ts \
  crates/hf-gui/src/lib/scheduleRecovery.ts \
  crates/hf-gui/src/views/FeatureViews.tsx \
  crates/hf-gui/src/components/ScheduleRecoveryPanel.tsx \
  crates/hf-gui/src/i18n.extra.ts \
  crates/hf-gui/src/__tests__/transport.test.ts \
  crates/hf-gui/src/__tests__/scheduleRecovery.test.ts \
  crates/hf-gui/src/__tests__/scheduleRecoveryPanel.test.tsx
git commit -m "feat: show one-time recovery in Automation"
```

---

### Task 9: Document Operator Recovery and the Dated Upstream Lesson

**Files:**
- Modify: `README.md`
- Modify: `docs/guides/GETTING_STARTED.md`
- Modify: `docs/design/grok-build-lessons-20260719.md`

**Interfaces:**
- Consumes: the CLI and REST contracts from Task 7 and the approved clean-room research.
- Produces: operator instructions that accurately describe acknowledgement, retry, and sandbox limits; a dated follow-up preserving the original July 19 baseline.

- [ ] **Step 1: Run a failing documentation check**

```bash
rg -q 'schedule recovery acknowledge' README.md || exit 1
rg -q 'schedule recovery acknowledge' docs/guides/GETTING_STARTED.md || exit 1
rg -q 'July 29, 2026 follow-up' docs/design/grok-build-lessons-20260719.md || exit 1
```

Expected: FAIL because the recovery commands and July 29 follow-up are absent.

- [ ] **Step 2: Add operator command and API documentation**

Add:

````markdown
#### Recover an ambiguous one-time campaign

```bash
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>
```

Acknowledgement records an expired, non-terminal occurrence as cancelled and
permanently consumes that one-time schedule. It does not prove or force the
termination of an orphaned sandbox process. To retry, create a new one-time
schedule so it receives a new schedule identifier and a new durable receipt.

The equivalent REST operations are:

```text
GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```
````

Update both English and Chinese command tables in `README.md`; keep the safety meaning equivalent in both languages.

- [ ] **Step 3: Add the clean-room research follow-up**

Append a section headed:

```markdown
## July 29, 2026 follow-up
```

Record:

```text
- Fresh upstream revision inspected: 5da6962e4adb9c857f3def762542b52b4ec3e522.
- July 22 sync a5727c5960452e7527a154b25cb5bf00cda0545e introduced
  the applicable durable one-shot occurrence-journal lesson.
- oxfuzz adopted only the architectural lesson: a permanent unique receipt,
  transactional pending history, fail-closed restart reconciliation, and
  explicit recovery.
- oxfuzz added its own 60-second renewable owner lease and 15-second heartbeat
  so a second process cannot acknowledge work still owned by a live scheduler.
- No grok-build implementation code or agent-specific notification protocol
  was copied.
- Exact repeated tool-call stationarity remains a separate candidate because
  oxfuzz already has loop guards and coverage-stagnation controls.
```

- [ ] **Step 4: Re-run documentation checks and safety wording scan**

```bash
rg -q 'schedule recovery acknowledge' README.md
rg -q 'schedule recovery acknowledge' docs/guides/GETTING_STARTED.md
rg -q 'July 29, 2026 follow-up' docs/design/grok-build-lessons-20260719.md
if rg -n -i 'acknowledgement (kills|terminates|retries|resumes)|acknowledge and retry' \
  README.md docs/guides/GETTING_STARTED.md \
  docs/design/grok-build-lessons-20260719.md
then
  exit 1
fi
```

Expected: PASS with no unsafe acknowledgement claim.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/guides/GETTING_STARTED.md \
  docs/design/grok-build-lessons-20260719.md
git commit -m "docs: explain one-time occurrence recovery"
```

---

## Final Verification

- [ ] **Step 1: Run the focused Rust regression suites**

```bash
set -o pipefail
cargo test -p hf-scheduler -p hf-storage -p hf-service -p hf-cli -p hf-web -p hf-gui 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS.

- [ ] **Step 2: Run frontend verification**

```bash
cd crates/hf-gui
npm test
npm run lint
npm run build
```

Expected: all commands exit `0`.

- [ ] **Step 3: Run the mandatory Rust gates in repository order**

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --workspace -- -D warnings
cargo clippy --workspace -- -D warnings
cargo check --workspace
cargo doc --workspace --no-deps
```

Expected: all five commands exit `0`, in exactly this order.

- [ ] **Step 4: Re-run tests after Clippy fixes and verify the core evidence**

First re-run the full Rust regression set after `clippy --fix`:

```bash
set -o pipefail
cargo test -p hf-scheduler -p hf-storage -p hf-service -p hf-cli -p hf-web -p hf-gui 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Then run the specifically named evidence tests:

```bash
set -o pipefail
cargo test -p hf-storage concurrent_reservations_have_one_winner 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-service two_service_schedulers_dispatch_one_time_at_most_once 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
set -o pipefail
cargo test -p hf-service acknowledgement_cancels_expired_receipt_and_survives_restart 2>&1 | \
  { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | \
  head -200
```

Expected: PASS; the race stores one receipt and one execution, and acknowledgement remains cancelled after restart.

- [ ] **Step 5: Verify architectural boundaries and repository cleanliness**

```bash
if rg -n 'sqlx|schedule_occurrences' \
  crates/hf-cli crates/hf-web crates/hf-gui/src crates/hf-gui/src-tauri
then
  exit 1
fi
if rg -n '#\\[allow\\((clippy|rustc_lint)|eslint-disable' \
  crates/hf-scheduler crates/hf-storage crates/hf-service crates/hf-cli \
  crates/hf-web crates/hf-gui
then
  exit 1
fi
git status --short
```

Expected: no presentation-layer SQL/journal decisions, no new inline lint suppression, and an empty working tree.

- [ ] **Step 6: Compare implementation against the approved success criteria**

Confirm each item with the cited evidence:

```text
1. Cross-process race: storage and two-service race tests.
2. Failure points do not retry: scheduler Reserve/Cursor/Running/Terminal tests.
3. No partial receipt/history state: storage rollback and transition tests.
4. Expired non-terminal state is visible: service recovery-list test.
5. Acknowledgement is idempotent and lease-safe: storage + restart tests.
6. Recurring schedules continue: unavailable/corrupt-journal service tests.
7. Corrupt evidence blocks all one-time work: strict row/startup tests.
8. Sandbox boundary is unchanged: no runtime profile or host execution change.
9. One DTO contract reaches all clients: CLI/REST/Tauri/transport/UI tests.
10. All targeted, frontend, formatting, lint, check, and doc commands passed.
```
