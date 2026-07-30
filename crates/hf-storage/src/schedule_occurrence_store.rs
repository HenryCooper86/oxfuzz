//! Durable one-time schedule occurrence receipt persistence.

use sqlx::{Row, Sqlite, Transaction};

use crate::store::{StorageError, Store};

const OCCURRENCE_SELECT: &str = "SELECT
    o.id,
    o.schedule_id,
    o.execution_id,
    o.triggered_at,
    o.state,
    o.owner_id,
    o.lease_expires_at,
    o.recovery_detail,
    e.status AS execution_status,
    e.data_json AS execution_data_json
FROM schedule_occurrences o
LEFT JOIN schedule_executions e ON e.id = o.execution_id";

/// A durable one-time schedule occurrence receipt and its optional execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleOccurrenceRecord {
    /// Unique occurrence identifier.
    pub id: String,
    /// Unique one-time schedule identifier.
    pub schedule_id: String,
    /// Soft reference to the associated schedule execution.
    pub execution_id: String,
    /// Time the schedule occurrence triggered.
    pub triggered_at: String,
    /// Durable occurrence lifecycle state.
    pub state: String,
    /// Scheduler instance that owns the non-terminal lease.
    pub owner_id: String,
    /// Lease expiry for a non-terminal receipt.
    pub lease_expires_at: Option<String>,
    /// Bounded operator-facing recovery context.
    pub recovery_detail: Option<String>,
    /// Associated execution state when execution history remains available.
    pub execution_status: Option<String>,
    /// Serialized execution when execution history remains available.
    pub execution_data_json: Option<String>,
}

/// Per-row occurrence inspection that preserves a safely decoded schedule
/// identity even when another column makes the receipt malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOccurrenceInspection {
    /// Every storage column decoded and passed structural validation.
    Valid(ScheduleOccurrenceRecord),
    /// The row is malformed; `schedule_id` is retained only when it is
    /// non-empty UTF-8 text.
    Malformed {
        /// Schedule identity that can be quarantined without interpreting any
        /// other damaged receipt field.
        schedule_id: Option<String>,
    },
}

/// Input used to atomically reserve an occurrence and pending execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScheduleOccurrence {
    /// Unique occurrence identifier.
    pub id: String,
    /// Unique one-time schedule identifier.
    pub schedule_id: String,
    /// Unique execution identifier.
    pub execution_id: String,
    /// Time the schedule occurrence triggered.
    pub triggered_at: String,
    /// Scheduler instance claiming the occurrence.
    pub owner_id: String,
    /// Initial reservation lease expiry.
    pub lease_expires_at: String,
    /// Initial execution status, which must be `pending`.
    pub execution_status: String,
    /// Serialized pending execution.
    pub execution_data_json: String,
}

/// Result of atomically reserving a one-time occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOccurrenceReservation {
    /// This caller inserted the durable receipt and pending execution.
    Reserved(ScheduleOccurrenceRecord),
    /// A receipt for this one-time schedule already exists.
    Existing(ScheduleOccurrenceRecord),
}

/// Input used to atomically transition an occurrence and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleOccurrenceTransition {
    /// Unique occurrence identifier.
    pub occurrence_id: String,
    /// Unique one-time schedule identifier.
    pub schedule_id: String,
    /// Unique execution identifier.
    pub execution_id: String,
    /// Expected lease owner.
    pub owner_id: String,
    /// Expected current occurrence state.
    pub from_state: String,
    /// Requested occurrence state.
    pub to_state: String,
    /// Lease expiry required by the destination state.
    pub lease_expires_at: Option<String>,
    /// Optional bounded recovery context.
    pub recovery_detail: Option<String>,
    /// Execution status paired with the destination state.
    pub execution_status: String,
    /// Serialized execution paired with the destination state.
    pub execution_data_json: String,
}

/// Result of attempting an atomic occurrence transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOccurrenceTransitionResult {
    /// The requested transition was applied.
    Applied(ScheduleOccurrenceRecord),
    /// The exact terminal transition had already been applied.
    Idempotent(ScheduleOccurrenceRecord),
    /// Existing durable state conflicts with the request.
    Conflict(ScheduleOccurrenceRecord),
    /// The requested occurrence does not exist.
    Missing,
}

/// Result of acknowledging an expired occurrence as cancelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOccurrenceAcknowledgement {
    /// The expired occurrence and its execution were cancelled.
    Acknowledged(ScheduleOccurrenceRecord),
    /// The occurrence was already cancelled.
    AlreadyCancelled(ScheduleOccurrenceRecord),
    /// Existing durable state is not eligible for acknowledgement.
    Conflict(ScheduleOccurrenceRecord),
    /// The requested occurrence does not exist.
    Missing,
}

impl Store {
    /// Atomically reserve a durable occurrence receipt and pending execution.
    ///
    /// # Errors
    /// Returns an error when the input is invalid or either paired write fails.
    pub async fn reserve_schedule_occurrence(
        &self,
        new: &NewScheduleOccurrence,
    ) -> Result<ScheduleOccurrenceReservation, StorageError> {
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

        let record = self.schedule_occurrence(&new.id).await?.ok_or_else(|| {
            StorageError::InvalidData("reserved occurrence is missing".to_owned())
        })?;
        Ok(ScheduleOccurrenceReservation::Reserved(record))
    }

    /// Atomically transition an occurrence and its existing execution.
    ///
    /// # Errors
    /// Returns an error when input validation fails, a SQL operation fails, or
    /// the referenced execution is missing.
    pub async fn transition_schedule_occurrence(
        &self,
        transition: &ScheduleOccurrenceTransition,
    ) -> Result<ScheduleOccurrenceTransitionResult, StorageError> {
        let allowed = matches!(
            (transition.from_state.as_str(), transition.to_state.as_str(),),
            ("reserved", "running" | "cancelled")
                | ("running", "completed" | "failed" | "cancelled")
        );
        if !allowed {
            let current = self.schedule_occurrence(&transition.occurrence_id).await?;
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
            || !lease_matches_state(&transition.to_state, transition.lease_expires_at.as_deref())
            || !detail_is_bounded(transition.recovery_detail.as_deref())
        {
            return Err(StorageError::InvalidData(
                "invalid one-time occurrence transition".to_owned(),
            ));
        }

        let mut transaction = self.pool().begin().await?;
        let updated = sqlx::query(
            "UPDATE schedule_occurrences
             SET state = ?1,
                 lease_expires_at = ?2,
                 recovery_detail = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?4
               AND schedule_id = ?5
               AND execution_id = ?6
               AND owner_id = ?7
               AND state = ?8",
        )
        .bind(&transition.to_state)
        .bind(transition.lease_expires_at.as_deref())
        .bind(transition.recovery_detail.as_deref())
        .bind(&transition.occurrence_id)
        .bind(&transition.schedule_id)
        .bind(&transition.execution_id)
        .bind(&transition.owner_id)
        .bind(&transition.from_state)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() == 0 {
            let current = load_by_id(&mut transaction, &transition.occurrence_id).await?;
            transaction.commit().await?;
            return Ok(match current {
                Some(record) if is_exact_terminal_repeat(&record, transition) => {
                    ScheduleOccurrenceTransitionResult::Idempotent(record)
                }
                Some(record) => ScheduleOccurrenceTransitionResult::Conflict(record),
                None => ScheduleOccurrenceTransitionResult::Missing,
            });
        }

        let execution = sqlx::query(
            "UPDATE schedule_executions
             SET status = ?1, data_json = ?2
             WHERE id = ?3",
        )
        .bind(&transition.execution_status)
        .bind(&transition.execution_data_json)
        .bind(&transition.execution_id)
        .execute(&mut *transaction)
        .await?;
        require_occurrence_execution(execution.rows_affected())?;
        let record = load_by_id(&mut transaction, &transition.occurrence_id)
            .await?
            .ok_or_else(|| {
                StorageError::InvalidData("transitioned occurrence is missing".to_owned())
            })?;
        transaction.commit().await?;
        Ok(ScheduleOccurrenceTransitionResult::Applied(record))
    }

    /// Renew a non-terminal occurrence lease owned by the caller.
    ///
    /// # Errors
    /// Returns an error when the input is invalid or the SQL update fails.
    pub async fn renew_schedule_occurrence_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        lease_expires_at: &str,
    ) -> Result<bool, StorageError> {
        if occurrence_id.is_empty() || owner_id.is_empty() || lease_expires_at.is_empty() {
            return Err(StorageError::InvalidData(
                "invalid one-time occurrence lease renewal".to_owned(),
            ));
        }
        let updated = sqlx::query(
            "UPDATE schedule_occurrences
             SET lease_expires_at = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2
               AND owner_id = ?3
               AND state IN ('reserved', 'running')",
        )
        .bind(lease_expires_at)
        .bind(occurrence_id)
        .bind(owner_id)
        .execute(self.pool())
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    /// Release a caller-owned lease for acknowledgement recovery.
    ///
    /// The release timestamp remains a non-null lease expiry so the durable
    /// non-terminal lease invariant is preserved.
    ///
    /// # Errors
    /// Returns an error when the input is invalid or the SQL update fails.
    pub async fn release_schedule_occurrence_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        released_at: &str,
        recovery_detail: &str,
    ) -> Result<bool, StorageError> {
        if occurrence_id.is_empty()
            || owner_id.is_empty()
            || released_at.is_empty()
            || !detail_is_bounded(Some(recovery_detail))
        {
            return Err(StorageError::InvalidData(
                "invalid one-time occurrence lease release".to_owned(),
            ));
        }
        let updated = sqlx::query(
            "UPDATE schedule_occurrences
             SET lease_expires_at = ?1,
                 recovery_detail = ?2,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?3
               AND owner_id = ?4
               AND state IN ('reserved', 'running')",
        )
        .bind(released_at)
        .bind(recovery_detail)
        .bind(occurrence_id)
        .bind(owner_id)
        .execute(self.pool())
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    /// Load a durable occurrence receipt by identifier.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn schedule_occurrence(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<ScheduleOccurrenceRecord>, StorageError> {
        let query = format!("{OCCURRENCE_SELECT} WHERE o.id = ?1");
        let row = sqlx::query(&query)
            .bind(occurrence_id)
            .fetch_optional(self.pool())
            .await?;
        row.as_ref().map(record_from_row).transpose()
    }

    /// List every durable occurrence receipt in deterministic trigger order.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_schedule_occurrences(
        &self,
    ) -> Result<Vec<ScheduleOccurrenceRecord>, StorageError> {
        self.inspect_schedule_occurrences()
            .await?
            .into_iter()
            .map(|inspection| match inspection {
                ScheduleOccurrenceInspection::Valid(record) => Ok(record),
                ScheduleOccurrenceInspection::Malformed { .. } => Err(StorageError::InvalidData(
                    "invalid stored one-time occurrence".to_owned(),
                )),
            })
            .collect()
    }

    /// Inspect every durable occurrence receipt without discarding the safe
    /// schedule identity of an individually malformed row.
    ///
    /// # Errors
    /// Returns an error only when SQLite cannot fetch the row set. Column
    /// decoding and structural failures are returned as per-row malformed
    /// inspections.
    pub async fn inspect_schedule_occurrences(
        &self,
    ) -> Result<Vec<ScheduleOccurrenceInspection>, StorageError> {
        let query = format!("{OCCURRENCE_SELECT} ORDER BY o.triggered_at, o.id");
        let rows = sqlx::query(&query).fetch_all(self.pool()).await?;
        Ok(rows
            .iter()
            .map(|row| match record_from_row(row) {
                Ok(record) => ScheduleOccurrenceInspection::Valid(record),
                Err(_) => ScheduleOccurrenceInspection::Malformed {
                    schedule_id: row
                        .try_get::<String, _>("schedule_id")
                        .ok()
                        .filter(|schedule_id| !schedule_id.is_empty()),
                },
            })
            .collect())
    }

    /// Acknowledge an expired non-terminal occurrence as cancelled.
    ///
    /// # Errors
    /// Returns an error when input validation fails, a SQL operation fails, or
    /// the referenced execution is missing.
    pub async fn acknowledge_schedule_occurrence(
        &self,
        occurrence_id: &str,
        acknowledged_at: &str,
        recovery_detail: &str,
        execution_status: &str,
        execution_data_json: &str,
    ) -> Result<ScheduleOccurrenceAcknowledgement, StorageError> {
        if occurrence_id.is_empty()
            || acknowledged_at.is_empty()
            || execution_status != "cancelled"
            || !detail_is_bounded(Some(recovery_detail))
        {
            return Err(StorageError::InvalidData(
                "invalid one-time occurrence acknowledgement".to_owned(),
            ));
        }

        let mut transaction = self.pool().begin().await?;
        let updated = sqlx::query(
            "UPDATE schedule_occurrences
             SET state = 'cancelled',
                 lease_expires_at = NULL,
                 recovery_detail = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2
               AND state IN ('reserved', 'running')
               AND julianday(lease_expires_at) <= julianday(?3)",
        )
        .bind(recovery_detail)
        .bind(occurrence_id)
        .bind(acknowledged_at)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() == 0 {
            let current = load_by_id(&mut transaction, occurrence_id).await?;
            transaction.commit().await?;
            return Ok(match current {
                Some(record) if record.state == "cancelled" => {
                    ScheduleOccurrenceAcknowledgement::AlreadyCancelled(record)
                }
                Some(record) => ScheduleOccurrenceAcknowledgement::Conflict(record),
                None => ScheduleOccurrenceAcknowledgement::Missing,
            });
        }

        let execution_id: String =
            sqlx::query_scalar("SELECT execution_id FROM schedule_occurrences WHERE id = ?1")
                .bind(occurrence_id)
                .fetch_one(&mut *transaction)
                .await?;
        let execution = sqlx::query(
            "UPDATE schedule_executions
             SET status = ?1, data_json = ?2
             WHERE id = ?3",
        )
        .bind(execution_status)
        .bind(execution_data_json)
        .bind(execution_id)
        .execute(&mut *transaction)
        .await?;
        require_occurrence_execution(execution.rows_affected())?;
        let record = load_by_id(&mut transaction, occurrence_id)
            .await?
            .ok_or_else(|| {
                StorageError::InvalidData("acknowledged occurrence is missing".to_owned())
            })?;
        transaction.commit().await?;
        Ok(ScheduleOccurrenceAcknowledgement::Acknowledged(record))
    }
}

async fn load_by_schedule(
    transaction: &mut Transaction<'_, Sqlite>,
    schedule_id: &str,
) -> Result<ScheduleOccurrenceRecord, StorageError> {
    let query = format!("{OCCURRENCE_SELECT} WHERE o.schedule_id = ?1");
    let row = sqlx::query(&query)
        .bind(schedule_id)
        .fetch_one(&mut **transaction)
        .await?;
    record_from_row(&row)
}

async fn load_by_id(
    transaction: &mut Transaction<'_, Sqlite>,
    occurrence_id: &str,
) -> Result<Option<ScheduleOccurrenceRecord>, StorageError> {
    let query = format!("{OCCURRENCE_SELECT} WHERE o.id = ?1");
    let row = sqlx::query(&query)
        .bind(occurrence_id)
        .fetch_optional(&mut **transaction)
        .await?;
    row.as_ref().map(record_from_row).transpose()
}

fn record_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ScheduleOccurrenceRecord, StorageError> {
    let record = ScheduleOccurrenceRecord {
        id: occurrence_column(row.try_get("id"))?,
        schedule_id: occurrence_column(row.try_get("schedule_id"))?,
        execution_id: occurrence_column(row.try_get("execution_id"))?,
        triggered_at: occurrence_column(row.try_get("triggered_at"))?,
        state: occurrence_column(row.try_get("state"))?,
        owner_id: occurrence_column(row.try_get("owner_id"))?,
        lease_expires_at: occurrence_column(row.try_get("lease_expires_at"))?,
        recovery_detail: occurrence_column(row.try_get("recovery_detail"))?,
        execution_status: occurrence_column(row.try_get("execution_status"))?,
        execution_data_json: occurrence_column(row.try_get("execution_data_json"))?,
    };
    if record.id.is_empty()
        || record.schedule_id.is_empty()
        || record.execution_id.is_empty()
        || record.owner_id.is_empty()
        || !lease_matches_state(&record.state, record.lease_expires_at.as_deref())
        || !detail_is_bounded(record.recovery_detail.as_deref())
    {
        return Err(StorageError::InvalidData(
            "invalid stored one-time occurrence".to_owned(),
        ));
    }
    Ok(record)
}

fn occurrence_column<T>(result: Result<T, sqlx::Error>) -> Result<T, StorageError> {
    result.map_err(|error| match error {
        sqlx::Error::ColumnDecode { .. } => {
            StorageError::InvalidData("invalid stored one-time occurrence column".to_owned())
        }
        other => StorageError::Db(other),
    })
}

fn lease_matches_state(state: &str, lease_expires_at: Option<&str>) -> bool {
    match state {
        "reserved" | "running" => lease_expires_at.is_some(),
        "completed" | "failed" | "cancelled" => lease_expires_at.is_none(),
        _ => false,
    }
}

fn detail_is_bounded(detail: Option<&str>) -> bool {
    detail.is_none_or(|value| value.len() <= 4_096)
}

fn is_exact_terminal_repeat(
    record: &ScheduleOccurrenceRecord,
    transition: &ScheduleOccurrenceTransition,
) -> bool {
    matches!(
        transition.to_state.as_str(),
        "completed" | "failed" | "cancelled"
    ) && record.id == transition.occurrence_id
        && record.schedule_id == transition.schedule_id
        && record.execution_id == transition.execution_id
        && record.owner_id == transition.owner_id
        && record.state == transition.to_state
        && record.lease_expires_at == transition.lease_expires_at
        && record.recovery_detail == transition.recovery_detail
        && record.execution_status.as_deref() == Some(transition.execution_status.as_str())
        && record.execution_data_json.as_deref() == Some(transition.execution_data_json.as_str())
}

fn require_occurrence_execution(rows_affected: u64) -> Result<(), StorageError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(StorageError::InvalidData(
            "occurrence execution is missing".to_owned(),
        ))
    }
}
