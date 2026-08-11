//! Persistence boundaries for records belonging to retired fuzzing engines.

use hf_core::retired_engine::{RETIRED_ENGINE_ID, RETIRED_ENGINE_IDS};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::{StorageError, Store};

/// Unicode `White_Space` code points used by Rust `str::trim`.
const RUST_TRIM_WHITESPACE_SQL: &str =
    "char(9,10,11,12,13,32,133,160,5760,8192,8193,8194,8195,8196,8197,8198,8199,8200,8201,8202,8232,8233,8239,8287,12288)";

pub(super) async fn validate_no_active_retired_engine_records(
    pool: &SqlitePool,
) -> Result<(), StorageError> {
    let mut run_query = QueryBuilder::<Sqlite>::new("SELECT id FROM runs WHERE ");
    push_normalized_identifier(&mut run_query, "engine");
    run_query.push(" IN (");
    push_retired_engine_id_binds(&mut run_query);
    run_query.push(
        ")
            OR CASE WHEN json_valid(config_json) THEN
                 json_type(config_json, '$.engine') = 'text'
                 AND ",
    );
    push_normalized_identifier(&mut run_query, "json_extract(config_json, '$.engine')");
    run_query.push(" IN (");
    push_retired_engine_id_binds(&mut run_query);
    run_query.push(") ELSE 0 END ORDER BY id LIMIT 20");
    reject_ids(pool, "run", run_query).await?;

    let mut harness_query = QueryBuilder::<Sqlite>::new("SELECT id FROM harnesses WHERE ");
    push_normalized_identifier(&mut harness_query, "engine");
    harness_query.push(" IN (");
    push_retired_engine_id_binds(&mut harness_query);
    harness_query.push(
        ")
            OR CASE WHEN json_valid(data_json) THEN
                 json_type(data_json, '$.engine') = 'text'
                 AND ",
    );
    push_normalized_identifier(&mut harness_query, "json_extract(data_json, '$.engine')");
    harness_query.push(" IN (");
    push_retired_engine_id_binds(&mut harness_query);
    harness_query.push(") ELSE 0 END ORDER BY id LIMIT 20");
    reject_ids(pool, "harness", harness_query).await?;

    let mut execution_query = QueryBuilder::<Sqlite>::new(
        "SELECT id FROM schedule_executions
         WHERE CASE WHEN json_valid(data_json) THEN
             json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
             AND ",
    );
    push_normalized_identifier(
        &mut execution_query,
        "json_extract(data_json, '$.request_summary.parameter_values.engine')",
    );
    execution_query.push(" IN (");
    push_retired_engine_id_binds(&mut execution_query);
    execution_query.push(") ELSE 0 END ORDER BY id LIMIT 20");
    reject_ids(pool, "schedule execution", execution_query).await
}

async fn reject_ids(
    pool: &SqlitePool,
    kind: &str,
    mut query: QueryBuilder<'_, Sqlite>,
) -> Result<(), StorageError> {
    let ids: Vec<String> = query.build_query_scalar().fetch_all(pool).await?;
    if ids.is_empty() {
        return Ok(());
    }
    Err(StorageError::InvalidData(format!(
        "fuzzing engine '{}' has been retired; active {kind} record(s): {}",
        RETIRED_ENGINE_ID,
        ids.join(", "),
    )))
}

fn push_normalized_identifier(query: &mut QueryBuilder<'_, Sqlite>, expression: &str) {
    query.push("lower(trim(");
    query.push(expression);
    query.push(", ");
    query.push(RUST_TRIM_WHITESPACE_SQL);
    query.push("))");
}

fn push_retired_engine_id_binds(query: &mut QueryBuilder<'_, Sqlite>) {
    let mut separated = query.separated(", ");
    for identifier in RETIRED_ENGINE_IDS {
        separated.push_bind(*identifier);
    }
}

fn push_schedule_id_filter<'args>(
    query: &mut QueryBuilder<'args, Sqlite>,
    schedule_ids: &'args [String],
) {
    query.push(" WHERE schedule_id IN (");
    let mut separated = query.separated(", ");
    for schedule_id in schedule_ids {
        separated.push_bind(schedule_id);
    }
    separated.push_unseparated(")");
}

impl Store {
    /// Archive and remove scheduler history linked to retired file schedules.
    ///
    /// # Errors
    /// Returns an error if archival or deletion cannot be completed atomically.
    pub async fn archive_schedule_history_for_retired_engine(
        &self,
        schedule_ids: &[String],
    ) -> Result<u64, StorageError> {
        let mut schedule_ids = schedule_ids.to_vec();
        schedule_ids.sort_unstable();
        schedule_ids.dedup();
        if schedule_ids.is_empty() {
            return Ok(0);
        }
        self.archive_schedule_history(&schedule_ids, None).await
    }

    /// Archive linked scheduler history and durably prove one retirement plan.
    ///
    /// The proof row is inserted in the same transaction as the evidence rows
    /// and source-row deletion. Retrying an identical operation is a no-op;
    /// reusing an operation ID for different plan evidence fails closed.
    ///
    /// # Errors
    /// Returns an error if evidence conflicts, the operation proof diverges, or
    /// the transaction cannot be completed atomically.
    pub async fn archive_schedule_history_for_retired_engine_operation(
        &self,
        operation_id: &str,
        plan_digest: &str,
        schedule_ids: &[String],
    ) -> Result<u64, StorageError> {
        let mut schedule_ids = schedule_ids.to_vec();
        schedule_ids.sort_unstable();
        schedule_ids.dedup();
        let schedule_ids_json = serde_json::to_string(&schedule_ids)?;
        if let Some((existing_digest, existing_ids)) = self
            .schedule_retirement_history_payload(operation_id)
            .await?
        {
            if existing_digest == plan_digest && existing_ids == schedule_ids_json {
                return Ok(0);
            }
            return Err(StorageError::InvalidData(
                "schedule-retirement operation proof conflicts with persisted evidence".to_owned(),
            ));
        }
        self.archive_schedule_history(
            &schedule_ids,
            Some((operation_id, plan_digest, &schedule_ids_json)),
        )
        .await
    }

    /// Return whether the exact operation-bound retirement history proof exists.
    ///
    /// # Errors
    /// Returns an error if the proof query or canonical serialization fails.
    pub async fn schedule_retirement_history_proven(
        &self,
        operation_id: &str,
        plan_digest: &str,
        schedule_ids: &[String],
    ) -> Result<bool, StorageError> {
        let mut schedule_ids = schedule_ids.to_vec();
        schedule_ids.sort_unstable();
        schedule_ids.dedup();
        let expected_ids = serde_json::to_string(&schedule_ids)?;
        let marker_matches = self
            .schedule_retirement_history_payload(operation_id)
            .await?
            .is_some_and(|(persisted_digest, persisted_ids)| {
                persisted_digest == plan_digest && persisted_ids == expected_ids
            });
        if !marker_matches || schedule_ids.is_empty() {
            return Ok(marker_matches);
        }
        let mut active =
            QueryBuilder::<Sqlite>::new("SELECT EXISTS(SELECT 1 FROM schedule_executions");
        push_schedule_id_filter(&mut active, &schedule_ids);
        active.push(" UNION ALL SELECT 1 FROM schedule_occurrences");
        push_schedule_id_filter(&mut active, &schedule_ids);
        active.push(")");
        let has_active: bool = active.build_query_scalar().fetch_one(self.pool()).await?;
        Ok(!has_active)
    }

    /// Return whether any schedule-retirement history proof exists.
    ///
    /// # Errors
    /// Returns an error if the proof query fails.
    pub async fn has_schedule_retirement_history_proof(&self) -> Result<bool, StorageError> {
        sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM schedule_retirement_operations
             )",
        )
        .fetch_one(self.pool())
        .await
        .map_err(StorageError::from)
    }

    async fn schedule_retirement_history_payload(
        &self,
        operation_id: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        sqlx::query_as(
            "SELECT plan_digest, schedule_ids_json
             FROM schedule_retirement_operations WHERE operation_id = ?1",
        )
        .bind(operation_id)
        .fetch_optional(self.pool())
        .await
        .map_err(StorageError::from)
    }

    async fn archive_schedule_history(
        &self,
        schedule_ids: &[String],
        operation_proof: Option<(&str, &str, &str)>,
    ) -> Result<u64, StorageError> {
        let mut transaction = self.pool().begin().await?;

        let mut occurrences = QueryBuilder::<Sqlite>::new(
            "INSERT INTO retired_engine_records
                (record_kind, record_id, retired_engine, payload_json, migration_version)
             SELECT
                'schedule_occurrence', id, ",
        );
        occurrences.push_bind(RETIRED_ENGINE_ID);
        occurrences.push(
            ",
                json_object(
                    'id', id,
                    'schedule_id', schedule_id,
                    'execution_id', execution_id,
                    'triggered_at', triggered_at,
                    'state', state,
                    'owner_id', owner_id,
                    'lease_expires_at', lease_expires_at,
                    'recovery_detail', recovery_detail,
                    'created_at', created_at,
                    'updated_at', updated_at
                ),
                24
             FROM schedule_occurrences",
        );
        push_schedule_id_filter(&mut occurrences, schedule_ids);
        let occurrence_count = occurrences
            .build()
            .execute(&mut *transaction)
            .await?
            .rows_affected();

        let mut executions = QueryBuilder::<Sqlite>::new(
            "INSERT INTO retired_engine_records
                (record_kind, record_id, retired_engine, payload_json, migration_version)
             SELECT
                'schedule_execution', id, ",
        );
        executions.push_bind(RETIRED_ENGINE_ID);
        executions.push(
            ",
                json_object(
                    'id', id,
                    'schedule_id', schedule_id,
                    'triggered_at', triggered_at,
                    'status', status,
                    'data_json', data_json
                ),
                24
             FROM schedule_executions",
        );
        push_schedule_id_filter(&mut executions, schedule_ids);
        let execution_count = executions
            .build()
            .execute(&mut *transaction)
            .await?
            .rows_affected();

        let mut delete_occurrences =
            QueryBuilder::<Sqlite>::new("DELETE FROM schedule_occurrences");
        push_schedule_id_filter(&mut delete_occurrences, schedule_ids);
        delete_occurrences
            .build()
            .execute(&mut *transaction)
            .await?;

        let mut delete_executions = QueryBuilder::<Sqlite>::new("DELETE FROM schedule_executions");
        push_schedule_id_filter(&mut delete_executions, schedule_ids);
        delete_executions.build().execute(&mut *transaction).await?;

        if let Some((operation_id, plan_digest, schedule_ids_json)) = operation_proof {
            sqlx::query(
                "INSERT INTO schedule_retirement_operations
                    (operation_id, plan_digest, schedule_ids_json)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(operation_id)
            .bind(plan_digest)
            .bind(schedule_ids_json)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(occurrence_count + execution_count)
    }
}
