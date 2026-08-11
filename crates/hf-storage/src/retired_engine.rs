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
        if schedule_ids.is_empty() {
            return Ok(0);
        }

        let mut schedule_ids = schedule_ids.to_vec();
        schedule_ids.sort_unstable();
        schedule_ids.dedup();
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
        push_schedule_id_filter(&mut occurrences, &schedule_ids);
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
        push_schedule_id_filter(&mut executions, &schedule_ids);
        let execution_count = executions
            .build()
            .execute(&mut *transaction)
            .await?
            .rows_affected();

        let mut delete_occurrences =
            QueryBuilder::<Sqlite>::new("DELETE FROM schedule_occurrences");
        push_schedule_id_filter(&mut delete_occurrences, &schedule_ids);
        delete_occurrences
            .build()
            .execute(&mut *transaction)
            .await?;

        let mut delete_executions = QueryBuilder::<Sqlite>::new("DELETE FROM schedule_executions");
        push_schedule_id_filter(&mut delete_executions, &schedule_ids);
        delete_executions.build().execute(&mut *transaction).await?;

        transaction.commit().await?;
        Ok(occurrence_count + execution_count)
    }
}
