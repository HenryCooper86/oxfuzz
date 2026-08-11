//! Persistence boundaries for records belonging to retired fuzzing engines.

use hf_core::retired_engine::RETIRED_ENGINE_ID;
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::{StorageError, Store};

const RETIRED_IDS: &str = "('clusterfuzzlite', 'cfl', 'cflite')";

pub(super) async fn validate_no_active_retired_engine_records(
    pool: &SqlitePool,
) -> Result<(), StorageError> {
    let run_query = format!(
        "SELECT id FROM runs
         WHERE lower(trim(engine)) IN {RETIRED_IDS}
            OR CASE WHEN json_valid(config_json) THEN
                 json_type(config_json, '$.engine') = 'text'
                 AND lower(trim(json_extract(config_json, '$.engine'))) IN {RETIRED_IDS}
               ELSE 0 END
         ORDER BY id LIMIT 20"
    );
    reject_ids(pool, "run", &run_query).await?;

    let harness_query = format!(
        "SELECT id FROM harnesses
         WHERE lower(trim(engine)) IN {RETIRED_IDS}
            OR CASE WHEN json_valid(data_json) THEN
                 json_type(data_json, '$.engine') = 'text'
                 AND lower(trim(json_extract(data_json, '$.engine'))) IN {RETIRED_IDS}
               ELSE 0 END
         ORDER BY id LIMIT 20"
    );
    reject_ids(pool, "harness", &harness_query).await?;

    let execution_query = format!(
        "SELECT id FROM schedule_executions
         WHERE CASE WHEN json_valid(data_json) THEN
             json_type(data_json, '$.request_summary.parameter_values.engine') = 'text'
             AND lower(trim(json_extract(
                 data_json,
                 '$.request_summary.parameter_values.engine'
             ))) IN {RETIRED_IDS}
         ELSE 0 END
         ORDER BY id LIMIT 20"
    );
    reject_ids(pool, "schedule execution", &execution_query).await
}

async fn reject_ids(pool: &SqlitePool, kind: &str, query: &str) -> Result<(), StorageError> {
    let ids: Vec<String> = sqlx::query_scalar(query).fetch_all(pool).await?;
    if ids.is_empty() {
        return Ok(());
    }
    Err(StorageError::InvalidData(format!(
        "fuzzing engine '{}' has been retired; active {kind} record(s): {}",
        RETIRED_ENGINE_ID,
        ids.join(", "),
    )))
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
                'schedule_occurrence', id, 'clusterfuzzlite',
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
        occurrences.push(" ON CONFLICT(record_kind, record_id) DO NOTHING");
        let occurrence_count = occurrences
            .build()
            .execute(&mut *transaction)
            .await?
            .rows_affected();

        let mut executions = QueryBuilder::<Sqlite>::new(
            "INSERT INTO retired_engine_records
                (record_kind, record_id, retired_engine, payload_json, migration_version)
             SELECT
                'schedule_execution', id, 'clusterfuzzlite',
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
        executions.push(" ON CONFLICT(record_kind, record_id) DO NOTHING");
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
