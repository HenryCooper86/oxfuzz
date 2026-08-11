//! Persistence boundaries for records belonging to retired fuzzing engines.

use hf_core::retired_engine::{RETIRED_ENGINE_ID, RETIRED_ENGINE_IDS};
use sqlx::{QueryBuilder, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

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

const MAX_RETIREMENT_IDS_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETIREMENT_SCHEDULE_ID_BYTES: usize = 512;
const MAX_RETIREMENT_SCHEDULE_IDS: usize = 4_096;

fn canonical_schedule_ids(schedule_ids: &[String]) -> Result<Vec<String>, StorageError> {
    let mut canonical = schedule_ids.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.is_empty()
        || canonical.len() > MAX_RETIREMENT_SCHEDULE_IDS
        || canonical.iter().any(|id| {
            id.is_empty()
                || id.len() > MAX_RETIREMENT_SCHEDULE_ID_BYTES
                || id.as_bytes().contains(&0)
        })
    {
        return Err(StorageError::InvalidData(
            "schedule-retirement proof contains an invalid schedule ID".to_owned(),
        ));
    }
    Ok(canonical)
}

fn validate_operation_binding(operation_id: &str, plan_digest: &str) -> Result<(), StorageError> {
    let canonical_uuid = Uuid::parse_str(operation_id)
        .map_err(|_| {
            StorageError::InvalidData("invalid schedule-retirement operation ID".to_owned())
        })?
        .to_string();
    if canonical_uuid != operation_id
        || plan_digest.len() != 64
        || !plan_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StorageError::InvalidData(
            "invalid schedule-retirement operation proof binding".to_owned(),
        ));
    }
    Ok(())
}

fn decode_proof_ids(schedule_ids_json: &str) -> Result<Vec<String>, StorageError> {
    if schedule_ids_json.len() > MAX_RETIREMENT_IDS_JSON_BYTES {
        return Err(StorageError::InvalidData(
            "schedule-retirement proof ID manifest is oversized".to_owned(),
        ));
    }
    let ids: Vec<String> = serde_json::from_str(schedule_ids_json).map_err(|_| {
        StorageError::InvalidData("malformed schedule-retirement proof ID manifest".to_owned())
    })?;
    let canonical = canonical_schedule_ids(&ids)?;
    if canonical != ids {
        return Err(StorageError::InvalidData(
            "schedule-retirement proof IDs are not sorted and unique".to_owned(),
        ));
    }
    Ok(ids)
}

async fn load_validated_proofs(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<Vec<(String, String, Vec<String>)>, StorageError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT operation_id, plan_digest, schedule_ids_json
         FROM schedule_retirement_operations ORDER BY operation_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut proofs = Vec::with_capacity(rows.len());
    for (operation_id, plan_digest, schedule_ids_json) in rows {
        validate_operation_binding(&operation_id, &plan_digest)?;
        let ids = decode_proof_ids(&schedule_ids_json)?;
        let tombstones: Vec<String> = sqlx::query_scalar(
            "SELECT schedule_id FROM schedule_retirement_schedule_ids
             WHERE operation_id = ?1 ORDER BY ordinal",
        )
        .bind(&operation_id)
        .fetch_all(&mut **transaction)
        .await?;
        if tombstones != ids {
            return Err(StorageError::InvalidData(
                "schedule-retirement proof tombstones do not match its ID manifest".to_owned(),
            ));
        }
        proofs.push((operation_id, plan_digest, ids));
    }
    Ok(proofs)
}

async fn has_active_schedule_history(
    transaction: &mut Transaction<'_, Sqlite>,
    schedule_ids: &[String],
) -> Result<bool, StorageError> {
    let mut active = QueryBuilder::<Sqlite>::new(
        "SELECT EXISTS(SELECT 1 FROM schedule_executions
         WHERE typeof(schedule_id) <> 'text' OR schedule_id IN (",
    );
    let mut execution_ids = active.separated(", ");
    for schedule_id in schedule_ids {
        execution_ids.push_bind(schedule_id);
    }
    execution_ids.push_unseparated(")");
    active.push(" UNION ALL SELECT 1 FROM schedule_occurrences");
    active.push(" WHERE typeof(schedule_id) <> 'text' OR schedule_id IN (");
    let mut occurrence_ids = active.separated(", ");
    for schedule_id in schedule_ids {
        occurrence_ids.push_bind(schedule_id);
    }
    occurrence_ids.push_unseparated(")");
    active.push(")");
    active
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(StorageError::from)
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
        self.archive_schedule_history(&schedule_ids).await
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
        validate_operation_binding(operation_id, plan_digest)?;
        let schedule_ids = canonical_schedule_ids(schedule_ids)?;
        let schedule_ids_json = serde_json::to_string(&schedule_ids)?;
        if schedule_ids_json.len() > MAX_RETIREMENT_IDS_JSON_BYTES {
            return Err(StorageError::InvalidData(
                "schedule-retirement proof ID manifest is oversized".to_owned(),
            ));
        }
        let mut transaction = self.pool().begin().await?;
        let proofs = load_validated_proofs(&mut transaction).await?;
        if has_non_text_schedule_history(&mut transaction).await? {
            return Err(StorageError::InvalidData(
                "schedule history contains a non-TEXT schedule ID".to_owned(),
            ));
        }
        if !proofs.is_empty() {
            let exact = proofs.len() == 1
                && proofs[0].0 == operation_id
                && proofs[0].1 == plan_digest
                && proofs[0].2 == schedule_ids;
            if exact && !has_active_schedule_history(&mut transaction, &schedule_ids).await? {
                transaction.commit().await?;
                return Ok(0);
            }
            return Err(StorageError::InvalidData(
                "schedule-retirement operation proof conflicts with persisted evidence".to_owned(),
            ));
        }
        let archived = archive_schedule_history_rows(&mut transaction, &schedule_ids).await?;
        sqlx::query(
            "INSERT INTO schedule_retirement_operations
                (operation_id, plan_digest, schedule_ids_json)
             VALUES (?1, ?2, ?3)",
        )
        .bind(operation_id)
        .bind(plan_digest)
        .bind(&schedule_ids_json)
        .execute(&mut *transaction)
        .await?;
        for (ordinal, schedule_id) in schedule_ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO schedule_retirement_schedule_ids
                    (schedule_id, operation_id, ordinal) VALUES (?1, ?2, ?3)",
            )
            .bind(schedule_id)
            .bind(operation_id)
            .bind(i64::try_from(ordinal).map_err(|_| {
                StorageError::InvalidData("too many schedule-retirement IDs".to_owned())
            })?)
            .execute(&mut *transaction)
            .await?;
        }
        if has_active_schedule_history(&mut transaction, &schedule_ids).await? {
            return Err(StorageError::InvalidData(
                "active history remains for a proven-retired schedule".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(archived)
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
        validate_operation_binding(operation_id, plan_digest)?;
        let schedule_ids = canonical_schedule_ids(schedule_ids)?;
        let mut transaction = self.pool().begin().await?;
        let proofs = load_validated_proofs(&mut transaction).await?;
        let marker_matches = proofs.len() == 1
            && proofs[0].0 == operation_id
            && proofs[0].1 == plan_digest
            && proofs[0].2 == schedule_ids;
        let proven =
            marker_matches && !has_active_schedule_history(&mut transaction, &schedule_ids).await?;
        transaction.commit().await?;
        Ok(proven)
    }

    /// Return whether any schedule-retirement history proof exists.
    ///
    /// # Errors
    /// Returns an error if the proof query fails.
    pub async fn has_schedule_retirement_history_proof(&self) -> Result<bool, StorageError> {
        let mut transaction = self.pool().begin().await?;
        let has_proof = !load_validated_proofs(&mut transaction).await?.is_empty();
        transaction.commit().await?;
        Ok(has_proof)
    }

    /// Return the permanent schedule identities bound by validated retirement proofs.
    ///
    /// # Errors
    /// Returns an error if any proof or normalized tombstone is malformed.
    pub async fn schedule_retirement_tombstone_ids(&self) -> Result<Vec<String>, StorageError> {
        let mut transaction = self.pool().begin().await?;
        let mut ids = load_validated_proofs(&mut transaction)
            .await?
            .into_iter()
            .flat_map(|(_, _, ids)| ids)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        transaction.commit().await?;
        Ok(ids)
    }

    async fn archive_schedule_history(&self, schedule_ids: &[String]) -> Result<u64, StorageError> {
        let mut transaction = self.pool().begin().await?;
        let archived = archive_schedule_history_rows(&mut transaction, schedule_ids).await?;
        transaction.commit().await?;
        Ok(archived)
    }
}

async fn has_non_text_schedule_history(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<bool, StorageError> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM schedule_executions WHERE typeof(schedule_id) <> 'text'
            UNION ALL
            SELECT 1 FROM schedule_occurrences WHERE typeof(schedule_id) <> 'text'
        )",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(StorageError::from)
}

async fn archive_schedule_history_rows(
    transaction: &mut Transaction<'_, Sqlite>,
    schedule_ids: &[String],
) -> Result<u64, StorageError> {
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
        .execute(&mut **transaction)
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
        .execute(&mut **transaction)
        .await?
        .rows_affected();

    let mut delete_occurrences = QueryBuilder::<Sqlite>::new("DELETE FROM schedule_occurrences");
    push_schedule_id_filter(&mut delete_occurrences, schedule_ids);
    delete_occurrences
        .build()
        .execute(&mut **transaction)
        .await?;

    let mut delete_executions = QueryBuilder::<Sqlite>::new("DELETE FROM schedule_executions");
    push_schedule_id_filter(&mut delete_executions, schedule_ids);
    delete_executions
        .build()
        .execute(&mut **transaction)
        .await?;

    Ok(occurrence_count + execution_count)
}
