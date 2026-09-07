use super::{
    validation::{enum_from, invalid, parse_uuid, run, unique_json, uuid},
    CoverageExperimentRunEvidenceV1,
};
use crate::{StorageError, Store};
use hf_core::{engine::EngineKind, harness::Harness, target::TargetCandidate};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

impl Store {
    /// Read exact campaign/config/harness/target/build metadata in one snapshot.
    /// No current workspace, coverage, provider, or runtime operation is performed.
    ///
    /// # Errors
    /// Returns not-found, missing-setup, malformed-data, chronology, or SQL errors.
    pub async fn coverage_experiment_run_evidence(
        &self,
        id: Uuid,
    ) -> Result<CoverageExperimentRunEvidenceV1, StorageError> {
        let mut tx = self.pool().begin().await?;
        let evidence = load_source(&mut tx, id).await?;
        tx.commit().await?;
        Ok(evidence)
    }
}
fn required<T>(value: Option<T>, field: &'static str) -> Result<T, StorageError> {
    value.ok_or(StorageError::CoverageExperimentMissingSetup { field })
}
pub(super) async fn load_source(
    connection: &mut SqliteConnection,
    id: Uuid,
) -> Result<CoverageExperimentRunEvidenceV1, StorageError> {
    uuid(id)?;
    let row = sqlx::query("SELECT * FROM runs WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(&mut *connection)
        .await?
        .ok_or_else(|| StorageError::NotFound(format!("run {id}")))?;
    parse_uuid(row.try_get("id")?)?;
    if let Some(config) = row.try_get::<Option<&str>, _>("config_json")? {
        let config_value = unique_json(config)?;
        json_uuid(&config_value, "harness_id")?;
        if config_value
            .get("replay_of")
            .is_some_and(|value| !value.is_null())
        {
            json_uuid(&config_value, "replay_of")?;
        }
    }
    let run_record = crate::store::run_from_row(&row)?;
    // Existing runs use variable-precision RFC3339 with offsets; the new snapshot
    // encodes their parsed UTC values canonically without rewriting run history.
    let config = required(run_record.config, "config")?;
    uuid(config.harness_id)?;
    let duration = required(config.duration, "duration")?;
    if duration.subsec_nanos() != 0 {
        return Err(invalid("subsecond duration"));
    }
    let harness_row = sqlx::query("SELECT * FROM harnesses WHERE id = ?1")
        .bind(config.harness_id.to_string())
        .fetch_optional(&mut *connection)
        .await?;
    let harness_row = required(harness_row, "harness")?;
    let harness_value = unique_json(harness_row.try_get("data_json")?)?;
    json_uuid(&harness_value, "id")?;
    json_uuid(&harness_value, "target_id")?;
    let harness: Harness = serde_json::from_value(harness_value)?;
    let harness_id = parse_uuid(harness_row.try_get("id")?)?;
    let target_id = parse_uuid(harness_row.try_get("target_id")?)?;
    let harness_engine: EngineKind = enum_from(harness_row.try_get("engine")?)?;
    let source: String = harness_row.try_get("source")?;
    if harness.id != harness_id
        || harness_id != config.harness_id
        || harness.target_id != target_id
        || harness.engine != harness_engine
        || harness.source != source
        || harness.engine != run_record.engine
        || config.engine != run_record.engine
        || config.sanitizer != harness.sanitizer
    {
        return Err(invalid("run/config/harness identity"));
    }
    let target_row =
        sqlx::query("SELECT id, project_root, symbol, data_json FROM targets WHERE id = ?1")
            .bind(target_id.to_string())
            .fetch_optional(&mut *connection)
            .await?;
    let target_row = required(target_row, "target")?;
    let target_value = unique_json(target_row.try_get("data_json")?)?;
    json_uuid(&target_value, "id")?;
    let target: TargetCandidate = serde_json::from_value(target_value)?;
    let project_root: String = target_row.try_get("project_root")?;
    let target_symbol: String = target_row.try_get("symbol")?;
    if target.id != parse_uuid(target_row.try_get("id")?)?
        || target.id != target_id
        || target.project_root.to_str() != Some(project_root.as_str())
        || target.symbol != target_symbol
        || project_root != run_record.project_root
    {
        return Err(invalid("run/target owner"));
    }
    let harness_rev = required(run_record.harness_rev, "harness_rev")?;
    if harness_rev != format!("{:x}", Sha256::digest(source.as_bytes())) {
        return Err(invalid("retained harness source digest"));
    }
    let edges = row
        .try_get::<Option<i64>, _>("edges")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| invalid("negative edges"))?;
    let build_inputs = crate::build_profile_store::load_inputs(connection, harness_id).await?;
    let evidence = CoverageExperimentRunEvidenceV1 {
        schema_version: 1,
        run_id: id,
        target_id,
        harness_id,
        project_root,
        target_symbol,
        engine: run_record.engine,
        status: run_record.status,
        kind: run_record.kind,
        started_at: run_record.started_at,
        ended_at: required(run_record.ended_at, "ended_at")?,
        duration_secs: duration.as_secs(),
        max_mem_mb: config.max_mem_mb,
        max_cpus: config.max_cpus,
        sanitizer: config.sanitizer,
        engine_env: config.env,
        engine_args: config.extra_args,
        seed: config.seed,
        seed_corpus: config
            .seed_corpus
            .map(|p| {
                p.into_os_string()
                    .into_string()
                    .map_err(|_| invalid("non-UTF8 seed corpus"))
            })
            .transpose()?,
        replay_of: config.replay_of,
        harness_rev,
        binary_rev: required(run_record.binary_rev, "binary_rev")?,
        source_rev: required(run_record.source_rev, "source_rev")?,
        corpus_rev: required(run_record.corpus_rev, "corpus_rev")?,
        sandbox_rev: required(run_record.sandbox_rev, "sandbox_rev")?,
        context_rev: run_record.context_rev,
        edges,
        build_inputs,
    };
    run(&evidence)?;
    Ok(evidence)
}

fn json_uuid(value: &serde_json::Value, field: &str) -> Result<Uuid, StorageError> {
    parse_uuid(
        value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("source UUID field"))?,
    )
}
