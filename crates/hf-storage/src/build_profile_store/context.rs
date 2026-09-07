//! Immutable configured context supplied to harness prompt rendering.
use super::{
    bounded_json, decode_canonical, deserialize_optional, invalid, parse_timestamp, parse_uuid,
    timestamp, validate_digest, validate_project, MAX_BUILD_DIAGNOSIS_HISTORY,
};
use crate::{StorageError, Store};
use chrono::{DateTime, Utc};
use hf_core::build::BuildContext;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};
use uuid::Uuid;

/// Exact compile context rendered into one configured harness provider request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessBuildContextEvidence {
    /// Durable envelope version; currently one.
    pub schema_version: u32,
    /// Validated compile context, preserving every rendered token and count.
    #[serde(deserialize_with = "deserialize_context")]
    pub context: BuildContext,
}

/// Retained configured prompt input, independent of later profile replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessBuildContextRecord {
    pub id: Uuid,
    pub project_root: String,
    pub profile_sha256: String,
    pub compile_database_sha256: String,
    pub evidence: HarnessBuildContextEvidence,
    pub created_at: DateTime<Utc>,
}

impl Store {
    /// Persist exact configured context before provider dispatch, accepting only identical retries.
    pub async fn append_harness_build_context(
        &self,
        record: &HarnessBuildContextRecord,
    ) -> Result<(), StorageError> {
        validate_context(record)?;
        let encoded = bounded_json(&record.evidence)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        if let Some(saved) = load_context(&mut tx, record.id).await? {
            if saved != *record {
                return Err(invalid("harness build context is immutable"));
            }
        } else {
            sqlx::query(
                "INSERT INTO harness_build_contexts
                 (id, project_root, profile_sha256, compile_database_sha256, context_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(record.id.to_string())
            .bind(&record.project_root)
            .bind(&record.profile_sha256)
            .bind(&record.compile_database_sha256)
            .bind(encoded)
            .bind(timestamp(record.created_at))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read and strictly decode one immutable configured prompt input.
    pub async fn harness_build_context(
        &self,
        id: Uuid,
    ) -> Result<Option<HarnessBuildContextRecord>, StorageError> {
        load_context(&mut *self.pool().acquire().await?, id).await
    }

    /// Read bounded newest-first configured prompt inputs for a canonical project.
    pub async fn harness_build_context_history(
        &self,
        project: &str,
        limit: usize,
    ) -> Result<Vec<HarnessBuildContextRecord>, StorageError> {
        validate_project(project)?;
        if !(1..=MAX_BUILD_DIAGNOSIS_HISTORY).contains(&limit) {
            return Err(invalid("context history limit must be in 1..=100"));
        }
        let rows = sqlx::query(
            "SELECT * FROM harness_build_contexts WHERE project_root = ?1
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )
        .bind(project)
        .bind(i64::try_from(limit).map_err(|_| invalid("invalid history limit"))?)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(context_from_row).collect()
    }
}

async fn load_context(
    connection: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<HarnessBuildContextRecord>, StorageError> {
    sqlx::query("SELECT * FROM harness_build_contexts WHERE id=?1")
        .bind(id.to_string())
        .fetch_optional(connection)
        .await?
        .as_ref()
        .map(context_from_row)
        .transpose()
}
fn context_from_row(row: &SqliteRow) -> Result<HarnessBuildContextRecord, StorageError> {
    let record = HarnessBuildContextRecord {
        id: parse_uuid(row.try_get("id")?)?,
        project_root: row.try_get("project_root")?,
        profile_sha256: row.try_get("profile_sha256")?,
        compile_database_sha256: row.try_get("compile_database_sha256")?,
        evidence: decode_canonical(row.try_get("context_json")?)?,
        created_at: parse_timestamp(row.try_get("created_at")?)?,
    };
    validate_context(&record)?;
    Ok(record)
}
fn validate_context(record: &HarnessBuildContextRecord) -> Result<(), StorageError> {
    validate_project(&record.project_root)?;
    validate_digest(&record.profile_sha256)?;
    validate_digest(&record.compile_database_sha256)?;
    if record.evidence.schema_version != 1 {
        return Err(invalid("unsupported harness context version"));
    }
    bounded_json(&record.evidence)?;
    Ok(())
}
fn deserialize_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BuildContext, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictContext {
        include_dirs: Vec<std::path::PathBuf>,
        defines: Vec<String>,
        #[serde(deserialize_with = "deserialize_optional")]
        std_flag: Option<String>,
        extra_flags: Vec<String>,
        entry_count: usize,
        dropped: Vec<String>,
    }
    let context = StrictContext::deserialize(deserializer)?;
    Ok(BuildContext {
        include_dirs: context.include_dirs,
        defines: context.defines,
        std_flag: context.std_flag,
        extra_flags: context.extra_flags,
        entry_count: context.entry_count,
        dropped: context.dropped,
    })
}
