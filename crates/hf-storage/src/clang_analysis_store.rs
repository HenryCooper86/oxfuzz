//! Durable Clang operations, immutable results, and exact model-visible context.
use crate::{StorageError, Store};
use hf_core::clang_analysis::ClangIndex;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// Durable analysis lifecycle, independent of any fuzzing approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClangOperationState {
    /// Immutable source input is being captured.
    Staging,
    /// The sandbox helper is running.
    Analyzing,
    /// Helper output is being normalized.
    Validating,
    /// Normalized evidence was atomically published.
    Done,
    /// No usable result was produced.
    Failed,
    /// Cancellation and teardown completed.
    Cancelled,
    /// The owning process disappeared.
    Interrupted,
}
impl ClangOperationState {
    /// Stable persisted spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Analyzing => "analyzing",
            Self::Validating => "validating",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }
    /// Whether no further operation work is allowed.
    #[must_use]
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }
}

/// Persisted admission and terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangOperationRecord {
    /// Service-owned ID.
    pub id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// Canonical C/C++ language ID.
    pub language: String,
    /// Current operation state.
    pub state: ClangOperationState,
    /// Exact resolved admission inputs.
    pub request_json: String,
    /// RFC3339 admission timestamp.
    pub started_at: String,
    /// RFC3339 terminal timestamp.
    pub ended_at: Option<String>,
    /// Bounded failure category.
    pub failure: Option<String>,
}

/// Immutable result and all freshness inputs needed to select it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangResultRecord {
    /// Owning operation.
    pub operation_id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// Digest of exact serialized input manifest.
    pub input_sha256: String,
    /// Dispatched immutable image.
    pub image_id: String,
    /// Exact versioned source, database, profile, and invocation fingerprint.
    pub inputs_json: String,
    /// Normalized helper output.
    pub index: ClangIndex,
}

/// Exact provider section retained before dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessClangContextRecord {
    /// Immutable context ID.
    pub id: Uuid,
    /// Selected analysis operation.
    pub operation_id: Uuid,
    /// Canonical project owner.
    pub project_root: String,
    /// Discovery target owner.
    pub target_id: Uuid,
    /// Renderer version, currently one.
    pub renderer_version: u32,
    /// Exact rendered section.
    pub rendered: String,
    /// RFC3339 creation time.
    pub created_at: String,
}

fn invalid(message: &str) -> StorageError {
    StorageError::InvalidData(message.into())
}

impl Store {
    /// Reserve one operation before any sandbox dispatch.
    pub async fn create_clang_operation(
        &self,
        record: &ClangOperationRecord,
    ) -> Result<(), StorageError> {
        if record.state != ClangOperationState::Staging || record.ended_at.is_some() {
            return Err(invalid("invalid Clang admission"));
        }
        sqlx::query("INSERT INTO clang_analysis_operations VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL)")
            .bind(record.id.to_string())
            .bind(&record.project_root)
            .bind(&record.language)
            .bind(record.state.as_str())
            .bind(&record.request_json)
            .bind(&record.started_at)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    /// Compare-and-swap a valid lifecycle transition; successful publication has its own method.
    pub async fn advance_clang_operation(
        &self,
        id: Uuid,
        expected: ClangOperationState,
        next: ClangOperationState,
        failure: Option<&str>,
    ) -> Result<(), StorageError> {
        if expected.terminal()
            || next == ClangOperationState::Done
            || !(next == ClangOperationState::Failed
                || next == ClangOperationState::Cancelled
                || next == ClangOperationState::Interrupted
                || (expected == ClangOperationState::Staging
                    && next == ClangOperationState::Analyzing)
                || (expected == ClangOperationState::Analyzing
                    && next == ClangOperationState::Validating))
        {
            return Err(invalid("invalid Clang transition"));
        }
        let ended = next.terminal().then(|| chrono::Utc::now().to_rfc3339());
        let changed = sqlx::query("UPDATE clang_analysis_operations SET state=?1,ended_at=?2,failure=?3 WHERE id=?4 AND state=?5")
            .bind(next.as_str()).bind(ended).bind(failure).bind(id.to_string()).bind(expected.as_str()).execute(self.pool()).await?;
        if changed.rows_affected() != 1 {
            return Err(invalid("Clang operation transition conflict"));
        }
        Ok(())
    }
    /// Read one strictly decoded operation.
    pub async fn clang_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<ClangOperationRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM clang_analysis_operations WHERE id=?1")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?;
        row.map(|r| {
            Ok(ClangOperationRecord {
                id,
                project_root: r.try_get("project_root")?,
                language: r.try_get("language")?,
                state: serde_json::from_value(serde_json::Value::String(r.try_get("state")?))?,
                request_json: r.try_get("request_json")?,
                started_at: r.try_get("started_at")?,
                ended_at: r.try_get("ended_at")?,
                failure: r.try_get("failure")?,
            })
        })
        .transpose()
    }
    /// Atomically publish immutable normalized output with the successful terminal transition.
    pub async fn publish_clang_result(
        &self,
        record: &ClangResultRecord,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let index = serde_json::to_string(&record.index)?;
        let existing=sqlx::query("SELECT index_json,inputs_json,input_sha256,image_id,project_root FROM clang_analysis_results WHERE operation_id=?1")
            .bind(record.operation_id.to_string()).fetch_optional(&mut *tx).await?;
        if let Some(row) = existing {
            if row.try_get::<String, _>("index_json")? != index
                || row.try_get::<String, _>("inputs_json")? != record.inputs_json
                || row.try_get::<String, _>("input_sha256")? != record.input_sha256
                || row.try_get::<String, _>("image_id")? != record.image_id
                || row.try_get::<String, _>("project_root")? != record.project_root
            {
                return Err(invalid("Clang result is immutable"));
            }
        } else {
            let changed=sqlx::query("UPDATE clang_analysis_operations SET state='done',ended_at=?1 WHERE id=?2 AND state='validating' AND project_root=?3")
                .bind(chrono::Utc::now().to_rfc3339()).bind(record.operation_id.to_string()).bind(&record.project_root).execute(&mut *tx).await?;
            if changed.rows_affected() != 1 {
                return Err(invalid("Clang publication transition conflict"));
            }
            sqlx::query("INSERT INTO clang_analysis_results VALUES (?1,?2,?3,?4,?5,?6)")
                .bind(record.operation_id.to_string())
                .bind(&record.project_root)
                .bind(&record.input_sha256)
                .bind(&record.image_id)
                .bind(&record.inputs_json)
                .bind(index)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    /// Read normalized retained output for one operation.
    pub async fn clang_result(&self, id: Uuid) -> Result<Option<ClangResultRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM clang_analysis_results WHERE operation_id=?1")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?;
        row.map(|r| {
            Ok(ClangResultRecord {
                operation_id: id,
                project_root: r.try_get("project_root")?,
                input_sha256: r.try_get("input_sha256")?,
                image_id: r.try_get("image_id")?,
                inputs_json: r.try_get("inputs_json")?,
                index: serde_json::from_str(&r.try_get::<String, _>("index_json")?)?,
            })
        })
        .transpose()
    }
    /// Select the newest successful analysis, independent of later failed attempts.
    pub async fn latest_clang_result(
        &self,
        project: &str,
    ) -> Result<Option<ClangResultRecord>, StorageError> {
        let id:Option<String>=sqlx::query_scalar("SELECT r.operation_id FROM clang_analysis_results r JOIN clang_analysis_operations o ON o.id=r.operation_id WHERE r.project_root=?1 AND o.state='done' ORDER BY o.started_at DESC,o.id DESC LIMIT 1")
            .bind(project).fetch_optional(self.pool()).await?;
        match id {
            Some(id) => {
                self.clang_result(
                    Uuid::parse_str(&id).map_err(|_| invalid("invalid Clang operation ID"))?,
                )
                .await
            }
            None => Ok(None),
        }
    }
    /// Retain the exact section before provider dispatch, accepting only identical retries.
    pub async fn append_harness_clang_context(
        &self,
        record: &HarnessClangContextRecord,
    ) -> Result<(), StorageError> {
        if record.renderer_version != 1 || record.rendered.len() > 65536 {
            return Err(invalid("invalid Clang context"));
        }
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let old = sqlx::query("SELECT * FROM harness_clang_contexts WHERE id=?1")
            .bind(record.id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(old) = old {
            if old.try_get::<String, _>("rendered")? != record.rendered
                || old.try_get::<String, _>("operation_id")? != record.operation_id.to_string()
                || old.try_get::<String, _>("target_id")? != record.target_id.to_string()
                || old.try_get::<String, _>("project_root")? != record.project_root
                || old.try_get::<String, _>("created_at")? != record.created_at
            {
                return Err(invalid("Clang context is immutable"));
            }
        } else {
            let owner: Option<String> = sqlx::query_scalar(
                "SELECT project_root FROM clang_analysis_results WHERE operation_id=?1",
            )
            .bind(record.operation_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
            if owner.as_deref() != Some(&record.project_root) {
                return Err(invalid("Clang context project mismatch"));
            }
            sqlx::query("INSERT INTO harness_clang_contexts VALUES (?1,?2,?3,?4,?5,?6,?7)")
                .bind(record.id.to_string())
                .bind(record.operation_id.to_string())
                .bind(&record.project_root)
                .bind(record.target_id.to_string())
                .bind(record.renderer_version)
                .bind(&record.rendered)
                .bind(&record.created_at)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    /// Recover only operations whose owning process has been proven absent by the caller.
    pub async fn interrupt_clang_operation(&self, id: Uuid) -> Result<(), StorageError> {
        if let Some(record) = self.clang_operation(id).await? {
            if !record.state.terminal() {
                self.advance_clang_operation(
                    id,
                    record.state,
                    ClangOperationState::Interrupted,
                    Some("owner_interrupted"),
                )
                .await?;
            }
        }
        Ok(())
    }
}

impl Store {
    /// Select successful evidence for the requested target and language before checking freshness.
    pub async fn latest_clang_result_for_target(
        &self,
        project: &str,
        target: Uuid,
        language: hf_core::target::TargetLanguage,
    ) -> Result<Option<ClangResultRecord>, StorageError> {
        let id:Option<String>=sqlx::query_scalar("SELECT r.operation_id FROM clang_analysis_results r JOIN clang_analysis_operations o ON o.id=r.operation_id WHERE r.project_root=?1 AND o.state='done' AND o.language=?3 AND EXISTS(SELECT 1 FROM json_each(o.request_json,'$.request.target_ids') WHERE value=?2) ORDER BY o.started_at DESC,o.id DESC LIMIT 1")
            .bind(project).bind(target.to_string()).bind(language.as_str()).fetch_optional(self.pool()).await?;
        match id {
            Some(id) => {
                self.clang_result(
                    Uuid::parse_str(&id).map_err(|_| invalid("invalid Clang operation ID"))?,
                )
                .await
            }
            None => Ok(None),
        }
    }
    /// Enumerate nonterminal operation IDs for ownership-checked restart recovery.
    pub async fn active_clang_operation_ids(&self) -> Result<Vec<Uuid>, StorageError> {
        let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM clang_analysis_operations WHERE state IN ('staging','analyzing','validating') ORDER BY started_at,id").fetch_all(self.pool()).await?;
        ids.into_iter()
            .map(|id| Uuid::parse_str(&id).map_err(|_| invalid("invalid Clang operation ID")))
            .collect()
    }
}
