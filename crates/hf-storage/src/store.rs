//! The SQLite-backed [`Store`] and its repository methods.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use hf_core::corpus::CorpusEntry;
use hf_core::crash::Crash;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::target::{TargetCandidate, TargetInventory};

/// Default database path used when `HF_DB_PATH` is unset.
const DEFAULT_DB_PATH: &str = "data/hobot_fuzz.db";

/// Errors raised by the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A SQL execution or connection error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A migration failed to apply.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A model failed to (de)serialize to/from JSON.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// A stored timestamp could not be parsed.
    #[error("invalid timestamp: {0}")]
    Timestamp(String),
    /// A stored identifier or model field is malformed.
    #[error("invalid stored data: {0}")]
    InvalidData(String),
    /// A requested row did not exist, so a mutation could not be applied.
    #[error("record not found: {0}")]
    NotFound(String),
}

impl From<StorageError> for ClassifiedError {
    fn from(e: StorageError) -> Self {
        ClassifiedError::Storage(e.to_string())
    }
}

/// The lifecycle status of a fuzz run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Created but not yet started.
    Pending,
    /// Actively fuzzing.
    Running,
    /// Completed normally.
    Done,
    /// Terminated with an error.
    Failed,
    /// Cancelled by the user before completing.
    Cancelled,
}

/// The purpose of a persisted execution.
///
/// Qualification smoke runs are retained as evidence, but they are not valid
/// coverage-regression baselines for full campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// A normal fuzzing campaign run.
    Campaign,
    /// A bounded harness-qualification smoke run.
    Smoke,
}

/// A project's stored auto-revert policy override (a full policy for one
/// project; absence means the project inherits the global policy).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProjectAutoRevert {
    /// Whether the policy is armed for this project.
    pub enabled: bool,
    /// The edge-coverage drop (percent) at or above which a revert fires.
    pub threshold_pct: f64,
    /// Report the regression without restoring the harness.
    pub notify_only: bool,
}

/// One auto-revert policy firing, for the durable audit trail.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AutoRevertEvent {
    /// Unique event id.
    pub id: String,
    /// When the policy fired (RFC3339).
    pub ts: String,
    /// Project the regressed run belonged to.
    pub project_root: String,
    /// Target symbol.
    pub target: String,
    /// The regressed run's id.
    pub run_id: String,
    /// The regressed harness revision.
    pub from_rev: String,
    /// The last-good revision that was (or would be) restored.
    pub to_rev: String,
    /// Peak edge coverage of the restored (previous) run.
    pub previous_edges: u64,
    /// Peak edge coverage of the regressed run.
    pub regressed_edges: u64,
    /// The percent coverage drop that triggered the policy.
    pub drop_pct: f64,
    /// `true` if the harness was restored; `false` for a notify-only flag.
    pub reverted: bool,
}

/// Lifecycle status of one sandboxed automotive protocol operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveOperationStatus {
    /// The operation has durable evidence and is executing in the sandbox.
    Running,
    /// The operation completed successfully.
    Done,
    /// The operation terminated with an error.
    Failed,
    /// The operator cancelled the operation.
    Cancelled,
}

impl AutomotiveOperationStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Cancelled)
    }
}

/// Durable evidence record for one automotive protocol operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomotiveOperationRecord {
    /// Service-owned operation identifier.
    pub id: Uuid,
    /// Canonical project root associated with the evidence.
    pub project_root: String,
    /// Operation kind such as `analyze_pcap` or `virtual_session`.
    pub operation: String,
    /// Execution mode such as `offline_pcap` or `virtual_can`.
    pub mode: String,
    /// Primary protocol, when the request selects one.
    pub protocol: Option<String>,
    /// Current lifecycle status.
    pub status: AutomotiveOperationStatus,
    /// Time execution was durably admitted.
    pub started_at: DateTime<Utc>,
    /// Terminal timestamp.
    pub ended_at: Option<DateTime<Utc>>,
    /// SHA-256 of the canonical request envelope.
    pub request_hash: String,
    /// SHA-256 of the complete sidecar transcript, when available.
    pub transcript_hash: Option<String>,
    /// Workspace-relative evidence directory.
    pub artifact_dir: String,
    /// Serialized approval evidence for exceptional modes.
    pub approval_json: Option<String>,
    /// Serialized domain result including state findings.
    pub result_json: Option<String>,
    /// Sanitized terminal failure reason.
    pub error: Option<String>,
}

/// One digest-addressed automotive protocol-state corpus promotion.
///
/// This evidence is intentionally separate from source-coverage corpus rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomotiveStateCorpusRecord {
    /// Canonical project root associated with the protocol evidence.
    pub project_root: String,
    /// Stable automotive protocol identifier.
    pub protocol: String,
    /// Validated protocol-state signature digest.
    pub state_digest: String,
    /// SHA-256 of the retained artifact bytes.
    pub artifact_sha256: String,
    /// Completed operation that observed the state and retained the source.
    pub source_operation_id: Uuid,
    /// Workspace-relative path to the digest-addressed retained copy.
    pub artifact_path: String,
    /// Time the first matching promotion was persisted.
    pub created_at: DateTime<Utc>,
}

/// A persisted fuzz-run record.
#[derive(Debug, Clone)]
pub struct RunRecord {
    /// Unique run identifier.
    pub id: Uuid,
    /// Project root the run targets.
    pub project_root: String,
    /// Engine used for the run.
    pub engine: EngineKind,
    /// Current lifecycle status.
    pub status: RunStatus,
    /// Whether this record is campaign output or qualification evidence.
    pub kind: RunKind,
    /// When the run was created.
    pub started_at: DateTime<Utc>,
    /// When the run finished, if it has.
    pub ended_at: Option<DateTime<Utc>>,
    /// The run configuration, if captured.
    pub config: Option<FuzzRunConfig>,
    /// Peak edge coverage reached, once the run finished.
    pub edges: Option<u64>,
    /// Peak executions/second reached, once the run finished.
    pub execs: Option<f64>,
    /// Crashes the fuzzer reported during the run (raw, pre-triage-dedup).
    pub crash_count: Option<u64>,
    /// Full SHA-256 digest of the approved harness source the run used, so a
    /// coverage change can be attributed to an exact revision.
    pub harness_rev: Option<String>,
    /// Full SHA-256 digest of the staged harness binary executed by this run.
    pub binary_rev: Option<String>,
    /// Workspace-relative directory containing this run's output evidence.
    pub evidence_dir: Option<String>,
    /// Digest of target sources, starting corpus, and runtime image used to
    /// decide whether two campaign coverage measurements are comparable.
    pub context_rev: Option<String>,
}

impl RunRecord {
    /// Build a new pending run record stamped at `now`.
    #[must_use]
    pub fn new(
        project_root: impl Into<String>,
        engine: EngineKind,
        config: Option<FuzzRunConfig>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            project_root: project_root.into(),
            engine,
            status: RunStatus::Pending,
            kind: RunKind::Campaign,
            started_at: now,
            ended_at: None,
            config,
            edges: None,
            execs: None,
            crash_count: None,
            harness_rev: None,
            binary_rev: None,
            evidence_dir: None,
            context_rev: None,
        }
    }
}

/// A SQLite-backed persistence store.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Connect to (creating if missing) the database at `db_path` and run
    /// pending migrations.
    ///
    /// # Errors
    /// Returns an error if the parent directory cannot be created, the database
    /// cannot be opened, or migrations fail.
    pub async fn connect(db_path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = db_path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StorageError::Db(sqlx::Error::Configuration(Box::new(e))))?;
            }
        }
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        Self::connect_with(opts).await
    }

    /// Connect using the `HF_DB_PATH` env var, defaulting to
    /// `data/hobot_fuzz.db`.
    ///
    /// # Errors
    /// See [`Store::connect`].
    pub async fn connect_from_env() -> Result<Self, StorageError> {
        let path = std::env::var("HF_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_owned());
        Self::connect(path).await
    }

    async fn connect_with(opts: SqliteConnectOptions) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let store = Self { pool };
        // One-time, self-healing cleanup of legacy duplicate crash rows left by
        // pre-deterministic-id triages. Idempotent: a no-op on a clean DB.
        store.dedupe_crashes().await?;
        // Purge children orphaned by older partial clears (harnesses/corpus were
        // once left behind when targets were deleted), which is why such
        // harnesses render with an "unknown" symbol. Idempotent on a clean DB.
        store.delete_orphans().await?;
        Ok(store)
    }

    /// Remove duplicate crash rows, keeping one representative per
    /// `(run_id, stack_signature)` -- preferring a row that already carries a
    /// drafted bug report, else the lexicographically smallest id. Rows with an
    /// empty signature are never collapsed (distinct un-signatured crashes are
    /// kept). Heals databases that accumulated duplicates before crash ids were
    /// made deterministic; idempotent thereafter.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn dedupe_crashes(&self) -> Result<(), StorageError> {
        sqlx::query(
            "DELETE FROM crashes
             WHERE stack_signature <> ''
               AND id NOT IN (
                 SELECT id FROM (
                   SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY run_id, stack_signature
                     ORDER BY (bug_report_json IS NOT NULL) DESC, id ASC
                   ) AS rn
                   FROM crashes WHERE stack_signature <> ''
                 ) WHERE rn = 1
               )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Access the underlying connection pool (for advanced callers/tests).
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // -- runs ---------------------------------------------------------------

    /// Insert a new run record.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or if the config cannot be serialized.
    pub async fn insert_run(&self, run: &RunRecord) -> Result<(), StorageError> {
        let config_json = match &run.config {
            Some(c) => Some(serde_json::to_string(c)?),
            None => None,
        };
        sqlx::query(
            "INSERT INTO runs (id, project_root, engine, status, started_at, ended_at, config_json, edges, execs, crash_count, harness_rev, binary_rev, evidence_dir, run_kind, context_rev)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )
        .bind(run.id.to_string())
        .bind(&run.project_root)
        .bind(enum_str(&run.engine))
        .bind(enum_str(&run.status))
        .bind(run.started_at.to_rfc3339())
        .bind(run.ended_at.map(|t| t.to_rfc3339()))
        .bind(config_json)
        .bind(run.edges.map(|e| i64::try_from(e).unwrap_or(i64::MAX)))
        .bind(run.execs)
        .bind(run.crash_count.map(|c| i64::try_from(c).unwrap_or(i64::MAX)))
        .bind(run.harness_rev.as_deref())
        .bind(run.binary_rev.as_deref())
        .bind(run.evidence_dir.as_deref())
        .bind(enum_str(&run.kind))
        .bind(run.context_rev.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // -- automotive operations --------------------------------------------

    /// Insert a newly admitted automotive operation before sandbox launch.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or when the initial status is not
    /// `Running`.
    pub async fn insert_automotive_operation(
        &self,
        operation: &AutomotiveOperationRecord,
    ) -> Result<(), StorageError> {
        if operation.status != AutomotiveOperationStatus::Running || operation.ended_at.is_some() {
            return Err(StorageError::InvalidData(
                "a new automotive operation must be running with no end time".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO automotive_operations
                (id, project_root, operation, mode, protocol, status, started_at, ended_at,
                 request_hash, transcript_hash, artifact_dir, approval_json, result_json, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )
        .bind(operation.id.to_string())
        .bind(&operation.project_root)
        .bind(&operation.operation)
        .bind(&operation.mode)
        .bind(operation.protocol.as_deref())
        .bind(enum_str(&operation.status))
        .bind(operation.started_at.to_rfc3339())
        .bind(operation.ended_at.map(|value| value.to_rfc3339()))
        .bind(&operation.request_hash)
        .bind(operation.transcript_hash.as_deref())
        .bind(&operation.artifact_dir)
        .bind(operation.approval_json.as_deref())
        .bind(operation.result_json.as_deref())
        .bind(operation.error.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark an automotive operation terminal and retain its transcript/result.
    ///
    /// # Errors
    /// Returns an error for a non-terminal status, missing id, or SQL failure.
    pub async fn complete_automotive_operation(
        &self,
        id: Uuid,
        status: AutomotiveOperationStatus,
        ended_at: DateTime<Utc>,
        transcript_hash: Option<&str>,
        result_json: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), StorageError> {
        if !status.is_terminal() {
            return Err(StorageError::InvalidData(
                "automotive operation completion requires a terminal status".to_owned(),
            ));
        }
        let result = sqlx::query(
            "UPDATE automotive_operations
             SET status = ?2, ended_at = ?3, transcript_hash = ?4, result_json = ?5, error = ?6
             WHERE id = ?1 AND status = 'running'",
        )
        .bind(id.to_string())
        .bind(enum_str(&status))
        .bind(ended_at.to_rfc3339())
        .bind(transcript_hash)
        .bind(result_json)
        .bind(error)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::NotFound(format!(
                "running automotive operation {id}"
            )));
        }
        Ok(())
    }

    /// Load one automotive operation by id.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn automotive_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<AutomotiveOperationRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT id, project_root, operation, mode, protocol, status, started_at, ended_at,
                    request_hash, transcript_hash, artifact_dir, approval_json, result_json, error
             FROM automotive_operations WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(automotive_operation_from_row).transpose()
    }

    /// List automotive evidence for a project, newest first.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn automotive_operations(
        &self,
        project_root: &str,
        limit: u32,
    ) -> Result<Vec<AutomotiveOperationRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, project_root, operation, mode, protocol, status, started_at, ended_at,
                    request_hash, transcript_hash, artifact_dir, approval_json, result_json, error
             FROM automotive_operations
             WHERE project_root = ?1 ORDER BY started_at DESC, id DESC LIMIT ?2",
        )
        .bind(project_root)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(automotive_operation_from_row).collect()
    }

    /// Persist a protocol-state corpus promotion or return the existing
    /// promotion with the same project, protocol, state, and artifact digests.
    ///
    /// # Errors
    /// Returns an error for empty fields, a missing source operation, malformed
    /// stored data, or a SQL failure.
    pub async fn record_automotive_state_corpus(
        &self,
        record: &AutomotiveStateCorpusRecord,
    ) -> Result<AutomotiveStateCorpusRecord, StorageError> {
        for (field, value) in [
            ("project_root", record.project_root.as_str()),
            ("protocol", record.protocol.as_str()),
            ("state_digest", record.state_digest.as_str()),
            ("artifact_sha256", record.artifact_sha256.as_str()),
            ("artifact_path", record.artifact_path.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(StorageError::InvalidData(format!(
                    "automotive state corpus {field} must not be empty"
                )));
            }
        }

        let mut transaction = self.pool.begin().await?;
        let source = sqlx::query(
            "SELECT project_root, protocol, status
             FROM automotive_operations WHERE id = ?1",
        )
        .bind(record.source_operation_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| {
            StorageError::NotFound(format!(
                "automotive source operation {}",
                record.source_operation_id
            ))
        })?;
        let source_project: String = source.try_get("project_root")?;
        let source_protocol: Option<String> = source.try_get("protocol")?;
        let source_status: String = source.try_get("status")?;
        if source_status != "done" {
            return Err(StorageError::InvalidData(
                "automotive state corpus source operation must be completed".to_owned(),
            ));
        }
        if source_project != record.project_root
            || source_protocol.as_deref() != Some(record.protocol.as_str())
        {
            return Err(StorageError::InvalidData(
                "automotive state corpus source project or protocol does not match".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO automotive_state_corpus
                (project_root, protocol, state_digest, artifact_sha256,
                 source_operation_id, artifact_path, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(project_root, protocol, state_digest, artifact_sha256) DO NOTHING",
        )
        .bind(&record.project_root)
        .bind(&record.protocol)
        .bind(&record.state_digest)
        .bind(&record.artifact_sha256)
        .bind(record.source_operation_id.to_string())
        .bind(&record.artifact_path)
        .bind(record.created_at.to_rfc3339())
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query(
            "SELECT project_root, protocol, state_digest, artifact_sha256,
                    source_operation_id, artifact_path, created_at
             FROM automotive_state_corpus
             WHERE project_root = ?1 AND protocol = ?2
               AND state_digest = ?3 AND artifact_sha256 = ?4",
        )
        .bind(&record.project_root)
        .bind(&record.protocol)
        .bind(&record.state_digest)
        .bind(&record.artifact_sha256)
        .fetch_one(&mut *transaction)
        .await?;
        let persisted = automotive_state_corpus_from_row(&row)?;
        transaction.commit().await?;
        Ok(persisted)
    }

    /// Load one exact automotive protocol-state corpus promotion.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn automotive_state_corpus_entry(
        &self,
        project_root: &str,
        protocol: &str,
        state_digest: &str,
        artifact_sha256: &str,
    ) -> Result<Option<AutomotiveStateCorpusRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT project_root, protocol, state_digest, artifact_sha256,
                    source_operation_id, artifact_path, created_at
             FROM automotive_state_corpus
             WHERE project_root = ?1 AND protocol = ?2
               AND state_digest = ?3 AND artifact_sha256 = ?4",
        )
        .bind(project_root)
        .bind(protocol)
        .bind(state_digest)
        .bind(artifact_sha256)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref()
            .map(automotive_state_corpus_from_row)
            .transpose()
    }

    /// List retained automotive state-corpus evidence for one project, newest
    /// first.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn automotive_state_corpus(
        &self,
        project_root: &str,
        limit: u32,
    ) -> Result<Vec<AutomotiveStateCorpusRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT project_root, protocol, state_digest, artifact_sha256,
                    source_operation_id, artifact_path, created_at
             FROM automotive_state_corpus
             WHERE project_root = ?1
             ORDER BY created_at DESC, protocol ASC, state_digest ASC, artifact_sha256 ASC
             LIMIT ?2",
        )
        .bind(project_root)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(automotive_state_corpus_from_row).collect()
    }

    /// Record a finished run's peak coverage (edges), throughput (execs/sec),
    /// and raw crash count.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_run_stats(
        &self,
        id: Uuid,
        edges: u64,
        execs: f64,
        crashes: u64,
    ) -> Result<(), StorageError> {
        let result =
            sqlx::query("UPDATE runs SET edges = ?2, execs = ?3, crash_count = ?4 WHERE id = ?1")
                .bind(id.to_string())
                .bind(i64::try_from(edges).unwrap_or(i64::MAX))
                .bind(execs)
                .bind(i64::try_from(crashes).unwrap_or(i64::MAX))
                .execute(&self.pool)
                .await?;
        require_one_run(result.rows_affected(), id)?;
        Ok(())
    }

    /// Store a run's intra-run coverage/throughput time series as a JSON blob.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_run_samples(&self, id: Uuid, samples_json: &str) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE runs SET samples_json = ?2 WHERE id = ?1")
            .bind(id.to_string())
            .bind(samples_json)
            .execute(&self.pool)
            .await?;
        require_one_run(result.rows_affected(), id)?;
        Ok(())
    }

    /// Read back a run's stored coverage/throughput time series JSON, if any.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn run_samples(&self, id: Uuid) -> Result<Option<String>, StorageError> {
        let row = sqlx::query("SELECT samples_json FROM runs WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| {
            r.try_get::<Option<String>, _>("samples_json")
                .ok()
                .flatten()
        }))
    }

    /// Store the harness source a run used (for revision diffs).
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_run_harness_source(&self, id: Uuid, source: &str) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE runs SET harness_source = ?2 WHERE id = ?1")
            .bind(id.to_string())
            .bind(source)
            .execute(&self.pool)
            .await?;
        require_one_run(result.rows_affected(), id)?;
        Ok(())
    }

    /// Read back a run's stored harness source, if any.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn run_harness_source(&self, id: Uuid) -> Result<Option<String>, StorageError> {
        let row = sqlx::query("SELECT harness_source FROM runs WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| {
            r.try_get::<Option<String>, _>("harness_source")
                .ok()
                .flatten()
        }))
    }

    /// Upsert a project's auto-revert policy override. A stored row fully
    /// specifies the policy for `project_root`; absence means inherit the global.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_project_auto_revert(
        &self,
        project_root: &str,
        override_: ProjectAutoRevert,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO project_settings \
                 (project_root, auto_revert_enabled, auto_revert_threshold_pct, auto_revert_notify_only) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(project_root) DO UPDATE SET \
                 auto_revert_enabled = ?2, \
                 auto_revert_threshold_pct = ?3, \
                 auto_revert_notify_only = ?4",
        )
        .bind(project_root)
        .bind(i64::from(override_.enabled))
        .bind(override_.threshold_pct)
        .bind(i64::from(override_.notify_only))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A project's auto-revert override, or `None` when it inherits the global.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn project_auto_revert(
        &self,
        project_root: &str,
    ) -> Result<Option<ProjectAutoRevert>, StorageError> {
        let row = sqlx::query(
            "SELECT auto_revert_enabled, auto_revert_threshold_pct, auto_revert_notify_only \
             FROM project_settings WHERE project_root = ?1",
        )
        .bind(project_root)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| ProjectAutoRevert {
            enabled: r.get::<i64, _>("auto_revert_enabled") != 0,
            threshold_pct: r.get::<f64, _>("auto_revert_threshold_pct"),
            notify_only: r.get::<i64, _>("auto_revert_notify_only") != 0,
        }))
    }

    /// Clear a project's auto-revert override, so it inherits the global policy.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn clear_project_auto_revert(&self, project_root: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM project_settings WHERE project_root = ?1")
            .bind(project_root)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Every project's auto-revert override, keyed by project root. For an
    /// at-a-glance view of which projects override the global policy.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn all_project_auto_reverts(
        &self,
    ) -> Result<Vec<(String, ProjectAutoRevert)>, StorageError> {
        let rows = sqlx::query(
            "SELECT project_root, auto_revert_enabled, auto_revert_threshold_pct, auto_revert_notify_only \
             FROM project_settings",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("project_root"),
                    ProjectAutoRevert {
                        enabled: r.get::<i64, _>("auto_revert_enabled") != 0,
                        threshold_pct: r.get::<f64, _>("auto_revert_threshold_pct"),
                        notify_only: r.get::<i64, _>("auto_revert_notify_only") != 0,
                    },
                )
            })
            .collect())
    }

    /// Append an auto-revert policy event to the durable audit trail.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn record_auto_revert_event(&self, ev: &AutoRevertEvent) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO auto_revert_events \
                 (id, ts, project_root, target, run_id, from_rev, to_rev, \
                  previous_edges, regressed_edges, drop_pct, reverted) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&ev.id)
        .bind(&ev.ts)
        .bind(&ev.project_root)
        .bind(&ev.target)
        .bind(&ev.run_id)
        .bind(&ev.from_rev)
        .bind(&ev.to_rev)
        .bind(i64::try_from(ev.previous_edges).unwrap_or(i64::MAX))
        .bind(i64::try_from(ev.regressed_edges).unwrap_or(i64::MAX))
        .bind(ev.drop_pct)
        .bind(i64::from(ev.reverted))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The auto-revert audit trail, newest first. Scoped to `project` when given,
    /// otherwise across all projects. `limit` caps the rows returned.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn list_auto_revert_events(
        &self,
        project: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AutoRevertEvent>, StorageError> {
        let rows = match project {
            Some(p) => {
                sqlx::query(
                    "SELECT id, ts, project_root, target, run_id, from_rev, to_rev, \
                            previous_edges, regressed_edges, drop_pct, reverted \
                     FROM auto_revert_events WHERE project_root = ?1 ORDER BY ts DESC LIMIT ?2",
                )
                .bind(p)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT id, ts, project_root, target, run_id, from_rev, to_rev, \
                            previous_edges, regressed_edges, drop_pct, reverted \
                     FROM auto_revert_events ORDER BY ts DESC LIMIT ?1",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows
            .iter()
            .map(|r| AutoRevertEvent {
                id: r.get::<String, _>("id"),
                ts: r.get::<String, _>("ts"),
                project_root: r.get::<String, _>("project_root"),
                target: r.get::<String, _>("target"),
                run_id: r.get::<String, _>("run_id"),
                from_rev: r.get::<String, _>("from_rev"),
                to_rev: r.get::<String, _>("to_rev"),
                previous_edges: u64::try_from(r.get::<i64, _>("previous_edges")).unwrap_or(0),
                regressed_edges: u64::try_from(r.get::<i64, _>("regressed_edges")).unwrap_or(0),
                drop_pct: r.get::<f64, _>("drop_pct"),
                reverted: r.get::<i64, _>("reverted") != 0,
            })
            .collect())
    }

    /// Update a run's status (and optionally its end time).
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_run_status(
        &self,
        id: Uuid,
        status: RunStatus,
        ended_at: Option<DateTime<Utc>>,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE runs SET status = ?2, ended_at = ?3 WHERE id = ?1")
            .bind(id.to_string())
            .bind(enum_str(&status))
            .bind(ended_at.map(|t| t.to_rfc3339()))
            .execute(&self.pool)
            .await?;
        require_one_run(result.rows_affected(), id)?;
        Ok(())
    }

    /// Fetch a run by id.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn get_run(&self, id: Uuid) -> Result<Option<RunRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM runs WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(run_from_row).transpose()
    }

    /// List runs, optionally filtered by project root, newest first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_runs(
        &self,
        project_root: Option<&str>,
    ) -> Result<Vec<RunRecord>, StorageError> {
        let rows = match project_root {
            Some(root) => {
                sqlx::query("SELECT * FROM runs WHERE project_root = ?1 ORDER BY started_at DESC")
                    .bind(root)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query("SELECT * FROM runs ORDER BY started_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        rows.iter().map(run_from_row).collect()
    }

    // -- targets ------------------------------------------------------------

    /// Insert or replace a target candidate.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or if the candidate cannot be
    /// serialized.
    pub async fn upsert_target(
        &self,
        t: &TargetCandidate,
        discovered_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let project = t.project_root.to_string_lossy().to_string();
        // Identity is (project, symbol), not the scanner's fresh UUID. Preserve
        // the first persisted id so rediscovery cannot orphan harness, corpus,
        // and crash rows that reference the target.
        let stable_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM targets WHERE project_root = ?1 AND symbol = ?2 LIMIT 1",
        )
        .bind(&project)
        .bind(&t.symbol)
        .fetch_optional(&self.pool)
        .await?;
        let mut persisted = t.clone();
        if let Some(id) = stable_id {
            persisted.id = Uuid::parse_str(&id).map_err(|e| {
                StorageError::InvalidData(format!("invalid persisted target id '{id}': {e}"))
            })?;
        }
        // Collapse any legacy duplicates without deleting the stable parent row
        // referenced by harness/corpus/crash records.
        sqlx::query("DELETE FROM targets WHERE project_root = ?1 AND symbol = ?2 AND id <> ?3")
            .bind(&project)
            .bind(&persisted.symbol)
            .bind(persisted.id.to_string())
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO targets
                (id, project_root, symbol, language, fit_score, rationale, discovered_at, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                project_root = excluded.project_root,
                symbol = excluded.symbol,
                language = excluded.language,
                fit_score = excluded.fit_score,
                rationale = excluded.rationale,
                discovered_at = excluded.discovered_at,
                data_json = excluded.data_json",
        )
        .bind(persisted.id.to_string())
        .bind(&project)
        .bind(&persisted.symbol)
        .bind(enum_str(&persisted.language))
        .bind(persisted.fit_score)
        .bind(&persisted.rationale)
        .bind(discovered_at.to_rfc3339())
        .bind(serde_json::to_string(&persisted)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear all learned campaign knowledge: every discovered target and its
    /// children (harnesses, corpus entries, crashes) plus all fuzz runs, across
    /// every project. Configuration is left untouched. Deletes children before
    /// parents so no row is orphaned mid-clear.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn clear_knowledge(&self) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        // `auto_revert_events` is campaign history, so it is cleared too;
        // `project_settings` is configuration and is intentionally left intact.
        for table in [
            "crashes",
            "corpus_entries",
            "harnesses",
            "runs",
            "targets",
            "auto_revert_events",
        ] {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Delete every persisted record belonging to a single project: its targets
    /// and runs, plus all children linked through them (harnesses, corpus
    /// entries, crashes). Other projects are left untouched. Runs in one
    /// transaction so a project is never partially deleted.
    ///
    /// Child tables carry only `target_id`/`run_id`, not `project_root`, so the
    /// project's target and run ids are resolved first and drive the child
    /// deletes.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn delete_project(&self, project_root: &str) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        let target_ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM targets WHERE project_root = ?1")
                .bind(project_root)
                .fetch_all(&mut *tx)
                .await?;
        let run_ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM runs WHERE project_root = ?1")
                .bind(project_root)
                .fetch_all(&mut *tx)
                .await?;
        for tid in &target_ids {
            for table in ["harnesses", "corpus_entries", "crashes"] {
                sqlx::query(&format!("DELETE FROM {table} WHERE target_id = ?1"))
                    .bind(tid)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        for rid in &run_ids {
            sqlx::query("DELETE FROM crashes WHERE run_id = ?1")
                .bind(rid)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM runs WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM targets WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        // Per-project settings and the audit trail are keyed by project_root
        // directly, so drop them here rather than leaving orphans that would
        // resurface if the same path is re-added.
        sqlx::query("DELETE FROM project_settings WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM auto_revert_events WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete a single run and the crashes it produced.
    ///
    /// # Errors
    /// Returns a storage error on a database failure.
    pub async fn delete_run(&self, run_id: &str) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM crashes WHERE run_id = ?1")
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("DELETE FROM runs WHERE id = ?1")
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::NotFound(format!("run {run_id}")));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Delete a single crash reproducer by id.
    ///
    /// # Errors
    /// Returns a storage error on a database failure.
    pub async fn delete_crash(&self, crash_id: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM crashes WHERE id = ?1")
            .bind(crash_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete one target's corpus entry by its content hash.
    ///
    /// # Errors
    /// Returns a storage error on a database failure.
    pub async fn delete_corpus_entry(
        &self,
        target_id: Uuid,
        sha256: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM corpus_entries WHERE target_id = ?1 AND sha256 = ?2")
            .bind(target_id.to_string())
            .bind(sha256)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::NotFound(format!(
                "corpus entry {target_id}/{sha256}"
            )));
        }
        Ok(())
    }

    /// Clear every persisted crash and corpus entry (the Artifacts browser).
    ///
    /// # Errors
    /// Returns a storage error on a database failure.
    pub async fn clear_all_artifacts(&self) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM crashes").execute(&mut *tx).await?;
        sqlx::query("DELETE FROM corpus_entries")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Clear every persisted run and the crashes it produced (Run History).
    ///
    /// # Errors
    /// Returns a storage error on a database failure.
    pub async fn clear_all_runs(&self) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM crashes").execute(&mut *tx).await?;
        sqlx::query("DELETE FROM runs").execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Remove child rows whose parent target no longer exists: harnesses,
    /// corpus entries, and crashes pointing at a `target_id` absent from
    /// `targets`. Repairs data orphaned by older partial clears (which is why
    /// such harnesses render with an "unknown" symbol). Idempotent.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn delete_orphans(&self) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        for table in ["harnesses", "corpus_entries", "crashes"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE target_id NOT IN (SELECT id FROM targets)"
            ))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Persist every candidate in an inventory.
    ///
    /// # Errors
    /// Returns an error on the first failed insert.
    pub async fn save_inventory(
        &self,
        inv: &TargetInventory,
        discovered_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        for candidate in &inv.candidates {
            self.upsert_target(candidate, discovered_at).await?;
        }
        Ok(())
    }

    /// List persisted targets for a project, highest fit score first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_targets(
        &self,
        project_root: &str,
    ) -> Result<Vec<TargetCandidate>, StorageError> {
        let rows = sqlx::query(
            "SELECT data_json FROM targets WHERE project_root = ?1 ORDER BY fit_score DESC",
        )
        .bind(project_root)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| json_col(&r, "data_json"))
            .collect()
    }

    /// List every persisted target across all projects, highest fit first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_all_targets(&self) -> Result<Vec<TargetCandidate>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM targets ORDER BY fit_score DESC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| json_col(r, "data_json")).collect()
    }

    // -- harnesses ----------------------------------------------------------

    /// Insert or replace a harness.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or serialization failure.
    pub async fn upsert_harness(&self, h: &Harness) -> Result<(), StorageError> {
        let smoke_json = match &h.smoke_run {
            Some(s) => Some(serde_json::to_string(s)?),
            None => None,
        };
        sqlx::query(
            "INSERT OR REPLACE INTO harnesses
                (id, target_id, engine, source, status, smoke_run_json, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(h.id.to_string())
        .bind(h.target_id.to_string())
        .bind(enum_str(&h.engine))
        .bind(&h.source)
        .bind(enum_str(&h.status))
        .bind(smoke_json)
        .bind(serde_json::to_string(h)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch a harness by id.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn get_harness(&self, id: Uuid) -> Result<Option<Harness>, StorageError> {
        let row = sqlx::query("SELECT data_json FROM harnesses WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| json_col(&r, "data_json")).transpose()
    }

    /// List harnesses for a target.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_harnesses(&self, target_id: Uuid) -> Result<Vec<Harness>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM harnesses WHERE target_id = ?1")
            .bind(target_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|r| json_col(&r, "data_json"))
            .collect()
    }

    /// List every persisted harness across targets.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_all_harnesses(&self) -> Result<Vec<Harness>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM harnesses")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| json_col(r, "data_json")).collect()
    }

    // -- crashes ------------------------------------------------------------

    /// Insert or replace a crash record.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or serialization failure.
    pub async fn upsert_crash(&self, c: &Crash) -> Result<(), StorageError> {
        let bug_json = match &c.bug_report {
            Some(b) => Some(serde_json::to_string(b)?),
            None => None,
        };
        sqlx::query(
            "INSERT OR REPLACE INTO crashes
                (id, run_id, target_id, stack_signature, kind, summary, minimized, bug_report_json, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(c.id.to_string())
        .bind(c.run_id.to_string())
        .bind(c.target_id.to_string())
        .bind(&c.stack_signature)
        .bind(enum_str(&c.kind))
        .bind(&c.summary)
        .bind(i64::from(c.minimized))
        .bind(bug_json)
        .bind(serde_json::to_string(c)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List crashes recorded for a run.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_crashes_by_run(&self, run_id: Uuid) -> Result<Vec<Crash>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM crashes WHERE run_id = ?1")
            .bind(run_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|r| json_col(&r, "data_json"))
            .collect()
    }

    /// List every persisted crash across all runs, newest insertion first.
    ///
    /// [`Crash`] has no creation timestamp, so the table's stable `SQLite`
    /// insertion order is the persisted chronology for this cross-run view.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_all_crashes(&self) -> Result<Vec<Crash>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM crashes ORDER BY rowid DESC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| json_col(r, "data_json")).collect()
    }

    // -- scheduler execution history ---------------------------------------

    /// Insert or update a persisted scheduler execution record.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn upsert_schedule_execution(
        &self,
        id: &str,
        schedule_id: &str,
        triggered_at: &str,
        status: &str,
        data_json: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT OR REPLACE INTO schedule_executions
                (id, schedule_id, triggered_at, status, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id)
        .bind(schedule_id)
        .bind(triggered_at)
        .bind(status)
        .bind(data_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retain only the newest `keep` historical executions for one schedule.
    ///
    /// Recency is ordered by `triggered_at`, with the execution id as a
    /// deterministic tie-breaker. Pending/running executions and executions
    /// that started within the rolling hourly-admission window are protected
    /// from history pruning. The protection keeps UI retention independent
    /// from live execution state and restart-safe hourly rate limiting.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn prune_schedule_executions(
        &self,
        schedule_id: &str,
        keep: usize,
    ) -> Result<u64, StorageError> {
        let admission_cutoff = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let result = sqlx::query(
            "DELETE FROM schedule_executions
             WHERE schedule_id = ?1
               AND status NOT IN ('pending', 'running')
               AND NOT CASE
                   WHEN json_valid(data_json)
                   THEN COALESCE(
                       julianday(json_extract(data_json, '$.started_at')) >= julianday(?3),
                       FALSE
                   )
                   ELSE FALSE
               END
               AND id NOT IN (
                   SELECT id FROM schedule_executions
                   WHERE schedule_id = ?1
                   ORDER BY triggered_at DESC, id DESC
                   LIMIT ?2
               )",
        )
        .bind(schedule_id)
        .bind(i64::try_from(keep).unwrap_or(i64::MAX))
        .bind(admission_cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Count execution starts for one schedule at or after an RFC 3339 cutoff.
    ///
    /// The actual `started_at` value is read from the serialized execution,
    /// rather than approximated with its earlier trigger time. Skipped and
    /// pending records have no start and do not consume a rate-limit slot.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or an invalid negative aggregate.
    pub async fn count_schedule_executions_since(
        &self,
        schedule_id: &str,
        since: &str,
    ) -> Result<u64, StorageError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedule_executions
             WHERE schedule_id = ?1
               AND status NOT IN ('pending', 'skipped')
               AND CASE
                   WHEN json_valid(data_json)
                   THEN COALESCE(
                       julianday(json_extract(data_json, '$.started_at')) >= julianday(?2),
                       FALSE
                   )
                   ELSE FALSE
               END",
        )
        .bind(schedule_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(count)
            .map_err(|_| StorageError::InvalidData("negative schedule execution count".to_owned()))
    }

    /// The most recent persisted executions (their `data_json`), newest first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn list_schedule_executions(&self, limit: i64) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query(
            "SELECT data_json FROM schedule_executions
             ORDER BY triggered_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| r.get::<String, _>("data_json"))
            .collect())
    }

    /// Delete all persisted schedule executions, returning how many were removed.
    ///
    /// Execution history is deliberately decoupled from the schedules themselves
    /// (so a run's outcome survives its schedule being deleted), which means the
    /// failures of a long-gone campaign otherwise sit in the history forever.
    /// This is how an operator clears them.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn clear_schedule_executions(&self) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM schedule_executions")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// The latest fire time per schedule: `(schedule_id, triggered_at)`.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn latest_schedule_fires(&self) -> Result<Vec<(String, String)>, StorageError> {
        let rows = sqlx::query(
            "SELECT schedule_id, MAX(triggered_at) AS last FROM schedule_executions
             GROUP BY schedule_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("schedule_id"),
                    r.get::<String, _>("last"),
                )
            })
            .collect())
    }

    // -- corpus -------------------------------------------------------------

    /// Insert or update a corpus entry, keyed by `(target_id, sha256)`.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or serialization failure.
    pub async fn upsert_corpus_entry(
        &self,
        target_id: Uuid,
        e: &CorpusEntry,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO corpus_entries
                (id, target_id, sha256, size, source, coverage_hash, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(target_id, sha256) DO UPDATE SET
                size = excluded.size,
                source = excluded.source,
                coverage_hash = excluded.coverage_hash,
                data_json = excluded.data_json",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(target_id.to_string())
        .bind(&e.sha256)
        .bind(i64::try_from(e.size).unwrap_or(i64::MAX))
        .bind(enum_str(&e.source))
        .bind(e.coverage_hash.clone())
        .bind(serde_json::to_string(e)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Transactionally replace the persisted corpus snapshot for one target.
    ///
    /// Rows absent from `entries` are removed. When a filesystem rescan reports
    /// a retained entry as `Manual`, its stronger persisted source is kept; a
    /// missing coverage hash is likewise filled from the prior row.
    ///
    /// # Errors
    /// Returns an error on duplicate hashes, SQL failure, malformed stored
    /// data, or serialization failure.
    pub async fn replace_corpus_entries(
        &self,
        target_id: Uuid,
        entries: &[CorpusEntry],
    ) -> Result<(), StorageError> {
        use std::collections::{HashMap, HashSet};

        let mut tx = self.pool.begin().await?;
        let existing_rows =
            sqlx::query("SELECT data_json FROM corpus_entries WHERE target_id = ?1")
                .bind(target_id.to_string())
                .fetch_all(&mut *tx)
                .await?;
        let existing = existing_rows
            .iter()
            .map(|row| json_col::<CorpusEntry>(row, "data_json"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| (entry.sha256.clone(), entry))
            .collect::<HashMap<_, _>>();

        let mut seen = HashSet::with_capacity(entries.len());
        let mut replacements = Vec::with_capacity(entries.len());
        for entry in entries {
            if !seen.insert(entry.sha256.clone()) {
                return Err(StorageError::InvalidData(format!(
                    "duplicate corpus hash for target {target_id}: {}",
                    entry.sha256
                )));
            }
            let mut merged = entry.clone();
            if let Some(previous) = existing.get(&entry.sha256) {
                if merged.source == hf_core::corpus::CorpusSource::Manual {
                    merged.source = previous.source;
                }
                if merged.coverage_hash.is_none() {
                    merged.coverage_hash.clone_from(&previous.coverage_hash);
                }
            }
            let json = serde_json::to_string(&merged)?;
            replacements.push((merged, json));
        }

        sqlx::query("DELETE FROM corpus_entries WHERE target_id = ?1")
            .bind(target_id.to_string())
            .execute(&mut *tx)
            .await?;
        for (entry, json) in replacements {
            sqlx::query(
                "INSERT INTO corpus_entries
                    (id, target_id, sha256, size, source, coverage_hash, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(target_id.to_string())
            .bind(&entry.sha256)
            .bind(i64::try_from(entry.size).unwrap_or(i64::MAX))
            .bind(enum_str(&entry.source))
            .bind(entry.coverage_hash.clone())
            .bind(json)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// List corpus entries for a target.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_corpus_entries(
        &self,
        target_id: Uuid,
    ) -> Result<Vec<CorpusEntry>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM corpus_entries WHERE target_id = ?1")
            .bind(target_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|r| json_col(&r, "data_json"))
            .collect()
    }

    /// List every persisted corpus entry across all targets.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_all_corpus_entries(&self) -> Result<Vec<CorpusEntry>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM corpus_entries")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|r| json_col(r, "data_json")).collect()
    }

    /// List every corpus entry together with its owning target id.
    pub async fn list_all_corpus_entries_with_targets(
        &self,
    ) -> Result<Vec<(Uuid, CorpusEntry)>, StorageError> {
        let rows = sqlx::query("SELECT target_id, data_json FROM corpus_entries")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let target_id = Uuid::parse_str(&row.get::<String, _>("target_id"))
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok((target_id, json_col::<CorpusEntry>(row, "data_json")?))
            })
            .collect()
    }

    // -- sessions -----------------------------------------------------------

    /// Create a conversation session (optionally a child of `parent`) and
    /// return its id.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn create_session(
        &self,
        parent: Option<Uuid>,
        created_at: DateTime<Utc>,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sessions (id, parent_id, title, created_at) VALUES (?1, ?2, NULL, ?3)",
        )
        .bind(id.to_string())
        .bind(parent.map(|p| p.to_string()))
        .bind(created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Append a message to a session. The sequence number is assigned
    /// automatically as `max(seq) + 1`.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn append_message(
        &self,
        session: Uuid,
        role: &str,
        content: &str,
        created_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        // Compute the next seq and insert in a SINGLE statement so the
        // read-then-write is atomic. A prior SELECT-then-INSERT had a TOCTOU
        // race: two concurrent appends to one session could read the same MAX
        // and write a duplicate seq. SQLite serializes writers, so an
        // `INSERT ... SELECT` evaluates the aggregate under the write lock.
        // (The `MAX` aggregate always yields exactly one row, even for a session
        // with no messages yet, so the first insert gets seq 0.)
        sqlx::query(
            "INSERT INTO messages (id, session_id, seq, role, content, created_at)
             SELECT ?1, ?2, COALESCE(MAX(seq), -1) + 1, ?3, ?4, ?5
             FROM messages WHERE session_id = ?2",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(session.to_string())
        .bind(role)
        .bind(content)
        .bind(created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return a session's messages as `(role, content)` pairs, oldest first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn session_history(
        &self,
        session: Uuid,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let rows = sqlx::query(
            "SELECT role, content FROM messages WHERE session_id = ?1 ORDER BY seq ASC",
        )
        .bind(session.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("role")?, r.try_get("content")?)))
            .collect()
    }
}

// -- helpers ----------------------------------------------------------------

/// Serialize an enum to its bare serde string name (no surrounding quotes).
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|val| val.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn automotive_operation_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<AutomotiveOperationRecord, StorageError> {
    let id = Uuid::parse_str(&row.try_get::<String, _>("id")?)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    let status = serde_json::from_value(serde_json::Value::String(row.try_get("status")?))?;
    let started_at = ts(&row.try_get::<String, _>("started_at")?)?;
    let ended_at = row
        .try_get::<Option<String>, _>("ended_at")?
        .as_deref()
        .map(ts)
        .transpose()?;
    Ok(AutomotiveOperationRecord {
        id,
        project_root: row.try_get("project_root")?,
        operation: row.try_get("operation")?,
        mode: row.try_get("mode")?,
        protocol: row.try_get("protocol")?,
        status,
        started_at,
        ended_at,
        request_hash: row.try_get("request_hash")?,
        transcript_hash: row.try_get("transcript_hash")?,
        artifact_dir: row.try_get("artifact_dir")?,
        approval_json: row.try_get("approval_json")?,
        result_json: row.try_get("result_json")?,
        error: row.try_get("error")?,
    })
}

fn automotive_state_corpus_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<AutomotiveStateCorpusRecord, StorageError> {
    let source_operation_id = Uuid::parse_str(&row.try_get::<String, _>("source_operation_id")?)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    let created_at = ts(&row.try_get::<String, _>("created_at")?)?;
    Ok(AutomotiveStateCorpusRecord {
        project_root: row.try_get("project_root")?,
        protocol: row.try_get("protocol")?,
        state_digest: row.try_get("state_digest")?,
        artifact_sha256: row.try_get("artifact_sha256")?,
        source_operation_id,
        artifact_path: row.try_get("artifact_path")?,
        created_at,
    })
}

/// Decode a JSON-text column into a model.
fn json_col<T: DeserializeOwned>(
    row: &sqlx::sqlite::SqliteRow,
    col: &str,
) -> Result<T, StorageError> {
    let raw: String = row.try_get(col)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Parse an RFC3339 timestamp column into UTC.
fn ts(raw: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| StorageError::Timestamp(e.to_string()))
}

/// Reconstruct a [`RunRecord`] from a row.
fn run_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<RunRecord, StorageError> {
    let id_str: String = row.try_get("id")?;
    let engine_str: String = row.try_get("engine")?;
    let status_str: String = row.try_get("status")?;
    let started_at: String = row.try_get("started_at")?;
    let ended_at: Option<String> = row.try_get("ended_at")?;
    let config_json: Option<String> = row.try_get("config_json")?;
    let config = match config_json {
        Some(c) => Some(serde_json::from_str(&c)?),
        None => None,
    };
    let edges: Option<i64> = row.try_get("edges")?;
    let execs: Option<f64> = row.try_get("execs")?;
    let crash_count: Option<i64> = row.try_get("crash_count")?;
    let harness_rev: Option<String> = row.try_get("harness_rev")?;
    let binary_rev: Option<String> = row.try_get("binary_rev")?;
    let evidence_dir: Option<String> = row.try_get("evidence_dir")?;
    let run_kind: String = row.try_get("run_kind")?;
    let context_rev: Option<String> = row.try_get("context_rev")?;
    Ok(RunRecord {
        id: Uuid::parse_str(&id_str)
            .map_err(|e| StorageError::Timestamp(format!("bad uuid: {e}")))?,
        project_root: row.try_get("project_root")?,
        engine: enum_from(&engine_str)?,
        status: enum_from(&status_str)?,
        kind: enum_from(&run_kind)?,
        started_at: ts(&started_at)?,
        ended_at: ended_at.as_deref().map(ts).transpose()?,
        config,
        edges: edges.map(|e| u64::try_from(e).unwrap_or(0)),
        execs,
        crash_count: crash_count.map(|c| u64::try_from(c).unwrap_or(0)),
        harness_rev,
        binary_rev,
        evidence_dir,
        context_rev,
    })
}

/// Decode a bare enum string name back into the enum.
fn enum_from<T: DeserializeOwned>(s: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}

fn require_one_run(rows_affected: u64, id: Uuid) -> Result<(), StorageError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(StorageError::NotFound(format!("run {id}")))
    }
}
