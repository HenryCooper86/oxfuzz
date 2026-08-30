//! The SQLite-backed [`Store`] and its repository methods.

use std::{path::Path, time::Duration};

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
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
const DEFAULT_DB_PATH: &str = "data/oxfuzz.db";
/// Maximum time a connection waits for another `SQLite` writer to finish.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

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

/// One guardrail authorization decision, for the durable policy audit trail.
///
/// The service records one row per authorization: the policy outcome, and the
/// human approval outcome where the approval gate was consulted. Recording is
/// best-effort -- a storage failure is logged and never changes the
/// authorization outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardrailDecisionRecord {
    /// Unique decision id (UUID).
    pub id: String,
    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
    /// The authorized action kind (`Action::kind`, e.g. `discover`,
    /// `run_fuzzer`, `corpus_op`).
    pub action: String,
    /// The action's assessed risk tier (low/medium/high/critical).
    pub risk_tier: String,
    /// The outcome: `allowed`/`denied`/`approved`/`denied_by_operator`.
    pub decision: String,
    /// The service entry point that authorized (e.g. `discover`, `run_fuzzer`).
    pub origin: String,
    /// The project the operation targeted, when one exists.
    pub project: Option<String>,
    /// The policy reason (bounded length), when the policy produced one.
    pub detail: Option<String>,
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

/// Kind of explicit human harness promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessApprovalKind {
    /// Crash-free smoke qualification was approved.
    CleanSmoke,
    /// Smoke findings were reviewed and explicitly accepted.
    KnownFindings,
}

/// Durable digest-bound provenance for one explicit harness promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessApprovalRecord {
    /// Service-owned approval id.
    pub id: Uuid,
    /// Exact promoted harness.
    pub harness_id: Uuid,
    /// Smoke-qualified source digest.
    pub source_sha256: String,
    /// Smoke-qualified binary digest.
    pub binary_sha256: String,
    /// Whether clean smoke or reviewed findings were approved.
    pub approval_kind: HarnessApprovalKind,
    /// Approval time.
    pub approved_at: DateTime<Utc>,
}

/// Durable independent LLM review of one exact harness source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessAiReviewRecord {
    /// Exact compiled harness reviewed before execution.
    pub harness_id: Uuid,
    /// Lowercase SHA-256 of the complete reviewed source.
    pub source_sha256: String,
    /// Lowercase SHA-256 of the compiled binary bound to this review.
    pub binary_sha256: String,
    /// Versioned review evidence, including provider response metadata.
    pub review_json: String,
    /// Time the accepted review was persisted.
    pub reviewed_at: DateTime<Utc>,
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
    /// Digest of the staged target-source inputs.
    pub source_rev: Option<String>,
    /// Digest of the starting corpus snapshot.
    pub corpus_rev: Option<String>,
    /// Typed exact image identity (`docker-image-id-sha256:<digest>`). Legacy
    /// untyped values are retained for migration but are not proof-bearing.
    pub sandbox_rev: Option<String>,
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
            source_rev: None,
            corpus_rev: None,
            sandbox_rev: None,
        }
    }
}

/// Lifecycle status of one explicit Semgrep enrichment operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepRunStatus {
    /// The bounded source snapshot is being prepared.
    Staging,
    /// The pinned scanner is executing in the sandbox.
    Scanning,
    /// Scanner output is being parsed and mapped.
    Validating,
    /// The normalized overlay is ready for atomic publication.
    Persisting,
    /// The complete overlay was published.
    Done,
    /// The operation terminated with a sanitized failure.
    Failed,
    /// The operator cancelled the operation.
    Cancelled,
}

/// Normalized Semgrep finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepFindingSeverity {
    /// Highest supported advisory severity.
    Error,
    /// Medium supported advisory severity.
    Warning,
    /// Informational advisory severity.
    Info,
}

/// Durable parent record for one Semgrep enrichment operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemgrepRunRecord {
    /// Service-owned operation identifier.
    pub id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// First-release language identifier (`c` or `cpp`).
    pub language: String,
    /// Digest of the staged eligible source snapshot.
    pub source_sha256: Option<String>,
    /// Pinned sandbox image reference.
    pub sandbox_image: String,
    /// Resolved sandbox image digest.
    pub sandbox_image_sha256: String,
    /// Pinned Semgrep version.
    pub semgrep_version: String,
    /// Pinned rule repository revision.
    pub rules_commit: String,
    /// Digest of the bundled rules tree.
    pub rules_tree_sha256: String,
    /// Typed scanner command schema version.
    pub command_schema_version: u32,
    /// Current operation lifecycle status.
    pub status: SemgrepRunStatus,
    /// Time the operation was durably admitted.
    pub started_at: DateTime<Utc>,
    /// Terminal timestamp.
    pub ended_at: Option<DateTime<Utc>>,
    /// Digest of normalized scanner output.
    pub output_sha256: Option<String>,
    /// Number of normalized findings.
    pub finding_count: Option<u32>,
    /// Number of candidates matched by at least one distinct rule.
    pub matched_candidate_count: Option<u32>,
    /// End-to-end operation duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Bounded sanitized terminal failure code.
    pub failure_code: Option<String>,
    /// Bounded sanitized terminal failure message.
    pub failure_message: Option<String>,
}

/// One normalized advisory Semgrep finding.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepFindingRecord {
    /// Parent operation identifier.
    pub scan_id: Uuid,
    /// Service-owned deterministic finding digest.
    pub fingerprint: String,
    /// Normalized rule identifier.
    pub rule_id: String,
    /// Normalized advisory severity.
    pub severity: SemgrepFindingSeverity,
    /// Bounded advisory message.
    pub message: String,
    /// Normalized project-relative source path.
    pub relative_file: String,
    /// One-based start line.
    pub start_line: u32,
    /// One-based start column.
    pub start_col: u32,
    /// One-based end line.
    pub end_line: u32,
    /// One-based end column.
    pub end_col: u32,
    /// Matched logical target, when mapping was unambiguous.
    pub target_id: Option<Uuid>,
    /// Nominal severity weight retained for presentation.
    pub nominal_weight: f64,
}

/// One candidate's base score and capped Semgrep overlay.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepTargetScoreRecord {
    /// Parent operation identifier.
    pub scan_id: Uuid,
    /// Logical target identifier.
    pub target_id: Uuid,
    /// Immutable base score observed at scan time.
    pub base_score: f64,
    /// Capped advisory boost.
    pub boost: f64,
    /// Capped effective score.
    pub effective_score: f64,
    /// Number of distinct matched rules.
    pub matched_rule_count: u32,
}

/// Atomically published Semgrep parent and normalized children.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepPublication {
    /// Operation metadata and terminal aggregate fields.
    pub run: SemgrepRunRecord,
    /// Every normalized finding, including unmatched findings.
    pub findings: Vec<SemgrepFindingRecord>,
    /// Every candidate score row for the scanned inventory.
    pub scores: Vec<SemgrepTargetScoreRecord>,
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
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(SQLITE_BUSY_TIMEOUT);
        Self::connect_with(opts).await
    }

    /// Connect using the `HF_DB_PATH` env var, defaulting to
    /// `data/oxfuzz.db`.
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
        crate::retired_engine::validate_no_active_retired_engine_records(&pool).await?;
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
            "INSERT INTO runs (id, project_root, engine, status, started_at, ended_at, config_json, edges, execs, crash_count, harness_rev, binary_rev, evidence_dir, run_kind, context_rev, source_rev, corpus_rev, sandbox_rev)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
        .bind(run.source_rev.as_deref())
        .bind(run.corpus_rev.as_deref())
        .bind(run.sandbox_rev.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // -- Semgrep enrichment ------------------------------------------------

    /// Insert a newly admitted Semgrep operation in the staging phase.
    ///
    /// # Errors
    /// Returns an error for malformed fields, a non-staging record, or a SQL
    /// failure such as an already-active operation for the project.
    pub async fn insert_semgrep_run(&self, run: &SemgrepRunRecord) -> Result<(), StorageError> {
        validate_semgrep_run(run)?;
        if run.status != SemgrepRunStatus::Staging
            || run.source_sha256.is_some()
            || run.ended_at.is_some()
            || run.output_sha256.is_some()
            || run.finding_count.is_some()
            || run.matched_candidate_count.is_some()
            || run.duration_ms.is_some()
            || run.failure_code.is_some()
            || run.failure_message.is_some()
        {
            return Err(StorageError::InvalidData(
                "a new Semgrep run must contain only staging-phase fields".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO semgrep_enrichment_runs
                (id, project_root, language, source_sha256, sandbox_image,
                 sandbox_image_sha256, semgrep_version, rules_commit, rules_tree_sha256,
                 command_schema_version, status, started_at, ended_at, output_sha256,
                 finding_count, matched_candidate_count, duration_ms, failure_code,
                 failure_message)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19)",
        )
        .bind(run.id.to_string())
        .bind(&run.project_root)
        .bind(&run.language)
        .bind(run.source_sha256.as_deref())
        .bind(&run.sandbox_image)
        .bind(&run.sandbox_image_sha256)
        .bind(&run.semgrep_version)
        .bind(&run.rules_commit)
        .bind(&run.rules_tree_sha256)
        .bind(i64::from(run.command_schema_version))
        .bind(enum_str(&run.status))
        .bind(run.started_at.to_rfc3339())
        .bind(run.ended_at.map(|value| value.to_rfc3339()))
        .bind(run.output_sha256.as_deref())
        .bind(run.finding_count.map(i64::from))
        .bind(run.matched_candidate_count.map(i64::from))
        .bind(run.duration_ms.map(to_i64).transpose()?)
        .bind(run.failure_code.as_deref())
        .bind(run.failure_message.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Compare-and-set one valid non-terminal Semgrep phase transition.
    ///
    /// The source digest is required when staging completes and cannot be
    /// changed by later transitions.
    ///
    /// # Errors
    /// Returns an error for an invalid transition, malformed digest, missing
    /// expected row, or SQL failure.
    pub async fn set_semgrep_phase(
        &self,
        id: Uuid,
        expected: SemgrepRunStatus,
        next: SemgrepRunStatus,
        source_sha256: Option<&str>,
    ) -> Result<(), StorageError> {
        let valid = matches!(
            (expected, next),
            (SemgrepRunStatus::Staging, SemgrepRunStatus::Scanning)
                | (SemgrepRunStatus::Scanning, SemgrepRunStatus::Validating)
                | (SemgrepRunStatus::Validating, SemgrepRunStatus::Persisting)
        );
        if !valid {
            return Err(StorageError::InvalidData(
                "invalid Semgrep phase transition".to_owned(),
            ));
        }
        if expected == SemgrepRunStatus::Staging {
            let source_sha256 = source_sha256.ok_or_else(|| {
                StorageError::InvalidData("staging completion requires a source SHA-256".to_owned())
            })?;
            require_sha256("source_sha256", source_sha256)?;
        } else if source_sha256.is_some() {
            return Err(StorageError::InvalidData(
                "source SHA-256 can only be set when staging completes".to_owned(),
            ));
        }
        let result = sqlx::query(
            "UPDATE semgrep_enrichment_runs
             SET status = ?3, source_sha256 = COALESCE(?4, source_sha256)
             WHERE id = ?1 AND status = ?2",
        )
        .bind(id.to_string())
        .bind(enum_str(&expected))
        .bind(enum_str(&next))
        .bind(source_sha256)
        .execute(&self.pool)
        .await?;
        require_one_semgrep_run(result.rows_affected(), id, expected)
    }

    /// Publish a complete Semgrep overlay in one database transaction.
    ///
    /// # Errors
    /// Returns an error for malformed or inconsistent records, a parent not in
    /// `persisting`, or any SQL failure. All writes are rolled back together.
    pub async fn publish_semgrep_run(
        &self,
        publication: &SemgrepPublication,
    ) -> Result<(), StorageError> {
        validate_semgrep_publication(publication)?;
        let mut tx = self.pool.begin().await?;
        let persisted_row = sqlx::query(SEMGREP_RUN_SELECT)
            .bind(publication.run.id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(persisted_row) = persisted_row else {
            return Err(StorageError::NotFound(format!(
                "persisting Semgrep run {}",
                publication.run.id
            )));
        };
        let persisted = semgrep_run_from_row(&persisted_row)?;
        if persisted.status != SemgrepRunStatus::Persisting {
            return Err(StorageError::NotFound(format!(
                "persisting Semgrep run {}",
                publication.run.id
            )));
        }
        require_same_semgrep_identity(&persisted, &publication.run)?;

        for finding in &publication.findings {
            sqlx::query(
                "INSERT INTO semgrep_findings
                    (scan_id, fingerprint, rule_id, severity, message, relative_file,
                     start_line, start_col, end_line, end_col, target_id, nominal_weight)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .bind(finding.scan_id.to_string())
            .bind(&finding.fingerprint)
            .bind(&finding.rule_id)
            .bind(enum_str(&finding.severity))
            .bind(&finding.message)
            .bind(&finding.relative_file)
            .bind(i64::from(finding.start_line))
            .bind(i64::from(finding.start_col))
            .bind(i64::from(finding.end_line))
            .bind(i64::from(finding.end_col))
            .bind(finding.target_id.map(|value| value.to_string()))
            .bind(finding.nominal_weight)
            .execute(&mut *tx)
            .await?;
        }
        for score in &publication.scores {
            sqlx::query(
                "INSERT INTO semgrep_target_scores
                    (scan_id, target_id, base_score, boost, effective_score,
                     matched_rule_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(score.scan_id.to_string())
            .bind(score.target_id.to_string())
            .bind(score.base_score)
            .bind(score.boost)
            .bind(score.effective_score)
            .bind(i64::from(score.matched_rule_count))
            .execute(&mut *tx)
            .await?;
        }

        let run = &publication.run;
        let result = sqlx::query(
            "UPDATE semgrep_enrichment_runs
             SET status = 'done', source_sha256 = ?2, ended_at = ?3, output_sha256 = ?4,
                 finding_count = ?5, matched_candidate_count = ?6, duration_ms = ?7,
                 failure_code = NULL, failure_message = NULL
             WHERE id = ?1 AND status = 'persisting'",
        )
        .bind(run.id.to_string())
        .bind(run.source_sha256.as_deref())
        .bind(run.ended_at.map(|value| value.to_rfc3339()))
        .bind(run.output_sha256.as_deref())
        .bind(run.finding_count.map(i64::from))
        .bind(run.matched_candidate_count.map(i64::from))
        .bind(run.duration_ms.map(to_i64).transpose()?)
        .execute(&mut *tx)
        .await?;
        require_one_semgrep_run(result.rows_affected(), run.id, SemgrepRunStatus::Persisting)?;
        tx.commit().await?;
        Ok(())
    }

    /// Terminate an active Semgrep run as failed or cancelled.
    ///
    /// Children are deleted before the parent transition in the same
    /// transaction, so neither terminal state can retain a partial overlay.
    ///
    /// # Errors
    /// Returns an error for an unsupported status, malformed failure fields, a
    /// missing/non-active row, or a SQL failure.
    pub async fn fail_semgrep_run(
        &self,
        id: Uuid,
        status: SemgrepRunStatus,
        failure_code: &str,
        failure_message: &str,
        ended_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if !matches!(
            status,
            SemgrepRunStatus::Failed | SemgrepRunStatus::Cancelled
        ) {
            return Err(StorageError::InvalidData(
                "Semgrep failure requires failed or cancelled status".to_owned(),
            ));
        }
        validate_failure(failure_code, failure_message)?;
        terminate_semgrep_run(
            &self.pool,
            id,
            status,
            failure_code,
            failure_message,
            ended_at,
            false,
        )
        .await
    }

    /// Compensate a published overlay whose recovery journal could not commit.
    ///
    /// # Errors
    /// Returns an error for malformed failure fields, a missing/non-done row,
    /// or a SQL failure.
    pub async fn compensate_semgrep_publication(
        &self,
        id: Uuid,
        failure_code: &str,
        failure_message: &str,
        ended_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        validate_failure(failure_code, failure_message)?;
        terminate_semgrep_run(
            &self.pool,
            id,
            SemgrepRunStatus::Failed,
            failure_code,
            failure_message,
            ended_at,
            true,
        )
        .await
    }

    /// Load one Semgrep operation parent by id.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn semgrep_run(&self, id: Uuid) -> Result<Option<SemgrepRunRecord>, StorageError> {
        let row = sqlx::query(SEMGREP_RUN_SELECT)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(semgrep_run_from_row).transpose()
    }

    /// Load every active Semgrep operation parent in deterministic start order.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn active_semgrep_runs(&self) -> Result<Vec<SemgrepRunRecord>, StorageError> {
        sqlx::query(SEMGREP_ACTIVE_RUNS_SELECT)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(semgrep_run_from_row)
            .collect()
    }

    /// Load one Semgrep parent and its normalized children.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn semgrep_publication(
        &self,
        id: Uuid,
    ) -> Result<Option<SemgrepPublication>, StorageError> {
        let Some(run) = self.semgrep_run(id).await? else {
            return Ok(None);
        };
        let finding_rows = sqlx::query(
            "SELECT scan_id, fingerprint, rule_id, severity, message, relative_file,
                    start_line, start_col, end_line, end_col, target_id, nominal_weight
             FROM semgrep_findings WHERE scan_id = ?1 ORDER BY fingerprint",
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let score_rows = sqlx::query(
            "SELECT scan_id, target_id, base_score, boost, effective_score, matched_rule_count
             FROM semgrep_target_scores WHERE scan_id = ?1 ORDER BY target_id",
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let findings = finding_rows
            .iter()
            .map(semgrep_finding_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let scores = score_rows
            .iter()
            .map(semgrep_score_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let publication = SemgrepPublication {
            run,
            findings,
            scores,
        };
        match publication.run.status {
            SemgrepRunStatus::Done => validate_semgrep_publication(&publication)?,
            SemgrepRunStatus::Failed | SemgrepRunStatus::Cancelled => {
                if !publication.findings.is_empty() || !publication.scores.is_empty() {
                    return Err(StorageError::InvalidData(
                        "terminal unsuccessful Semgrep run retained children".to_owned(),
                    ));
                }
            }
            _ => {
                if !publication.findings.is_empty() || !publication.scores.is_empty() {
                    return Err(StorageError::InvalidData(
                        "active Semgrep run retained published children".to_owned(),
                    ));
                }
            }
        }
        Ok(Some(publication))
    }

    /// Load the newest complete Semgrep publication for a project/language.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed persisted data.
    pub async fn latest_semgrep_publication(
        &self,
        project_root: &str,
        language: &str,
    ) -> Result<Option<SemgrepPublication>, StorageError> {
        if !matches!(language, "c" | "cpp") {
            return Err(StorageError::InvalidData(
                "Semgrep language must be c or cpp".to_owned(),
            ));
        }
        let id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM semgrep_enrichment_runs
             WHERE project_root = ?1 AND language = ?2 AND status = 'done'
             ORDER BY ended_at DESC, id DESC LIMIT 1",
        )
        .bind(project_root)
        .bind(language)
        .fetch_optional(&self.pool)
        .await?;
        let Some(id) = id else {
            return Ok(None);
        };
        let id = Uuid::parse_str(&id)
            .map_err(|error| StorageError::InvalidData(format!("Semgrep run id: {error}")))?;
        self.semgrep_publication(id).await
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

    /// Atomically claim a physical-bench approval for single use.
    ///
    /// A physical automotive replay authorizes real transmissions on a vehicle
    /// bench, so each human approval must authorize at most one operation. This
    /// inserts the approval id into the single-use ledger and reports whether the
    /// claim succeeded: `true` when this call was the first to consume it,
    /// `false` when it was already consumed. The `PRIMARY KEY` on `approval_id`
    /// makes the second claim fail atomically -- the race-free primitive a
    /// read-then-write check cannot provide, so two concurrent executions cannot
    /// both proceed on one approval.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or when `approval_id` is empty.
    pub async fn consume_automotive_approval(
        &self,
        approval_id: &str,
        scope_sha256: &str,
        operation_id: Uuid,
        project_root: &str,
        consumed_at: DateTime<Utc>,
    ) -> Result<bool, StorageError> {
        if approval_id.trim().is_empty() {
            return Err(StorageError::InvalidData(
                "automotive approval id must not be empty".to_owned(),
            ));
        }
        let result = sqlx::query(
            "INSERT INTO automotive_consumed_approvals
                (approval_id, scope_sha256, operation_id, project_root, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(approval_id) DO NOTHING",
        )
        .bind(approval_id)
        .bind(scope_sha256)
        .bind(operation_id.to_string())
        .bind(project_root)
        .bind(consumed_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        // SQLite reports zero changed rows when the conflicting insert is
        // ignored, i.e. the approval was already consumed.
        Ok(result.rows_affected() == 1)
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
    /// Record one closeout step outcome for a run, replacing any earlier
    /// outcome for the same step.
    ///
    /// Written before the next step begins, so an interrupted closeout resumes
    /// at the first step that never reached a terminal outcome.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn record_closeout_step(
        &self,
        run_id: Uuid,
        step: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO run_closeout_steps (run_id, step, outcome, detail, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(run_id, step) DO UPDATE SET \
                 outcome = excluded.outcome, \
                 detail = excluded.detail, \
                 recorded_at = excluded.recorded_at",
        )
        .bind(run_id.to_string())
        .bind(step)
        .bind(outcome)
        .bind(detail)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every recorded closeout step for a run, as `(step, outcome, detail)`.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn closeout_steps(
        &self,
        run_id: Uuid,
    ) -> Result<Vec<(String, String, String)>, StorageError> {
        let rows =
            sqlx::query("SELECT step, outcome, detail FROM run_closeout_steps WHERE run_id = ?1")
                .bind(run_id.to_string())
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<String, _>("step"),
                    row.get::<String, _>("outcome"),
                    row.get::<String, _>("detail"),
                )
            })
            .collect())
    }

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

    // -- guardrail decisions --------------------------------------------------

    /// Append a guardrail authorization decision to the durable audit trail.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn record_guardrail_decision(
        &self,
        record: &GuardrailDecisionRecord,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO guardrail_decisions \
                 (id, decided_at, action, risk_tier, decision, origin, project, detail) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&record.id)
        .bind(
            record
                .decided_at
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        )
        .bind(&record.action)
        .bind(&record.risk_tier)
        .bind(&record.decision)
        .bind(&record.origin)
        .bind(record.project.as_deref())
        .bind(record.detail.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The guardrail decision audit trail, newest first. `limit` caps the rows
    /// returned. `rowid` breaks timestamp ties so same-microsecond decisions
    /// still list in insertion order.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_guardrail_decisions(
        &self,
        limit: i64,
    ) -> Result<Vec<GuardrailDecisionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, decided_at, action, risk_tier, decision, origin, project, detail \
             FROM guardrail_decisions ORDER BY decided_at DESC, rowid DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(guardrail_decision_from_row).collect()
    }

    /// Retain only the newest `keep` decisions, returning how many were
    /// removed. Recency is ordered by `decided_at`, with the rowid as the
    /// insertion-order tie-breaker (mirrors schedule-execution retention).
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn prune_guardrail_decisions(&self, keep: usize) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM guardrail_decisions
             WHERE rowid NOT IN (
                 SELECT rowid FROM guardrail_decisions
                 ORDER BY decided_at DESC, rowid DESC
                 LIMIT ?1
             )",
        )
        .bind(i64::try_from(keep).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
        // Identity is (project, symbol, file), not the scanner's fresh UUID.
        // Preserve the first persisted id so rediscovery cannot orphan harness,
        // corpus, and crash rows that reference the target. The file component
        // is the candidate's root-relative path, matching the migration 0019
        // backfill, so a rescan re-homes onto the legacy row of the same
        // definition while a same-named function in another file gets its own
        // row.
        //
        // The read (stable id), duplicate-collapse, and write run in a single
        // transaction so two concurrent discover/save_inventory operations on
        // the same project cannot both observe "no existing row" and each insert
        // a distinct id; the unique index on (project_root, symbol, file) is the
        // backstop that rejects a duplicate even if the ordering ever slips.
        let file = t.relative_file();
        let mut tx = self.pool.begin().await?;
        let stable_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM targets WHERE project_root = ?1 AND symbol = ?2 AND file = ?3 LIMIT 1",
        )
        .bind(&project)
        .bind(&t.symbol)
        .bind(&file)
        .fetch_optional(&mut *tx)
        .await?;
        let mut persisted = t.clone();
        if let Some(id) = stable_id {
            persisted.id = Uuid::parse_str(&id).map_err(|e| {
                StorageError::InvalidData(format!("invalid persisted target id '{id}': {e}"))
            })?;
        }
        // Collapse any legacy duplicates without deleting the stable parent row
        // referenced by harness/corpus/crash records.
        sqlx::query(
            "DELETE FROM targets WHERE project_root = ?1 AND symbol = ?2 AND file = ?3 AND id <> ?4",
        )
        .bind(&project)
        .bind(&persisted.symbol)
        .bind(&file)
        .bind(persisted.id.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO targets
                (id, project_root, symbol, file, language, fit_score, rationale, discovered_at, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                project_root = excluded.project_root,
                symbol = excluded.symbol,
                file = excluded.file,
                language = excluded.language,
                fit_score = excluded.fit_score,
                rationale = excluded.rationale,
                discovered_at = excluded.discovered_at,
                data_json = excluded.data_json",
        )
        .bind(persisted.id.to_string())
        .bind(&project)
        .bind(&persisted.symbol)
        .bind(&file)
        .bind(enum_str(&persisted.language))
        .bind(persisted.fit_score)
        .bind(&persisted.rationale)
        .bind(discovered_at.to_rfc3339())
        .bind(serde_json::to_string(&persisted)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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
        // `automotive_state_corpus` is deleted before `automotive_operations`
        // because it holds a foreign key into it.
        for table in [
            "harness_work_order_attempts",
            "harness_work_order_submissions",
            "harness_work_orders",
            "crashes",
            "corpus_entries",
            "harnesses",
            "runs",
            "semgrep_findings",
            "semgrep_target_scores",
            "semgrep_enrichment_runs",
            "targets",
            "auto_revert_events",
            "automotive_state_corpus",
            "automotive_operations",
            "automotive_consumed_approvals",
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
        sqlx::query(
            "DELETE FROM harness_work_order_attempts
             WHERE submission_id IN (
                 SELECT s.id FROM harness_work_order_submissions s
                 JOIN harness_work_orders w ON w.id = s.work_order_id
                 WHERE w.project_root = ?1
             )",
        )
        .bind(project_root)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM harness_work_order_submissions
             WHERE work_order_id IN (
                 SELECT id FROM harness_work_orders WHERE project_root = ?1
             )",
        )
        .bind(project_root)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM harness_work_orders WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM semgrep_findings
             WHERE scan_id IN (
                 SELECT id FROM semgrep_enrichment_runs WHERE project_root = ?1
             )",
        )
        .bind(project_root)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM semgrep_target_scores
             WHERE scan_id IN (
                 SELECT id FROM semgrep_enrichment_runs WHERE project_root = ?1
             )",
        )
        .bind(project_root)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM semgrep_enrichment_runs WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
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
        // Automotive evidence is also keyed by project_root; delete the state
        // corpus before the operations it references (FK), so re-adding the same
        // path cannot resurface stale automotive evidence.
        sqlx::query("DELETE FROM automotive_state_corpus WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM automotive_operations WHERE project_root = ?1")
            .bind(project_root)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM automotive_consumed_approvals WHERE project_root = ?1")
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
        sqlx::query(
            "DELETE FROM harness_work_order_attempts
             WHERE submission_id NOT IN (
                 SELECT s.id FROM harness_work_order_submissions s
                 JOIN harness_work_orders w ON w.id = s.work_order_id
                 JOIN targets t ON t.id = w.target_id
             )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM harness_work_order_submissions
             WHERE work_order_id NOT IN (
                 SELECT w.id FROM harness_work_orders w
                 JOIN targets t ON t.id = w.target_id
             )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM harness_work_orders
             WHERE target_id NOT IN (SELECT id FROM targets)",
        )
        .execute(&mut *tx)
        .await?;
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

    /// Persist the independent LLM review for one exact harness source.
    ///
    /// The first review is immutable through this API. An exact retry succeeds;
    /// a conflicting review for the same harness id fails loudly.
    ///
    /// # Errors
    /// Returns an error for an invalid digest or JSON object, a conflicting
    /// existing review, malformed stored evidence, or an SQL failure.
    pub async fn record_harness_ai_review(
        &self,
        review: &HarnessAiReviewRecord,
    ) -> Result<(), StorageError> {
        let parsed: serde_json::Value = serde_json::from_str(&review.review_json)?;
        if !is_sha256(&review.source_sha256)
            || !is_sha256(&review.binary_sha256)
            || !parsed.is_object()
        {
            return Err(StorageError::InvalidData(
                "harness AI review requires lowercase source/binary SHA-256 digests and a JSON object"
                    .to_owned(),
            ));
        }

        sqlx::query(
            "INSERT INTO harness_ai_reviews
                (harness_id, source_sha256, binary_sha256, review_json, reviewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(harness_id) DO NOTHING",
        )
        .bind(review.harness_id.to_string())
        .bind(&review.source_sha256)
        .bind(&review.binary_sha256)
        .bind(&review.review_json)
        .bind(review.reviewed_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let persisted = self.harness_ai_review(review.harness_id).await?;
        if persisted.as_ref() != Some(review) {
            return Err(StorageError::InvalidData(format!(
                "conflicting harness AI review already exists for {}",
                review.harness_id
            )));
        }
        Ok(())
    }

    /// Load the independent LLM review for a harness source revision.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed stored evidence.
    pub async fn harness_ai_review(
        &self,
        harness_id: Uuid,
    ) -> Result<Option<HarnessAiReviewRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT harness_id, source_sha256, binary_sha256, review_json, reviewed_at
             FROM harness_ai_reviews WHERE harness_id = ?1",
        )
        .bind(harness_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|value| harness_ai_review_from_row(&value))
            .transpose()
    }

    /// Atomically persist a promoted harness and its digest-bound human approval.
    /// Exact retries return the first approval record.
    ///
    /// # Errors
    /// Returns an error when the harness is not promoted, a digest is malformed,
    /// serialization fails, or the transaction cannot commit.
    pub async fn promote_harness_with_approval(
        &self,
        harness: &Harness,
        approval_kind: HarnessApprovalKind,
        source_sha256: &str,
        binary_sha256: &str,
        approved_at: DateTime<Utc>,
    ) -> Result<HarnessApprovalRecord, StorageError> {
        if harness.status != hf_core::harness::HarnessStatus::Promoted
            || !is_sha256(source_sha256)
            || !is_sha256(binary_sha256)
        {
            return Err(StorageError::InvalidData(
                "harness approval requires promoted status and lowercase SHA-256 digests"
                    .to_owned(),
            ));
        }

        let mut transaction = self.pool.begin().await?;
        let approval_kind_text = enum_str(&approval_kind);
        let existing = sqlx::query(
            "SELECT id, harness_id, source_sha256, binary_sha256, approval_kind, approved_at
             FROM harness_approvals
             WHERE harness_id = ?1 AND source_sha256 = ?2 AND binary_sha256 = ?3
                   AND approval_kind = ?4",
        )
        .bind(harness.id.to_string())
        .bind(source_sha256)
        .bind(binary_sha256)
        .bind(&approval_kind_text)
        .fetch_optional(&mut *transaction)
        .await?;

        let approval = if let Some(row) = existing {
            harness_approval_from_row(&row)?
        } else {
            let approval = HarnessApprovalRecord {
                id: Uuid::new_v4(),
                harness_id: harness.id,
                source_sha256: source_sha256.to_owned(),
                binary_sha256: binary_sha256.to_owned(),
                approval_kind,
                approved_at,
            };
            sqlx::query(
                "INSERT INTO harness_approvals
                    (id, harness_id, source_sha256, binary_sha256, approval_kind, approved_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(approval.id.to_string())
            .bind(approval.harness_id.to_string())
            .bind(&approval.source_sha256)
            .bind(&approval.binary_sha256)
            .bind(&approval_kind_text)
            .bind(approval.approved_at.to_rfc3339())
            .execute(&mut *transaction)
            .await?;
            approval
        };

        let smoke_json = harness
            .smoke_run
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        sqlx::query(
            "INSERT OR REPLACE INTO harnesses
                (id, target_id, engine, source, status, smoke_run_json, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(harness.id.to_string())
        .bind(harness.target_id.to_string())
        .bind(enum_str(&harness.engine))
        .bind(&harness.source)
        .bind(enum_str(&harness.status))
        .bind(smoke_json)
        .bind(serde_json::to_string(harness)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(approval)
    }

    /// Load the exact approval for a harness source/binary revision.
    ///
    /// # Errors
    /// Returns an error on SQL failure or malformed stored evidence.
    pub async fn harness_approval(
        &self,
        harness_id: Uuid,
        source_sha256: &str,
        binary_sha256: &str,
    ) -> Result<Option<HarnessApprovalRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT id, harness_id, source_sha256, binary_sha256, approval_kind, approved_at
             FROM harness_approvals
             WHERE harness_id = ?1 AND source_sha256 = ?2 AND binary_sha256 = ?3
             ORDER BY approved_at DESC, rowid DESC LIMIT 1",
        )
        .bind(harness_id.to_string())
        .bind(source_sha256)
        .bind(binary_sha256)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|value| harness_approval_from_row(&value))
            .transpose()
    }

    // -- crashes ------------------------------------------------------------

    /// Insert or replace a crash record.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or serialization failure.
    pub async fn upsert_crash(&self, c: &Crash) -> Result<(), StorageError> {
        self.upsert_crashes(std::slice::from_ref(c)).await
    }

    /// Insert or replace one triage result as an atomic crash batch.
    ///
    /// A triage pass is one evidence-producing operation. Committing only a
    /// prefix would make retries and reports disagree about the run's result,
    /// so any failed row rolls back the entire batch.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or serialization failure.
    pub async fn upsert_crashes(&self, crashes: &[Crash]) -> Result<(), StorageError> {
        let serialized = crashes
            .iter()
            .map(|crash| {
                let bug_json = crash
                    .bug_report
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?;
                Ok((bug_json, serde_json::to_string(crash)?))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        let mut transaction = self.pool.begin().await?;
        for (crash, (bug_json, data_json)) in crashes.iter().zip(serialized) {
            // ON CONFLICT(id) DO UPDATE (not INSERT OR REPLACE) so re-triaging
            // an existing crash keeps its original rowid; list_all_crashes
            // orders by rowid to mean "first seen", and a delete+reinsert would
            // jump a re-processed old crash to the top of that view.
            sqlx::query(
                "INSERT INTO crashes
                    (id, run_id, target_id, stack_signature, kind, summary, minimized, bug_report_json, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                    run_id = excluded.run_id,
                    target_id = excluded.target_id,
                    stack_signature = excluded.stack_signature,
                    kind = excluded.kind,
                    summary = excluded.summary,
                    minimized = excluded.minimized,
                    bug_report_json = excluded.bug_report_json,
                    data_json = excluded.data_json",
            )
            .bind(crash.id.to_string())
            .bind(crash.run_id.to_string())
            .bind(crash.target_id.to_string())
            .bind(&crash.stack_signature)
            .bind(enum_str(&crash.kind))
            .bind(&crash.summary)
            .bind(i64::from(crash.minimized))
            .bind(bug_json)
            .bind(data_json)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
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

    /// Load a single persisted crash by id, or `None` if it is absent.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn get_crash(&self, crash_id: Uuid) -> Result<Option<Crash>, StorageError> {
        let row = sqlx::query("SELECT data_json FROM crashes WHERE id = ?1")
            .bind(crash_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| json_col(&r, "data_json")).transpose()
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
            "INSERT INTO schedule_executions
                (id, schedule_id, triggered_at, status, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                schedule_id = excluded.schedule_id,
                triggered_at = excluded.triggered_at,
                status = excluded.status,
                data_json = excluded.data_json",
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
                   SELECT execution_id
                   FROM schedule_occurrences
                   WHERE state IN ('reserved', 'running')
               )
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

    /// Delete clearable schedule executions, returning how many were removed.
    ///
    /// Execution history is deliberately decoupled from the schedules themselves
    /// (so a run's outcome survives its schedule being deleted), which means the
    /// failures of a long-gone campaign otherwise sit in the history forever.
    /// This is how an operator clears them. Executions referenced by non-terminal
    /// one-time occurrence receipts remain protected.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn clear_schedule_executions(&self) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM schedule_executions
             WHERE id NOT IN (
                 SELECT execution_id
                 FROM schedule_occurrences
                 WHERE state IN ('reserved', 'running')
             )",
        )
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

const SEMGREP_RUN_SELECT: &str = "SELECT id, project_root, language, source_sha256,
    sandbox_image, sandbox_image_sha256, semgrep_version, rules_commit, rules_tree_sha256,
    command_schema_version, status, started_at, ended_at, output_sha256, finding_count,
    matched_candidate_count, duration_ms, failure_code, failure_message
    FROM semgrep_enrichment_runs WHERE id = ?1";

const SEMGREP_ACTIVE_RUNS_SELECT: &str = "SELECT id, project_root, language, source_sha256,
    sandbox_image, sandbox_image_sha256, semgrep_version, rules_commit, rules_tree_sha256,
    command_schema_version, status, started_at, ended_at, output_sha256, finding_count,
    matched_candidate_count, duration_ms, failure_code, failure_message
    FROM semgrep_enrichment_runs
    WHERE status IN ('staging','scanning','validating','persisting')
    ORDER BY started_at, id";

/// Serialize an enum to its bare serde string name (no surrounding quotes).
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|val| val.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn validate_semgrep_run(run: &SemgrepRunRecord) -> Result<(), StorageError> {
    if run.project_root.trim().is_empty()
        || run.sandbox_image.trim().is_empty()
        || run.semgrep_version.trim().is_empty()
    {
        return Err(StorageError::InvalidData(
            "Semgrep project, image, and version must not be empty".to_owned(),
        ));
    }
    if !matches!(run.language.as_str(), "c" | "cpp") {
        return Err(StorageError::InvalidData(
            "Semgrep language must be c or cpp".to_owned(),
        ));
    }
    if run.command_schema_version != 1 {
        return Err(StorageError::InvalidData(
            "unsupported Semgrep command schema version".to_owned(),
        ));
    }
    require_sha256("sandbox_image_sha256", &run.sandbox_image_sha256)?;
    require_sha256("rules_tree_sha256", &run.rules_tree_sha256)?;
    if run.rules_commit.len() != 40
        || !run
            .rules_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StorageError::InvalidData(
            "rules_commit must be a lowercase 40-character Git hash".to_owned(),
        ));
    }
    for (field, value) in [
        ("source_sha256", run.source_sha256.as_deref()),
        ("output_sha256", run.output_sha256.as_deref()),
    ] {
        if let Some(value) = value {
            require_sha256(field, value)?;
        }
    }
    if run.finding_count.is_some_and(|count| count > 50_000) {
        return Err(StorageError::InvalidData(
            "Semgrep finding count exceeds 50,000".to_owned(),
        ));
    }
    if let (Some(started_at), Some(ended_at)) = (Some(run.started_at), run.ended_at) {
        if ended_at < started_at {
            return Err(StorageError::InvalidData(
                "Semgrep end time precedes start time".to_owned(),
            ));
        }
    }
    if let Some(code) = &run.failure_code {
        validate_failure_piece("failure_code", code, 64)?;
    }
    if let Some(message) = &run.failure_message {
        validate_failure_piece("failure_message", message, 1_024)?;
    }

    match run.status {
        SemgrepRunStatus::Staging => {
            if run.source_sha256.is_some() {
                return Err(StorageError::InvalidData(
                    "staging Semgrep run cannot have a source digest".to_owned(),
                ));
            }
            require_nonterminal_run(run)?;
        }
        SemgrepRunStatus::Scanning
        | SemgrepRunStatus::Validating
        | SemgrepRunStatus::Persisting => {
            if run.source_sha256.is_none() {
                return Err(StorageError::InvalidData(
                    "post-staging Semgrep run requires a source digest".to_owned(),
                ));
            }
            require_nonterminal_run(run)?;
        }
        SemgrepRunStatus::Done => {
            if run.source_sha256.is_none()
                || run.ended_at.is_none()
                || run.output_sha256.is_none()
                || run.finding_count.is_none()
                || run.matched_candidate_count.is_none()
                || run.duration_ms.is_none()
                || run.failure_code.is_some()
                || run.failure_message.is_some()
            {
                return Err(StorageError::InvalidData(
                    "done Semgrep run has incomplete terminal fields".to_owned(),
                ));
            }
        }
        SemgrepRunStatus::Failed | SemgrepRunStatus::Cancelled => {
            if run.ended_at.is_none()
                || run.failure_code.is_none()
                || run.failure_message.is_none()
                || run.output_sha256.is_some()
                || run.finding_count.is_some()
                || run.matched_candidate_count.is_some()
                || run.duration_ms.is_some()
            {
                return Err(StorageError::InvalidData(
                    "failed or cancelled Semgrep run has inconsistent terminal fields".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn require_nonterminal_run(run: &SemgrepRunRecord) -> Result<(), StorageError> {
    if run.ended_at.is_some()
        || run.output_sha256.is_some()
        || run.finding_count.is_some()
        || run.matched_candidate_count.is_some()
        || run.duration_ms.is_some()
        || run.failure_code.is_some()
        || run.failure_message.is_some()
    {
        return Err(StorageError::InvalidData(
            "active Semgrep run has terminal fields".to_owned(),
        ));
    }
    Ok(())
}

fn validate_semgrep_publication(publication: &SemgrepPublication) -> Result<(), StorageError> {
    validate_semgrep_run(&publication.run)?;
    if publication.run.status != SemgrepRunStatus::Done {
        return Err(StorageError::InvalidData(
            "Semgrep publication parent must be done".to_owned(),
        ));
    }
    let finding_count = u32::try_from(publication.findings.len())
        .map_err(|_| StorageError::InvalidData("too many Semgrep findings".to_owned()))?;
    let matched_candidate_count = u32::try_from(
        publication
            .scores
            .iter()
            .filter(|score| score.matched_rule_count > 0)
            .count(),
    )
    .map_err(|_| StorageError::InvalidData("too many Semgrep scores".to_owned()))?;
    if publication.run.finding_count != Some(finding_count)
        || publication.run.matched_candidate_count != Some(matched_candidate_count)
    {
        return Err(StorageError::InvalidData(
            "Semgrep terminal counts do not match publication children".to_owned(),
        ));
    }
    for finding in &publication.findings {
        if finding.scan_id != publication.run.id {
            return Err(StorageError::InvalidData(
                "Semgrep finding belongs to another scan".to_owned(),
            ));
        }
        validate_semgrep_finding(finding)?;
    }
    for score in &publication.scores {
        if score.scan_id != publication.run.id {
            return Err(StorageError::InvalidData(
                "Semgrep score belongs to another scan".to_owned(),
            ));
        }
        validate_semgrep_score(score)?;
    }
    Ok(())
}

fn require_same_semgrep_identity(
    persisted: &SemgrepRunRecord,
    publication: &SemgrepRunRecord,
) -> Result<(), StorageError> {
    if persisted.id != publication.id
        || persisted.project_root != publication.project_root
        || persisted.language != publication.language
        || persisted.source_sha256 != publication.source_sha256
        || persisted.sandbox_image != publication.sandbox_image
        || persisted.sandbox_image_sha256 != publication.sandbox_image_sha256
        || persisted.semgrep_version != publication.semgrep_version
        || persisted.rules_commit != publication.rules_commit
        || persisted.rules_tree_sha256 != publication.rules_tree_sha256
        || persisted.command_schema_version != publication.command_schema_version
        || persisted.started_at != publication.started_at
    {
        return Err(StorageError::InvalidData(
            "Semgrep publication identity differs from its persisted parent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_semgrep_finding(finding: &SemgrepFindingRecord) -> Result<(), StorageError> {
    require_sha256("finding fingerprint", &finding.fingerprint)?;
    if finding.rule_id.is_empty() || finding.rule_id.len() > 512 {
        return Err(StorageError::InvalidData(
            "Semgrep rule id must be 1..=512 bytes".to_owned(),
        ));
    }
    if finding.message.len() > 4_096 {
        return Err(StorageError::InvalidData(
            "Semgrep message exceeds 4,096 bytes".to_owned(),
        ));
    }
    validate_relative_path(&finding.relative_file)?;
    if finding.start_line == 0
        || finding.start_col == 0
        || finding.end_line == 0
        || finding.end_col == 0
        || (finding.end_line, finding.end_col) < (finding.start_line, finding.start_col)
    {
        return Err(StorageError::InvalidData(
            "Semgrep coordinates are invalid".to_owned(),
        ));
    }
    let expected_weight: f64 = match finding.severity {
        SemgrepFindingSeverity::Error => 0.10,
        SemgrepFindingSeverity::Warning => 0.05,
        SemgrepFindingSeverity::Info => 0.01,
    };
    if finding.nominal_weight.to_bits() != expected_weight.to_bits() {
        return Err(StorageError::InvalidData(
            "Semgrep nominal weight does not match severity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_semgrep_score(score: &SemgrepTargetScoreRecord) -> Result<(), StorageError> {
    if !score.base_score.is_finite()
        || !score.boost.is_finite()
        || !score.effective_score.is_finite()
        || !(0.0..=1.0).contains(&score.base_score)
        || !(0.0..=0.20).contains(&score.boost)
        || !(0.0..=1.0).contains(&score.effective_score)
    {
        return Err(StorageError::InvalidData(
            "Semgrep score contains an invalid weight".to_owned(),
        ));
    }
    let boost_units = score.boost / 0.01;
    let rounded_boost_units = boost_units.round();
    let boost_unit_scale = boost_units.abs().max(1.0);
    if (boost_units - rounded_boost_units).abs() > f64::EPSILON * 16.0 * boost_unit_scale {
        return Err(StorageError::InvalidData(
            "Semgrep boost is not a canonical 0.01 increment".to_owned(),
        ));
    }
    let expected_effective = (score.base_score + score.boost).min(1.0);
    let comparison_scale = score
        .effective_score
        .abs()
        .max(expected_effective.abs())
        .max(1.0);
    if (score.effective_score - expected_effective).abs() > f64::EPSILON * 8.0 * comparison_scale {
        return Err(StorageError::InvalidData(
            "Semgrep effective score does not equal the capped base plus boost".to_owned(),
        ));
    }
    let boost_is_zero = score.boost.abs().to_bits() == 0.0_f64.to_bits();
    if (score.matched_rule_count == 0) != boost_is_zero {
        return Err(StorageError::InvalidData(
            "Semgrep boost and matched-rule count are inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), StorageError> {
    let bytes = value.as_bytes();
    let has_drive_prefix = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if value.is_empty()
        || value.len() > 4_096
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains('\0')
        || has_drive_prefix
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(StorageError::InvalidData(
            "Semgrep source path is not normalized and relative".to_owned(),
        ));
    }
    Ok(())
}

fn validate_failure(code: &str, message: &str) -> Result<(), StorageError> {
    validate_failure_piece("failure_code", code, 64)?;
    validate_failure_piece("failure_message", message, 1_024)
}

fn validate_failure_piece(field: &str, value: &str, max_len: usize) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > max_len || value.contains('\0') {
        return Err(StorageError::InvalidData(format!(
            "Semgrep {field} must be 1..={max_len} bytes without NUL"
        )));
    }
    Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<(), StorageError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(StorageError::InvalidData(format!(
            "Semgrep {field} must be a lowercase SHA-256"
        )))
    }
}

fn to_i64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::InvalidData("Semgrep duration exceeds i64".to_owned()))
}

fn semgrep_run_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<SemgrepRunRecord, StorageError> {
    let id = Uuid::parse_str(&row.try_get::<String, _>("id")?)
        .map_err(|error| StorageError::InvalidData(format!("Semgrep run id: {error}")))?;
    let command_schema_version = u32::try_from(row.try_get::<i64, _>("command_schema_version")?)
        .map_err(|_| StorageError::InvalidData("invalid Semgrep schema version".to_owned()))?;
    let finding_count = optional_u32(row, "finding_count")?;
    let matched_candidate_count = optional_u32(row, "matched_candidate_count")?;
    let duration_ms = optional_u64(row, "duration_ms")?;
    let run = SemgrepRunRecord {
        id,
        project_root: row.try_get("project_root")?,
        language: row.try_get("language")?,
        source_sha256: row.try_get("source_sha256")?,
        sandbox_image: row.try_get("sandbox_image")?,
        sandbox_image_sha256: row.try_get("sandbox_image_sha256")?,
        semgrep_version: row.try_get("semgrep_version")?,
        rules_commit: row.try_get("rules_commit")?,
        rules_tree_sha256: row.try_get("rules_tree_sha256")?,
        command_schema_version,
        status: enum_from(&row.try_get::<String, _>("status")?)?,
        started_at: ts(&row.try_get::<String, _>("started_at")?)?,
        ended_at: row
            .try_get::<Option<String>, _>("ended_at")?
            .as_deref()
            .map(ts)
            .transpose()?,
        output_sha256: row.try_get("output_sha256")?,
        finding_count,
        matched_candidate_count,
        duration_ms,
        failure_code: row.try_get("failure_code")?,
        failure_message: row.try_get("failure_message")?,
    };
    validate_semgrep_run(&run)?;
    Ok(run)
}

fn semgrep_finding_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SemgrepFindingRecord, StorageError> {
    let target_id = row
        .try_get::<Option<String>, _>("target_id")?
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|error| StorageError::InvalidData(format!("Semgrep target id: {error}")))
        })
        .transpose()?;
    let finding = SemgrepFindingRecord {
        scan_id: Uuid::parse_str(&row.try_get::<String, _>("scan_id")?)
            .map_err(|error| StorageError::InvalidData(format!("Semgrep scan id: {error}")))?,
        fingerprint: row.try_get("fingerprint")?,
        rule_id: row.try_get("rule_id")?,
        severity: enum_from(&row.try_get::<String, _>("severity")?)?,
        message: row.try_get("message")?,
        relative_file: row.try_get("relative_file")?,
        start_line: positive_u32(row, "start_line")?,
        start_col: positive_u32(row, "start_col")?,
        end_line: positive_u32(row, "end_line")?,
        end_col: positive_u32(row, "end_col")?,
        target_id,
        nominal_weight: row.try_get("nominal_weight")?,
    };
    validate_semgrep_finding(&finding)?;
    Ok(finding)
}

fn semgrep_score_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SemgrepTargetScoreRecord, StorageError> {
    let score = SemgrepTargetScoreRecord {
        scan_id: Uuid::parse_str(&row.try_get::<String, _>("scan_id")?)
            .map_err(|error| StorageError::InvalidData(format!("Semgrep scan id: {error}")))?,
        target_id: Uuid::parse_str(&row.try_get::<String, _>("target_id")?)
            .map_err(|error| StorageError::InvalidData(format!("Semgrep target id: {error}")))?,
        base_score: row.try_get("base_score")?,
        boost: row.try_get("boost")?,
        effective_score: row.try_get("effective_score")?,
        matched_rule_count: u32::try_from(row.try_get::<i64, _>("matched_rule_count")?).map_err(
            |_| StorageError::InvalidData("invalid Semgrep matched-rule count".to_owned()),
        )?,
    };
    validate_semgrep_score(&score)?;
    Ok(score)
}

fn positive_u32(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<u32, StorageError> {
    let value = u32::try_from(row.try_get::<i64, _>(column)?)
        .map_err(|_| StorageError::InvalidData(format!("invalid Semgrep {column}")))?;
    if value == 0 {
        Err(StorageError::InvalidData(format!(
            "invalid Semgrep {column}"
        )))
    } else {
        Ok(value)
    }
}

fn optional_u32(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<u32>, StorageError> {
    row.try_get::<Option<i64>, _>(column)?
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| StorageError::InvalidData(format!("invalid Semgrep {column}")))
        })
        .transpose()
}

fn optional_u64(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<u64>, StorageError> {
    row.try_get::<Option<i64>, _>(column)?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| StorageError::InvalidData(format!("invalid Semgrep {column}")))
        })
        .transpose()
}

async fn terminate_semgrep_run(
    pool: &SqlitePool,
    id: Uuid,
    status: SemgrepRunStatus,
    failure_code: &str,
    failure_message: &str,
    ended_at: DateTime<Utc>,
    require_done: bool,
) -> Result<(), StorageError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query("SELECT status, started_at FROM semgrep_enrichment_runs WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(StorageError::NotFound(format!("Semgrep run {id}")));
    };
    let existing_status: SemgrepRunStatus = enum_from(&row.try_get::<String, _>("status")?)?;
    let allowed = if require_done {
        existing_status == SemgrepRunStatus::Done
    } else {
        matches!(
            existing_status,
            SemgrepRunStatus::Staging
                | SemgrepRunStatus::Scanning
                | SemgrepRunStatus::Validating
                | SemgrepRunStatus::Persisting
        )
    };
    if !allowed {
        return Err(StorageError::NotFound(format!("Semgrep run {id}")));
    }
    let started_at = ts(&row.try_get::<String, _>("started_at")?)?;
    if ended_at < started_at {
        return Err(StorageError::InvalidData(
            "Semgrep end time precedes start time".to_owned(),
        ));
    }
    sqlx::query("DELETE FROM semgrep_findings WHERE scan_id = ?1")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM semgrep_target_scores WHERE scan_id = ?1")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    let result = sqlx::query(
        "UPDATE semgrep_enrichment_runs
         SET status = ?2, ended_at = ?3, output_sha256 = NULL, finding_count = NULL,
             matched_candidate_count = NULL, duration_ms = NULL, failure_code = ?4,
             failure_message = ?5
         WHERE id = ?1 AND status = ?6",
    )
    .bind(id.to_string())
    .bind(enum_str(&status))
    .bind(ended_at.to_rfc3339())
    .bind(failure_code)
    .bind(failure_message)
    .bind(enum_str(&existing_status))
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StorageError::NotFound(format!("Semgrep run {id}")));
    }
    tx.commit().await?;
    Ok(())
}

fn require_one_semgrep_run(
    rows_affected: u64,
    id: Uuid,
    expected: SemgrepRunStatus,
) -> Result<(), StorageError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(StorageError::NotFound(format!(
            "{} Semgrep run {id}",
            enum_str(&expected)
        )))
    }
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

/// Reconstruct a [`GuardrailDecisionRecord`] from a row.
fn guardrail_decision_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<GuardrailDecisionRecord, StorageError> {
    Ok(GuardrailDecisionRecord {
        id: row.try_get("id")?,
        decided_at: ts(&row.try_get::<String, _>("decided_at")?)?,
        action: row.try_get("action")?,
        risk_tier: row.try_get("risk_tier")?,
        decision: row.try_get("decision")?,
        origin: row.try_get("origin")?,
        project: row.try_get("project")?,
        detail: row.try_get("detail")?,
    })
}

fn harness_approval_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<HarnessApprovalRecord, StorageError> {
    Ok(HarnessApprovalRecord {
        id: Uuid::parse_str(&row.try_get::<String, _>("id")?)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        harness_id: Uuid::parse_str(&row.try_get::<String, _>("harness_id")?)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        source_sha256: row.try_get("source_sha256")?,
        binary_sha256: row.try_get("binary_sha256")?,
        approval_kind: enum_from(&row.try_get::<String, _>("approval_kind")?)?,
        approved_at: ts(&row.try_get::<String, _>("approved_at")?)?,
    })
}

fn harness_ai_review_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<HarnessAiReviewRecord, StorageError> {
    let harness_id = Uuid::parse_str(&row.try_get::<String, _>("harness_id")?)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    let source_sha256: String = row.try_get("source_sha256")?;
    let binary_sha256: String = row.try_get("binary_sha256")?;
    let review_json: String = row.try_get("review_json")?;
    if !is_sha256(&source_sha256)
        || !is_sha256(&binary_sha256)
        || !serde_json::from_str::<serde_json::Value>(&review_json)?.is_object()
    {
        return Err(StorageError::InvalidData(
            "stored harness AI review has invalid digest or JSON evidence".to_owned(),
        ));
    }
    Ok(HarnessAiReviewRecord {
        harness_id,
        source_sha256,
        binary_sha256,
        review_json,
        reviewed_at: ts(&row.try_get::<String, _>("reviewed_at")?)?,
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    let source_rev: Option<String> = row.try_get("source_rev")?;
    let corpus_rev: Option<String> = row.try_get("corpus_rev")?;
    let sandbox_rev: Option<String> = row.try_get("sandbox_rev")?;
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
        source_rev,
        corpus_rev,
        sandbox_rev,
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
