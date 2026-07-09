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
            started_at: now,
            ended_at: None,
            config,
            edges: None,
            execs: None,
            crash_count: None,
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
            "INSERT INTO runs (id, project_root, engine, status, started_at, ended_at, config_json, edges, execs, crash_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
        .execute(&self.pool)
        .await?;
        Ok(())
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
        sqlx::query("UPDATE runs SET edges = ?2, execs = ?3, crash_count = ?4 WHERE id = ?1")
            .bind(id.to_string())
            .bind(i64::try_from(edges).unwrap_or(i64::MAX))
            .bind(execs)
            .bind(i64::try_from(crashes).unwrap_or(i64::MAX))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store a run's intra-run coverage/throughput time series as a JSON blob.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn set_run_samples(&self, id: Uuid, samples_json: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE runs SET samples_json = ?2 WHERE id = ?1")
            .bind(id.to_string())
            .bind(samples_json)
            .execute(&self.pool)
            .await?;
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
        sqlx::query("UPDATE runs SET status = ?2, ended_at = ?3 WHERE id = ?1")
            .bind(id.to_string())
            .bind(enum_str(&status))
            .bind(ended_at.map(|t| t.to_rfc3339()))
            .execute(&self.pool)
            .await?;
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
        // Identity is (project, symbol), not the row id: the scanner assigns a
        // fresh UUID to a candidate on every discovery pass, so keying only on
        // id would let the same symbol accumulate duplicate rows. Drop any prior
        // row for this symbol before inserting the latest.
        sqlx::query("DELETE FROM targets WHERE project_root = ?1 AND symbol = ?2")
            .bind(&project)
            .bind(&t.symbol)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT OR REPLACE INTO targets
                (id, project_root, symbol, language, fit_score, rationale, discovered_at, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(t.id.to_string())
        .bind(&project)
        .bind(&t.symbol)
        .bind(enum_str(&t.language))
        .bind(t.fit_score)
        .bind(&t.rationale)
        .bind(discovered_at.to_rfc3339())
        .bind(serde_json::to_string(t)?)
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
        for table in ["crashes", "corpus_entries", "harnesses", "runs", "targets"] {
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

    /// List every persisted crash across all runs, newest-first by id order.
    ///
    /// # Errors
    /// Returns an error on a SQL failure or malformed stored data.
    pub async fn list_all_crashes(&self) -> Result<Vec<Crash>, StorageError> {
        let rows = sqlx::query("SELECT data_json FROM crashes")
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

    /// The most recent persisted executions (their `data_json`), newest first.
    ///
    /// # Errors
    /// Returns an error on a SQL failure.
    pub async fn list_schedule_executions(&self, limit: i64) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query(
            "SELECT data_json FROM schedule_executions ORDER BY triggered_at DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| r.get::<String, _>("data_json"))
            .collect())
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
    Ok(RunRecord {
        id: Uuid::parse_str(&id_str)
            .map_err(|e| StorageError::Timestamp(format!("bad uuid: {e}")))?,
        project_root: row.try_get("project_root")?,
        engine: enum_from(&engine_str)?,
        status: enum_from(&status_str)?,
        started_at: ts(&started_at)?,
        ended_at: ended_at.as_deref().map(ts).transpose()?,
        config,
        edges: edges.map(|e| u64::try_from(e).unwrap_or(0)),
        execs,
        crash_count: crash_count.map(|c| u64::try_from(c).unwrap_or(0)),
    })
}

/// Decode a bare enum string name back into the enum.
fn enum_from<T: DeserializeOwned>(s: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}
