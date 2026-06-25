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
        Ok(Self { pool })
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
            "INSERT INTO runs (id, project_root, engine, status, started_at, ended_at, config_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(run.id.to_string())
        .bind(&run.project_root)
        .bind(enum_str(&run.engine))
        .bind(enum_str(&run.status))
        .bind(run.started_at.to_rfc3339())
        .bind(run.ended_at.map(|t| t.to_rfc3339()))
        .bind(config_json)
        .execute(&self.pool)
        .await?;
        Ok(())
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
        sqlx::query(
            "INSERT OR REPLACE INTO targets
                (id, project_root, symbol, language, fit_score, rationale, discovered_at, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(t.id.to_string())
        .bind(t.project_root.to_string_lossy().to_string())
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
        let next_seq: i64 = sqlx::query(
            "SELECT COALESCE(MAX(seq), -1) + 1 AS next FROM messages WHERE session_id = ?1",
        )
        .bind(session.to_string())
        .fetch_one(&self.pool)
        .await?
        .try_get("next")?;
        sqlx::query(
            "INSERT INTO messages (id, session_id, seq, role, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(session.to_string())
        .bind(next_seq)
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
    Ok(RunRecord {
        id: Uuid::parse_str(&id_str)
            .map_err(|e| StorageError::Timestamp(format!("bad uuid: {e}")))?,
        project_root: row.try_get("project_root")?,
        engine: enum_from(&engine_str)?,
        status: enum_from(&status_str)?,
        started_at: ts(&started_at)?,
        ended_at: ended_at.as_deref().map(ts).transpose()?,
        config,
    })
}

/// Decode a bare enum string name back into the enum.
fn enum_from<T: DeserializeOwned>(s: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}
