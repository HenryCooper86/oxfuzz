// SQLite-backed TraceStore implementation for persistent diagnostics storage.
//
// Stores trace and observation records in the shared SQLite database so that
// diagnostic data survives application restarts. The schema is created by
// `hf-storage` forward migrations before this store is constructed.
//
// All queries use `sqlx::query_as` / `sqlx::query` (no compile-time
// verification) to avoid requiring DATABASE_URL during builds.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::trace_store::{TraceStore, TraceStoreError};
use crate::types::{
    Observation, ObservationStatus, ObservationType, Score, ScoreSource, ScoreValue, Trace,
    TraceStatus,
};

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

fn storage_err(msg: impl Into<String>) -> TraceStoreError {
    TraceStoreError::Storage {
        message: msg.into(),
    }
}

fn required_column<T>(value: Option<T>, column: &str) -> Result<T, TraceStoreError> {
    value.ok_or_else(|| storage_err(format!("decode {column}: unexpected NULL")))
}

fn decode_json<T: serde::de::DeserializeOwned>(
    value: Option<&str>,
    column: &str,
) -> Result<T, TraceStoreError> {
    serde_json::from_str(required_column(value, column)?)
        .map_err(|error| storage_err(format!("decode {column}: {error}")))
}

fn decode_optional_uuid(
    value: Option<&str>,
    column: &str,
) -> Result<Option<Uuid>, TraceStoreError> {
    value
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|error| storage_err(format!("decode {column}: {error}")))
}

fn decode_counter<T: TryFrom<i64>>(value: Option<i64>, column: &str) -> Result<T, TraceStoreError> {
    T::try_from(required_column(value, column)?)
        .map_err(|_| storage_err(format!("decode {column}: counter out of range")))
}

fn encode_counter(value: u64, column: &str) -> Result<i64, TraceStoreError> {
    i64::try_from(value).map_err(|_| {
        storage_err(format!(
            "encode {column}: counter exceeds SQLite integer range"
        ))
    })
}

fn finite_number(value: Option<f64>, column: &str) -> Result<f64, TraceStoreError> {
    let value = required_column(value, column)?;
    if !value.is_finite() {
        return Err(storage_err(format!("{column}: non-finite number")));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Enum <-> &str helpers
// ---------------------------------------------------------------------------

fn trace_status_to_str(s: TraceStatus) -> &'static str {
    match s {
        TraceStatus::Active => "active",
        TraceStatus::Completed => "completed",
        TraceStatus::Failed => "failed",
        TraceStatus::Cancelled => "cancelled",
    }
}

fn str_to_trace_status(s: &str) -> Result<TraceStatus, TraceStoreError> {
    Ok(match s {
        "active" => TraceStatus::Active,
        "completed" => TraceStatus::Completed,
        "failed" => TraceStatus::Failed,
        "cancelled" => TraceStatus::Cancelled,
        _ => return Err(storage_err("decode diag_traces.status: unknown status")),
    })
}

fn obs_type_to_str(t: ObservationType) -> &'static str {
    match t {
        ObservationType::Generation => "generation",
        ObservationType::ToolCall => "tool_call",
        ObservationType::Span => "span",
        ObservationType::UserInput => "user_input",
        ObservationType::McpCall => "mcp_call",
        ObservationType::Retrieval => "retrieval",
        ObservationType::Embedding => "embedding",
        ObservationType::Reranking => "reranking",
        ObservationType::SubAgent => "sub_agent",
        ObservationType::Planning => "planning",
        ObservationType::Reflection => "reflection",
        ObservationType::Guardrail => "guardrail",
        ObservationType::Hook => "hook",
        ObservationType::Cache => "cache",
    }
}

fn str_to_obs_type(s: &str) -> Result<ObservationType, TraceStoreError> {
    Ok(match s {
        "generation" => ObservationType::Generation,
        "tool_call" => ObservationType::ToolCall,
        "span" => ObservationType::Span,
        "user_input" => ObservationType::UserInput,
        "mcp_call" => ObservationType::McpCall,
        "retrieval" => ObservationType::Retrieval,
        "embedding" => ObservationType::Embedding,
        "reranking" => ObservationType::Reranking,
        "sub_agent" => ObservationType::SubAgent,
        "planning" => ObservationType::Planning,
        "reflection" => ObservationType::Reflection,
        "guardrail" => ObservationType::Guardrail,
        "hook" => ObservationType::Hook,
        "cache" => ObservationType::Cache,
        _ => {
            return Err(storage_err(
                "decode diag_observations.obs_type: unknown type",
            ))
        }
    })
}

fn obs_status_to_str(s: ObservationStatus) -> &'static str {
    match s {
        ObservationStatus::Running => "running",
        ObservationStatus::Completed => "completed",
        ObservationStatus::Failed => "failed",
    }
}

fn str_to_obs_status(s: &str) -> Result<ObservationStatus, TraceStoreError> {
    Ok(match s {
        "running" => ObservationStatus::Running,
        "completed" => ObservationStatus::Completed,
        "failed" => ObservationStatus::Failed,
        _ => {
            return Err(storage_err(
                "decode diag_observations.status: unknown status",
            ))
        }
    })
}

// ---------------------------------------------------------------------------
// Row types for sqlx::FromRow
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct TraceRow {
    id: String,
    session_id: String,
    name: String,
    status: Option<String>,
    user_input: Option<String>,
    metadata: Option<String>,
    started_at: String,
    completed_at: Option<String>,
    total_input_tokens: Option<i64>,
    total_output_tokens: Option<i64>,
    total_cost_usd: Option<f64>,
    llm_duration_ms: Option<i64>,
    tool_duration_ms: Option<i64>,
    tags: Option<String>,
    replay_context: Option<String>,
}

impl TraceRow {
    /// Decode a persisted row. Malformed ids/timestamps are hard errors: a
    /// corrupt row must fail the read, never be silently dropped from the
    /// result set (`DATABASE_SCHEMA.md` §7).
    fn into_trace(self) -> Result<Trace, TraceStoreError> {
        let id = Uuid::parse_str(&self.id)
            .map_err(|e| storage_err(format!("decode diag_traces.id {:?}: {e}", self.id)))?;
        let session_id = Uuid::parse_str(&self.session_id).map_err(|e| {
            storage_err(format!(
                "decode diag_traces.session_id {:?}: {e}",
                self.session_id
            ))
        })?;
        let started_at: DateTime<Utc> = self.started_at.parse().map_err(|e| {
            storage_err(format!(
                "decode diag_traces.started_at {:?}: {e}",
                self.started_at
            ))
        })?;
        // A genuine NULL stays None, but a present-but-corrupt timestamp is a hard
        // error (matches `started_at`): silently dropping it would yield a
        // "completed" trace with no completion time and a None duration.
        let completed_at: Option<DateTime<Utc>> = self
            .completed_at
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| {
                storage_err(format!(
                    "decode diag_traces.completed_at {:?}: {e}",
                    self.completed_at
                ))
            })?;
        let metadata = decode_json(self.metadata.as_deref(), "diag_traces.metadata")?;
        let status = str_to_trace_status(required_column(
            self.status.as_deref(),
            "diag_traces.status",
        )?)?;
        let tags = decode_json(self.tags.as_deref(), "diag_traces.tags")?;
        let replay_context: Option<serde_json::Value> = self
            .replay_context
            .as_deref()
            .map(|value| decode_json(Some(value), "diag_traces.replay_context"))
            .transpose()?;
        Ok(Trace {
            id,
            session_id,
            name: self.name,
            metadata,
            tags,
            status,
            started_at,
            completed_at,
            total_input_tokens: decode_counter(
                self.total_input_tokens,
                "diag_traces.total_input_tokens",
            )?,
            total_output_tokens: decode_counter(
                self.total_output_tokens,
                "diag_traces.total_output_tokens",
            )?,
            total_cost_usd: finite_number(self.total_cost_usd, "diag_traces.total_cost_usd")?,
            user_input: self.user_input,
            total_duration_ms: completed_at.map(|end| {
                u64::try_from((end - started_at).num_milliseconds().max(0)).unwrap_or(0)
            }),
            llm_duration_ms: decode_counter(self.llm_duration_ms, "diag_traces.llm_duration_ms")?,
            tool_duration_ms: decode_counter(
                self.tool_duration_ms,
                "diag_traces.tool_duration_ms",
            )?,
            replay_context,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ObsRow {
    id: String,
    trace_id: String,
    parent_id: Option<String>,
    session_id: Option<String>,
    obs_type: Option<String>,
    name: String,
    status: Option<String>,
    model: Option<String>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cost_usd: Option<f64>,
    input: Option<String>,
    output: Option<String>,
    metadata: Option<String>,
    sequence: Option<i64>,
    started_at: String,
    completed_at: Option<String>,
    depth: Option<i64>,
    path: Option<String>,
    error_message: Option<String>,
}

impl ObsRow {
    /// Decode a persisted row. Malformed ids/timestamps are hard errors: a
    /// corrupt row must fail the read, never be silently dropped from the
    /// result set (`DATABASE_SCHEMA.md` §7).
    fn into_observation(self) -> Result<Observation, TraceStoreError> {
        let id = Uuid::parse_str(&self.id)
            .map_err(|e| storage_err(format!("decode diag_observations.id {:?}: {e}", self.id)))?;
        let trace_id = Uuid::parse_str(&self.trace_id).map_err(|e| {
            storage_err(format!(
                "decode diag_observations.trace_id {:?}: {e}",
                self.trace_id
            ))
        })?;
        let started_at: DateTime<Utc> = self.started_at.parse().map_err(|e| {
            storage_err(format!(
                "decode diag_observations.started_at {:?}: {e}",
                self.started_at
            ))
        })?;
        // Present-but-corrupt timestamp is a hard error (matches `started_at`); a
        // silently-dropped `completed_at` yields a None `duration_ms()` that
        // undercounts LLM-wait accounting instead of failing the read.
        let completed_at: Option<DateTime<Utc>> = self
            .completed_at
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| {
                storage_err(format!(
                    "decode diag_observations.completed_at {:?}: {e}",
                    self.completed_at
                ))
            })?;
        let input = decode_json(self.input.as_deref(), "diag_observations.input")?;
        let output = decode_json(self.output.as_deref(), "diag_observations.output")?;
        let metadata = decode_json(self.metadata.as_deref(), "diag_observations.metadata")?;
        let path = decode_json(self.path.as_deref(), "diag_observations.path")?;
        Ok(Observation {
            id,
            trace_id,
            parent_id: decode_optional_uuid(
                self.parent_id.as_deref(),
                "diag_observations.parent_id",
            )?,
            session_id: decode_optional_uuid(
                self.session_id.as_deref(),
                "diag_observations.session_id",
            )?,
            obs_type: str_to_obs_type(required_column(
                self.obs_type.as_deref(),
                "diag_observations.obs_type",
            )?)?,
            name: self.name,
            input,
            output,
            model: self.model,
            input_tokens: decode_counter(self.input_tokens, "diag_observations.input_tokens")?,
            output_tokens: decode_counter(self.output_tokens, "diag_observations.output_tokens")?,
            cost_usd: finite_number(self.cost_usd, "diag_observations.cost_usd")?,
            status: str_to_obs_status(required_column(
                self.status.as_deref(),
                "diag_observations.status",
            )?)?,
            started_at,
            completed_at,
            metadata,
            sequence: decode_counter(self.sequence, "diag_observations.sequence")?,
            depth: decode_counter(self.depth, "diag_observations.depth")?,
            path,
            error_message: self.error_message,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ScoreRow {
    id: String,
    trace_id: String,
    observation_id: Option<String>,
    name: String,
    value: Option<f64>,
    data_type: Option<String>,
    string_value: Option<String>,
    comment: Option<String>,
    source: Option<String>,
    created_at: String,
}

impl ScoreRow {
    /// Decode a persisted row. Malformed ids/timestamps are hard errors: a
    /// corrupt row must fail the read, never be silently dropped from the
    /// result set (`DATABASE_SCHEMA.md` §7).
    fn into_score(self) -> Result<Score, TraceStoreError> {
        let id = Uuid::parse_str(&self.id)
            .map_err(|e| storage_err(format!("decode diag_scores.id {:?}: {e}", self.id)))?;
        let trace_id = Uuid::parse_str(&self.trace_id).map_err(|e| {
            storage_err(format!(
                "decode diag_scores.trace_id {:?}: {e}",
                self.trace_id
            ))
        })?;
        let observation_id =
            decode_optional_uuid(self.observation_id.as_deref(), "diag_scores.observation_id")?;
        let created_at: DateTime<Utc> = self.created_at.parse().map_err(|e| {
            storage_err(format!(
                "decode diag_scores.created_at {:?}: {e}",
                self.created_at
            ))
        })?;
        let data_type = required_column(self.data_type.as_deref(), "diag_scores.data_type")?;
        let value = match data_type {
            "boolean" => {
                let value = finite_number(self.value, "diag_scores.value")?;
                let boolean = if value == 0.0 {
                    false
                } else if value.to_bits() == 1.0_f64.to_bits() {
                    true
                } else {
                    return Err(storage_err("decode diag_scores.value: invalid boolean"));
                };
                ScoreValue::Boolean(boolean)
            }
            "categorical" => ScoreValue::Categorical(required_column(
                self.string_value,
                "diag_scores.string_value",
            )?),
            "numeric" => ScoreValue::Numeric(finite_number(self.value, "diag_scores.value")?),
            _ => return Err(storage_err("decode diag_scores.data_type: unknown type")),
        };
        let source = match self.source.as_deref() {
            Some("llm") => ScoreSource::Llm,
            Some("human") => ScoreSource::Human,
            Some("user_feedback") => ScoreSource::UserFeedback,
            Some("external") => ScoreSource::External,
            Some("system") => ScoreSource::System,
            _ => return Err(storage_err("decode diag_scores.source: unknown source")),
        };
        Ok(Score {
            id,
            trace_id,
            observation_id,
            name: self.name,
            value,
            source,
            comment: self.comment,
            created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// SqliteTraceStore
// ---------------------------------------------------------------------------

/// SQLite-backed trace store for persistent diagnostics.
///
/// Data is stored in `diag_traces` and `diag_observations` tables created
/// by migration `011_diagnostics`.
#[derive(Debug, Clone)]
pub struct SqliteTraceStore {
    pool: SqlitePool,
}

impl SqliteTraceStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TraceStore for SqliteTraceStore {
    async fn insert_trace(&self, trace: Trace) -> Result<(), TraceStoreError> {
        let id = trace.id.to_string();
        let session_id = trace.session_id.to_string();
        let status = trace_status_to_str(trace.status);
        let metadata = serde_json::to_string(&trace.metadata).unwrap_or_else(|_| "null".into());
        let started_at = trace.started_at.to_rfc3339();
        let completed_at = trace.completed_at.map(|t| t.to_rfc3339());
        let input_toks =
            encode_counter(trace.total_input_tokens, "diag_traces.total_input_tokens")?;
        let output_toks =
            encode_counter(trace.total_output_tokens, "diag_traces.total_output_tokens")?;
        let llm_ms = encode_counter(trace.llm_duration_ms, "diag_traces.llm_duration_ms")?;
        let tool_ms = encode_counter(trace.tool_duration_ms, "diag_traces.tool_duration_ms")?;

        let tags = serde_json::to_string(&trace.tags).unwrap_or_else(|_| "[]".into());
        let replay_context = trace
            .replay_context
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok());

        sqlx::query(
            "INSERT INTO diag_traces \
             (id, session_id, name, status, user_input, metadata, started_at, completed_at, \
              total_input_tokens, total_output_tokens, total_cost_usd, llm_duration_ms, tool_duration_ms, \
              tags, replay_context) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&id)
        .bind(&session_id)
        .bind(&trace.name)
        .bind(status)
        .bind(&trace.user_input)
        .bind(&metadata)
        .bind(&started_at)
        .bind(&completed_at)
        .bind(input_toks)
        .bind(output_toks)
        .bind(finite_number(Some(trace.total_cost_usd), "diag_traces.total_cost_usd")?)
        .bind(llm_ms)
        .bind(tool_ms)
        .bind(&tags)
        .bind(&replay_context)
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(format!("insert_trace: {e}")))?;
        Ok(())
    }

    async fn get_trace(&self, id: Uuid) -> Result<Trace, TraceStoreError> {
        let id_str = id.to_string();
        let row: Option<TraceRow> = sqlx::query_as(
            "SELECT id, session_id, name, status, user_input, metadata, started_at, completed_at, \
             total_input_tokens, total_output_tokens, total_cost_usd, llm_duration_ms, tool_duration_ms, \
             tags, replay_context \
             FROM diag_traces WHERE id = ?1",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| storage_err(format!("get_trace: {e}")))?;

        match row {
            Some(row) => row.into_trace(),
            None => Err(TraceStoreError::TraceNotFound { id }),
        }
    }

    async fn update_trace(&self, trace: Trace) -> Result<(), TraceStoreError> {
        let id = trace.id.to_string();
        let status = trace_status_to_str(trace.status);
        let metadata = serde_json::to_string(&trace.metadata).unwrap_or_else(|_| "null".into());
        let completed_at = trace.completed_at.map(|t| t.to_rfc3339());
        let input_toks =
            encode_counter(trace.total_input_tokens, "diag_traces.total_input_tokens")?;
        let output_toks =
            encode_counter(trace.total_output_tokens, "diag_traces.total_output_tokens")?;
        let llm_ms = encode_counter(trace.llm_duration_ms, "diag_traces.llm_duration_ms")?;
        let tool_ms = encode_counter(trace.tool_duration_ms, "diag_traces.tool_duration_ms")?;

        let tags = serde_json::to_string(&trace.tags).unwrap_or_else(|_| "[]".into());
        let replay_context = trace
            .replay_context
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok());

        let rows = sqlx::query(
            "UPDATE diag_traces SET \
             status = ?1, metadata = ?2, completed_at = ?3, \
             total_input_tokens = ?4, total_output_tokens = ?5, total_cost_usd = ?6, \
             llm_duration_ms = ?7, tool_duration_ms = ?8, tags = ?9, replay_context = ?10 \
             WHERE id = ?11",
        )
        .bind(status)
        .bind(&metadata)
        .bind(&completed_at)
        .bind(input_toks)
        .bind(output_toks)
        .bind(finite_number(
            Some(trace.total_cost_usd),
            "diag_traces.total_cost_usd",
        )?)
        .bind(llm_ms)
        .bind(tool_ms)
        .bind(&tags)
        .bind(&replay_context)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(format!("update_trace: {e}")))?
        .rows_affected();

        if rows == 0 {
            return Err(TraceStoreError::TraceNotFound { id: trace.id });
        }
        Ok(())
    }

    async fn list_traces(
        &self,
        status: Option<TraceStatus>,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<Trace>, TraceStoreError> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let status_str = status.map(trace_status_to_str);
        let since_str = since.map(|s| s.to_rfc3339());

        let rows: Vec<TraceRow> = sqlx::query_as(
            "SELECT id, session_id, name, status, user_input, metadata, started_at, completed_at, \
             total_input_tokens, total_output_tokens, total_cost_usd, llm_duration_ms, tool_duration_ms, \
             tags, replay_context \
             FROM diag_traces \
             WHERE (?1 IS NULL OR status = ?1) \
               AND (?2 IS NULL OR started_at >= ?2) \
             ORDER BY started_at DESC LIMIT ?3",
        )
        .bind(status_str)
        .bind(&since_str)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| storage_err(format!("list_traces: {e}")))?;

        rows.into_iter().map(TraceRow::into_trace).collect()
    }

    async fn insert_observation(&self, obs: Observation) -> Result<(), TraceStoreError> {
        let id = obs.id.to_string();
        let trace_id = obs.trace_id.to_string();
        let parent_id = obs.parent_id.map(|u| u.to_string());
        let session_id = obs.session_id.map(|u| u.to_string());
        let obs_type = obs_type_to_str(obs.obs_type);
        let status = obs_status_to_str(obs.status);
        let input = serde_json::to_string(&obs.input).unwrap_or_else(|_| "null".into());
        let output = serde_json::to_string(&obs.output).unwrap_or_else(|_| "null".into());
        let metadata = serde_json::to_string(&obs.metadata).unwrap_or_else(|_| "null".into());
        let started_at = obs.started_at.to_rfc3339();
        let completed_at = obs.completed_at.map(|t| t.to_rfc3339());
        let input_toks = encode_counter(obs.input_tokens, "diag_observations.input_tokens")?;
        let output_toks = encode_counter(obs.output_tokens, "diag_observations.output_tokens")?;
        let seq = i64::from(obs.sequence);

        let depth = i64::from(obs.depth);
        let path_json: String =
            serde_json::to_string(&obs.path.iter().map(Uuid::to_string).collect::<Vec<_>>())
                .unwrap_or_else(|_| "[]".into());

        sqlx::query(
            "INSERT INTO diag_observations \
             (id, trace_id, parent_id, session_id, obs_type, name, status, model, \
              input_tokens, output_tokens, cost_usd, input, output, metadata, \
              sequence, started_at, completed_at, depth, path, error_message) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20) \
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&id)
        .bind(&trace_id)
        .bind(&parent_id)
        .bind(&session_id)
        .bind(obs_type)
        .bind(&obs.name)
        .bind(status)
        .bind(&obs.model)
        .bind(input_toks)
        .bind(output_toks)
        .bind(finite_number(Some(obs.cost_usd), "diag_observations.cost_usd")?)
        .bind(&input)
        .bind(&output)
        .bind(&metadata)
        .bind(seq)
        .bind(&started_at)
        .bind(&completed_at)
        .bind(depth)
        .bind(&path_json)
        .bind(&obs.error_message)
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(format!("insert_observation: {e}")))?;
        Ok(())
    }

    async fn update_observation(&self, obs: Observation) -> Result<(), TraceStoreError> {
        let id = obs.id.to_string();
        let status = obs_status_to_str(obs.status);
        let output = serde_json::to_string(&obs.output).unwrap_or_else(|_| "null".into());
        let metadata = serde_json::to_string(&obs.metadata).unwrap_or_else(|_| "null".into());
        let completed_at = obs.completed_at.map(|t| t.to_rfc3339());
        let input_toks = encode_counter(obs.input_tokens, "diag_observations.input_tokens")?;
        let output_toks = encode_counter(obs.output_tokens, "diag_observations.output_tokens")?;

        let rows = sqlx::query(
            "UPDATE diag_observations SET \
             status = ?1, output = ?2, metadata = ?3, completed_at = ?4, \
             input_tokens = ?5, output_tokens = ?6, cost_usd = ?7, \
             error_message = ?8, model = ?9 \
             WHERE id = ?10",
        )
        .bind(status)
        .bind(&output)
        .bind(&metadata)
        .bind(&completed_at)
        .bind(input_toks)
        .bind(output_toks)
        .bind(finite_number(
            Some(obs.cost_usd),
            "diag_observations.cost_usd",
        )?)
        .bind(&obs.error_message)
        .bind(&obs.model)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(format!("update_observation: {e}")))?
        .rows_affected();

        if rows == 0 {
            return Err(TraceStoreError::ObservationNotFound { id: obs.id });
        }
        Ok(())
    }

    async fn get_observations(&self, trace_id: Uuid) -> Result<Vec<Observation>, TraceStoreError> {
        let trace_id_str = trace_id.to_string();
        let rows: Vec<ObsRow> = sqlx::query_as(
            "SELECT id, trace_id, parent_id, session_id, obs_type, name, status, model, \
             input_tokens, output_tokens, cost_usd, input, output, metadata, sequence, \
             started_at, completed_at, depth, path, error_message \
             FROM diag_observations WHERE trace_id = ?1 ORDER BY sequence ASC",
        )
        .bind(&trace_id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| storage_err(format!("get_observations: {e}")))?;

        rows.into_iter().map(ObsRow::into_observation).collect()
    }

    async fn insert_score(&self, score: Score) -> Result<(), TraceStoreError> {
        let id = score.id.to_string();
        let trace_id = score.trace_id.to_string();
        let observation_id = score.observation_id.map(|u| u.to_string());
        let created_at = score.created_at.to_rfc3339();

        // Decompose ScoreValue enum into flat DB columns.
        let (value_f64, data_type, string_value): (f64, &str, Option<String>) = match &score.value {
            ScoreValue::Numeric(v) => (
                finite_number(Some(*v), "diag_scores.value")?,
                "numeric",
                None,
            ),
            ScoreValue::Boolean(b) => (if *b { 1.0 } else { 0.0 }, "boolean", None),
            ScoreValue::Categorical(s) => (0.0, "categorical", Some(s.clone())),
        };

        let source_str = match score.source {
            ScoreSource::System => "system",
            ScoreSource::Llm => "llm",
            ScoreSource::Human => "human",
            ScoreSource::UserFeedback => "user_feedback",
            ScoreSource::External => "external",
        };

        sqlx::query(
            "INSERT INTO diag_scores \
             (id, trace_id, observation_id, name, value, data_type, string_value, \
              comment, source, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&id)
        .bind(&trace_id)
        .bind(&observation_id)
        .bind(&score.name)
        .bind(value_f64)
        .bind(data_type)
        .bind(&string_value)
        .bind(&score.comment)
        .bind(source_str)
        .bind(&created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(format!("insert_score: {e}")))?;
        Ok(())
    }

    async fn get_scores(&self, trace_id: Uuid) -> Result<Vec<Score>, TraceStoreError> {
        let trace_id_str = trace_id.to_string();
        let rows: Vec<ScoreRow> = sqlx::query_as(
            "SELECT id, trace_id, observation_id, name, value, data_type, string_value, \
             comment, source, created_at \
             FROM diag_scores WHERE trace_id = ?1 ORDER BY created_at ASC",
        )
        .bind(&trace_id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| storage_err(format!("get_scores: {e}")))?;

        rows.into_iter().map(ScoreRow::into_score).collect()
    }

    async fn delete_before(&self, before: DateTime<Utc>) -> Result<u64, TraceStoreError> {
        let before_str = before.to_rfc3339();
        let n = sqlx::query("DELETE FROM diag_traces WHERE started_at < ?1")
            .bind(&before_str)
            .execute(&self.pool)
            .await
            .map_err(|e| storage_err(format!("delete_before: {e}")))?
            .rows_affected();
        Ok(n)
    }

    async fn delete_traces_by_session(&self, session_id: &str) -> Result<u64, TraceStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| storage_err(format!("delete_traces_by_session begin: {e}")))?;

        sqlx::query(
            "DELETE FROM diag_scores \
             WHERE trace_id IN (SELECT id FROM diag_traces WHERE session_id = ?1)",
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| storage_err(format!("delete_traces_by_session scores: {e}")))?;

        sqlx::query(
            "DELETE FROM diag_observations \
             WHERE trace_id IN (SELECT id FROM diag_traces WHERE session_id = ?1)",
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| storage_err(format!("delete_traces_by_session observations: {e}")))?;

        let n = sqlx::query("DELETE FROM diag_traces WHERE session_id = ?1")
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_err(format!("delete_traces_by_session traces: {e}")))?
            .rows_affected();

        tx.commit()
            .await
            .map_err(|e| storage_err(format!("delete_traces_by_session commit: {e}")))?;

        Ok(n)
    }

    async fn delete_all_traces(&self) -> Result<u64, TraceStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| storage_err(format!("delete_all_traces begin: {e}")))?;

        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM diag_traces")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| storage_err(format!("delete_all_traces count: {e}")))?;

        sqlx::query("DELETE FROM diag_scores")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_err(format!("delete_all_traces scores: {e}")))?;
        sqlx::query("DELETE FROM diag_observations")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_err(format!("delete_all_traces observations: {e}")))?;
        sqlx::query("DELETE FROM diag_traces")
            .execute(&mut *tx)
            .await
            .map_err(|e| storage_err(format!("delete_all_traces traces: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| storage_err(format!("delete_all_traces commit: {e}")))?;

        Ok(u64::try_from(count).unwrap_or(0))
    }

    async fn list_traces_by_session(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<Trace>, TraceStoreError> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows: Vec<TraceRow> = sqlx::query_as(
            "SELECT id, session_id, name, status, user_input, metadata, started_at, completed_at, \
             total_input_tokens, total_output_tokens, total_cost_usd, llm_duration_ms, tool_duration_ms, \
             tags, replay_context \
             FROM diag_traces WHERE session_id = ?1 ORDER BY started_at DESC LIMIT ?2",
        )
        .bind(session_id)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| storage_err(format!("list_traces_by_session: {e}")))?;

        rows.into_iter().map(TraceRow::into_trace).collect()
    }

    async fn get_observations_by_trace_ids(
        &self,
        trace_ids: &[Uuid],
    ) -> Result<Vec<Observation>, TraceStoreError> {
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Build a single query with IN (...) placeholders.
        let placeholders: Vec<String> = (1..=trace_ids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT id, trace_id, parent_id, session_id, obs_type, name, status, model, \
             input_tokens, output_tokens, cost_usd, input, output, metadata, sequence, \
             started_at, completed_at, depth, path, error_message \
             FROM diag_observations WHERE trace_id IN ({}) ORDER BY sequence ASC",
            placeholders.join(", ")
        );

        let mut query = sqlx::query_as::<_, ObsRow>(&sql);
        for id in trace_ids {
            query = query.bind(id.to_string());
        }

        let rows: Vec<ObsRow> = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| storage_err(format!("get_observations_by_trace_ids: {e}")))?;

        rows.into_iter().map(ObsRow::into_observation).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScoreSource;

    /// Build a `SqliteTraceStore` over a real (tempfile-backed) database with
    /// the migrated `diag_*` schema. The `TempDir` must stay alive for the
    /// duration of the test.
    async fn test_store() -> (hf_storage::Store, SqliteTraceStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        // Store::connect runs the forward migrations (0003_diagnostics).
        let store = hf_storage::Store::connect(dir.path().join("hf.db"))
            .await
            .expect("connect");
        let traces = SqliteTraceStore::new(store.pool().clone());
        (store, traces, dir)
    }

    #[tokio::test]
    async fn corrupt_trace_payloads_fail_instead_of_becoming_empty_defaults() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "durable trace");
        traces.insert_trace(trace.clone()).await.unwrap();
        for (column, value) in [
            ("metadata", "{"),
            ("tags", "[42]"),
            ("replay_context", "{"),
            ("status", "unrecognized"),
        ] {
            let original: Option<String> =
                sqlx::query_scalar(&format!("SELECT {column} FROM diag_traces WHERE id = ?"))
                    .bind(trace.id.to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            sqlx::query(&format!("UPDATE diag_traces SET {column} = ? WHERE id = ?"))
                .bind(value)
                .bind(trace.id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
            let result = traces.get_trace(trace.id).await;
            assert!(result.is_err(), "{column}: {result:?}");
            sqlx::query(&format!("UPDATE diag_traces SET {column} = ? WHERE id = ?"))
                .bind(original)
                .bind(trace.id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn corrupt_observation_payloads_and_links_fail_the_read() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "durable trace");
        traces.insert_trace(trace.clone()).await.unwrap();
        let observation = Observation::new(trace.id, ObservationType::Generation, "model response");
        traces
            .insert_observation(observation.clone())
            .await
            .unwrap();
        for (column, value) in [
            ("input", "{"),
            ("output", "{"),
            ("metadata", "{"),
            ("path", "[\"not-a-uuid\"]"),
            ("parent_id", "not-a-uuid"),
            ("session_id", "not-a-uuid"),
            ("status", "unrecognized"),
            ("obs_type", "unrecognized"),
        ] {
            let original: Option<String> = sqlx::query_scalar(&format!(
                "SELECT {column} FROM diag_observations WHERE id = ?"
            ))
            .bind(observation.id.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
            sqlx::query(&format!(
                "UPDATE diag_observations SET {column} = ? WHERE id = ?"
            ))
            .bind(value)
            .bind(observation.id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
            let result = traces.get_observations(trace.id).await;
            assert!(result.is_err(), "{column}: {result:?}");
            sqlx::query(&format!(
                "UPDATE diag_observations SET {column} = ? WHERE id = ?"
            ))
            .bind(original)
            .bind(observation.id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn corrupt_rating_discriminants_fail_instead_of_changing_meaning() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "durable trace");
        traces.insert_trace(trace.clone()).await.unwrap();
        let rating = Score::numeric(trace.id, "quality", 1.0, ScoreSource::Human);
        traces.insert_score(rating.clone()).await.unwrap();
        for (column, value) in [("data_type", "unrecognized"), ("source", "unrecognized")] {
            let original: String =
                sqlx::query_scalar(&format!("SELECT {column} FROM diag_scores WHERE id = ?"))
                    .bind(rating.id.to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            sqlx::query(&format!("UPDATE diag_scores SET {column} = ? WHERE id = ?"))
                .bind(value)
                .bind(rating.id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
            let result = traces.get_scores(trace.id).await;
            assert!(result.is_err(), "{column}: {result:?}");
            sqlx::query(&format!("UPDATE diag_scores SET {column} = ? WHERE id = ?"))
                .bind(original)
                .bind(rating.id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn malformed_numeric_evidence_is_not_silently_reset() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "numeric evidence");
        traces.insert_trace(trace.clone()).await.unwrap();
        let observation = Observation::new(trace.id, ObservationType::Generation, "generation");
        traces
            .insert_observation(observation.clone())
            .await
            .unwrap();
        for (table, column, value, id) in [
            ("diag_traces", "total_input_tokens", -1, trace.id),
            ("diag_traces", "total_output_tokens", -1, trace.id),
            ("diag_traces", "llm_duration_ms", -1, trace.id),
            ("diag_traces", "tool_duration_ms", -1, trace.id),
            ("diag_observations", "input_tokens", -1, observation.id),
            ("diag_observations", "output_tokens", -1, observation.id),
            ("diag_observations", "sequence", -1, observation.id),
            (
                "diag_observations",
                "depth",
                i64::from(u32::MAX) + 1,
                observation.id,
            ),
        ] {
            sqlx::query(&format!("UPDATE {table} SET {column} = ? WHERE id = ?"))
                .bind(value)
                .bind(id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
            let failed = if table == "diag_traces" {
                traces.get_trace(trace.id).await.is_err()
            } else {
                traces.get_observations(trace.id).await.is_err()
            };
            assert!(failed, "{table}.{column} must retain its decoding error");
            sqlx::query(&format!("UPDATE {table} SET {column} = 0 WHERE id = ?"))
                .bind(id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_score_payloads_fail_instead_of_becoming_other_values() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "numeric evidence");
        traces.insert_trace(trace.clone()).await.unwrap();
        let rating = Score::numeric(trace.id, "quality", 1.0, ScoreSource::Human);
        traces.insert_score(rating.clone()).await.unwrap();
        for (kind, value) in [
            ("boolean", 2.0),
            ("numeric", f64::INFINITY),
            ("categorical", 0.0),
        ] {
            sqlx::query("UPDATE diag_scores SET data_type = ?, value = ? WHERE id = ?")
                .bind(kind)
                .bind(value)
                .bind(rating.id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
            assert!(
                traces.get_scores(trace.id).await.is_err(),
                "{kind}: {value}"
            );
        }
    }

    #[tokio::test]
    async fn diagnostic_writes_reject_counters_that_cannot_be_stored_exactly() {
        let (_store, traces, _dir) = test_store().await;
        let mut trace = Trace::new(Uuid::new_v4(), "numeric evidence");
        trace.total_input_tokens = u64::MAX;
        assert!(traces.insert_trace(trace.clone()).await.is_err());
        trace.total_input_tokens = 0;
        traces.insert_trace(trace.clone()).await.unwrap();
        trace.tool_duration_ms = u64::MAX;
        assert!(traces.update_trace(trace.clone()).await.is_err());
        assert_eq!(
            traces.get_trace(trace.id).await.unwrap().tool_duration_ms,
            0
        );
        let mut observation = Observation::new(trace.id, ObservationType::Generation, "generation");
        observation.output_tokens = u64::MAX;
        assert!(traces.insert_observation(observation).await.is_err());
        assert!(traces.get_observations(trace.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nonfinite_diagnostic_costs_fail_reads_and_writes() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "cost evidence");
        traces.insert_trace(trace.clone()).await.unwrap();
        let observation = Observation::new(trace.id, ObservationType::Generation, "generation");
        traces
            .insert_observation(observation.clone())
            .await
            .unwrap();
        for (table, column, id) in [
            ("diag_traces", "total_cost_usd", trace.id),
            ("diag_observations", "cost_usd", observation.id),
        ] {
            sqlx::query(&format!("UPDATE {table} SET {column} = ? WHERE id = ?"))
                .bind(f64::INFINITY)
                .bind(id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
            let failed = if table == "diag_traces" {
                traces.get_trace(trace.id).await.is_err()
            } else {
                traces.get_observations(trace.id).await.is_err()
            };
            assert!(failed, "{table}.{column}");
            sqlx::query(&format!("UPDATE {table} SET {column} = 0.0 WHERE id = ?"))
                .bind(id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
        }
        let mut invalid_trace = Trace::new(Uuid::new_v4(), "invalid cost");
        invalid_trace.total_cost_usd = f64::INFINITY;
        assert!(traces.insert_trace(invalid_trace).await.is_err());
        let mut invalid_observation =
            Observation::new(trace.id, ObservationType::Generation, "invalid cost");
        invalid_observation.cost_usd = f64::INFINITY;
        assert!(traces
            .insert_observation(invalid_observation)
            .await
            .is_err());
        assert!(traces
            .insert_score(Score::numeric(
                trace.id,
                "quality",
                f64::INFINITY,
                ScoreSource::Human
            ))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn list_traces_propagates_corrupt_row_decode_failure() {
        let (store, traces, _dir) = test_store().await;
        let session = Uuid::new_v4();
        traces
            .insert_trace(Trace::new(session, "good"))
            .await
            .expect("insert valid trace");
        // A row written outside the encoder with an unparseable id must
        // surface as an error, not be silently dropped (DATABASE_SCHEMA.md
        // §7: a deserialization failure is never a successful empty/shrunk
        // collection).
        sqlx::query(
            "INSERT INTO diag_traces (id, session_id, name, started_at) \
             VALUES ('not-a-uuid', ?1, 'corrupt', '2024-01-01T00:00:00Z')",
        )
        .bind(session.to_string())
        .execute(store.pool())
        .await
        .expect("insert corrupt trace row");

        let err = traces
            .list_traces(None, None, 10)
            .await
            .expect_err("corrupt row must fail the read, not shrink it");
        assert!(err.to_string().contains("decode diag_traces"), "{err}");

        let err = traces
            .list_traces_by_session(&session.to_string(), 10)
            .await
            .expect_err("corrupt row must fail the session listing");
        assert!(err.to_string().contains("decode diag_traces"), "{err}");
    }

    #[tokio::test]
    async fn list_traces_propagates_unparseable_timestamp() {
        let (store, traces, _dir) = test_store().await;
        let session = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO diag_traces (id, session_id, name, started_at) \
             VALUES (?1, ?2, 'corrupt-time', 'not-a-timestamp')",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(session.to_string())
        .execute(store.pool())
        .await
        .expect("insert corrupt trace row");

        let err = traces
            .list_traces(None, None, 10)
            .await
            .expect_err("unparseable started_at must fail the read");
        assert!(err.to_string().contains("decode diag_traces"), "{err}");
    }

    #[tokio::test]
    async fn get_observations_propagates_corrupt_row_decode_failure() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "t");
        let trace_id = trace.id;
        traces.insert_trace(trace).await.expect("insert trace");
        traces
            .insert_observation(Observation::new(
                trace_id,
                ObservationType::Generation,
                "good",
            ))
            .await
            .expect("insert valid observation");
        sqlx::query(
            "INSERT INTO diag_observations (id, trace_id, obs_type, name, started_at) \
             VALUES ('bad-id', ?1, 'generation', 'corrupt', '2024-01-01T00:00:00Z')",
        )
        .bind(trace_id.to_string())
        .execute(store.pool())
        .await
        .expect("insert corrupt observation row");

        let err = traces
            .get_observations(trace_id)
            .await
            .expect_err("corrupt row must fail the read, not shrink it");
        assert!(
            err.to_string().contains("decode diag_observations"),
            "{err}"
        );

        let err = traces
            .get_observations_by_trace_ids(&[trace_id])
            .await
            .expect_err("corrupt row must fail the batch read");
        assert!(
            err.to_string().contains("decode diag_observations"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn get_scores_propagates_corrupt_row_decode_failure() {
        let (store, traces, _dir) = test_store().await;
        let trace = Trace::new(Uuid::new_v4(), "t");
        let trace_id = trace.id;
        traces.insert_trace(trace).await.expect("insert trace");
        traces
            .insert_score(Score::numeric(
                trace_id,
                "quality",
                1.0,
                ScoreSource::System,
            ))
            .await
            .expect("insert valid score");
        sqlx::query(
            "INSERT INTO diag_scores (id, trace_id, name, created_at) \
             VALUES ('bad-id', ?1, 'corrupt', '2024-01-01T00:00:00Z')",
        )
        .bind(trace_id.to_string())
        .execute(store.pool())
        .await
        .expect("insert corrupt score row");

        let err = traces
            .get_scores(trace_id)
            .await
            .expect_err("corrupt row must fail the read, not shrink it");
        assert!(err.to_string().contains("decode diag_scores"), "{err}");
    }

    #[tokio::test]
    async fn list_traces_by_session_returns_newest_first() {
        let (_store, traces, _dir) = test_store().await;
        let session = Uuid::new_v4();
        let mut old = Trace::new(session, "old");
        old.started_at = Utc::now() - chrono::Duration::hours(2);
        let mut mid = Trace::new(session, "mid");
        mid.started_at = Utc::now() - chrono::Duration::hours(1);
        let new = Trace::new(session, "new");
        // Insert oldest-first so an ASC query would return them reversed.
        traces.insert_trace(old).await.expect("insert old");
        traces.insert_trace(mid).await.expect("insert mid");
        traces.insert_trace(new).await.expect("insert new");

        let names: Vec<String> = traces
            .list_traces_by_session(&session.to_string(), 10)
            .await
            .expect("list traces")
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, ["new", "mid", "old"]);
    }
}
