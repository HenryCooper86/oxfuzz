//! Service-owned facade for the model agent loop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_agent::{Agent, AgentBackend, AgentRegistry, EventSink};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use hf_core::types::{Message, SessionId, TokenUsage};
use serde_json::Value;

use crate::ServiceContainer;

/// Inputs for one service-orchestrated chat turn.
pub struct AgentTurnRequest {
    pub project: Option<PathBuf>,
    pub agent_id: Option<String>,
    pub session: Option<SessionId>,
    pub history_fallback: Vec<Message>,
    pub message: String,
    /// User-visible text persisted in the transcript when `message` contains
    /// an internal mode instruction. Defaults to `message` when absent.
    pub display_message: Option<String>,
}

impl ServiceContainer {
    /// Run one agent turn with service-owned tools, persistence, diagnostics,
    /// and guardrails.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if transcript loading or the model call fails.
    pub async fn run_chat_turn(
        &self,
        request: AgentTurnRequest,
        sink: &dyn EventSink,
    ) -> Result<String, ClassifiedError> {
        let _turn_guard = match &request.session {
            Some(id) => Some(self.chat_session_guard(id).await?),
            _ => None,
        };

        let history =
            if let (Some(id), Some(manager)) = (&request.session, self.session_manager()) {
                manager.read_transcript(id).await.map_err(|error| {
                    ClassifiedError::Internal(format!("read transcript: {error}"))
                })?
            } else {
                request.history_fallback
            };
        let registry = AgentRegistry::with_user_dir(agent_definitions_dir());
        let definition = request
            .agent_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .and_then(|id| registry.get(id).cloned())
            .unwrap_or_else(|| registry.default_agent());
        let backend: Arc<dyn AgentBackend> = Arc::new(self.clone());
        let agent = Agent::with_definition(backend, request.project, definition);
        let answer = agent.run_turn(history, &request.message, sink).await?;

        if let Some(id) = &request.session {
            let display_message = request
                .display_message
                .unwrap_or_else(|| request.message.clone());
            self.persist_chat_turn_unlocked(
                id,
                &[
                    Message::user(display_message),
                    Message::assistant(answer.clone()),
                ],
            )
            .await?;
        }
        Ok(answer)
    }

    async fn dispatch_agent_tool(
        &self,
        project: &Path,
        name: &str,
        args: &Value,
    ) -> Result<String, ClassifiedError> {
        match name {
            "discover" => {
                let language = parse_language(arg_str(args, "lang").unwrap_or("c"))?;
                let inventory = self.discover(project, language).await?;
                let targets: Vec<Value> = inventory
                    .ranked()
                    .into_iter()
                    .take(10)
                    .map(|candidate| {
                        serde_json::json!({
                            "symbol": candidate.symbol,
                            "fit_score": candidate.fit_score,
                            "kind": format!("{:?}", candidate.kind),
                            "location": format!("{}:{}", candidate.location.file.display(), candidate.location.line),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "targets": targets }).to_string())
            }
            "harness" => {
                let target = arg_str(args, "target")?;
                let engine = parse_engine(arg_str(args, "engine").unwrap_or("libfuzzer"))?;
                let language = parse_language(arg_str(args, "lang").unwrap_or("c"))?;
                let draft = self
                    .harness_draft(project, target, engine, language)
                    .await?;
                let compile = self
                    .harness_compile(draft.source, project, engine, target, language)
                    .await?;
                let smoke = self
                    .harness_smoke(project, target, engine, language)
                    .await?;
                Ok(serde_json::json!({
                    "compiled": format!("{:?}", compile.status),
                    "binary": compile.binary_name,
                    "smoke": smoke,
                    "approval_required": true,
                    "next_action": "Ask the operator to review and explicitly promote this exact revision.",
                })
                .to_string())
            }
            "run" => {
                let target = arg_str(args, "target")?;
                let engine = parse_engine(arg_str(args, "engine").unwrap_or("libfuzzer"))?;
                let duration_secs = args
                    .get("duration_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(60);
                let summary = self
                    .run_fuzzer(project, target, engine, duration_secs, &|_| {})
                    .await?;
                Ok(serde_json::json!({
                    "edges": summary.edges,
                    "execs_per_sec": summary.execs,
                    "crashes": summary.crashes,
                })
                .to_string())
            }
            "triage" => {
                let target = arg_str(args, "target")?;
                let crashes = self.triage(project, target).await?;
                let items: Vec<Value> = crashes
                    .iter()
                    .map(|crash| {
                        serde_json::json!({
                            "kind": format!("{:?}", crash.kind),
                            "summary": crash.summary,
                            "stack_signature": crash.stack_signature,
                            "minimized": crash.minimized,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "unique_crashes": items.len(),
                    "crashes": items,
                })
                .to_string())
            }
            "corpus" => {
                let target = arg_str(args, "target")?;
                let result = match arg_str(args, "op").unwrap_or("list") {
                    "seed" => format!(
                        "seeded {} entries",
                        self.corpus_seed(project, target).await?
                    ),
                    "grow" => format!(
                        "corpus now {} entries",
                        self.corpus_grow(project, target).await?
                    ),
                    "prune" => format!("pruned to {} entries", self.corpus_prune(project, target)?),
                    "list" => format!(
                        "{} entries",
                        self.corpus_list(project, target)?.entries.len()
                    ),
                    other => {
                        return Err(ClassifiedError::Validation(format!(
                            "unknown corpus op: {other}"
                        )))
                    }
                };
                Ok(serde_json::json!({ "result": result }).to_string())
            }
            other => Err(ClassifiedError::Validation(format!(
                "unknown tool: {other}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl AgentBackend for ServiceContainer {
    fn provider_pool(&self) -> Option<Arc<dyn hf_core::provider::ProviderPool>> {
        ServiceContainer::provider_pool(self)
    }

    async fn record_usage(&self, operation: &str, model: &str, usage: &TokenUsage) {
        self.diagnostics().record(operation, model, usage).await;
    }

    async fn approve_tool(&self, tool: &str, agent: &str) -> bool {
        self.approve_agent_tool(tool, agent).await
    }

    async fn dispatch_tool(
        &self,
        project: &Path,
        name: &str,
        args: &Value,
    ) -> Result<String, ClassifiedError> {
        self.dispatch_agent_tool(project, name, args).await
    }

    async fn knowledge_search(
        &self,
        project: &Path,
        query: &str,
        limit: usize,
    ) -> Result<Value, ClassifiedError> {
        let project = project.to_path_buf();
        let query = query.to_owned();
        tokio::task::spawn_blocking(move || {
            if !crate::knowledge::is_indexed(&project) {
                crate::knowledge::index_project(&project)?;
            }
            serde_json::to_value(crate::knowledge::search_project(&project, &query, limit))
                .map_err(|error| ClassifiedError::Internal(error.to_string()))
        })
        .await
        .map_err(|error| ClassifiedError::Internal(format!("knowledge task: {error}")))?
    }

    fn skills_dir(&self) -> PathBuf {
        crate::repo_root().map_or_else(|| PathBuf::from("skills"), |root| root.join("skills"))
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, ClassifiedError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ClassifiedError::Validation(format!("missing string arg '{key}'")))
}

fn parse_language(value: &str) -> Result<TargetLanguage, ClassifiedError> {
    value.parse().map_err(ClassifiedError::Validation)
}

fn parse_engine(value: &str) -> Result<EngineKind, ClassifiedError> {
    value.parse().map_err(ClassifiedError::Validation)
}

fn agent_definitions_dir() -> PathBuf {
    crate::repo_root().map_or_else(|| PathBuf::from("agents"), |root| root.join("agents"))
}
