//! Service-owned facade for the model agent loop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_agent::{Agent, AgentBackend, AgentDefinition, AgentRegistry, EventSink, RegistryError};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use hf_core::types::{Message, SessionId, TokenUsage};
use serde_json::Value;

use crate::ServiceContainer;

/// One executable capability shown in agent editors.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentToolDefinition {
    pub name: String,
    pub description: String,
}

/// Service-resolved summary for the Agents surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentRegistryInfo {
    pub model: String,
    pub provider_type: String,
    pub guardrails: String,
    pub tools: Vec<AgentToolDefinition>,
}

fn agent_registry_error(error: &RegistryError) -> ClassifiedError {
    match error {
        RegistryError::InvalidId(_) | RegistryError::NotFound(_) => {
            ClassifiedError::Validation(error.to_string())
        }
        RegistryError::NoUserDir | RegistryError::Io(_) | RegistryError::Serialize(_) => {
            ClassifiedError::Internal(error.to_string())
        }
    }
}

fn skill_registry_error(error: &hf_skills::SkillError) -> ClassifiedError {
    match error {
        hf_skills::SkillError::InvalidName(_) | hf_skills::SkillError::NotFound(_) => {
            ClassifiedError::Validation(error.to_string())
        }
        hf_skills::SkillError::NoUserDir | hf_skills::SkillError::Io(_) => {
            ClassifiedError::Internal(error.to_string())
        }
    }
}

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
    /// Resolve the active provider identity, guardrail mode, and executable
    /// agent tool roster for presentation layers.
    #[must_use]
    pub fn agent_registry_info(&self) -> AgentRegistryInfo {
        let models = crate::config::list_models();
        let first = models.first();
        AgentRegistryInfo {
            model: first.map_or_else(|| "(none configured)".to_owned(), |item| item.model.clone()),
            provider_type: first
                .map(|item| item.provider_type.clone())
                .unwrap_or_default(),
            guardrails: match std::env::var("HF_GUARDRAILS").as_deref() {
                Ok("permissive") => "permissive (audited)".to_owned(),
                _ => "approval required".to_owned(),
            },
            tools: self.agent_tool_definitions(),
        }
    }

    /// Return the authoritative roster of tools assignable to a user agent.
    #[must_use]
    pub fn agent_tool_definitions(&self) -> Vec<AgentToolDefinition> {
        hf_agent::TOOL_SPECS
            .iter()
            .map(|(name, description)| AgentToolDefinition {
                name: (*name).to_owned(),
                description: (*description).to_owned(),
            })
            .collect()
    }

    /// List shipped and user-authored agent definitions from the canonical
    /// service-owned registry.
    #[must_use]
    pub fn list_agent_definitions(&self) -> Vec<AgentDefinition> {
        AgentRegistry::with_user_dir(agent_definitions_dir()).list()
    }

    /// Read one agent definition from the canonical registry.
    #[must_use]
    pub fn get_agent_definition(&self, id: &str) -> Option<AgentDefinition> {
        AgentRegistry::with_user_dir(agent_definitions_dir())
            .get(id)
            .cloned()
    }

    /// Save one user-authored agent definition using atomic replacement.
    ///
    /// # Errors
    /// Returns a validation error for an invalid id, or an internal error when
    /// the canonical registry cannot be written.
    pub fn save_agent_definition(
        &self,
        definition: AgentDefinition,
    ) -> Result<(), ClassifiedError> {
        validate_agent_definition(&definition, &self.list_skill_definitions())?;
        AgentRegistry::with_user_dir(agent_definitions_dir())
            .save(definition)
            .map_err(|error| agent_registry_error(&error))
    }

    /// Delete a user agent, or reset a built-in override.
    ///
    /// # Errors
    /// Returns a validation error for an invalid or unknown id, or an internal
    /// error when the canonical registry cannot be updated.
    pub fn delete_agent_definition(&self, id: &str) -> Result<(), ClassifiedError> {
        AgentRegistry::with_user_dir(agent_definitions_dir())
            .delete(id)
            .map_err(|error| agent_registry_error(&error))
    }

    /// List shipped and user-authored skills from the canonical registry.
    #[must_use]
    pub fn list_skill_definitions(&self) -> Vec<hf_skills::SkillDefinition> {
        hf_skills::SkillRegistry::with_user_dir(skill_definitions_dir()).list()
    }

    /// Read one skill definition from the canonical registry.
    #[must_use]
    pub fn get_skill_definition(&self, name: &str) -> Option<hf_skills::SkillDefinition> {
        hf_skills::SkillRegistry::with_user_dir(skill_definitions_dir())
            .get(name)
            .cloned()
    }

    /// Save one user-authored skill using atomic file replacement.
    ///
    /// # Errors
    /// Returns a validation error for an invalid name, or an internal error
    /// when the canonical registry cannot be written.
    pub fn save_skill_definition(
        &self,
        definition: hf_skills::SkillDefinition,
    ) -> Result<(), ClassifiedError> {
        validate_skill_definition(&definition)?;
        hf_skills::SkillRegistry::with_user_dir(skill_definitions_dir())
            .save(definition)
            .map_err(|error| skill_registry_error(&error))
    }

    /// Delete a user skill, or reset a built-in override.
    ///
    /// # Errors
    /// Returns a validation error for an invalid or unknown name, or an
    /// internal error when the canonical registry cannot be updated.
    pub fn delete_skill_definition(&self, name: &str) -> Result<(), ClassifiedError> {
        hf_skills::SkillRegistry::with_user_dir(skill_definitions_dir())
            .delete(name)
            .map_err(|error| skill_registry_error(&error))
    }

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
        let definition = match request.agent_id.as_deref().filter(|id| !id.is_empty()) {
            Some(id) => registry
                .get(id)
                .cloned()
                .ok_or_else(|| ClassifiedError::Validation(format!("unknown agent '{id}'")))?,
            None => registry.default_agent(),
        };
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
                let language = parse_language(arg_str(args, "lang").unwrap_or("c"))?;
                let requested_engine = args
                    .get("engine")
                    .and_then(Value::as_str)
                    .map(parse_engine)
                    .transpose()?;
                let engine = crate::config::resolve_harness_engine(requested_engine, language)
                    .map_err(ClassifiedError::Validation)?;
                let draft = self
                    .harness_draft(project, target, engine, language)
                    .await?;
                let compile = self
                    .harness_compile(draft.source, project, engine, target, language)
                    .await?;
                let smoke = self
                    .harness_smoke(project, target, engine, language)
                    .await?;
                // Steer the orchestrator on the smoke verdict (L2 increment 3): a
                // clean pass points at human promotion; a hollow pass (Suspect) or
                // Fail carries the reasons back and directs a refine + re-smoke,
                // never promotion. Advisory only -- promotion stays a human action
                // and any refine merely PROPOSES a new revision (AGENTS.md 2.12).
                let next = crate::verification::harness_next_step(&smoke.verdict);
                Ok(serde_json::json!({
                    "compiled": format!("{:?}", compile.status),
                    "binary": compile.binary_name,
                    "smoke": smoke,
                    "approval_required": true,
                    "promotion_ready": next.promotion_ready,
                    "next_action": next.guidance,
                })
                .to_string())
            }
            "refine" => {
                // Close the L2 loop (increment 3b): reshape the CURRENT harness
                // toward uncovered code and recompile a PROPOSAL. It returns a
                // compiled-but-unqualified revision -- never promoted -- so the
                // orchestrator must still re-smoke it and a human must promote
                // (AGENTS.md 2.12). This acts on the not-promotion-ready guidance
                // that `harness` emits on a hollow pass.
                let target = arg_str(args, "target")?;
                let language = parse_language(arg_str(args, "lang").unwrap_or("c"))?;
                let requested_engine = args
                    .get("engine")
                    .and_then(Value::as_str)
                    .map(parse_engine)
                    .transpose()?;
                let engine = crate::config::resolve_harness_engine(requested_engine, language)
                    .map_err(ClassifiedError::Validation)?;
                // Bound the coverage-guided repair passes; default modestly and
                // floor at 1 so a refine always attempts at least one repair.
                let max_repairs = args
                    .get("max_repairs")
                    .and_then(Value::as_u64)
                    .and_then(|n| usize::try_from(n).ok())
                    .unwrap_or(2)
                    .max(1);
                let outcome = self
                    .harness_refine(project, target, engine, language, max_repairs)
                    .await?;
                Ok(serde_json::json!({
                    "refined": format!("{:?}", outcome.status),
                    "binary": outcome.binary_name,
                    "repairs_used": outcome.repairs_used,
                    "promotion_ready": false,
                    "next_action": "This is a PROPOSED revision: recompiled but not yet \
                        qualified. Re-run smoke qualification (the `harness` flow's smoke step) \
                        on it, and a human must promote it before any campaign.",
                })
                .to_string())
            }
            "run" => {
                let target = arg_str(args, "target")?;
                let requested_engine = args
                    .get("engine")
                    .and_then(Value::as_str)
                    .map(parse_engine)
                    .transpose()?;
                let requested_duration = args.get("duration_secs").and_then(Value::as_u64);
                let resolved =
                    crate::config::resolve_fuzzing_run(requested_engine, requested_duration)
                        .map_err(ClassifiedError::Validation)?;
                let summary = self
                    .run_fuzzer(
                        project,
                        target,
                        resolved.engine,
                        resolved.duration_secs,
                        &|_| {},
                    )
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
                // LLM crash verifier (L2 increment 4): an advisory per-crash
                // verdict on whether each looks like a deterministically-reproducing
                // genuine target bug vs a harness/setup artifact. Best-effort -- it
                // is `None` when no provider is configured -- and never reclassifies
                // a crash; it only informs the orchestrator's review.
                let verdicts = self.verify_crashes(target, &crashes).await;
                let items: Vec<Value> = crashes
                    .iter()
                    .zip(verdicts)
                    .map(|(crash, verdict)| {
                        serde_json::json!({
                            "kind": format!("{:?}", crash.kind),
                            "summary": crash.summary,
                            "stack_signature": crash.stack_signature,
                            "minimized": crash.minimized,
                            "verdict": verdict,
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
                    "prune" => format!(
                        "pruned to {} entries",
                        self.corpus_prune(project, target).await?
                    ),
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
        skill_definitions_dir()
    }

    fn agents_dir(&self) -> PathBuf {
        agent_definitions_dir()
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
    crate::init::config_dir().join("agents")
}

fn skill_definitions_dir() -> PathBuf {
    crate::init::config_dir().join("skills")
}

fn validate_agent_definition(
    definition: &AgentDefinition,
    skills: &[hf_skills::SkillDefinition],
) -> Result<(), ClassifiedError> {
    if definition.name.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "agent name must not be empty".to_owned(),
        ));
    }
    if definition.system_prompt.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "agent system prompt must not be empty".to_owned(),
        ));
    }
    if !(1..=50).contains(&definition.max_iterations) {
        return Err(ClassifiedError::Validation(
            "agent max_iterations must be between 1 and 50".to_owned(),
        ));
    }
    if definition
        .temperature
        .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
    {
        return Err(ClassifiedError::Validation(
            "agent temperature must be finite and between 0 and 2".to_owned(),
        ));
    }
    let known_tool = |candidate: &str| {
        candidate == hf_agent::DELEGATE_TOOL
            || hf_agent::TOOL_SPECS
                .iter()
                .any(|(name, _)| *name == candidate)
    };
    if let Some(unknown) = definition
        .allowed_tools
        .iter()
        .find(|candidate| !known_tool(candidate))
    {
        return Err(ClassifiedError::Validation(format!(
            "unknown agent tool '{unknown}'"
        )));
    }
    if let Some(unknown) = definition
        .skills
        .iter()
        .find(|candidate| !skills.iter().any(|skill| skill.name == candidate.as_str()))
    {
        return Err(ClassifiedError::Validation(format!(
            "unknown agent skill '{unknown}'"
        )));
    }
    Ok(())
}

fn validate_skill_definition(
    definition: &hf_skills::SkillDefinition,
) -> Result<(), ClassifiedError> {
    if definition.name.trim() != definition.name {
        return Err(ClassifiedError::Validation(
            "skill name must not contain surrounding whitespace".to_owned(),
        ));
    }
    if definition.version.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "skill version must not be empty".to_owned(),
        ));
    }
    if definition.description.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "skill description must not be empty".to_owned(),
        ));
    }
    if definition.body.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "skill body must not be empty".to_owned(),
        ));
    }
    if definition.body.chars().count() > 8_000 {
        return Err(ClassifiedError::Validation(
            "skill body exceeds the 8,000 character prompt budget".to_owned(),
        ));
    }
    Ok(())
}
