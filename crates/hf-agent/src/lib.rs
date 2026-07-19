//! hf-agent: the autonomous agent loop.
//!
//! A ReAct-style loop drives a service-owned [`AgentBackend`] on the model's
//! behalf: each step the model either calls a tool or returns a final answer.
//! This crate owns loop mechanics but has no dependency on `hf-service`, which
//! keeps orchestration dependencies pointing inward. Progress is streamed to
//! an [`EventSink`] so presentation layers can render it live.
//!
//! Context budget order per turn (pillar 2.4, token efficiency): prune dead
//! tool-call branches from the assembled conversation (zero model cost), then
//! compact via LLM summary only when pruning alone cannot fit the budget, then
//! trim to the budget before every model call. `hf-context`'s
//! `ContextWindowGuard` is deliberately not wired here: it evaluates the
//! provider-pipeline's categorized `AssembledContext`, while this loop carries
//! a flat `Vec<Message>` budget -- the seams do not meet without a parallel
//! accounting layer. `hf-context`'s `WorkingMemory` is deliberately not wired
//! either: per-turn scratch (tool outcomes) already lives in `messages` at
//! full fidelity and flows through prune/compact, so injecting a second copy
//! would spend tokens twice; run/target identifiers exist only in `hf-service`
//! (session/request layer), not at this port.

mod agent_tools;
mod definition;
mod event;
mod registry;
mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, RouteRequest, ToolCallingMode};
use hf_core::types::{Message, Role, TokenUsage};
use hf_guardrails::{LoopGuard, StepRecord};
use hf_tools::registry::ToolRegistryImpl;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::OnceCell;

pub use definition::{AgentDefinition, AgentRole, Autonomy, TrustTier};
pub use event::{AgentEvent, CollectingSink, EventSink, NullSink};
pub use registry::{AgentRegistry, RegistryError, DEFAULT_AGENT_ID};
pub use tools::{catalog_for, TOOL_SPECS};

/// Service capabilities consumed by the agent loop. `hf-service` implements
/// this port and remains the sole owner of fuzzing orchestration, persistence,
/// diagnostics, and guardrail decisions.
#[async_trait::async_trait]
pub trait AgentBackend: Send + Sync {
    /// Active model-provider pool, when configured.
    fn provider_pool(&self) -> Option<Arc<dyn hf_core::provider::ProviderPool>>;

    /// Record one model call in the service diagnostics ledger.
    async fn record_usage(&self, operation: &str, model: &str, usage: &TokenUsage);

    /// Ask the service guardrails whether a manual-autonomy tool may run.
    async fn approve_tool(&self, tool: &str, agent: &str) -> bool;

    /// Dispatch a fuzzing-domain tool through the service facade.
    async fn dispatch_tool(
        &self,
        project: &std::path::Path,
        name: &str,
        args: &Value,
    ) -> Result<String, ClassifiedError>;

    /// Search the service-owned project knowledge index.
    async fn knowledge_search(
        &self,
        project: &std::path::Path,
        query: &str,
        limit: usize,
    ) -> Result<Value, ClassifiedError>;

    /// Root containing user-editable skill definitions.
    fn skills_dir(&self) -> PathBuf;

    /// Root containing user-editable agent definitions.
    fn agents_dir(&self) -> PathBuf;
}

/// Default routing tags when an agent specifies none.
const ROUTE_TAGS: &[&str] = &["general", "reasoning", "code"];

/// One decoded step of the model's plan.
#[derive(Debug, Deserialize)]
struct Step {
    #[serde(default)]
    thought: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    args: Option<Value>,
    #[serde(default, rename = "final")]
    final_answer: Option<String>,
}

/// The autonomous fuzzing agent. Its behavior -- system prompt, callable tools,
/// model routing, and iteration budget -- is fully determined by its
/// [`AgentDefinition`].
pub struct Agent {
    backend: Arc<dyn AgentBackend>,
    project: Option<PathBuf>,
    definition: AgentDefinition,
    max_iterations: usize,
    registry: OnceCell<Arc<ToolRegistryImpl>>,
    /// How many delegation hops deep this agent is. The orchestrator runs at 0
    /// and may delegate to specialists (depth 1); specialists cannot delegate
    /// further, which bounds fan-out and prevents delegation cycles.
    delegation_depth: usize,
}

/// Maximum delegation depth: the orchestrator (0) may spawn specialists (1);
/// a specialist may not delegate again.
const MAX_DELEGATION_DEPTH: usize = 1;

/// The tool name the orchestrator uses to hand a scoped task to a specialist
/// sub-agent.
pub const DELEGATE_TOOL: &str = "delegate";

/// Number of most-recent messages kept verbatim when compacting a long
/// conversation; everything older is summarized into one message.
const COMPACTION_RETAIN: usize = 6;

/// A [`CompactionLlm`](hf_context::CompactionLlm) backed by the provider pool,
/// so the agent can summarize old turns with a real model instead of dropping
/// them. This is what turns long conversations from "silently truncated" into
/// "summarized", preserving earlier context across the turn.
struct PoolCompactionLlm {
    pool: Arc<dyn hf_core::provider::ProviderPool>,
    backend: Arc<dyn AgentBackend>,
}

#[async_trait::async_trait]
impl hf_context::CompactionLlm for PoolCompactionLlm {
    async fn summarize(&self, prompt: &str) -> Result<String, String> {
        let req = ChatRequest::from_messages(vec![Message::user(prompt.to_owned())]);
        let resp = self
            .pool
            .chat_completion(&req, &RouteRequest::with_tags(ROUTE_TAGS))
            .await
            .map_err(|e| e.to_string())?;
        // Record the summarization spend so long-session compaction shows up in
        // the cost summary instead of silently understating agent usage.
        self.backend
            .record_usage("agent_compaction", &resp.model, &resp.usage)
            .await;
        Ok(resp.text().trim().to_owned())
    }
}

impl Agent {
    /// Create an agent bound to a service backend and an optional project
    /// root, driven by the default (orchestrator) agent definition.
    #[must_use]
    pub fn new(backend: Arc<dyn AgentBackend>, project: Option<PathBuf>) -> Self {
        Self::with_definition(backend, project, AgentRegistry::builtin().default_agent())
    }

    /// Create an agent driven by a specific [`AgentDefinition`].
    #[must_use]
    pub fn with_definition(
        backend: Arc<dyn AgentBackend>,
        project: Option<PathBuf>,
        definition: AgentDefinition,
    ) -> Self {
        let max_iterations = definition.max_iterations.max(1);
        Self {
            backend,
            project,
            definition,
            max_iterations,
            registry: OnceCell::new(),
            delegation_depth: 0,
        }
    }

    /// Set this agent's delegation depth (used when spawned as a sub-agent).
    #[must_use]
    fn at_delegation_depth(mut self, depth: usize) -> Self {
        self.delegation_depth = depth;
        self
    }

    /// The definition driving this agent.
    #[must_use]
    pub fn definition(&self) -> &AgentDefinition {
        &self.definition
    }

    /// Override the maximum number of reason/act iterations per turn.
    #[must_use]
    pub fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n.max(1);
        self
    }

    fn system_prompt(&self) -> String {
        let catalog = tools::catalog_for(&self.definition.allowed_tools);
        // Inject the playbooks the agent references. Built-in skills are always
        // available; user skills come from the repo's `skills/` directory.
        let skills = if self.definition.skills.is_empty() {
            None
        } else {
            let registry = hf_skills::SkillRegistry::with_user_dir(self.backend.skills_dir());
            registry.render(&self.definition.skills)
        };
        hf_prompt::build_agent_system_prompt(hf_prompt::AgentPromptInput {
            role_prompt: &self.definition.system_prompt,
            project_workspace: self.project.as_deref(),
            skills: skills.as_deref(),
            tool_catalog: &catalog,
            inspection_catalog: agent_tools::INSPECTION_CATALOG,
        })
    }

    /// Run one agent turn: reason, optionally call tools, and produce a final
    /// answer. Emits [`AgentEvent`]s to `sink` throughout.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if no provider pool is configured or an LLM
    /// call fails. Tool failures are fed back to the model rather than
    /// aborting the turn.
    pub async fn run_turn(
        &self,
        history: Vec<Message>,
        user_message: &str,
        sink: &dyn EventSink,
    ) -> Result<String, ClassifiedError> {
        sink.emit(AgentEvent::Started).await;

        let pool = self.backend.provider_pool().ok_or_else(|| {
            let msg = "no LLM provider configured (set HF_PROVIDER_API_KEY)".to_owned();
            ClassifiedError::Provider(msg)
        })?;

        let mut messages = Vec::with_capacity(history.len() + 2);
        messages.push(Message::system(self.system_prompt()));
        messages.extend(history);
        messages.push(Message::user(user_message.to_owned()));

        // Prune dead tool-call branches (failed, empty, or repeated) before
        // falling back to LLM compaction: pruning costs no model call, so
        // compaction is the last resort when pruning alone cannot fit the
        // budget.
        Self::prune_over_budget(&mut messages);

        // Summarize older turns into memory when the conversation is over budget,
        // so long sessions retain earlier context instead of losing it to plain
        // window truncation.
        self.maybe_compact(&mut messages).await;

        // Route to the providers this agent prefers, falling back to the
        // default tag set when the agent specifies none.
        let route: Vec<&str> = if self.definition.model_tags.is_empty() {
            ROUTE_TAGS.to_vec()
        } else {
            self.definition.route_tags()
        };

        // Runaway-loop detection. `max_iterations` below is the hard backstop;
        // the guard catches stuck repetition/oscillation/redundant-call patterns
        // before the full step budget is spent.
        let mut loop_guard = LoopGuard::with_defaults();

        for _ in 0..self.max_iterations {
            // Cheaply shrink stale tool output (fuzzer logs, coverage/crash dumps)
            // in place before the budget cut (L3): the newest results stay intact,
            // older ones are soft-trimmed, and the oldest are cleared -- so aged
            // high-volume output stops crowding out live context, with no model
            // call. Persists across iterations as results age.
            hf_context::prune_tool_results_by_age(&mut messages);
            // Trim history to the context budget before each call so long
            // multi-turn conversations don't overflow the model window.
            let mut trimmed = hf_context::assemble(&messages, hf_context::DEFAULT_BUDGET_TOKENS);
            // Context assembly relies on the internal `Tool` role to recognize
            // and remove results whose originating turn was trimmed. Convert
            // only the provider-facing copy after assembly because this agent's
            // JSON step protocol does not use native tool-call identifiers.
            for message in &mut trimmed {
                if message.role == Role::Tool {
                    message.role = Role::User;
                    message.tool_call_id = None;
                }
            }
            let mut req = ChatRequest::from_messages(trimmed);
            // This agent uses its JSON step protocol in the system prompt rather
            // than provider-native function calls. Keep the request and result
            // messages in that mode so strict providers do not receive a
            // `role: tool` message without a native `tool_call_id`.
            req.tool_calling_mode = ToolCallingMode::PromptBased;
            // Apply the agent's configured sampling temperature (previously set
            // in the definition but never plumbed into the request).
            req.temperature = self.definition.temperature;
            let resp = pool
                .chat_completion(&req, &RouteRequest::with_tags(&route))
                .await?;
            // Record the turn's token usage/cost as a diagnostic so interactive
            // agent spend shows up in the cost summary, like rank/harness/triage
            // (which route through LlmProviderBridge::with_diagnostics).
            self.backend
                .record_usage("agent_chat", &resp.model, &resp.usage)
                .await;
            let content = resp.text().trim().to_owned();

            let Some(step) = parse_step(&content) else {
                // Not a tool-protocol object: treat as the final answer.
                sink.emit(AgentEvent::Complete {
                    content: content.clone(),
                })
                .await;
                return Ok(content);
            };

            if let Some(thought) = &step.thought {
                if !thought.is_empty() {
                    sink.emit(AgentEvent::Thinking {
                        text: thought.clone(),
                    })
                    .await;
                }
            }

            if let Some(answer) = step.final_answer {
                sink.emit(AgentEvent::Complete {
                    content: answer.clone(),
                })
                .await;
                return Ok(answer);
            }

            let Some(tool) = step.tool else {
                // A parsed step with neither a `tool` call nor a `final` answer
                // is an incomplete protocol emission -- e.g. the model narrated a
                // thought without acting. Returning `content` here would leak the
                // raw protocol JSON to the user AND end the turn prematurely
                // (the agent giving up mid-task). Instead, feed a corrective
                // observation and continue so the model emits a proper next step.
                // The thought, if any, was already surfaced as a `Thinking` event
                // above. A loop-guard record ensures a model stuck emitting
                // incomplete steps still aborts cleanly instead of spinning to
                // the iteration cap.
                if let Some(detection) = loop_guard.record(StepRecord::tool(
                    "<incomplete-step>".to_owned(),
                    String::new(),
                )) {
                    let message = format!(
                        "Stopping: detected a runaway {} loop -- {}.",
                        detection.pattern.as_str(),
                        detection.reason
                    );
                    sink.emit(AgentEvent::Error {
                        message: message.clone(),
                    })
                    .await;
                    return Ok(message);
                }
                messages.push(Message::new(Role::Assistant, content));
                messages.push(Message::new(
                    Role::User,
                    "Your previous step had neither a `tool` call nor a `final` \
                     answer. Respond with a valid step: call a `tool` to make \
                     progress, or provide a `final` answer to finish."
                        .to_owned(),
                ));
                continue;
            };

            let args = step.args.unwrap_or(Value::Null);
            sink.emit(AgentEvent::ToolCall {
                name: tool.clone(),
                args: args.clone(),
            })
            .await;

            // A manual-autonomy agent gates every tool (including reads) on
            // operator approval. Tighten-only: Assist/Auto are unchanged, and a
            // decline is fed back so the model can adapt rather than silently
            // bypassing the human gate.
            let result = if self.definition.autonomy == Autonomy::Manual
                && !self
                    .backend
                    .approve_tool(&tool, &self.definition.name)
                    .await
            {
                agent_tools::error_json(format!(
                    "approval declined: the {} agent runs with manual autonomy, so '{tool}' \
                     requires operator approval",
                    self.definition.name
                ))
            } else if tool == DELEGATE_TOOL {
                // Delegation is a permitted tool like any other, so respect the
                // agent's allow-list before spawning a sub-agent.
                if self.definition.allowed_tools.iter().all(|t| t != &tool) {
                    agent_tools::error_json(format!(
                        "tool '{tool}' is not permitted for the {} agent",
                        self.definition.name
                    ))
                } else {
                    self.handle_delegate(&args).await
                }
            } else if agent_tools::INSPECTION_TOOLS.contains(&tool.as_str()) {
                // Inspection tools read files relative to the project workspace,
                // which is also the root reads are confined to. With no project
                // set there is no root, so an absolute path would escape to the
                // host -- and the agent reads attacker-controlled target source
                // (a prompt-injection surface). Refuse rather than allow that.
                match self.project.as_deref().and_then(|p| p.to_str()) {
                    Some(wd) => {
                        let backend = Arc::clone(&self.backend);
                        let registry = self
                            .registry
                            .get_or_init(|| agent_tools::build_inspection_registry(backend))
                            .await;
                        agent_tools::dispatch_inspection(registry, &tool, &args, Some(wd)).await
                    }
                    None => agent_tools::error_json(
                        "no project workspace is set; file inspection is unavailable",
                    ),
                }
            } else if self.definition.allowed_tools.iter().all(|t| t != &tool) {
                agent_tools::error_json(format!(
                    "tool '{tool}' is not permitted for the {} agent",
                    self.definition.name
                ))
            } else if let Err(err) = tools::validate_tool_args(&tool, &args) {
                // Schema-validate the call before dispatch (L1): a hallucinated or
                // wrong-typed argument is rejected with a structured, correctable
                // message rather than being silently mis-parsed or defaulted by the
                // dispatcher's ad-hoc arg extraction.
                agent_tools::error_json(format!("invalid arguments for tool '{tool}': {err}"))
            } else {
                match self.project.as_deref() {
                    Some(project) => {
                        match self.backend.dispatch_tool(project, &tool, &args).await {
                            Ok(response) => response,
                            Err(error) => agent_tools::error_json(error),
                        }
                    }
                    None => agent_tools::error_json(
                        "no project selected; choose a project folder first",
                    ),
                }
            };
            sink.emit(AgentEvent::ToolResult {
                name: tool.clone(),
                summary: truncate(&result, 400),
            })
            .await;

            // Feed the loop guard the (tool, normalized-args) signature. A
            // detected runaway pattern aborts the turn early with a clear reason.
            if let Some(detection) =
                loop_guard.record(StepRecord::tool(tool.clone(), args.to_string()))
            {
                let message = format!(
                    "Stopping: detected a runaway {} loop -- {}.",
                    detection.pattern.as_str(),
                    detection.reason
                );
                sink.emit(AgentEvent::Error {
                    message: message.clone(),
                })
                .await;
                return Ok(message);
            }

            // Record the model's action and the tool result, then continue.
            messages.push(Message::new(Role::Assistant, content));
            messages.push(Message::new(
                Role::Tool,
                format!("result of {tool}: {result}"),
            ));
        }

        let exhausted = "Reached the step limit for this turn without a final answer.".to_owned();
        sink.emit(AgentEvent::Complete {
            content: exhausted.clone(),
        })
        .await;
        Ok(exhausted)
    }

    /// Handle a `delegate` tool call: run a scoped task on a specialist
    /// sub-agent and return its final answer as the tool result. The sub-agent
    /// runs to completion with no streaming (per the autonomy standard) and
    /// cannot delegate further, which bounds fan-out and prevents cycles.
    ///
    /// Returns an `error_json` string (never `Err`) for any problem, so a bad
    /// delegation is fed back to the model rather than aborting the parent turn.
    async fn handle_delegate(&self, args: &Value) -> String {
        if self.delegation_depth >= MAX_DELEGATION_DEPTH {
            return agent_tools::error_json(
                "delegation depth exceeded: a delegated sub-agent may not delegate again",
            );
        }
        let Some(agent_id) = args.get("agent").and_then(Value::as_str) else {
            return agent_tools::error_json("delegate requires a string 'agent' id");
        };
        let Some(task) = args.get("task").and_then(Value::as_str) else {
            return agent_tools::error_json("delegate requires a string 'task'");
        };
        // Resolve the specialist from the same registry the driving agent came
        // from: built-ins plus user agents/overrides in the backend's agents
        // dir (mirroring how skills resolve through `SkillRegistry`).
        let registry = AgentRegistry::with_user_dir(self.backend.agents_dir());
        let Some(definition) = registry.get(agent_id).cloned() else {
            return agent_tools::error_json(format!("unknown agent '{agent_id}' to delegate to"));
        };
        // The orchestrator must not delegate to itself (that is just recursion
        // with no specialization).
        if definition.id == self.definition.id {
            return agent_tools::error_json("cannot delegate to self");
        }
        let sub =
            Agent::with_definition(Arc::clone(&self.backend), self.project.clone(), definition)
                .at_delegation_depth(self.delegation_depth + 1);
        // Box the recursive turn: an async fn that awaits itself needs indirection.
        let run = Box::pin(sub.run_turn(Vec::new(), task, &NullSink));
        match run.await {
            Ok(answer) => answer,
            Err(e) => agent_tools::error_json(format!("delegated agent '{agent_id}' failed: {e}")),
        }
    }

    /// Prune dead tool-call branches (failed, empty, or repeated) from the
    /// assembled conversation via `hf-context`'s intra-turn pruner -- the only
    /// pruner operating on an in-memory `Vec<Message>`, which is the shape this
    /// loop has (the store-backed `PruningEngine`/`ProgressivePruning` need a
    /// `ChatMessageStore` and a subagent delegator this layer does not have).
    /// Runs before [`Self::maybe_compact`] because it costs no model call;
    /// compaction stays the last resort when pruning alone cannot fit the
    /// budget. Gated on the same budget check as compaction, so under-budget
    /// conversations pass through byte-identical. Best-effort: the pruner only
    /// rewrites `messages` in place and cannot fail the turn.
    fn prune_over_budget(messages: &mut Vec<Message>) {
        if hf_context::total_tokens(messages) <= hf_context::DEFAULT_BUDGET_TOKENS {
            return;
        }
        // The budget check above (not loop depth) is the trigger here, so the
        // pruner's iteration gate is disabled; its token threshold still keeps
        // tiny cleanups from rewriting history.
        let config = hf_context::pruning::config::IntraTurnPruningConfig {
            min_iteration: 0,
            ..hf_context::pruning::config::IntraTurnPruningConfig::default()
        };
        let pruner = hf_context::pruning::IntraTurnPruner::from_config(&config);
        let report = pruner.prune_working_history(messages, 0);
        if !report.skipped {
            tracing::debug!(
                messages_removed = report.messages_removed,
                tokens_saved = report.tokens_saved,
                "pruned dead tool-call branches before compaction"
            );
        }
    }

    /// When the conversation exceeds the context budget, summarize the older
    /// messages (keeping the system prompt and the most recent
    /// [`COMPACTION_RETAIN`] messages) into a single summary message via the
    /// LLM, so earlier context is preserved as memory rather than silently
    /// dropped by window truncation. Best-effort: any failure leaves `messages`
    /// unchanged (the loop still trims to budget before each call).
    async fn maybe_compact(&self, messages: &mut Vec<Message>) {
        if hf_context::total_tokens(messages) <= hf_context::DEFAULT_BUDGET_TOKENS {
            return;
        }
        // Need the system prompt + a summary + retained tail to be worthwhile.
        if messages.len() <= COMPACTION_RETAIN + 2 {
            return;
        }
        let Some(pool) = self.backend.provider_pool() else {
            return;
        };

        // Split: [system] [middle .. to summarize] [recent tail].
        // Snap the tail boundary forward to the next user turn (L6): our per-call
        // assembler drops leading non-user messages (to avoid orphaning a tool
        // result from a summarized tool call), so a tail that began mid-exchange
        // would be silently dropped -- losing context that was neither summarized
        // nor kept. A user boundary also never splits an assistant tool call from
        // its result. With no user turn to anchor the tail, skip compaction.
        let system = messages.first().cloned();
        let Some(tail_start) = safe_compaction_tail_start(messages, COMPACTION_RETAIN) else {
            return;
        };
        let middle: Vec<String> = messages[1..tail_start]
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect();
        if middle.is_empty() {
            return;
        }

        let engine = hf_context::CompactionEngine::with_llm(
            hf_context::CompactionConfig::default(),
            Box::new(PoolCompactionLlm {
                pool,
                backend: Arc::clone(&self.backend),
            }),
        );
        // Summarize everything in `middle` (retain 0 -- the tail is kept below).
        let result = engine.compact_async_with_retain(&middle, 0).await;
        if result.summary.trim().is_empty() {
            return;
        }

        let mut rebuilt = Vec::with_capacity(COMPACTION_RETAIN + 2);
        if let Some(sys) = system {
            rebuilt.push(sys);
        }
        rebuilt.push(Message::new(
            Role::System,
            format!("[Summary of earlier conversation]\n{}", result.summary),
        ));
        rebuilt.extend_from_slice(&messages[tail_start..]);
        *messages = rebuilt;
    }
}

/// The compaction tail boundary, snapped forward to the next user turn at or
/// after the nominal `len - retain` split. Anchoring the retained tail on a user
/// message keeps the per-call assembler from dropping it (it drops leading
/// non-user messages), and the summary/tail boundary never splits an assistant
/// tool call from its result. Returns `None` when no user turn exists at or after
/// the nominal split, so the caller can skip compaction rather than emit a
/// user-less tail.
fn safe_compaction_tail_start(messages: &[Message], retain: usize) -> Option<usize> {
    let nominal = messages.len().saturating_sub(retain);
    (nominal..messages.len()).find(|&i| matches!(messages[i].role, Role::User))
}

/// Parse a model reply into a [`Step`], tolerating code fences, surrounding
/// prose, and trailing junk (e.g. a stray extra `}` some models emit).
fn parse_step(content: &str) -> Option<Step> {
    if let Ok(step) = serde_json::from_str::<Step>(content) {
        return Some(step);
    }
    // Find the first `{` and parse the first complete JSON value from there.
    // The streaming deserializer stops at the end of the first value, so it
    // ignores any trailing characters (closing fences, extra braces, prose).
    let start = content.find('{')?;
    if let Ok(step) = serde_json::Deserializer::from_str(&content[start..])
        .into_iter::<Step>()
        .next()?
    {
        return Some(step);
    }

    parse_relaxed_final_step(&content[start..])
}

/// Recover the final answer from JSON-looking protocol output that is not valid
/// JSON, most commonly because a provider emitted literal newlines inside the
/// `"final"` string. This fallback intentionally only recovers final answers:
/// malformed tool calls are not executed.
fn parse_relaxed_final_step(content: &str) -> Option<Step> {
    let final_answer = extract_relaxed_string_field(content, "final")?;
    Some(Step {
        thought: extract_relaxed_string_field(content, "thought"),
        tool: None,
        args: None,
        final_answer: Some(final_answer),
    })
}

/// Extract a quoted string field from a JSON-like object, accepting literal
/// newlines in the string value.
fn extract_relaxed_string_field(content: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let key_pos = content.find(&key)?;
    let after_key = &content[key_pos + key.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    read_relaxed_quoted_string(after_colon)
}

/// Read a JSON-style quoted string, with common escapes decoded and literal
/// newlines accepted. Returns `None` when `value` does not start with a quote.
fn read_relaxed_quoted_string(value: &str) -> Option<String> {
    let mut chars = value.chars();
    if chars.next()? != '"' {
        return None;
    }

    let mut out = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            match ch {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

/// Truncate a string to `max` chars with an ellipsis, for event summaries.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod compaction_boundary_tests {
    use super::safe_compaction_tail_start;
    use hf_core::types::{Message, Role};

    fn a(text: &str) -> Message {
        Message::new(Role::Assistant, text.to_owned())
    }
    fn t(text: &str) -> Message {
        Message::new(Role::Tool, text.to_owned())
    }

    #[test]
    fn snaps_forward_past_a_mid_exchange_split_to_the_next_user_turn() {
        // Nominal split (len 8 - retain 3 = index 5) lands on a tool result mid
        // exchange; the boundary snaps forward to the user turn at index 6 so the
        // retained tail begins with a user message the assembler will keep.
        let msgs = vec![
            Message::system("s"),
            Message::user("q1"),
            a("a1"),
            t("r1"),
            a("a2"),
            t("r2"),
            Message::user("q2"),
            a("a3"),
        ];
        assert_eq!(safe_compaction_tail_start(&msgs, 3), Some(6));
    }

    #[test]
    fn keeps_the_nominal_split_when_it_already_lands_on_a_user_turn() {
        let msgs = vec![
            Message::system("s"),
            Message::user("q1"),
            a("a1"),
            Message::user("q2"),
            a("a2"),
        ];
        // len 5 - retain 2 = index 3, which is user("q2"): no snap needed.
        assert_eq!(safe_compaction_tail_start(&msgs, 2), Some(3));
    }

    #[test]
    fn is_none_when_no_user_turn_anchors_the_tail() {
        // The only user turn is before the nominal split, so the tail would be
        // all assistant/tool -- which the assembler strips. Signal "skip".
        let msgs = vec![Message::user("q"), a("a1"), t("r1"), a("a2"), t("r2")];
        assert_eq!(safe_compaction_tail_start(&msgs, 2), None);
    }
}
