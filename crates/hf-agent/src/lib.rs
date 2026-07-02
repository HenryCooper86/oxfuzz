//! hf-agent: the autonomous agent loop.
//!
//! A ReAct-style loop drives the fuzzing tools (`hf-service`) on the model's
//! behalf: each step the model either calls a tool or returns a final answer.
//! Tool calls flow through the [`ServiceContainer`], so every privileged action
//! is still guardrail-gated (AGENTS.md 2.12). Progress is streamed to an
//! [`EventSink`] so presentation layers can render it live.

mod agent_tools;
mod definition;
mod event;
mod registry;
mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, RouteRequest};
use hf_core::types::{Message, Role, SessionId};
use hf_guardrails::{LoopGuard, StepRecord};
use hf_service::ServiceContainer;
use hf_tools::registry::ToolRegistryImpl;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::OnceCell;

pub use definition::{AgentDefinition, AgentRole, Autonomy, TrustTier};
pub use event::{AgentEvent, CollectingSink, EventSink, NullSink};
pub use registry::{AgentRegistry, RegistryError, DEFAULT_AGENT_ID};
pub use tools::{catalog_for, TOOL_CATALOG, TOOL_SPECS};

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
    container: ServiceContainer,
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
        Ok(resp.text().trim().to_owned())
    }
}

impl Agent {
    /// Create an agent bound to a service container and an optional project
    /// root, driven by the default (orchestrator) agent definition.
    #[must_use]
    pub fn new(container: ServiceContainer, project: Option<PathBuf>) -> Self {
        Self::with_definition(container, project, AgentRegistry::builtin().default_agent())
    }

    /// Create an agent driven by a specific [`AgentDefinition`].
    #[must_use]
    pub fn with_definition(
        container: ServiceContainer,
        project: Option<PathBuf>,
        definition: AgentDefinition,
    ) -> Self {
        let max_iterations = definition.max_iterations.max(1);
        Self {
            container,
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
        let project = self
            .project
            .as_ref()
            .map_or_else(|| "(none selected)".to_owned(), |p| p.display().to_string());
        let catalog = tools::catalog_for(&self.definition.allowed_tools);
        // Inject the playbooks the agent references. Built-in skills are always
        // available; user skills come from the repo's `skills/` directory.
        let skills_block = if self.definition.skills.is_empty() {
            String::new()
        } else {
            let registry = hf_skills::SkillRegistry::with_user_dir(skills_dir());
            registry
                .render(&self.definition.skills)
                .map(|s| format!("{s}\n\n"))
                .unwrap_or_default()
        };
        format!(
            "{role}\n\nThe active project is: {project}.\n\n{skills_block}{catalog}\n{inspection}\n\n\
Respond with EXACTLY ONE JSON object and nothing else:\n\
- To call a tool: {{\"thought\":\"<brief reasoning>\",\"tool\":\"<name>\",\"args\":{{...}}}}\n\
- To answer the user: {{\"thought\":\"<brief reasoning>\",\"final\":\"<answer>\"}}\n\
Do not wrap the JSON in code fences or add prose around it. After a tool runs \
you receive its result and continue until you can give a final answer.",
            role = self.definition.system_prompt.trim(),
            inspection = agent_tools::INSPECTION_CATALOG,
        )
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

        let pool = self.container.provider_pool().ok_or_else(|| {
            let msg = "no LLM provider configured (set HF_PROVIDER_API_KEY)".to_owned();
            ClassifiedError::Provider(msg)
        })?;

        let mut messages = Vec::with_capacity(history.len() + 2);
        messages.push(Message::system(self.system_prompt()));
        messages.extend(history);
        messages.push(Message::user(user_message.to_owned()));

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
            // Trim history to the context budget before each call so long
            // multi-turn conversations don't overflow the model window.
            let trimmed = hf_context::assemble(&messages, hf_context::DEFAULT_BUDGET_TOKENS);
            let mut req = ChatRequest::from_messages(trimmed);
            // Apply the agent's configured sampling temperature (previously set
            // in the definition but never plumbed into the request).
            req.temperature = self.definition.temperature;
            let resp = pool
                .chat_completion(&req, &RouteRequest::with_tags(&route))
                .await?;
            // Record the turn's token usage/cost as a diagnostic so interactive
            // agent spend shows up in the cost summary, like rank/harness/triage
            // (which route through LlmProviderBridge::with_diagnostics).
            self.container
                .diagnostics()
                .record("agent_chat", &resp.model, &resp.usage)
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
                // No tool and no final: accept the raw content as the answer.
                sink.emit(AgentEvent::Complete {
                    content: content.clone(),
                })
                .await;
                return Ok(content);
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
                    .container
                    .approve_agent_tool(&tool, &self.definition.name)
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
                        let registry = self
                            .registry
                            .get_or_init(agent_tools::build_inspection_registry)
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
            } else {
                match tools::dispatch(&self.container, self.project.as_deref(), &tool, &args).await
                {
                    Ok(r) => r,
                    Err(e) => agent_tools::error_json(e),
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
        // Resolve the specialist from the built-in roster.
        let registry = AgentRegistry::builtin();
        let Some(definition) = registry.get(agent_id).cloned() else {
            return agent_tools::error_json(format!("unknown agent '{agent_id}' to delegate to"));
        };
        // The orchestrator must not delegate to itself (that is just recursion
        // with no specialization).
        if definition.id == self.definition.id {
            return agent_tools::error_json("cannot delegate to self");
        }
        let sub = Agent::with_definition(self.container.clone(), self.project.clone(), definition)
            .at_delegation_depth(self.delegation_depth + 1);
        // Box the recursive turn: an async fn that awaits itself needs indirection.
        let run = Box::pin(sub.run_turn(Vec::new(), task, &NullSink));
        match run.await {
            Ok(answer) => answer,
            Err(e) => agent_tools::error_json(format!("delegated agent '{agent_id}' failed: {e}")),
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
        let Some(pool) = self.container.provider_pool() else {
            return;
        };

        // Split: [system] [middle .. to summarize] [recent tail].
        let system = messages.first().cloned();
        let tail_start = messages.len() - COMPACTION_RETAIN;
        let middle: Vec<String> = messages[1..tail_start]
            .iter()
            .map(|m| format!("{:?}: {}", m.role, m.content))
            .collect();
        if middle.is_empty() {
            return;
        }

        let engine = hf_context::CompactionEngine::with_llm(
            hf_context::CompactionConfig::default(),
            Box::new(PoolCompactionLlm { pool }),
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

/// Resolve the skills directory: `<repo>/skills`, else `./skills`. User skills
/// live here; built-in skills are embedded and always available.
fn skills_dir() -> PathBuf {
    hf_service::repo_root().map_or_else(|| PathBuf::from("skills"), |r| r.join("skills"))
}

/// Run one chat turn through the agent loop, the single code path shared by
/// every presentation layer (GUI/web/CLI) so they all drive the agent
/// identically (AGENTS.md 2.9 -- orchestration lives here, not in the
/// presentation crates).
///
/// History is resolved from the persistent session transcript when `session`
/// names one and a database is configured; otherwise `history_fallback` is
/// used. After a successful turn, when a session is active the pre-turn state is
/// checkpointed and the user+assistant messages are appended so the turn can be
/// rolled back. The `container` must already carry the desired guardrail policy
/// (e.g. an interactive approval gate for the GUI).
///
/// # Errors
/// Returns `ClassifiedError` if the session transcript cannot be read, no
/// provider is configured, or an LLM call fails.
#[allow(clippy::too_many_arguments)]
pub async fn run_chat_turn(
    container: ServiceContainer,
    project: Option<PathBuf>,
    agent_id: Option<&str>,
    agents_dir: PathBuf,
    session: Option<SessionId>,
    history_fallback: Vec<Message>,
    message: &str,
    sink: &dyn EventSink,
) -> Result<String, ClassifiedError> {
    // Resolve the conversation history: prefer the persisted transcript.
    let has_session = session.is_some() && container.session_manager().is_some();

    // Serialize turns on the same session for the whole read-modify-write below:
    // reading the history, running the turn, then appending user+assistant and
    // checkpointing. Two concurrent turns on one session would otherwise read the
    // same pre-turn length, mint duplicate checkpoint turn numbers, and interleave
    // their four appends. The guard is held until this function returns; distinct
    // sessions take distinct locks and still run concurrently.
    let _turn_guard = match &session {
        Some(id) if has_session => Some(container.session_turn_lock(id).lock_owned().await),
        _ => None,
    };

    let history = if let (Some(id), Some(manager)) = (&session, container.session_manager()) {
        manager
            .read_transcript(id)
            .await
            .map_err(|e| ClassifiedError::Internal(format!("read transcript: {e}")))?
    } else {
        history_fallback
    };
    // Transcript length before this turn -- a rollback restores to here.
    let message_count_before = u32::try_from(history.len()).unwrap_or(u32::MAX);

    // Select the agent definition (default: orchestrator) and run the turn.
    let registry = AgentRegistry::with_user_dir(agents_dir);
    let definition = agent_id
        .filter(|s| !s.is_empty())
        .and_then(|id| registry.get(id).cloned())
        .unwrap_or_else(|| registry.default_agent());
    let agent = Agent::with_definition(container.clone(), project, definition);
    let answer = agent.run_turn(history, message, sink).await?;

    // Persist the turn (checkpoint + user/assistant messages) when a session is
    // active, so the conversation survives and can be rolled back.
    if has_session {
        if let Some(id) = &session {
            container
                .chat_create_checkpoint(id, message_count_before)
                .await;
            if let Some(manager) = container.session_manager() {
                let _ = manager.append_message(id, &Message::user(message)).await;
                let _ = manager
                    .append_message(id, &Message::assistant(answer.clone()))
                    .await;
            }
        }
    }

    Ok(answer)
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
