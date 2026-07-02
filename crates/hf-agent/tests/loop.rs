//! Tests for the agent reason/act loop using a scripted provider pool.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use hf_agent::{run_chat_turn, Agent, AgentEvent, CollectingSink};
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
    RouteRequest,
};
use hf_service::ServiceContainer;
use tokio::sync::Mutex;

/// A provider pool that returns pre-scripted replies in order.
struct ScriptedPool {
    replies: Mutex<VecDeque<String>>,
    /// The `temperature` on the most recent request (to assert it was applied).
    last_temperature: Mutex<Option<f64>>,
}

impl ScriptedPool {
    fn new(replies: Vec<&str>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().map(str::to_owned).collect()),
            last_temperature: Mutex::new(None),
        }
    }
}

#[async_trait]
impl ProviderPool for ScriptedPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        *self.last_temperature.lock().await = request.temperature;
        let content = self
            .replies
            .lock()
            .await
            .pop_front()
            .unwrap_or_else(|| "{\"final\":\"(exhausted)\"}".to_owned());
        Ok(ChatResponse {
            id: "scripted".to_owned(),
            model: "scripted".to_owned(),
            content: Some(content),
            reasoning_content: None,
            tool_calls: Vec::new(),
            // Non-zero usage so a recorded diagnostic carries real token counts.
            usage: hf_core::types::TokenUsage {
                input_tokens: 12,
                output_tokens: 8,
                ..Default::default()
            },
            finish_reason: FinishReason::Stop,
            raw_request: None,
            raw_response: None,
            provider_id: None,
            generated_images: Vec::new(),
        })
    }
    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "no stream".to_owned(),
        })
    }
    fn report_error(&self, _provider_id: &hf_core::types::ProviderId, _error: &ProviderError) {}
    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}
    async fn thaw(&self, _provider_id: &hf_core::types::ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn agent_with(replies: Vec<&str>, project: Option<std::path::PathBuf>) -> Agent {
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let pool = Arc::new(ScriptedPool::new(replies));
    let container = ServiceContainer::new(runtime, Some(pool));
    Agent::new(container, project)
}

#[tokio::test]
async fn agent_turn_records_diagnostics_cost() {
    // An interactive agent turn must show up in the cost summary, like
    // rank/harness/triage -- otherwise interactive-agent spend is invisible.
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let pool = Arc::new(ScriptedPool::new(vec![
        r#"{"thought":"easy","final":"done"}"#,
    ]));
    let container = ServiceContainer::new(runtime, Some(pool));
    let agent = Agent::new(container.clone(), None);
    let sink = CollectingSink::new();

    let before = container.cost_summary().await.calls;
    agent.run_turn(vec![], "hi", &sink).await.unwrap();
    let after = container.cost_summary().await;

    assert_eq!(
        after.calls,
        before + 1,
        "the turn's LLM call must be recorded"
    );
    assert_eq!(after.input_tokens, 12);
    assert_eq!(after.output_tokens, 8);
}

#[tokio::test]
async fn agent_applies_configured_temperature() {
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let pool = Arc::new(ScriptedPool::new(vec![r#"{"final":"ok"}"#]));
    let captured = Arc::clone(&pool);
    let container = ServiceContainer::new(runtime, Some(pool));

    let def = hf_agent::AgentDefinition::from_toml(
        "id = \"tempy\"\n\
         name = \"Tempy\"\n\
         description = \"d\"\n\
         role = \"orchestrator\"\n\
         system_prompt = \"you are a test\"\n\
         temperature = 0.25\n",
    )
    .expect("valid definition toml");
    let agent = Agent::with_definition(container, None, def);
    let sink = CollectingSink::new();
    agent.run_turn(vec![], "hi", &sink).await.unwrap();

    assert_eq!(
        *captured.last_temperature.lock().await,
        Some(0.25),
        "the agent's configured temperature must reach the provider request"
    );
}

#[tokio::test]
async fn direct_final_answer() {
    let agent = agent_with(vec![r#"{"thought":"easy","final":"hello there"}"#], None);
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "hi", &sink).await.unwrap();
    assert_eq!(out, "hello there");
    let events = sink.events().await;
    assert!(matches!(events.first(), Some(AgentEvent::Started)));
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::Complete { content } if content == "hello there")));
}

#[tokio::test]
async fn tool_call_then_final() {
    // Step 1 calls an unknown tool (deterministic error fed back), step 2 ends.
    let agent = agent_with(
        vec![
            r#"{"thought":"inspect","tool":"bogus","args":{"x":1}}"#,
            r#"{"thought":"done","final":"all set"}"#,
        ],
        Some(std::env::temp_dir()),
    );
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "do something", &sink).await.unwrap();
    assert_eq!(out, "all set");

    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "bogus")));
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolResult { name, .. } if name == "bogus")));
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::Complete { content } if content == "all set")));
}

#[tokio::test]
async fn inspection_tool_refused_without_project() {
    // With no project set, an inspection tool reading an absolute host path must
    // be refused (no workspace to confine reads to) -- the agent reads
    // attacker-controlled target source, so this is a prompt-injection surface.
    let agent = agent_with(
        vec![
            r#"{"thought":"peek","tool":"FileRead","args":{"path":"/etc/hosts"}}"#,
            r#"{"final":"done"}"#,
        ],
        None,
    );
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "read it", &sink).await.unwrap();
    assert_eq!(out, "done");

    let events = sink.events().await;
    let summary = events
        .iter()
        .find_map(|e| match e {
            AgentEvent::ToolResult { summary, .. } => Some(summary.clone()),
            _ => None,
        })
        .expect("a tool result was emitted");
    assert!(
        summary.contains("no project workspace"),
        "expected refusal, got: {summary}"
    );
}

#[tokio::test]
async fn non_json_reply_is_treated_as_final() {
    let agent = agent_with(vec!["Just a plain answer with no JSON."], None);
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "hi", &sink).await.unwrap();
    assert_eq!(out, "Just a plain answer with no JSON.");
}

#[tokio::test]
async fn tolerates_trailing_junk_in_tool_call() {
    // Some models emit a stray extra '}' (or code fences) after the object.
    // The agent must still parse the tool call, not give up and echo the JSON.
    let agent = agent_with(
        vec![
            r#"{"thought":"x","tool":"bogus","args":{"a":1}}}"#,
            r#"```json
{"thought":"done","final":"all set"}
```"#,
        ],
        Some(std::env::temp_dir()),
    );
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "go", &sink).await.unwrap();
    assert_eq!(out, "all set");
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "bogus")));
}

#[tokio::test]
async fn missing_provider_errors() {
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let container = ServiceContainer::new(runtime, None);
    let agent = Agent::new(container, None);
    let sink = CollectingSink::new();
    assert!(agent.run_turn(vec![], "hi", &sink).await.is_err());
}

#[tokio::test]
async fn loop_guard_aborts_redundant_tool_calls() {
    // The model repeats the same tool with identical args. The loop guard
    // (redundant-tool threshold 3) must abort the turn before max_iterations,
    // emitting an Error event with a clear reason.
    let repeated = r#"{"thought":"again","tool":"bogus","args":{"a":1}}"#;
    let agent = agent_with(
        vec![repeated, repeated, repeated, repeated, repeated],
        Some(std::env::temp_dir()),
    )
    .with_max_iterations(8);
    let sink = CollectingSink::new();
    let out = agent.run_turn(vec![], "go", &sink).await.unwrap();
    assert!(
        out.contains("runaway") && out.contains("redundant"),
        "expected a runaway-loop abort message, got: {out}"
    );
    let events = sink.events().await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AgentEvent::Error { message } if message.contains("runaway"))),
        "expected an Error event for the detected loop"
    );
}

#[tokio::test]
async fn run_chat_turn_drives_default_agent_without_session() {
    // The shared presentation-layer entry point: with no session it uses the
    // supplied fallback history and the default (orchestrator) agent.
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let pool = Arc::new(ScriptedPool::new(vec![
        r#"{"thought":"easy","final":"shared path works"}"#,
    ]));
    let container = ServiceContainer::new(runtime, Some(pool));
    let sink = CollectingSink::new();

    let out = run_chat_turn(
        container,
        None,
        None,                 // default agent
        std::env::temp_dir(), // no user agent defs -> builtin default
        None,                 // no persistent session
        Vec::new(),           // empty fallback history
        "hello",
        &sink,
    )
    .await
    .unwrap();

    assert_eq!(out, "shared path works");
    let events = sink.events().await;
    assert!(events
        .iter()
        .any(|e| matches!(e, AgentEvent::Complete { content } if content == "shared path works")));
}
