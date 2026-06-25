//! Tests for the agent reason/act loop using a scripted provider pool.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use hf_agent::{Agent, AgentEvent, CollectingSink};
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmResponse, ProviderPool};
use hf_core::types::Message;
use hf_service::ServiceContainer;
use tokio::sync::Mutex;

/// A provider pool that returns pre-scripted replies in order.
struct ScriptedPool {
    replies: Mutex<VecDeque<String>>,
}

impl ScriptedPool {
    fn new(replies: Vec<&str>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().map(str::to_owned).collect()),
        }
    }
}

#[async_trait]
impl ProviderPool for ScriptedPool {
    async fn complete(
        &self,
        _tags: &[&str],
        _messages: Vec<Message>,
    ) -> Result<LlmResponse, ClassifiedError> {
        let content = self
            .replies
            .lock()
            .await
            .pop_front()
            .unwrap_or_else(|| "{\"final\":\"(exhausted)\"}".to_owned());
        Ok(LlmResponse {
            content,
            usage: hf_core::types::TokenUsage::default(),
            model: "scripted".to_owned(),
        })
    }
    async fn freeze(&self, _provider_id: &str) {}
    async fn thaw(&self, _provider_id: &str) {}
}

fn agent_with(replies: Vec<&str>, project: Option<std::path::PathBuf>) -> Agent {
    let runtime = Arc::new(hf_runtime::StubRuntime);
    let pool = Arc::new(ScriptedPool::new(replies));
    let container = ServiceContainer::new(runtime, Some(pool));
    Agent::new(container, project)
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
