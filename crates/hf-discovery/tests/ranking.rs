//! Tests for LLM-assisted ranking.

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, LlmProvider, ProviderError,
    ProviderMetadata,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetInventory, TargetKind,
    TargetLanguage,
};
use hf_core::types::TokenUsage;
use hf_discovery::rank;
use std::path::PathBuf;
use uuid::Uuid;

/// A mock LLM provider that returns a canned ranking JSON.
struct MockRanker {
    response: String,
}

#[async_trait::async_trait]
impl LlmProvider for MockRanker {
    async fn chat_completion(&self, _request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        Ok(ChatResponse {
            id: "mock".to_owned(),
            model: "mock".to_owned(),
            content: Some(self.response.clone()),
            reasoning_content: None,
            tool_calls: Vec::new(),
            usage: TokenUsage::default(),
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
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "no stream".to_owned(),
        })
    }
    fn metadata(&self) -> &ProviderMetadata {
        mock_provider_metadata()
    }
}

fn mock_provider_metadata() -> &'static ProviderMetadata {
    use hf_core::provider::{ProviderCapability, ProviderType, ToolCallingMode};
    static M: std::sync::OnceLock<ProviderMetadata> = std::sync::OnceLock::new();
    M.get_or_init(|| ProviderMetadata {
        id: hf_core::types::ProviderId::from_string("mock"),
        provider_type: ProviderType::Custom,
        model: "mock".to_owned(),
        tags: Vec::new(),
        capabilities: vec![ProviderCapability::Text],
        max_concurrency: 1,
        context_window: 128_000,
        cost_per_1k_input: 0.0,
        cost_per_1k_output: 0.0,
        tool_calling_mode: ToolCallingMode::Native,
    })
}

fn cand(symbol: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/p"),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/json.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some(format!("int {symbol}(const char*, size_t);")),
        input_surface: InputSurface::Bytes,
        complexity: 10,
        fit_score: 0.5,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    }
}

#[tokio::test]
async fn rank_merges_llm_rationale_and_scores() {
    let llm = MockRanker {
        response: r#"[
            {"symbol":"parse_value","fit_score":0.95,"rationale":"Top-level JSON parser taking raw bytes."},
            {"symbol":"parse_array","fit_score":0.88,"rationale":"Recursive array parser with allocations."}
        ]"#
        .to_owned(),
    };
    let inv = TargetInventory {
        project_root: PathBuf::from("/p"),
        candidates: vec![cand("parse_value"), cand("parse_array"), cand("skip_ws")],
        call_graph: std::collections::HashMap::new(),
    };
    let ranked = rank(inv, Box::new(llm)).await.expect("rank should succeed");
    let pv = ranked
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_value")
        .expect("parse_value present");
    assert!(
        (pv.fit_score - 0.95).abs() < 1e-6,
        "fit_score should be updated"
    );
    assert!(
        pv.rationale.contains("Top-level JSON parser"),
        "rationale should be merged; got: {}",
        pv.rationale
    );
    // skip_ws was not in the LLM response; keep heuristic score, empty rationale.
    let ws = ranked
        .candidates
        .iter()
        .find(|c| c.symbol == "skip_ws")
        .expect("skip_ws present");
    assert!(
        (ws.fit_score - 0.5).abs() < 1e-6,
        "unranked candidate keeps heuristic score"
    );
}

#[tokio::test]
async fn rank_falls_back_on_invalid_json() {
    let llm = MockRanker {
        response: "not json at all".to_owned(),
    };
    let inv = TargetInventory {
        project_root: PathBuf::from("/p"),
        candidates: vec![cand("parse_value")],
        call_graph: std::collections::HashMap::new(),
    };
    let ranked = rank(inv, Box::new(llm))
        .await
        .expect("rank should not error on bad json");
    let pv = ranked
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_value")
        .expect("parse_value present");
    assert!(
        (pv.fit_score - 0.5).abs() < 1e-6,
        "fit_score should be unchanged"
    );
}
