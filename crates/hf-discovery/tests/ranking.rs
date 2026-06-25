//! Tests for LLM-assisted ranking.

use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetInventory, TargetKind,
    TargetLanguage,
};
use hf_core::types::{Message, TokenUsage};
use hf_discovery::rank;
use std::path::PathBuf;
use uuid::Uuid;

/// A mock LLM provider that returns a canned ranking JSON.
struct MockRanker {
    response: String,
}

#[async_trait::async_trait]
impl LlmProvider for MockRanker {
    fn id(&self) -> &'static str {
        "mock-ranker"
    }
    async fn complete(&self, _messages: Vec<Message>) -> Result<LlmResponse, ClassifiedError> {
        Ok(LlmResponse {
            content: self.response.clone(),
            usage: TokenUsage::default(),
            model: "mock".to_owned(),
        })
    }
    async fn stream(
        &self,
        _messages: Vec<Message>,
    ) -> Result<
        Box<dyn futures::Stream<Item = Result<String, ClassifiedError>> + Send + Unpin>,
        ClassifiedError,
    > {
        Err(ClassifiedError::Provider("no stream".to_owned()))
    }
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
        },
        signature: Some(format!("int {symbol}(const char*, size_t);")),
        input_surface: InputSurface::Bytes,
        complexity: 10,
        fit_score: 0.5,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
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
