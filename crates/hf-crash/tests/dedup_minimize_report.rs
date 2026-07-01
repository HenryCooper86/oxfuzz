//! Tests for dedup, minimize args, and LLM bug report drafting.

use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, LlmProvider, ProviderError,
    ProviderMetadata,
};
use hf_core::types::TokenUsage;
use hf_crash::{build_minimize_args, dedup, draft_report};
use std::path::PathBuf;
use uuid::Uuid;

fn crash(sig: &str, kind: CrashKind) -> Crash {
    Crash {
        id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("/work/crash-1"),
        stack_signature: sig.to_owned(),
        kind,
        summary: "test crash".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    }
}

#[test]
fn dedup_collapses_same_signature() {
    let crashes = vec![
        crash("abc123", CrashKind::Asan),
        crash("abc123", CrashKind::Asan),
        crash("def456", CrashKind::Segv),
    ];
    let result = dedup(crashes);
    assert_eq!(result.len(), 2, "should dedup to 2");
    let sigs: Vec<&str> = result.iter().map(|c| c.stack_signature.as_str()).collect();
    assert!(sigs.contains(&"abc123"));
    assert!(sigs.contains(&"def456"));
}

#[test]
fn dedup_keeps_empty_signatures() {
    let crashes = vec![crash("", CrashKind::Other), crash("", CrashKind::Other)];
    let result = dedup(crashes);
    assert_eq!(result.len(), 2, "empty signatures should not be deduped");
}

#[test]
fn dedup_empty_input() {
    let result = dedup(Vec::new());
    assert!(result.is_empty());
}

#[test]
fn minimize_args_libfuzzer() {
    let args = build_minimize_args(
        EngineKind::LibFuzzer,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
    )
    .expect("libFuzzer should have a minimizer");
    // The binary must be argv[0], the crash file must be the positional input
    // (last arg, not a flag value), and the minimized result goes to
    // -exact_artifact_path (the output, never the crash itself).
    assert_eq!(args.first().map(String::as_str), Some("/work/fuzz_bin"));
    assert_eq!(args.last().map(String::as_str), Some("/work/crash-1"));
    assert!(args.iter().any(|a| a == "-minimize_crash=1"));
    assert!(args.iter().any(|a| a == "-exact_artifact_path=/work/out"));
    assert!(
        !args
            .iter()
            .any(|a| a.contains("-exact_artifact_path=/work/crash-1")),
        "crash input must not be used as the output path"
    );
}

#[test]
fn minimize_args_afl() {
    let args = build_minimize_args(
        EngineKind::AflPlusPlus,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/minimized",
    )
    .expect("AFL++ should have a minimizer");
    assert_eq!(args.first().map(String::as_str), Some("afl-tmin"));
    // afl-tmin needs the target after `--` with a `@@` file placeholder, or it
    // has no program to run.
    let sep = args
        .iter()
        .position(|a| a == "--")
        .expect("must have -- separator");
    assert_eq!(
        args.get(sep + 1).map(String::as_str),
        Some("/work/fuzz_bin")
    );
    assert_eq!(args.get(sep + 2).map(String::as_str), Some("@@"));
    // Input/output flags precede the separator.
    let i = args.iter().position(|a| a == "-i").expect("-i");
    assert_eq!(args.get(i + 1).map(String::as_str), Some("/work/crash-1"));
    let o = args.iter().position(|a| a == "-o").expect("-o");
    assert_eq!(args.get(o + 1).map(String::as_str), Some("/work/minimized"));
}

#[test]
fn minimize_args_honggfuzz_none() {
    let args = build_minimize_args(
        EngineKind::Honggfuzz,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
    );
    assert!(args.is_none(), "honggfuzz has no built-in minimizer");
}

struct MockLlm {
    response: String,
}

#[async_trait::async_trait]
impl LlmProvider for MockLlm {
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

#[tokio::test]
async fn draft_report_parses_llm_json() {
    let llm = MockLlm {
        response: r##"{
            "title": "heap-buffer-overflow in parse_string",
            "summary": "parse_string reads past buffer end on truncated input.",
            "repro_steps": "clang -fsanitize=fuzzer,address fuzz.c && ./fuzz_bin crash-1",
            "stack": "#0 parse_string #1 parse_value",
            "severity_guess": "high"
        }"##
        .to_owned(),
    };
    let crash = crash("sig", CrashKind::Asan);
    let report = draft_report(&crash, "==ERROR: asan==", Box::new(llm))
        .await
        .expect("draft should succeed");
    assert_eq!(report.title, "heap-buffer-overflow in parse_string");
    assert_eq!(report.severity_guess, "high");
    assert!(report.repro_steps.contains("clang"));
}

#[tokio::test]
async fn draft_report_falls_back_on_invalid_json() {
    let llm = MockLlm {
        response: "not json".to_owned(),
    };
    let crash = crash("sig", CrashKind::Asan);
    let report = draft_report(&crash, "asan log", Box::new(llm))
        .await
        .expect("should not error on bad json");
    assert!(report.title.contains("Asan"));
    assert_eq!(report.severity_guess, "uncertain");
}
