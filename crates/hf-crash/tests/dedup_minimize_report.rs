//! Tests for dedup, minimize args, and LLM bug report drafting.

use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse};
use hf_core::types::{Message, TokenUsage};
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
    let joined = args.join(" ");
    assert!(joined.contains("-minimize_crash=1"));
    assert!(joined.contains("/work/crash-1"));
    assert!(joined.contains("/work/fuzz_bin"));
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
    let joined = args.join(" ");
    assert!(joined.contains("afl-tmin"));
    assert!(joined.contains("-i") && joined.contains("/work/crash-1"));
    assert!(joined.contains("-o") && joined.contains("/work/minimized"));
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
    fn id(&self) -> &str {
        "mock"
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
