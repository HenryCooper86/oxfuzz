//! LLM-assisted bug report drafting.

use hf_core::crash::{BugReport, Crash};
use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::types::Message;
use serde::Deserialize;

/// Maximum characters of target source to include in the triage prompt, so a
/// large project does not blow the context window.
pub const MAX_SOURCE_CONTEXT_CHARS: usize = 8000;

/// Length to keep from `s`, floored to a UTF-8 char boundary so slicing
/// `&s[..n]` never panics on a multibyte character straddling the limit.
/// Source with non-ASCII bytes (accented identifiers, non-English comments,
/// a stray `©`) routinely crosses the 8000-byte mark mid-character.
fn char_floor(s: &str, max: usize) -> usize {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Draft a bug report for a crash using an LLM.
///
/// When `source` is provided (the relevant target source), the model is asked
/// to also infer the root cause and propose a fix (ideally a unified diff),
/// which is the output users act on. `source` is truncated by the caller to a
/// sane budget.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails. Invalid JSON is tolerated:
/// a minimal report is returned.
pub async fn draft_report(
    crash: &Crash,
    log: &str,
    source: Option<&str>,
    llm: Box<dyn LlmProvider>,
) -> Result<BugReport, ClassifiedError> {
    draft_report_with_context(crash, log, source, None, llm).await
}

/// Draft a bug report for a crash using an LLM, optionally augmented with
/// related project context retrieved from the knowledge index (rendered by
/// the caller). `None` renders the [`draft_report`] prompt unchanged, so a
/// missing index or failed retrieval degrades gracefully.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails. Invalid JSON is tolerated:
/// a minimal report is returned.
pub async fn draft_report_with_context(
    crash: &Crash,
    log: &str,
    source: Option<&str>,
    related_context: Option<&str>,
    llm: Box<dyn LlmProvider>,
) -> Result<BugReport, ClassifiedError> {
    let source_block = source.map_or_else(String::new, |s| {
        format!(
            "\nTarget source (for root-cause analysis):\n```\n{}\n```\n",
            &s[..char_floor(s, MAX_SOURCE_CONTEXT_CHARS)]
        )
    });
    let related_block = related_context.map_or_else(String::new, |r| format!("\n{r}\n"));
    let prompt = format!(
        "You are the triage-agent for oxfuzz.\n\
         Your job: classify this crash, draft a bug report, and -- when source is \
         provided -- identify the root cause and propose a fix.\n\
         Output JSON with fields: title, summary, repro_steps, stack, severity_guess, \
         root_cause, suggested_fix.\n\
         severity_guess must be one of: low, medium, high, critical.\n\
         root_cause: one or two sentences on what is wrong in the code and why the \
         input triggers it (empty string if you cannot tell).\n\
         suggested_fix: a minimal fix, ideally a unified-diff patch against the source \
         (empty string if you cannot propose one).\n\
         Do not exaggerate severity. If uncertain, say so in the summary.\n\
         \n\
         Crash kind: {:?}\n\
         Summary: {}\n\
         Stack signature: {}\n\
         {source_block}{related_block}\n\
         Log:\n\
         {}",
        crash.kind, crash.summary, crash.stack_signature, log,
    );
    let messages = vec![Message::user(prompt)];
    let req = ChatRequest::from_messages(messages);
    let resp = llm.chat_completion(&req).await?;
    let report: BugReportUpdate = match parse_report_json(resp.text()) {
        Some(r) => r,
        None => {
            return Ok(BugReport {
                title: format!("{:?} in target", crash.kind),
                summary: crash.summary.clone(),
                repro_steps: format!(
                    "Run fuzzer with crash input: {}",
                    crash.input_path.display()
                ),
                stack: crash.stack_signature.clone(),
                severity_guess: "uncertain".to_owned(),
                root_cause: None,
                suggested_fix: None,
            });
        }
    };
    Ok(BugReport {
        title: report.title,
        summary: report.summary,
        repro_steps: report.repro_steps,
        stack: report.stack,
        severity_guess: report.severity_guess,
        root_cause: non_empty(&report.root_cause),
        suggested_fix: non_empty(&report.suggested_fix),
    })
}

/// Parse the first JSON object out of a model response, tolerating surrounding
/// prose or code fences.
fn parse_report_json(text: &str) -> Option<BugReportUpdate> {
    if let Ok(r) = serde_json::from_str::<BugReportUpdate>(text) {
        return Some(r);
    }
    let start = text.find('{')?;
    serde_json::Deserializer::from_str(&text[start..])
        .into_iter::<BugReportUpdate>()
        .next()?
        .ok()
}

/// Map an empty/blank string to `None` so absent fields are not stored as `""`.
fn non_empty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[derive(Debug, Deserialize)]
struct BugReportUpdate {
    title: String,
    summary: String,
    repro_steps: String,
    stack: String,
    severity_guess: String,
    #[serde(default)]
    root_cause: String,
    #[serde(default)]
    suggested_fix: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::provider::{
        ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderMetadata,
    };
    use hf_core::types::TokenUsage;
    use std::sync::{Arc, Mutex};

    /// A provider that records the last prompt it received, so tests can
    /// assert what context actually reached the model.
    struct CaptureLlm {
        seen: Arc<Mutex<String>>,
    }

    #[async_trait::async_trait]
    impl LlmProvider for CaptureLlm {
        async fn chat_completion(
            &self,
            request: &ChatRequest,
        ) -> Result<ChatResponse, ProviderError> {
            *self.seen.lock().expect("capture lock") = request
                .messages
                .last()
                .map(|m| m.content.clone())
                .unwrap_or_default();
            Ok(ChatResponse {
                id: "capture".to_owned(),
                model: "capture".to_owned(),
                content: Some("not json".to_owned()),
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
            use hf_core::provider::{ProviderCapability, ProviderType, ToolCallingMode};
            static M: std::sync::OnceLock<ProviderMetadata> = std::sync::OnceLock::new();
            M.get_or_init(|| ProviderMetadata {
                id: hf_core::types::ProviderId::from_string("capture"),
                provider_type: ProviderType::Custom,
                model: "capture".to_owned(),
                tags: Vec::new(),
                capabilities: vec![ProviderCapability::Text],
                max_concurrency: 1,
                context_window: 128_000,
                cost_per_1k_input: 0.0,
                cost_per_1k_output: 0.0,
                tool_calling_mode: ToolCallingMode::Native,
            })
        }
    }

    fn crash() -> Crash {
        Crash {
            id: uuid::Uuid::new_v4(),
            run_id: uuid::Uuid::new_v4(),
            target_id: uuid::Uuid::new_v4(),
            input_path: std::path::PathBuf::from("/work/crash-1"),
            stack_signature: "parse_header+0x12".to_owned(),
            kind: hf_core::crash::CrashKind::Asan,
            summary: "heap-buffer-overflow in parse_header".to_owned(),
            minimized: false,
            bug_report: None,
            casr: None,
        }
    }

    #[tokio::test]
    async fn draft_report_with_context_includes_related_block() {
        let seen = Arc::new(Mutex::new(String::new()));
        let report = draft_report_with_context(
            &crash(),
            "asan log",
            None,
            Some("Related project context:\n--- caller.c ---\nparse_header(buf, len);"),
            Box::new(CaptureLlm {
                seen: Arc::clone(&seen),
            }),
        )
        .await
        .expect("draft should tolerate non-json");
        // Invalid JSON still yields a minimal report (generation proceeds).
        assert_eq!(report.severity_guess, "uncertain");
        let prompt = seen.lock().expect("capture lock").clone();
        assert!(prompt.contains("Related project context"), "{prompt}");
        assert!(prompt.contains("parse_header(buf, len);"), "{prompt}");
    }

    #[tokio::test]
    async fn draft_report_without_context_sends_base_prompt() {
        let seen = Arc::new(Mutex::new(String::new()));
        draft_report(
            &crash(),
            "asan log",
            None,
            Box::new(CaptureLlm {
                seen: Arc::clone(&seen),
            }),
        )
        .await
        .expect("draft should succeed");
        let prompt = seen.lock().expect("capture lock").clone();
        assert!(!prompt.contains("Related project context"), "{prompt}");
    }

    #[test]
    fn parses_root_cause_and_fix_from_json() {
        let json = r#"{"title":"UAF","summary":"use after free","repro_steps":"run","stack":"f->g",
            "severity_guess":"high","root_cause":"frees buf then reads it",
            "suggested_fix":"--- a\n+++ b\n@@ move free after read"}"#;
        let r = parse_report_json(json).expect("valid json");
        assert_eq!(
            non_empty(&r.root_cause).as_deref(),
            Some("frees buf then reads it")
        );
        assert!(non_empty(&r.suggested_fix)
            .unwrap()
            .contains("move free after read"));
    }

    #[test]
    fn empty_fix_becomes_none() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("  "), None);
        assert_eq!(non_empty("x"), Some("x".to_owned()));
    }

    #[test]
    fn tolerates_missing_root_cause_and_fix_fields() {
        // Older-style response without the new fields still parses.
        let json =
            r#"{"title":"t","summary":"s","repro_steps":"r","stack":"st","severity_guess":"low"}"#;
        let r = parse_report_json(json).expect("valid json");
        assert_eq!(r.root_cause, "");
        assert_eq!(r.suggested_fix, "");
    }

    #[test]
    fn char_floor_never_splits_a_multibyte_char() {
        // A 3-byte char (U+00A9 is 2 bytes; U+20AC EURO SIGN is 3 bytes) placed
        // so the limit lands in its middle must floor back to a boundary, so the
        // subsequent slice does not panic.
        let s = "abc€def"; // '€' occupies bytes 3..6
        for max in 0..=s.len() {
            let end = char_floor(s, max);
            assert!(s.is_char_boundary(end), "floor must land on a boundary");
            let _ = &s[..end]; // must not panic
            assert!(end <= max);
        }
        // A limit that lands inside '€' (byte 4 or 5) floors to byte 3.
        assert_eq!(char_floor(s, 4), 3);
        assert_eq!(char_floor(s, 5), 3);
        assert_eq!(char_floor(s, 6), 6);
        // Beyond the string keeps the whole string.
        assert_eq!(char_floor(s, 999), s.len());
    }
}
