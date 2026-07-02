//! LLM-assisted bug report drafting.

use hf_core::crash::{BugReport, Crash};
use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::types::Message;
use serde::Deserialize;

/// Maximum characters of target source to include in the triage prompt, so a
/// large project does not blow the context window.
pub const MAX_SOURCE_CONTEXT_CHARS: usize = 8000;

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
    let source_block = source.map_or_else(String::new, |s| {
        format!(
            "\nTarget source (for root-cause analysis):\n```\n{}\n```\n",
            &s[..s.len().min(MAX_SOURCE_CONTEXT_CHARS)]
        )
    });
    let prompt = format!(
        "You are the triage-agent for hobot_fuzz.\n\
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
         {source_block}\n\
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
}
