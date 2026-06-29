//! LLM-assisted bug report drafting.

use hf_core::crash::{BugReport, Crash};
use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::types::Message;
use serde::Deserialize;

/// Draft a bug report for a crash using an LLM.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails or the response is not
/// valid JSON. Invalid JSON is tolerated: a minimal report is returned.
pub async fn draft_report(
    crash: &Crash,
    log: &str,
    llm: Box<dyn LlmProvider>,
) -> Result<BugReport, ClassifiedError> {
    let prompt = format!(
        "You are the triage-agent for hobot_fuzz.\n\
         Your job: classify this crash and draft a bug report.\n\
         Output JSON with fields: title, summary, repro_steps, stack, severity_guess.\n\
         severity_guess must be one of: low, medium, high, critical.\n\
         Do not exaggerate severity. If uncertain, say so in the summary.\n\
         \n\
         Crash kind: {:?}\n\
         Summary: {}\n\
         Stack signature: {}\n\
         \n\
         Log:\n\
         {}",
        crash.kind, crash.summary, crash.stack_signature, log,
    );
    let messages = vec![Message::user(prompt)];
    let req = ChatRequest::from_messages(messages);
    let resp = llm.chat_completion(&req).await?;
    let report: BugReportUpdate = match serde_json::from_str(resp.text()) {
        Ok(r) => r,
        Err(_) => {
            return Ok(BugReport {
                title: format!("{:?} in target", crash.kind),
                summary: crash.summary.clone(),
                repro_steps: format!(
                    "Run fuzzer with crash input: {}",
                    crash.input_path.display()
                ),
                stack: crash.stack_signature.clone(),
                severity_guess: "uncertain".to_owned(),
            });
        }
    };
    Ok(BugReport {
        title: report.title,
        summary: report.summary,
        repro_steps: report.repro_steps,
        stack: report.stack,
        severity_guess: report.severity_guess,
    })
}

#[derive(Debug, Deserialize)]
struct BugReportUpdate {
    title: String,
    summary: String,
    repro_steps: String,
    stack: String,
    severity_guess: String,
}
