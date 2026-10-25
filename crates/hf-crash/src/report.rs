//! Bug-report parsing.
//!
//! The service renders the drafting prompt (`hf_prompt::render_bug_report_prompt`),
//! retains it, and dispatches it; this module turns the model's answer into a
//! [`BugReport`].

use hf_core::crash::{BugReport, Crash};
use serde::Deserialize;

/// Turn a bug-report model response into a [`BugReport`].
///
/// The response is expected to be a JSON object; surrounding prose or code
/// fences are tolerated. An unparseable response yields a minimal report from
/// the crash evidence itself, so a malformed answer never loses the finding.
#[must_use]
pub fn bug_report_from_response(crash: &Crash, response: &str) -> BugReport {
    let Some(report) = parse_report_json(response) else {
        return BugReport {
            title: format!("{:?} in target", crash.kind),
            summary: crash.summary.clone(),
            repro_steps: format!(
                "Run fuzzer with crash input: {}",
                crash.input_path.display()
            ),
            stack: crash
                .casr
                .as_ref()
                .map(|casr| casr.stack.join("\n"))
                .unwrap_or_default(),
            severity_guess: "uncertain".to_owned(),
            root_cause: None,
            suggested_fix: None,
        };
    };
    BugReport {
        title: report.title,
        summary: report.summary,
        repro_steps: report.repro_steps,
        stack: report.stack,
        severity_guess: report.severity_guess,
        root_cause: non_empty(&report.root_cause),
        suggested_fix: non_empty(&report.suggested_fix),
    }
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
    fn a_json_object_inside_prose_is_found() {
        let text = "Here is the report:\n```json\n{\"title\":\"t\",\"summary\":\"s\",\"repro_steps\":\"r\",\"stack\":\"st\",\"severity_guess\":\"low\"}\n```";
        assert_eq!(parse_report_json(text).expect("embedded json").title, "t");
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
