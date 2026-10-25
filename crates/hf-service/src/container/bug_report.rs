//! LLM bug-report drafting for triaged crashes.
//!
//! The prompt shows the model the code under test (the target definition and
//! the lines around the faulting line), the normalized stack, and the harness
//! labelled as the driver it is, so its root cause and fix are about the
//! project rather than about generated harness code. Each prompt is retained
//! in `crash_report_drafts` before dispatch and its response after
//! (Engineering Protocol 2.13).

use std::path::Path;
use std::sync::Arc;

use hf_core::crash::{BugReport, Crash};
use hf_core::provider::{ChatRequest, LlmProvider as _, ProviderPool};
use hf_core::target::TargetCandidate;
use hf_core::types::Message;
use hf_storage::Store;

use super::target_source::{read_crash_site, read_target_definition};
use super::{LlmProviderBridge, ServiceContainer};

/// Everything one draft is built from besides the crash record.
pub(super) struct BugReportInputs<'a> {
    /// Canonical project root; every source excerpt is read from inside it.
    pub(super) root: &'a Path,
    /// The project path as the caller named it (knowledge-index key).
    pub(super) project: &'a Path,
    /// The target selector of the run.
    pub(super) target: &'a str,
    /// The crash's sanitizer or engine log, or its summary.
    pub(super) log: &'a str,
    /// The run's retained harness source.
    pub(super) harness_source: Option<&'a str>,
    /// The persisted discovery target the crash belongs to.
    pub(super) candidate: Option<&'a TargetCandidate>,
}

/// Render the drafting prompt from the crash and its inputs.
pub(super) fn bug_report_prompt(crash: &Crash, inputs: &BugReportInputs<'_>) -> String {
    let target_definition = inputs.candidate.and_then(|candidate| {
        read_target_definition(inputs.root, candidate).map(|definition| {
            hf_prompt::render_target_source_section(
                &definition.relative_file,
                candidate.location.line,
                &definition.excerpt,
            )
        })
    });
    let crash_site = hf_crash::fault_location(inputs.log, crash.casr.as_ref())
        .and_then(|(file, line)| read_crash_site(inputs.root, &file, line))
        .map(|site| {
            hf_prompt::render_crash_site_section(
                &site.relative_file,
                site.first_line,
                site.crash_line,
                &site.excerpt,
            )
        });
    // Related project context is empty when the project is not indexed,
    // which renders the prompt without the section.
    let related =
        crate::knowledge::triage_related_context(inputs.project, inputs.target, &crash.summary);
    let related = hf_prompt::render_related_context_section(&related);
    hf_prompt::render_bug_report_prompt(
        crash,
        &hf_prompt::BugReportEvidence {
            log: inputs.log,
            harness_source: inputs.harness_source,
            target_definition: target_definition.as_deref(),
            crash_site: crash_site.as_deref(),
            related_context: (!related.is_empty()).then_some(related.as_str()),
        },
    )
}

impl ServiceContainer {
    /// Draft one bug report: render the prompt, retain it, dispatch it,
    /// retain the response, and parse it.
    ///
    /// Returns `None`, with a warning, when the prompt exceeds the retained
    /// size, cannot be retained (the provider is then never called), or the
    /// provider call fails. A report is advisory enrichment of a finding that
    /// triage has already persisted, so none of these fail triage.
    pub(super) async fn draft_bug_report(
        &self,
        store: &Store,
        pool: Arc<dyn ProviderPool>,
        crash: &Crash,
        inputs: &BugReportInputs<'_>,
    ) -> Option<BugReport> {
        let prompt = bug_report_prompt(crash, inputs);
        if prompt.len() > hf_storage::MAX_CRASH_REPORT_DRAFT_BYTES {
            tracing::warn!(
                crash = %crash.id,
                bytes = prompt.len(),
                "bug-report prompt exceeds the retained size; no report drafted"
            );
            return None;
        }
        let record = hf_storage::CrashReportDraftRecord {
            id: uuid::Uuid::new_v4(),
            crash_id: crash.id,
            run_id: crash.run_id,
            project_root: inputs.root.to_string_lossy().into_owned(),
            prompt_version: hf_prompt::BUG_REPORT_PROMPT_VERSION,
            prompt,
            response: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };
        if let Err(error) = store.begin_crash_report_draft(&record).await {
            tracing::warn!(crash = %crash.id, %error, "bug-report prompt not retained; no report drafted");
            return None;
        }
        let bridge = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
        let request = ChatRequest::from_messages(vec![Message::user(record.prompt)]);
        let response = match bridge.chat_completion(&request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(crash = %crash.id, %error, "bug report drafting failed");
                return None;
            }
        };
        let text = response.text();
        if let Err(error) = store
            .complete_crash_report_draft(record.id, text, chrono::Utc::now())
            .await
        {
            // The prompt is retained; only the raw response is missing. The
            // parsed report is still stored on the crash row.
            tracing::warn!(crash = %crash.id, %error, "bug-report response not retained");
        }
        Some(hf_crash::bug_report_from_response(crash, text))
    }
}
