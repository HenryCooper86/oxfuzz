//! A report asks for its coverage measurement once.
//!
//! The report shows coverage totals and a covered-function count. Both come
//! from one sandboxed measurement that compiles and executes the harness, so
//! composing a report is one approval decision, not one per figure. Asking
//! twice showed an operator two prompts for one click and wrote two audit
//! rows for one refusal.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_service::{Action, AiPolicy, ApprovalGate, ServiceContainer};

/// Declines every request and counts them.
#[derive(Default)]
struct CountingDecline {
    coverage_requests: AtomicUsize,
}

#[async_trait::async_trait]
impl ApprovalGate for CountingDecline {
    async fn request_approval(&self, action: &Action, _: &str) -> bool {
        if matches!(action, Action::RunHarness) {
            self.coverage_requests.fetch_add(1, Ordering::SeqCst);
        }
        false
    }
}

#[tokio::test]
async fn composing_a_report_requests_its_coverage_measurement_once() {
    common::install_managed_workspace("oxfuzz_report_coverage_it");
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "int parse_entry(const unsigned char *data, unsigned long size) { return size && data[0]; }\n",
    )
    .unwrap();
    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    std::fs::create_dir_all(&workspace).unwrap();
    // A staged harness is the measurement's only precondition.
    std::fs::write(
        workspace.join("harness.c"),
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }\n",
    )
    .unwrap();

    let gate = Arc::new(CountingDecline::default());
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_guardrails(
        hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy::default(),
            Arc::clone(&gate) as Arc<dyn ApprovalGate>,
        ),
    );

    let markdown = container
        .generate_report_for_run(
            project.path(),
            "parse_entry",
            hf_service::ReportLanguage::En,
            None,
            AiPolicy::Off,
        )
        .await
        .expect("a declined measurement still yields the fact-sheet");

    assert!(markdown.contains("## Executive Summary"), "{markdown}");
    assert_eq!(
        gate.coverage_requests.load(Ordering::SeqCst),
        1,
        "one report is one coverage decision"
    );
}
