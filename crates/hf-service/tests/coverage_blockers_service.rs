//! Coverage Blocker Explorer service contract.
//!
//! An absent measurement is reported as absent, with no blocker list derived
//! from it, and exploration executes nothing.

#![cfg(feature = "coverage-blockers")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::target::TargetLanguage;
use hf_service::coverage_blockers::{MeasurementStatus, NextExperimentKind};
use hf_service::{CoverageBlockerRequest, ServiceContainer};

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_blockers_it");
}

/// A runtime that records commands and never produces a coverage export.
struct CountingRuntime {
    calls: AtomicUsize,
}

impl CountingRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CountingRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "no coverage tooling".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

fn write_sample_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size) {\n\
         \x20 if (size > 0 && data[0] == 'A') { return 1; }\n\
         \x20 return 0;\n}\n",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn no_coverage_measurement_reports_unavailable_with_no_blocker_list() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = CountingRuntime::new();
    let container = ServiceContainer::new(runtime.clone(), None);

    let view = container
        .explore_coverage_blockers(CoverageBlockerRequest {
            project: project.path().display().to_string(),
            target: "parse_entry".to_owned(),
            lang: TargetLanguage::C,
        })
        .await
        .expect("an absent measurement is a result, not an error");

    match view.measurement {
        MeasurementStatus::Unavailable { ref reason_code } => {
            assert!(
                !reason_code.is_empty(),
                "an absent measurement names why it is absent"
            );
        }
        MeasurementStatus::Available { .. } => {
            panic!("no coverage pipeline ran, so no measurement can be available")
        }
    }
    assert!(
        view.blockers.is_empty(),
        "a blocker list derived from no measurement would be fabrication"
    );
    assert_eq!(
        view.experiment.kind,
        NextExperimentKind::NoExperimentAvailable
    );
}

#[tokio::test]
async fn an_unknown_target_is_refused_rather_than_explored_as_empty() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = CountingRuntime::new();
    let container = ServiceContainer::new(runtime.clone(), None);

    let error = container
        .explore_coverage_blockers(CoverageBlockerRequest {
            project: project.path().display().to_string(),
            target: "not_a_function".to_owned(),
            lang: TargetLanguage::C,
        })
        .await
        .expect_err("an unknown target is not an empty exploration");
    assert!(
        error.to_string().contains("not_a_function"),
        "the refusal names the target: {error}"
    );
}
