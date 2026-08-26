//! Concolic enrichment through the service.
//!
//! With no sandbox image the pass must report unavailable and leave the corpus
//! untouched, rather than reporting a completed pass that did nothing.

#![cfg(feature = "concolic-enrichment")]

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_service::{ConcolicAvailability, ServiceContainer};
use uuid::Uuid;

#[tokio::test]
async fn a_missing_toolchain_is_unavailable_with_a_reason() {
    // StubRuntime reports no image, which is the same shape as an image
    // without the SymCC layer.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let availability = container.concolic_availability().await;

    assert!(
        matches!(availability, ConcolicAvailability::Unavailable { .. }),
        "an absent toolchain is unavailable, not a failed pass"
    );
}

#[tokio::test]
async fn an_unavailable_toolchain_does_not_touch_the_corpus() {
    let dir = tempfile::tempdir().unwrap();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let result = container.corpus_concolic(dir.path(), "parse_packet").await;

    assert!(
        result.is_err(),
        "a pass that cannot run reports so rather than returning an empty success"
    );
}

/// Answers the availability probe (`command -v symcc`) as present, then fails
/// every other command -- standing in for a sandbox image that has `SymCC`
/// but whose instrumented build does not succeed.
struct AvailableButBuildFailsRuntime;

#[async_trait]
impl RuntimeAdapter for AvailableButBuildFailsRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        if cmd.iter().any(|arg| arg.contains("command -v symcc")) {
            return Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            });
        }
        Err(ClassifiedError::Sandbox(
            "symcc: no such target harness.c".to_owned(),
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        panic!("the concolic pass does not write files directly through the runtime")
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        panic!("the concolic pass does not read files directly through the runtime")
    }
}

/// A dedicated workspace root for this test file only, isolated from every
/// other integration test binary (each `tests/*.rs` file is its own process).
fn workspace_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_concolic_service_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().unwrap();
        root
    })
}

#[tokio::test]
async fn a_build_failure_is_reported_as_an_error_never_as_an_empty_success() {
    // Note: both tests above short-circuit at the availability check, since
    // `StubRuntime` errors on every `run_command` -- neither reaches the
    // build. This double answers the probe so the pass actually reaches
    // `run_concolic_pass` and its build step.
    let root = workspace_root();
    let project = root.join("build_failure_project");
    std::fs::create_dir_all(&project).unwrap();

    let container = ServiceContainer::new(Arc::new(AvailableButBuildFailsRuntime), None);
    let workspace = hf_service::workspace_dir(&project, "parse_packet");
    let corpus_dir = workspace.join("corpus");
    std::fs::create_dir_all(&corpus_dir).unwrap();
    std::fs::write(corpus_dir.join("seed"), b"AAAA").unwrap();

    let result = container.corpus_concolic(&project, "parse_packet").await;

    assert!(
        result.is_err(),
        "a build that never produced an instrumented binary must not be reported as a \
         completed pass that solved nothing -- that is indistinguishable from a pass that \
         legitimately solved nothing"
    );
}
