//! Integration test for coverage-based corpus minimization
//! (`corpus_prune_coverage`): inputs with identical edge coverage collapse even
//! when their bytes differ.

use std::sync::Arc;

use hf_service::ServiceContainer;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "HF_WORKSPACE_DIR",
            std::env::temp_dir().join("hobot_fuzz_covprune_it_workspace"),
        );
    });
}

/// A runtime that returns canned `afl-showmap` output keyed on the input path:
/// inputs `a` and `b` cover the same edges; `c` covers an extra edge.
struct ShowmapRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for ShowmapRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let input = cmd.last().cloned().unwrap_or_default();
        let stdout = if input.ends_with("/c") {
            "1:1\n2:1\n3:1\n".to_owned()
        } else {
            // a and b share coverage.
            "1:1\n2:1\n".to_owned()
        };
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
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

#[tokio::test]
async fn coverage_prune_collapses_same_coverage_inputs() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("covproj");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    // Three distinct-content inputs, so content-dedup alone would keep all 3.
    std::fs::write(corpus.join("a"), b"input-aaaa").unwrap();
    std::fs::write(corpus.join("b"), b"input-bbbb").unwrap();
    std::fs::write(corpus.join("c"), b"input-cccc").unwrap();
    // The compiled harness must exist for coverage measurement to run.
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();

    let container = ServiceContainer::new(Arc::new(ShowmapRuntime), None);
    let outcome = container
        .corpus_prune_coverage(&project, target)
        .await
        .expect("coverage prune should run");

    assert_eq!(outcome.before, 3);
    // a and b collapse (same coverage); c survives. => 2.
    assert_eq!(outcome.after, 2, "coverage-equal inputs should collapse");
}
