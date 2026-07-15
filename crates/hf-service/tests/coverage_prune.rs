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
struct ShowmapRuntime {
    saw_read_only: std::sync::atomic::AtomicBool,
    fail_showmap: bool,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for ShowmapRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let is_showmap = cmd.first().is_some_and(|command| command == "afl-showmap");
        if is_showmap && self.fail_showmap {
            return Err(hf_core::error::ClassifiedError::Sandbox(
                "showmap unavailable".to_owned(),
            ));
        }
        let input = cmd.last().cloned().unwrap_or_default();
        let stdout = if !is_showmap {
            "DONE exec/s: 64".to_owned()
        } else if input.ends_with("/c") {
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

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        if cmd.first().is_some_and(|command| command == "afl-showmap") {
            self.saw_read_only.store(
                opts.workspace_read_only,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        self.run_command(cmd, cwd, limits).await
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

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("coverage.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(ShowmapRuntime {
        saw_read_only: std::sync::atomic::AtomicBool::new(false),
        fail_showmap: false,
    });
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::AflPlusPlus,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::AflPlusPlus)
        .await
        .unwrap();
    let outcome = container
        .corpus_prune_coverage(&project, target)
        .await
        .expect("coverage prune should run");

    assert_eq!(outcome.before, 3);
    // a and b collapse (same coverage); c survives. => 2.
    assert_eq!(outcome.after, 2, "coverage-equal inputs should collapse");
    assert!(runtime
        .saw_read_only
        .load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn coverage_prune_propagates_sandbox_failure_without_pruning() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("covprune-failure-project");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_failure";
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("a"), b"first distinct input").unwrap();
    std::fs::write(corpus.join("b"), b"second distinct input").unwrap();
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("failure.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(ShowmapRuntime {
        saw_read_only: std::sync::atomic::AtomicBool::new(false),
        fail_showmap: true,
    });
    let container = ServiceContainer::new(runtime, None).with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::AflPlusPlus,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::AflPlusPlus)
        .await
        .unwrap();

    let error = container
        .corpus_prune_coverage(&project, target)
        .await
        .expect_err("sandbox failures must not be reported as successful pruning");

    assert!(error.to_string().contains("showmap unavailable"));
    assert_eq!(hf_corpus::list(&corpus).unwrap().entries.len(), 2);
}
