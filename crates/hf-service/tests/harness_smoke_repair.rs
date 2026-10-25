//! Smoke-failure repair: a harness that compiles but never runs is rewritten
//! from the engine output, recompiled as a new revision, and smoke-qualified
//! again (harness-generation-design section 3 step 5).

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::{HarnessReviewBypass, ServiceContainer};

const SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

/// Engine output of a smoke run that never reached the harness.
const SILENT_ENGINE_OUTPUT: &str = "INFO: Seed: 1\n[!] the entry point returned non-zero";

/// Compiles every harness; the first `silent_smokes` smoke runs produce no
/// fuzzer activity, later ones report throughput.
struct FlakyHarnessRuntime {
    silent_smokes: usize,
    smokes: AtomicUsize,
}

impl FlakyHarnessRuntime {
    fn respond(&self, cmd: &[String], cwd: &Path) -> CommandResult {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        let smoke = cmd.iter().any(|arg| arg.starts_with("-max_total_time"));
        let stdout = if smoke {
            let index = self.smokes.fetch_add(1, Ordering::SeqCst);
            if index < self.silent_smokes {
                SILENT_ENGINE_OUTPUT.to_owned()
            } else {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned()
            }
        } else {
            std::fs::create_dir_all(cwd).unwrap();
            std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
            String::new()
        };
        CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        }
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for FlakyHarnessRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(self.respond(cmd, cwd))
    }

    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(self.respond(cmd, cwd))
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// A new harness revision for each non-review prompt.
fn revision(index: usize, _prompt: &str) -> String {
    format!(
        "```c\n/* revision {index} */\nint parse_entry(const unsigned char *, unsigned long);\nint LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {{ parse_entry(data, size); return 0; }}\n```"
    )
}

async fn fixture(
    silent_smokes: usize,
) -> (
    tempfile::TempDir,
    Arc<hf_test_utils::RecordingHarnessPool>,
    Arc<hf_storage::Store>,
    ServiceContainer,
) {
    common::install_managed_workspace("oxfuzz_smoke_repair_it");
    let project = tempfile::tempdir().unwrap();
    let config = project.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\ncollect_function_coverage = true\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\", \"syzkaller\"]\n\
         default_engine = \"libfuzzer\"\ndefault_duration_secs = 60\n\
         [fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 600\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("smoke-repair.db"))
            .await
            .unwrap(),
    );
    let pool = hf_test_utils::RecordingHarnessPool::new(revision);
    let runtime = Arc::new(FlakyHarnessRuntime {
        silent_smokes,
        smokes: AtomicUsize::new(0),
    });
    let container =
        ServiceContainer::new(runtime, Some(Arc::clone(&pool) as _)).with_store(Arc::clone(&store));
    container
        .harness_compile(
            SOURCE.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap();
    (project, pool, store, container)
}

#[tokio::test]
async fn a_silent_smoke_run_is_repaired_and_requalified() {
    let (project, pool, store, container) = fixture(1).await;

    let attempts = Mutex::new(Vec::new());
    let qualified = container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            2,
            &|attempt, reason: &str| attempts.lock().unwrap().push((attempt, reason.to_owned())),
        )
        .await
        .expect("the repaired revision should smoke-qualify");

    assert!(qualified.smoke.summary.passed);
    assert_eq!(qualified.smoke_repairs, 1);
    let attempts = attempts.into_inner().unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].0, 1);
    assert!(attempts[0].1.contains(hf_harness::SMOKE_NO_ACTIVITY));

    // The repair prompt carried the engine output of the failed smoke run.
    let repairs = pool.prompts_containing("A previous attempt");
    let repair = repairs
        .first()
        .expect("a repair prompt must have been sent");
    assert!(repair.contains("smoke run failed"), "{repair}");
    assert!(
        repair.contains("the entry point returned non-zero"),
        "{repair}"
    );

    // The qualified revision is a new one; the failed revision is not reused.
    let harnesses = store.list_all_harnesses().await.unwrap();
    assert_eq!(harnesses.len(), 2, "the repair compiled a second revision");
    let qualified_revision = harnesses
        .iter()
        .find(|harness| harness.status == hf_core::harness::HarnessStatus::SmokePassed)
        .expect("one revision smoke-passed");
    assert_ne!(qualified_revision.source, SOURCE);
    assert!(qualified_revision
        .source
        .contains("parse_entry(data, size)"));
}

#[tokio::test]
async fn smoke_repair_stops_at_its_budget_with_the_smoke_error() {
    let (project, pool, _store, container) = fixture(usize::MAX).await;

    let error = container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            1,
            &|_, _: &str| {},
        )
        .await
        .expect_err("a harness that never runs must not qualify");
    assert!(
        hf_harness::repairable_smoke_failure(&error).is_some(),
        "the final error is the smoke failure itself: {error}"
    );
    assert_eq!(
        pool.prompts_containing("A previous attempt").len(),
        1,
        "one repair within a budget of one"
    );
}

#[tokio::test]
async fn a_zero_budget_never_repairs() {
    let (project, pool, _store, container) = fixture(1).await;

    container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            0,
            &|_, _: &str| {},
        )
        .await
        .expect_err("without a repair budget the smoke failure surfaces");
    assert!(pool.prompts_containing("A previous attempt").is_empty());
}
