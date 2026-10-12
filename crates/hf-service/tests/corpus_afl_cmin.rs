//! Integration tests for batch corpus distillation (`corpus_afl_cmin`): one
//! sandboxed `afl-cmin` invocation reduces the corpus to a minimum covering
//! set, validated host-side before adoption, with the retained corpus never
//! touched by a failed or garbage run.

mod common;

use std::sync::Arc;

use hf_service::ServiceContainer;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let workspace = common::install_managed_workspace("oxfuzz_aflcmin_it");
        let config = workspace.parent().unwrap().join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("oxfuzz.toml"),
            r#"
[fuzzing]
enabled_engines = ["libfuzzer", "afl++", "honggfuzz", "syzkaller"]
default_engine = "libfuzzer"
default_duration_secs = 60

[fuzzing.sandbox]
max_mem_mb = 3072
max_cpus = 3
max_duration_secs = 7200
"#,
        )
        .unwrap();
        std::env::set_var("HF_CONFIG_DIR", config);
    });
}

/// How the stub afl-cmin invocation behaves.
#[derive(Clone, Copy)]
enum CminBehavior {
    /// Copy the listed corpus entries into the output directory.
    Distill(&'static [&'static str]),
    /// Exit 0 with an empty output directory.
    Empty,
    /// Exit 0 with an output entry whose bytes were never in the corpus.
    Foreign,
    /// Exit 1 with a diagnostic.
    Fail,
}

/// A runtime that answers compile/smoke probes generically and simulates
/// `afl-cmin` by resolving the container paths through the sandbox mounts.
struct CminRuntime {
    behavior: CminBehavior,
    cmin_argv: std::sync::Mutex<Option<Vec<String>>>,
    cmin_limits: std::sync::Mutex<Option<hf_core::runtime::ResourceLimits>>,
    corpus_mount_writable: std::sync::atomic::AtomicBool,
    hardened_mounts: std::sync::atomic::AtomicBool,
}

impl CminRuntime {
    fn new(behavior: CminBehavior) -> Self {
        Self {
            behavior,
            cmin_argv: std::sync::Mutex::new(None),
            cmin_limits: std::sync::Mutex::new(None),
            corpus_mount_writable: std::sync::atomic::AtomicBool::new(false),
            hardened_mounts: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

fn option_value(cmd: &[String], flag: &str) -> String {
    let at = cmd.iter().position(|arg| arg == flag).expect(flag);
    cmd.get(at + 1).expect(flag).clone()
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CminRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        if hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64) {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        if cmd.first().is_some_and(|command| command == "afl-cmin") {
            *self.cmin_argv.lock().unwrap() = Some(cmd.to_vec());
            *self.cmin_limits.lock().unwrap() = Some(limits.clone());
            let input_container = option_value(cmd, "-i");
            let output_container = option_value(cmd, "-o");
            let input = opts
                .extra_mounts
                .iter()
                .find(|mount| mount.container_path == input_container)
                .expect("run-owned corpus snapshot mount");
            let output = opts
                .extra_mounts
                .iter()
                .find(|mount| mount.container_path == output_container)
                .expect("run-owned distillation output mount");
            self.corpus_mount_writable
                .store(!input.read_only, std::sync::atomic::Ordering::Relaxed);
            self.hardened_mounts.store(
                opts.workspace_read_only
                    && !output.read_only
                    && opts.max_file_size_bytes == Some(16 * 1024 * 1024),
                std::sync::atomic::Ordering::Relaxed,
            );
            match self.behavior {
                CminBehavior::Distill(survivors) => {
                    for name in survivors {
                        std::fs::write(
                            output.host_path.join(name),
                            std::fs::read(input.host_path.join(name)).unwrap(),
                        )
                        .unwrap();
                    }
                }
                CminBehavior::Empty => {}
                CminBehavior::Foreign => {
                    std::fs::write(output.host_path.join("foreign"), b"never in the corpus")
                        .unwrap();
                }
                CminBehavior::Fail => {
                    return Ok(hf_core::runtime::CommandResult {
                        exit_code: 1,
                        stdout: String::new(),
                        stderr: "afl-cmin: no instrumentation output detected".to_owned(),
                        workspace: cwd.to_path_buf(),
                        termination: hf_core::runtime::CommandTermination::Completed,
                    });
                }
            }
        }
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
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
        _opts: &hf_core::runtime::SandboxOptions,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
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

/// Compile, smoke, and promote an AFL++ harness for `target` with a three
/// entry corpus; returns the corpus directory.
async fn promoted_afl_target(
    container: &ServiceContainer,
    project: &std::path::Path,
    target: &str,
) -> std::path::PathBuf {
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C, None,
            false,
        )
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(project, target);
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("a"), b"input-aaaa").unwrap();
    std::fs::write(corpus.join("b"), b"input-bbbb").unwrap();
    std::fs::write(corpus.join("c"), b"input-cccc").unwrap();
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();
    container
        .harness_smoke(
            project,
            target,
            hf_core::engine::EngineKind::AflPlusPlus,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(project, target, hf_core::engine::EngineKind::AflPlusPlus)
        .await
        .unwrap();
    corpus
}

#[tokio::test]
async fn afl_cmin_distills_the_corpus_in_one_batch_invocation() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cminproj");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmin.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CminRuntime::new(CminBehavior::Distill(&["a", "c"])));
    let container = ServiceContainer::new(
        runtime.clone(),
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    let corpus = promoted_afl_target(&container, &project, target).await;

    // Smoke qualification retains its own run evidence; a distillation must
    // not add to it.
    let runs = hf_service::workspace_dir(&project, target).join("runs");
    let runs_before: Vec<std::ffi::OsString> = std::fs::read_dir(&runs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();

    let outcome = container
        .corpus_afl_cmin(&project, target)
        .await
        .expect("batch distillation should run");

    assert_eq!(outcome.before, 3);
    assert_eq!(outcome.before_bytes, 30);
    assert_eq!(outcome.after, 2);
    assert_eq!(outcome.after_bytes, 20);
    let retained = hf_corpus::list(&corpus).unwrap();
    let mut names: Vec<String> = retained
        .entries
        .iter()
        .map(|entry| {
            entry
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["a", "c"],
        "only the distilled survivors stay retained"
    );

    let argv = runtime.cmin_argv.lock().unwrap().clone().unwrap();
    assert_eq!(argv.first().map(String::as_str), Some("afl-cmin"));
    // One batch invocation carries the corpus, the output, the sanitizer-safe
    // memory setting, the configured per-input timeout, and the resolved CPU
    // fan-out; the target argv is the shared file-input contract.
    assert_eq!(option_value(&argv, "-m"), "none");
    assert_eq!(option_value(&argv, "-t"), "1000");
    assert_eq!(option_value(&argv, "-T"), "3");
    let input_container = option_value(&argv, "-i");
    let output_container = option_value(&argv, "-o");
    assert!(input_container.ends_with("/corpus"), "{argv:?}");
    assert!(output_container.ends_with("/out"), "{argv:?}");
    let separator = argv.iter().position(|arg| arg == "--").unwrap();
    let target_argv = &argv[separator + 1..];
    assert_eq!(target_argv.len(), 2, "{argv:?}");
    assert!(target_argv[0].ends_with("/input/harness"), "{argv:?}");
    assert_eq!(target_argv[1], "@@");

    // The sandbox posture: workspace read-only, corpus snapshot writable
    // (afl-cmin writes a link probe into its input dir), bounded output.
    assert!(runtime
        .corpus_mount_writable
        .load(std::sync::atomic::Ordering::Relaxed));
    assert!(runtime
        .hardened_mounts
        .load(std::sync::atomic::Ordering::Relaxed));
    let limits = runtime.cmin_limits.lock().unwrap().clone().unwrap();
    assert_eq!(limits.max_mem_mb, 3072);
    assert_eq!(limits.max_cpus, 3);
    assert_eq!(limits.max_duration_secs, 600);

    // Staging is run-scoped and cleaned up after adoption: the operation
    // leaves no new entry in the target's runs directory.
    let runs_after: Vec<std::ffi::OsString> = std::fs::read_dir(&runs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        runs_before, runs_after,
        "the run staging directory must not outlive the operation"
    );
}

#[tokio::test]
async fn afl_cmin_rejects_an_empty_survivor_set_and_keeps_the_corpus() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cminempty");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_empty";
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_empty(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmin-empty.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CminRuntime::new(CminBehavior::Empty));
    let container = ServiceContainer::new(
        runtime,
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    let corpus = promoted_afl_target(&container, &project, target).await;

    let error = container
        .corpus_afl_cmin(&project, target)
        .await
        .expect_err("an empty distillation must fail loud");

    assert!(error.to_string().contains("empty survivor set"), "{error}");
    assert_eq!(
        hf_corpus::list(&corpus).unwrap().entries.len(),
        3,
        "the retained corpus is untouched"
    );
}

#[tokio::test]
async fn afl_cmin_rejects_output_that_was_never_in_the_corpus() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cminforeign");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_foreign";
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_foreign(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmin-foreign.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CminRuntime::new(CminBehavior::Foreign));
    let container = ServiceContainer::new(
        runtime,
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    let corpus = promoted_afl_target(&container, &project, target).await;

    let error = container
        .corpus_afl_cmin(&project, target)
        .await
        .expect_err("a garbage distillation must fail loud");

    assert!(error.to_string().contains("never in the corpus"), "{error}");
    assert_eq!(hf_corpus::list(&corpus).unwrap().entries.len(), 3);
}

#[tokio::test]
async fn afl_cmin_propagates_sandbox_failure_without_distilling() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cminfail");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_fail";
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_fail(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmin-fail.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CminRuntime::new(CminBehavior::Fail));
    let container = ServiceContainer::new(
        runtime,
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    let corpus = promoted_afl_target(&container, &project, target).await;

    let error = container
        .corpus_afl_cmin(&project, target)
        .await
        .expect_err("a failed afl-cmin run must fail loud");

    assert!(error.to_string().contains("status 1"), "{error}");
    assert_eq!(hf_corpus::list(&corpus).unwrap().entries.len(), 3);
}

#[tokio::test]
async fn afl_cmin_requires_a_promoted_afl_harness() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cminunpromoted");
    std::fs::create_dir_all(&project).unwrap();
    let target = "parse_unpromoted";
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_unpromoted(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmin-unpromoted.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CminRuntime::new(CminBehavior::Distill(&["a"])));
    let container = ServiceContainer::new(
        runtime.clone(),
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C, None,
            false,
        )
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("a"), b"input-aaaa").unwrap();
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();

    let error = container
        .corpus_afl_cmin(&project, target)
        .await
        .expect_err("an unpromoted harness must not drive distillation");

    assert!(
        error
            .to_string()
            .contains("explicitly promoted AFL++ harness"),
        "{error}"
    );
    assert!(
        runtime.cmin_argv.lock().unwrap().is_none(),
        "no sandbox invocation happened"
    );
}
