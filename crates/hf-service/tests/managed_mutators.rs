#![cfg(feature = "managed-mutators")]
mod common;
use hf_core::{
    engine::EngineKind,
    error::ClassifiedError,
    runtime::{
        CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
    },
    target::TargetLanguage,
};
use hf_service::ServiceContainer;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const BASE:&str="#include <stdint.h>\n#include <stddef.h>\nint parse(const uint8_t*d,size_t n);\nint LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return parse(d,n);}";
const MUTATOR:&str="void *afl_custom_init(void *afl,unsigned int seed){return afl;} void afl_custom_deinit(void *state){} size_t afl_custom_fuzz(void*s,unsigned char*b,size_t n,unsigned char**out,unsigned char*a,size_t z,size_t max){*out=b;return n;}";
type Call = (Vec<String>, std::collections::HashMap<String, String>);
#[derive(Default)]
struct Runtime {
    calls: Mutex<Vec<Call>>,
}
#[async_trait::async_trait]
impl RuntimeAdapter for Runtime {
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
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        _options: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls
            .lock()
            .unwrap()
            .push((cmd.to_vec(), limits.env.clone()));
        if cmd.first().is_some_and(|part| part == "bash") {
            let name = if cmd.join(" ").contains("-DOXFUZZ_MUTATOR_BUILD") {
                "fuzz_parse.mutator.so"
            } else {
                "fuzz_parse"
            };
            std::fs::write(cwd.join(name), format!("built:{name}")).unwrap();
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: "exec/s: 512\nOXFUZZ_NATIVE_MUTATION_OK_V1\n".into(),
            stderr: String::new(),
            workspace: cwd.into(),
            termination: CommandTermination::Completed,
        })
    }
    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        options: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        on_line("exec speed : 512/sec");
        self.run_command_opts(cmd, cwd, limits, options).await
    }
    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        std::fs::write(path, content).unwrap();
        Ok(())
    }
    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        std::fs::read_to_string(path).map_err(|error| ClassifiedError::Internal(error.to_string()))
    }
}

#[tokio::test]
async fn imported_mutator_requires_new_approval_and_stages_exact_native_library() {
    common::install_managed_workspace("managed-mutators");
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("parser.c"),"#include <stddef.h>\n#include <stdint.h>\nint parse(const uint8_t*d,size_t n){return n && d[0];}").unwrap();
    let config = directory.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\ncollect_function_coverage=false\n[fuzzing.sandbox]\nmax_cpus=1\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("test.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(Runtime::default());
    let service = ServiceContainer::new(
        runtime.clone(),
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store.clone());
    let original = service
        .harness_compile(
            BASE.into(),
            &project,
            EngineKind::AflPlusPlus,
            "parse",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap();
    let attached = service
        .attach_managed_mutator(
            &project,
            "parse",
            EngineKind::AflPlusPlus,
            original.harness_id,
            MUTATOR.into(),
        )
        .await
        .unwrap();
    assert_ne!(attached.harness_id, original.harness_id);
    assert_eq!(attached.status, hf_core::harness::HarnessStatus::Compiled);
    assert!(attached.mutator.as_ref().unwrap().self_test.is_none());
    let error = service
        .run_fuzzer(
            &project,
            "parse",
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            &|_| {},
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("promot") || error.to_string().contains("qualif"));
    service
        .harness_smoke(
            &project,
            "parse",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    let observed = service
        .managed_mutator_status(&project, "parse", EngineKind::AflPlusPlus)
        .await
        .unwrap();
    assert!(
        observed
            .mutator
            .as_ref()
            .unwrap()
            .self_test
            .as_ref()
            .unwrap()
            .mutation_observed
    );
    service
        .harness_promote(&project, "parse", EngineKind::AflPlusPlus)
        .await
        .unwrap();
    let run = service
        .run_fuzzer(
            &project,
            "parse",
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            &|_| {},
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap();
    {
        let calls = runtime.calls.lock().unwrap();
        let (_, env) = calls
            .iter()
            .rev()
            .find(|(cmd, _)| cmd.first().is_some_and(|s| s == "afl-fuzz"))
            .unwrap();
        let library = env.get("AFL_CUSTOM_MUTATOR_LIBRARY").unwrap();
        assert!(library.contains(&run.run_id.to_string()));
        assert!(library.ends_with("/input/harness.mutator.so"));
    }
    let retained = store.get_run(run.run_id).await.unwrap().unwrap();
    assert!(retained.config.unwrap().input_manifest_sha256.is_some());
    // Exact replay uses retained library bytes even if the live build was changed.
    std::fs::write(original.workspace.join("fuzz_parse.mutator.so"), "tampered").unwrap();
    let review = service.replay_review(run.run_id).await.unwrap();
    let replay = service
        .replay_run_reviewed(review, &|_| {}, &|_| {})
        .await
        .unwrap();
    assert_ne!(replay.run_id, run.run_id);
    let replay_record = store.get_run(replay.run_id).await.unwrap().unwrap();
    assert_eq!(replay_record.config.unwrap().replay_of, Some(run.run_id));
    #[cfg(feature = "coverage-experiments")]
    {
        let baseline = store
            .coverage_experiment_run_evidence(run.run_id)
            .await
            .unwrap();
        let repeated = store
            .coverage_experiment_run_evidence(replay.run_id)
            .await
            .unwrap();
        assert_eq!(
            baseline.engine_env, repeated.engine_env,
            "identical retained plugins compare by artifact/image, not run allocation path"
        );
    }
    let approved = service.replay_review(run.run_id).await.unwrap();
    let before_tamper = runtime.calls.lock().unwrap().len();
    std::fs::write(
        original
            .workspace
            .join(format!("runs/{}/input/harness.mutator.so", run.run_id)),
        "foreign plugin",
    )
    .unwrap();
    assert!(service
        .replay_run_reviewed(approved, &|_| {}, &|_| {})
        .await
        .is_err());
    assert_eq!(runtime.calls.lock().unwrap().len(), before_tamper);

    let error = service
        .run_fuzzer(
            &project,
            "parse",
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            &|_| {},
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("mutator"), "{error}");
}
