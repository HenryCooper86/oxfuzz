//! Exact compilation inputs and configured admission through shared service operations.
mod common;
use hf_core::{
    engine::EngineKind,
    error::ClassifiedError,
    runtime::{
        CommandResult, ImmutableImageReference, ResourceLimits, RuntimeAdapter, SandboxOptions,
    },
    target::TargetLanguage,
};
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Runtime {
    commands: Mutex<Vec<(Vec<String>, Option<String>)>>,
    image: AtomicUsize,
    image_calls: AtomicUsize,
    move_on_image_call: AtomicUsize,
    pause_image_on_call: AtomicUsize,
    pause: AtomicUsize,
    pause_corpus: AtomicUsize,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl RuntimeAdapter for Runtime {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        let call = self.image_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.pause_image_on_call.load(Ordering::SeqCst) == call {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        if self.move_on_image_call.load(Ordering::SeqCst) == call {
            self.image.store(1, Ordering::SeqCst);
        }
        Ok(Some(ImmutableImageReference::from_sha256_id(format!(
            "sha256:{}",
            if self.image.load(Ordering::SeqCst) == 0 {
                "a"
            } else {
                "b"
            }
            .repeat(64)
        ))?))
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
        _: &ResourceLimits,
        options: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands
            .lock()
            .unwrap()
            .push((cmd.to_vec(), options.image.clone()));
        if cmd.first().is_some_and(|s| s == "bash") {
            if self.pause.swap(0, Ordering::SeqCst) == 1 {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            std::fs::write(cwd.join("fuzz_parse_entry"), b"compiled binary").unwrap();
        }
        let showmap = cmd.first().is_some_and(|arg| arg.contains("afl-showmap"));
        let merge = cmd.iter().any(|arg| arg == "-merge=1");
        if (merge
            || (showmap
                && !cmd
                    .iter()
                    .any(|arg| arg.contains(".seed-survival-baseline"))))
            && self.pause_corpus.swap(0, Ordering::SeqCst) == 1
        {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        if merge {
            let output = cwd.join(cmd[2].trim_start_matches("/work/"));
            std::fs::create_dir_all(&output).unwrap();
            std::fs::write(output.join("survivor"), b"seed").unwrap();
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: if showmap {
                "000001:1\n".into()
            } else {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".into()
            },
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        options: &SandboxOptions,
        _: &tokio_util::sync::CancellationToken,
        _: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, options).await
    }
    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        Ok(())
    }
    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap())
    }
}
#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
    pending_seed: AtomicUsize,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for Provider {
    async fn chat_completion(
        &self,
        _: &hf_core::provider::ChatRequest,
        _: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let pending = self.pending_seed.swap(0, Ordering::SeqCst);
        if pending != 0 {
            self.entered.notify_one();
            self.resume.notified().await;
            if pending == 2 {
                return Err(hf_core::provider::ProviderError::Other {
                    message: "seed provider unavailable".into(),
                });
            }
            return Ok(hf_test_utils::fixtures::make_chat_response(
                r#"["deadbeef112233445566778899"]"#,
            ));
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["safe"]}"#,
        ))
    }
    async fn chat_completion_stream(
        &self,
        _: &hf_core::provider::ChatRequest,
        _: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        unreachable!()
    }
    fn report_error(&self, _: &hf_core::types::ProviderId, _: &hf_core::provider::ProviderError) {}
    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        vec![]
    }
    async fn freeze(&self, _: &hf_core::types::ProviderId, _: String) {}
    async fn thaw(
        &self,
        _: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}
struct Fixture {
    project: tempfile::TempDir,
    store: Arc<hf_storage::Store>,
    runtime: Arc<Runtime>,
    provider: Arc<Provider>,
    service: ServiceContainer,
}
impl Fixture {
    async fn new() -> Self {
        common::install_managed_workspace("oxfuzz_build_inputs_it");
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("parse.c"), "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n").unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::default());
        let provider = Arc::new(Provider::default());
        let service = ServiceContainer::new(runtime.clone(), Some(provider.clone()))
            .with_store(store.clone());
        Self {
            project,
            store,
            runtime,
            provider,
            service,
        }
    }
    async fn compile(&self) -> hf_service::CompileOutcome {
        self.service
            .harness_compile(
                "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
                    .into(),
                self.project.path(),
                EngineKind::LibFuzzer,
                "parse_entry",
                TargetLanguage::C,
            )
            .await
            .unwrap()
    }
    #[cfg(feature = "build-doctor")]
    async fn configure(&self) {
        std::fs::write(
            self.project.path().join("CMakeLists.txt"),
            "project(parser)\n",
        )
        .unwrap();
        self.database("-DOLD=1");
        self.service
            .save_build_profile(hf_service::SaveBuildProfileRequest {
                project: self.project.path().to_string_lossy().into(),
                component_root: ".".into(),
                build_system: hf_service::ProfileBuildSystem::CMake,
                compile_database_path: "compile_commands.json".into(),
                cmake_definitions: std::collections::BTreeMap::default(),
                dependencies: vec![],
            })
            .await
            .unwrap();
        assert_eq!(
            self.service
                .diagnose_build(self.project.path())
                .await
                .unwrap()
                .profile_state,
            hf_service::BuildProfileState::Ready
        );
        self.runtime.commands.lock().unwrap().clear();
    }
    fn database(&self, flag: &str) {
        std::fs::write(self.project.path().join("compile_commands.json"), serde_json::to_vec(&serde_json::json!([{"directory": self.project.path(), "file":"parse.c", "arguments":["cc",flag,"-c","parse.c"]}])).unwrap()).unwrap();
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[tokio::test]
async fn unconfigured_compile_persists_null_inputs_and_dispatches_immutable_image() {
    let f = Fixture::new().await;
    let compiled = f.compile().await;
    let inputs = f
        .store
        .harness_build_inputs(compiled.harness_id)
        .await
        .unwrap()
        .expect("successful compile retains inputs");
    assert_eq!(inputs.profile_sha256, None);
    assert_eq!(inputs.compile_database_sha256, None);
    assert_eq!(inputs.compile_flags_sha256, digest(b"[]"));
    assert_eq!(
        f.runtime
            .commands
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .as_deref(),
        Some(inputs.sandbox_image_id.as_str())
    );
}
#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn pending_compile_retains_original_database_and_next_review_refuses_it() {
    let f = Fixture::new().await;
    f.configure().await;
    let original = std::fs::read(f.project.path().join("compile_commands.json")).unwrap();
    f.runtime.pause.store(1, Ordering::SeqCst);
    let compile = f.compile();
    let mutate = async {
        f.runtime.entered.notified().await;
        f.database("-DNEW=1");
        f.runtime.resume.notify_one();
    };
    let (compiled, ()) = tokio::join!(compile, mutate);
    let inputs = f
        .store
        .harness_build_inputs(compiled.harness_id)
        .await
        .unwrap()
        .expect("captured inputs");
    assert_eq!(
        inputs.compile_database_sha256.as_deref(),
        Some(digest(&original).as_str())
    );
    assert_eq!(inputs.compile_flags_sha256, digest(br#"["-DOLD=1"]"#));
    let calls = f.runtime.commands.lock().unwrap().len();
    let error = f
        .service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("rebuilt and requalified"),
        "{error}"
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.runtime.commands.lock().unwrap().len(), calls);
}
#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn configured_image_movement_stops_generate_before_discovery_or_provider() {
    let f = Fixture::new().await;
    f.configure().await;
    f.runtime.image.store(1, Ordering::SeqCst);
    let result = f
        .service
        .harness_generate(
            f.project.path(),
            "not_discovered",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await;
    assert!(result.unwrap_err().to_string().contains("Stale"));
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    assert!(f.runtime.commands.lock().unwrap().is_empty());
    assert!(f.store.list_all_targets().await.unwrap().is_empty());
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn configured_prompt_context_is_retained_before_provider_and_write_failure_stops_dispatch() {
    let f = Fixture::new().await;
    f.configure().await;
    f.service
        .harness_draft(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    let root = f.project.path().canonicalize().unwrap();
    let retained = f
        .store
        .harness_build_context_history(root.to_str().unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].evidence.context.defines, vec!["-DOLD=1"]);
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
    sqlx::query("CREATE TRIGGER reject_context BEFORE INSERT ON harness_build_contexts BEGIN SELECT RAISE(ABORT,'test persistence failure'); END").execute(f.store.pool()).await.unwrap();
    assert!(f
        .service
        .harness_draft(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C
        )
        .await
        .is_err());
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn image_movement_at_final_smoke_dispatch_is_refused() {
    let f = Fixture::new().await;
    f.configure().await;
    f.compile().await;
    f.runtime.commands.lock().unwrap().clear();
    f.runtime.image_calls.store(0, Ordering::SeqCst);
    f.runtime.move_on_image_call.store(3, Ordering::SeqCst);
    let result = f
        .service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await;
    assert!(result.is_err(), "final image change must refuse smoke");
    assert!(f.runtime.commands.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_store_prevents_generation_provider_and_runtime() {
    let f = Fixture::new().await;
    let service = ServiceContainer::new(f.runtime.clone(), Some(f.provider.clone()));
    let error = service
        .harness_generate(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("persistent service store"));
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    assert!(f.runtime.commands.lock().unwrap().is_empty());
    assert_eq!(f.runtime.image_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rust_compile_pins_image_and_records_only_flags_emitted_by_cargo() {
    let f = Fixture::new().await;
    std::fs::write(
        f.project.path().join("Cargo.toml"),
        "[package]\nname=\"parse_sample\"\nversion=\"0.1.0\"\n",
    )
    .unwrap();
    std::fs::create_dir(f.project.path().join("src")).unwrap();
    std::fs::write(
        f.project.path().join("src/lib.rs"),
        "pub fn parse_entry(data: &[u8]) -> usize { data.len() }\n",
    )
    .unwrap();
    for database in [false, true] {
        if database {
            f.database("-DNEVER_EMITTED=1");
        }
        let compiled=f.service.harness_compile("#![no_main]\nlibfuzzer_sys::fuzz_target!(|data: &[u8]| { parse_sample::parse_entry(data); });".into(),f.project.path(),EngineKind::LibFuzzer,"parse_entry",TargetLanguage::Rust).await.unwrap();
        let inputs = f
            .store
            .harness_build_inputs(compiled.harness_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inputs.profile_sha256, None);
        assert_eq!(inputs.compile_flags_sha256, digest(b"[]"));
        assert_eq!(
            inputs.compile_database_sha256.is_some(),
            database && cfg!(feature = "build-context")
        );
        let calls = f.runtime.commands.lock().unwrap();
        let (argv, image) = calls.last().unwrap();
        assert_eq!(image.as_deref(), Some(inputs.sandbox_image_id.as_str()));
        assert!(argv.join(" ").contains("cargo fuzz build"));
        assert!(!argv.join(" ").contains("NEVER_EMITTED"));
    }
}

#[tokio::test]
async fn atomic_input_storage_failure_publishes_no_active_revision() {
    let f = Fixture::new().await;
    sqlx::query("CREATE TRIGGER reject_inputs BEFORE INSERT ON harness_build_inputs BEGIN SELECT RAISE(ABORT,'test input failure'); END").execute(f.store.pool()).await.unwrap();
    let result = f
        .service
        .harness_compile(
            "source".into(),
            f.project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await;
    assert!(result.is_err());
    assert!(f.store.list_all_harnesses().await.unwrap().is_empty());
    let workspace = hf_service::workspace_dir(f.project.path(), "parse_entry");
    assert!(!workspace.join("harness.active").exists());
    assert!(!workspace.join("harness.source").exists());
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn changed_configured_inputs_block_shared_lifecycle_and_rebuild_restores_eligibility() {
    for mutation in ["profile", "marker", "database_bytes", "flags", "image"] {
        let f = Fixture::new().await;
        f.configure().await;
        let first = f.compile().await;
        f.service
            .harness_smoke(
                f.project.path(),
                "parse_entry",
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        f.service
            .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
            .await
            .unwrap();
        match mutation {
            "profile" => {
                let profile = f
                    .service
                    .build_profile(f.project.path())
                    .await
                    .unwrap()
                    .unwrap();
                f.service
                    .save_build_profile(hf_service::SaveBuildProfileRequest {
                        project: profile.project_root,
                        component_root: profile.component_root,
                        build_system: profile.build_system,
                        compile_database_path: profile.compile_database_path,
                        cmake_definitions: std::collections::BTreeMap::from([(
                            "BUILD_TESTING".into(),
                            "OFF".into(),
                        )]),
                        dependencies: profile.dependencies,
                    })
                    .await
                    .unwrap();
                f.service.diagnose_build(f.project.path()).await.unwrap();
            }
            "marker" => std::fs::write(
                f.project.path().join("CMakeLists.txt"),
                "project(changed)\n",
            )
            .unwrap(),
            "database_bytes" => {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(f.project.path().join("compile_commands.json"))
                    .unwrap()
                    .write_all(b"\n")
                    .unwrap();
            }
            "flags" => f.database("-DNEW=1"),
            "image" => f.runtime.image.store(1, Ordering::SeqCst),
            _ => unreachable!(),
        }
        let providers = f.provider.calls.load(Ordering::SeqCst);
        let commands = f.runtime.commands.lock().unwrap().len();
        let review = f
            .service
            .harness_smoke(
                f.project.path(),
                "parse_entry",
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await;
        assert!(review.is_err(), "{mutation}");
        let campaign = f
            .service
            .run_campaign(
                f.project.path(),
                Some("parse_entry"),
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                1,
                1,
            )
            .await;
        assert!(campaign.is_err(), "{mutation}");
        let direct = f
            .service
            .run_fuzzer(
                f.project.path(),
                "parse_entry",
                EngineKind::LibFuzzer,
                1,
                &|_| {},
            )
            .await;
        assert!(direct.is_err(), "{mutation}");
        std::fs::create_dir_all(first.workspace.join("corpus")).unwrap();
        std::fs::write(first.workspace.join("corpus/seed"), b"seed").unwrap();
        assert!(
            f.service
                .corpus_minimize(f.project.path(), "parse_entry")
                .await
                .is_err(),
            "{mutation}"
        );
        assert_eq!(
            f.provider.calls.load(Ordering::SeqCst),
            providers,
            "{mutation}"
        );
        assert_eq!(
            f.runtime.commands.lock().unwrap().len(),
            commands,
            "{mutation}"
        );
        let image_calls = f.runtime.image_calls.load(Ordering::SeqCst);
        assert_eq!(
            f.service
                .corpus_capabilities(f.project.path(), "parse_entry")
                .await
                .unwrap()
                .minimize
                .available,
            mutation == "image",
            "read-only diagnosis cannot observe live tag movement: {mutation}"
        );
        assert_eq!(f.runtime.image_calls.load(Ordering::SeqCst), image_calls);
        // Saving current marker/image assumptions and diagnosing authorizes a rebuild.
        if matches!(mutation, "marker" | "image") {
            let profile = f
                .service
                .build_profile(f.project.path())
                .await
                .unwrap()
                .unwrap();
            f.service
                .save_build_profile(hf_service::SaveBuildProfileRequest {
                    project: profile.project_root,
                    component_root: profile.component_root,
                    build_system: profile.build_system,
                    compile_database_path: profile.compile_database_path,
                    cmake_definitions: profile.cmake_definitions,
                    dependencies: profile.dependencies,
                })
                .await
                .unwrap();
            f.service.diagnose_build(f.project.path()).await.unwrap();
        }
        let rebuilt = f.compile().await;
        assert_ne!(rebuilt.harness_id, first.harness_id);
        f.service
            .harness_smoke(
                f.project.path(),
                "parse_entry",
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        f.service
            .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
            .await
            .unwrap();
        assert!(
            f.service
                .corpus_capabilities(f.project.path(), "parse_entry")
                .await
                .unwrap()
                .minimize
                .available
        );
    }
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn configured_capabilities_need_retained_diagnosis_and_inputs_without_runtime() {
    let f = Fixture::new().await;
    f.configure().await;
    let compiled = f.compile().await;
    f.service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    f.service
        .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    let image_calls = f.runtime.image_calls.load(Ordering::SeqCst);
    let commands = f.runtime.commands.lock().unwrap().len();
    let providers = f.provider.calls.load(Ordering::SeqCst);
    assert!(
        f.service
            .corpus_capabilities(f.project.path(), "parse_entry")
            .await
            .unwrap()
            .minimize
            .available
    );
    sqlx::query("DELETE FROM build_diagnosis_runs")
        .execute(f.store.pool())
        .await
        .unwrap();
    assert_eq!(
        f.service
            .corpus_capabilities(f.project.path(), "parse_entry")
            .await
            .unwrap()
            .minimize
            .reason_code
            .as_deref(),
        Some("build_diagnosis_unavailable")
    );
    assert_eq!(f.runtime.image_calls.load(Ordering::SeqCst), image_calls);
    assert_eq!(f.runtime.commands.lock().unwrap().len(), commands);
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), providers);
    f.service.diagnose_build(f.project.path()).await.unwrap();
    sqlx::query("DELETE FROM harness_build_inputs WHERE harness_id=?1")
        .bind(compiled.harness_id.to_string())
        .execute(f.store.pool())
        .await
        .unwrap();
    assert!(
        !f.service
            .corpus_capabilities(f.project.path(), "parse_entry")
            .await
            .unwrap()
            .minimize
            .available
    );
    assert!(f
        .service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C
        )
        .await
        .is_err());
    f.service
        .clear_build_profile(f.project.path())
        .await
        .unwrap();
    assert!(
        f.service
            .corpus_capabilities(f.project.path(), "parse_entry")
            .await
            .unwrap()
            .minimize
            .available
    );
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn deleted_configured_database_reports_needs_build_before_dispatch() {
    let f = Fixture::new().await;
    f.configure().await;
    std::fs::remove_file(f.project.path().join("compile_commands.json")).unwrap();
    let error = f
        .service
        .harness_generate(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("NeedsBuild"), "{error}");
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
    assert!(f.runtime.commands.lock().unwrap().is_empty());
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn configured_database_without_extra_flags_is_present_compilation_evidence() {
    let f = Fixture::new().await;
    f.configure().await;
    let bytes=serde_json::to_vec(&serde_json::json!([{"directory":f.project.path(),"file":"parse.c","arguments":["cc","-c","parse.c"]}])).unwrap();
    std::fs::write(f.project.path().join("compile_commands.json"), &bytes).unwrap();
    let compiled = f.compile().await;
    let inputs = f
        .store
        .harness_build_inputs(compiled.harness_id)
        .await
        .unwrap()
        .unwrap();
    assert!(inputs.profile_sha256.is_some());
    assert_eq!(inputs.compile_database_sha256, Some(digest(&bytes)));
    assert_eq!(inputs.compile_flags_sha256, digest(b"[]"));
    assert_eq!(
        std::fs::read(compiled.workspace.join("CMakeLists.txt")).unwrap(),
        std::fs::read(f.project.path().join("CMakeLists.txt")).unwrap()
    );
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn staged_marker_preserves_exact_non_utf8_comment_bytes() {
    let f = Fixture::new().await;
    f.configure().await;
    let marker = b"project(parser)\n#\xff\n";
    std::fs::write(f.project.path().join("CMakeLists.txt"), marker).unwrap();
    f.service
        .save_build_profile(hf_service::SaveBuildProfileRequest {
            project: f.project.path().to_string_lossy().into_owned(),
            component_root: ".".into(),
            build_system: hf_service::ProfileBuildSystem::CMake,
            compile_database_path: "compile_commands.json".into(),
            cmake_definitions: std::collections::BTreeMap::new(),
            dependencies: vec![],
        })
        .await
        .unwrap();
    f.service.diagnose_build(f.project.path()).await.unwrap();
    let compiled = f.compile().await;
    assert_eq!(
        std::fs::read(compiled.workspace.join("CMakeLists.txt")).unwrap(),
        marker
    );
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn pending_compile_retains_original_profile_after_concurrent_save() {
    let f = Fixture::new().await;
    f.configure().await;
    let original = f
        .service
        .build_profile(f.project.path())
        .await
        .unwrap()
        .unwrap();
    f.runtime.pause.store(1, Ordering::SeqCst);
    let compile = f.compile();
    let mutate = async {
        f.runtime.entered.notified().await;
        f.service
            .save_build_profile(hf_service::SaveBuildProfileRequest {
                project: original.project_root.clone(),
                component_root: original.component_root.clone(),
                build_system: original.build_system,
                compile_database_path: original.compile_database_path.clone(),
                cmake_definitions: std::collections::BTreeMap::from([(
                    "BUILD_TESTING".into(),
                    "OFF".into(),
                )]),
                dependencies: original.dependencies.clone(),
            })
            .await
            .unwrap();
        f.runtime.resume.notify_one();
    };
    let (compiled, ()) = tokio::join!(compile, mutate);
    let inputs = f
        .store
        .harness_build_inputs(compiled.harness_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inputs.profile_sha256.as_deref(),
        Some(original.profile_sha256.as_str())
    );
    f.service.diagnose_build(f.project.path()).await.unwrap();
    let error = f
        .service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("rebuilt and requalified"),
        "{error}"
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn promotion_rechecks_inputs_after_final_harness_reload() {
    let f = Fixture::new().await;
    f.configure().await;
    let compiled = f.compile().await;
    f.service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    f.runtime.image_calls.store(0, Ordering::SeqCst);
    f.runtime.pause_image_on_call.store(2, Ordering::SeqCst);
    let promotion =
        f.service
            .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer);
    let mutate = async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.runtime.entered.notified(),
        )
        .await
        .expect("promotion must recheck after final reload");
        f.database("-DCHANGED_DURING_PROMOTION=1");
        f.runtime.resume.notify_one();
    };
    let (result, ()) = tokio::join!(promotion, mutate);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("rebuilt and requalified"));
    assert_eq!(
        f.store
            .get_harness(compiled.harness_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        hf_core::harness::HarnessStatus::SmokePassed
    );
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn final_direct_and_corpus_image_resolution_cannot_select_a_moved_tag() {
    for corpus in [false, true] {
        let f = Fixture::new().await;
        f.configure().await;
        let compiled = f.compile().await;
        f.service
            .harness_smoke(
                f.project.path(),
                "parse_entry",
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        f.service
            .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
            .await
            .unwrap();
        std::fs::create_dir_all(compiled.workspace.join("corpus")).unwrap();
        std::fs::write(compiled.workspace.join("corpus/seed"), b"seed").unwrap();
        f.runtime.commands.lock().unwrap().clear();
        f.runtime.image_calls.store(0, Ordering::SeqCst);
        f.runtime.move_on_image_call.store(2, Ordering::SeqCst);
        let failed = if corpus {
            f.service
                .corpus_minimize(f.project.path(), "parse_entry")
                .await
                .is_err()
        } else {
            f.service
                .run_fuzzer(
                    f.project.path(),
                    "parse_entry",
                    EngineKind::LibFuzzer,
                    1,
                    &|_| {},
                )
                .await
                .is_err()
        };
        assert!(failed);
        assert!(f.runtime.commands.lock().unwrap().is_empty());
    }
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn unavailable_compiled_inputs_require_rebuild_before_qualification() {
    let f = Fixture::new().await;
    f.configure().await;
    f.compile().await;
    std::fs::remove_file(f.project.path().join("compile_commands.json")).unwrap();
    let error = f
        .service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("rebuilt and requalified"),
        "{error}"
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn pending_corpus_engine_input_change_preserves_corpus_and_stops_regeneration_provider() {
    for regeneration in [true, false] {
        let f = Fixture::new().await;
        f.configure().await;
        let engine = if regeneration {
            EngineKind::AflPlusPlus
        } else {
            EngineKind::LibFuzzer
        };
        let compiled = f
            .service
            .harness_compile(
                "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
                    .into(),
                f.project.path(),
                engine,
                "parse_entry",
                TargetLanguage::C,
            )
            .await
            .unwrap();
        f.service
            .harness_smoke(f.project.path(), "parse_entry", engine, TargetLanguage::C)
            .await
            .unwrap();
        f.service
            .harness_promote(f.project.path(), "parse_entry", engine)
            .await
            .unwrap();
        let corpus = compiled.workspace.join("corpus");
        if corpus.exists() {
            std::fs::remove_dir_all(&corpus).unwrap();
        }
        std::fs::create_dir_all(&corpus).unwrap();
        std::fs::write(corpus.join("seed_0"), b"original").unwrap();
        let providers = f.provider.calls.load(Ordering::SeqCst);
        f.runtime.pause_corpus.store(1, Ordering::SeqCst);
        let operation = async {
            if regeneration {
                f.service
                    .regenerate_dead_seeds(f.project.path(), "parse_entry", TargetLanguage::C)
                    .await
                    .map(|_| ())
            } else {
                f.service
                    .corpus_minimize(f.project.path(), "parse_entry")
                    .await
                    .map(|_| ())
            }
        };
        let mutation = async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                f.runtime.entered.notified(),
            )
            .await
            .expect("fake engine must await corpus result");
            f.database("-DCHANGED_DURING_CORPUS=1");
            f.runtime.resume.notify_one();
        };
        let (result, ()) = tokio::join!(operation, mutation);
        assert!(
            result.is_err(),
            "input changes during engine work must refuse corpus mutation"
        );
        assert_eq!(std::fs::read(corpus.join("seed_0")).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&corpus).unwrap().count(), 1);
        assert_eq!(f.provider.calls.load(Ordering::SeqCst), providers);
    }
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn image_change_after_run_reservation_is_retained_failed_before_engine_dispatch() {
    let f = Fixture::new().await;
    f.configure().await;
    let compiled = f.compile().await;
    f.service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    f.service
        .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    std::fs::create_dir_all(compiled.workspace.join("corpus")).unwrap();
    std::fs::write(compiled.workspace.join("corpus/seed"), b"seed").unwrap();
    f.runtime.commands.lock().unwrap().clear();
    let reserved = Mutex::new(None);
    let result = f
        .service
        .run_fuzzer_observed(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            1,
            &|_| {},
            &|id| {
                *reserved.lock().unwrap() = Some(id);
                f.runtime.image.store(1, Ordering::SeqCst);
            },
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("rebuilt and requalified"));
    let id = reserved
        .lock()
        .unwrap()
        .expect("run was reserved before final recheck");
    assert_eq!(
        f.store.get_run(id).await.unwrap().unwrap().status,
        hf_storage::RunStatus::Failed
    );
    assert!(f.runtime.commands.lock().unwrap().is_empty());
}

#[cfg(feature = "build-doctor")]
async fn campaign_pending_seed_preserves_corpus(provider_fails: bool) {
    let f = Fixture::new().await;
    f.configure().await;
    let compiled = f.compile().await;
    f.service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    f.service
        .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    f.service
        .corpus_seed(f.project.path(), "parse_entry")
        .await
        .unwrap();
    let corpus = compiled.workspace.join("corpus");
    let inventory = || {
        std::fs::read_dir(&corpus)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let original = inventory();
    let rows = || {
        sqlx::query_scalar::<_, String>("SELECT data_json FROM corpus_entries ORDER BY data_json")
            .fetch_all(f.store.pool())
    };
    let original_rows = rows().await.unwrap();
    assert!(!original.is_empty());
    assert!(!original_rows.is_empty());
    let calls = f.provider.calls.load(Ordering::SeqCst);
    f.runtime.commands.lock().unwrap().clear();
    f.provider
        .pending_seed
        .store(if provider_fails { 2 } else { 1 }, Ordering::SeqCst);
    let campaign = f.service.run_campaign(
        f.project.path(),
        Some("parse_entry"),
        EngineKind::LibFuzzer,
        TargetLanguage::C,
        1,
        1,
    );
    let mutation = async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.provider.entered.notified(),
        )
        .await
        .expect("campaign seed provider must be pending");
        f.database("-DCHANGED_DURING_CAMPAIGN_SEEDS=1");
        f.provider.resume.notify_one();
    };
    let (result, ()) = tokio::join!(campaign, mutation);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("rebuilt and requalified"));
    assert_eq!(
        inventory(),
        original,
        "pending campaign seeds must not change retained corpus bytes or inventory"
    );
    assert_eq!(
        rows().await.unwrap(),
        original_rows,
        "pending campaign seeds must not change durable corpus rows"
    );
    assert_eq!(f.provider.calls.load(Ordering::SeqCst), calls + 1);
    assert!(
        f.runtime.commands.lock().unwrap().is_empty(),
        "stale campaign must not dispatch the fuzzer"
    );
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn campaign_pending_seed_success_rechecks_inputs_before_publication() {
    campaign_pending_seed_preserves_corpus(false).await;
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn campaign_pending_seed_failure_rechecks_inputs_before_heuristic_publication() {
    campaign_pending_seed_preserves_corpus(true).await;
}

#[cfg(feature = "build-doctor")]
#[tokio::test]
async fn campaign_rechecks_after_seed_discovery_before_provider() {
    let f = Fixture::new().await;
    f.configure().await;
    let compiled = f.compile().await;
    f.service
        .harness_smoke(
            f.project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    f.service
        .harness_promote(f.project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    f.service
        .corpus_seed(f.project.path(), "parse_entry")
        .await
        .unwrap();
    let calls = f.provider.calls.load(Ordering::SeqCst);
    f.runtime.commands.lock().unwrap().clear();
    f.runtime.image_calls.store(0, Ordering::SeqCst);
    f.runtime.move_on_image_call.store(2, Ordering::SeqCst);
    let result = f
        .service
        .run_campaign(
            f.project.path(),
            Some("parse_entry"),
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            1,
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("rebuilt and requalified"));
    assert_eq!(
        f.provider.calls.load(Ordering::SeqCst),
        calls,
        "seed provider must not run after its admission sees the changed image"
    );
    assert_eq!(
        std::fs::read_dir(compiled.workspace.join("corpus"))
            .unwrap()
            .count(),
        2
    );
    assert!(f.runtime.commands.lock().unwrap().is_empty());
}
