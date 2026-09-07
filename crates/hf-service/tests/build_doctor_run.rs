//! Retained profile diagnosis and sandbox execution behavior.
#![cfg(feature = "build-doctor")]

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
    SandboxNetworkMode, SandboxOptions,
};
use hf_service::{
    ProfileBuildSystem, RunBuildPlanRequest, SaveBuildProfileRequest, ServiceContainer,
};
use hf_storage::{BuildProfileState, BuildTerminalStatus};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
struct Call {
    argv: Vec<String>,
    cwd: PathBuf,
    opts: SandboxOptions,
    empty: bool,
}
struct BuildRuntime {
    calls: Mutex<Vec<Call>>,
    image: Mutex<String>,
    image_calls: AtomicUsize,
    pause_image_call: usize,
    image_entered: tokio::sync::Notify,
    image_resume: tokio::sync::Notify,
    termination: CommandTermination,
    probe_termination: CommandTermination,
    exit_code: i32,
    output: String,
    artifact: Option<String>,
    probe_missing: Option<String>,
    probe_stderr: String,
    runtime_error: bool,
    fail_build: bool,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    pause: bool,
}
impl BuildRuntime {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            image: Mutex::new(format!("sha256:{}", "f".repeat(64))),
            image_calls: AtomicUsize::new(0),
            pause_image_call: 0,
            image_entered: tokio::sync::Notify::new(),
            image_resume: tokio::sync::Notify::new(),
            termination: CommandTermination::Completed,
            probe_termination: CommandTermination::Completed,
            exit_code: 0,
            output: String::new(),
            artifact: Some("valid".into()),
            probe_missing: None,
            probe_stderr: String::new(),
            runtime_error: false,
            fail_build: false,
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            pause: false,
        }
    }
    fn builds(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.argv[0] != "/bin/sh" && c.argv[0] != "pkg-config")
            .cloned()
            .collect()
    }
}
#[async_trait]
impl RuntimeAdapter for BuildRuntime {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        let call = self.image_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.pause_image_call {
            self.image_entered.notify_one();
            self.image_resume.notified().await;
        }
        ImmutableImageReference::from_sha256_id(self.image.lock().unwrap().clone()).map(Some)
    }
    async fn run_command(
        &self,
        _: &[String],
        _: &Path,
        _: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        panic!("image and workdir options required")
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        let probe = cmd[0] == "/bin/sh" || cmd[0] == "pkg-config";
        self.calls.lock().unwrap().push(Call {
            argv: cmd.to_vec(),
            cwd: cwd.into(),
            opts: opts.clone(),
            empty: std::fs::read_dir(cwd).unwrap().next().is_none(),
        });
        if self.runtime_error || (!probe && self.fail_build && cmd[0] != "mkdir") {
            return Err(ClassifiedError::Sandbox("runtime unavailable".into()));
        }
        if !probe && self.pause {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        if !probe && cmd[0] != "mkdir" && self.exit_code == 0 {
            if let Some(artifact) = &self.artifact {
                let path = cwd.join("build/parser/compile_commands.json");
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                let raw = if artifact == "valid" {
                    serde_json::json!([{"directory":"/work/components/parser", "file":"/work/components/parser/a.c", "arguments":["cc", "-I/work/include", "-DSELECTED=1", "-std=c11", "-c", "a.c"]}]).to_string()
                } else {
                    artifact.clone()
                };
                std::fs::write(path, raw).unwrap();
            }
        }
        Ok(CommandResult {
            exit_code: if probe {
                if self.probe_missing.as_ref() == cmd.last() {
                    if cmd[0] == "/bin/sh" {
                        127
                    } else {
                        1
                    }
                } else {
                    0
                }
            } else {
                self.exit_code
            },
            stdout: if probe {
                String::new()
            } else {
                self.output.clone()
            },
            stderr: if probe {
                self.probe_stderr.clone()
            } else {
                String::new()
            },
            workspace: cwd.into(),
            termination: if probe {
                self.probe_termination
            } else {
                self.termination
            },
        })
    }
    async fn write_file(&self, _: &Path, _: &str) -> Result<(), ClassifiedError> {
        panic!("not used")
    }
    async fn read_file(&self, _: &Path) -> Result<String, ClassifiedError> {
        panic!("not used")
    }
}
fn workspace() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("oxfuzz_task4_{}", uuid::Uuid::new_v4()));
        // SAFETY: all tests initialize the same workspace through this OnceLock.
        unsafe { std::env::set_var("HF_WORKSPACE_DIR", &root) };
        hf_service::initialize_workspace_root().unwrap()
    })
}
struct Fixture {
    _dir: tempfile::TempDir,
    project: PathBuf,
    service: ServiceContainer,
    runtime: Arc<BuildRuntime>,
    profile: hf_service::BuildProfileView,
}
async fn fixture(runtime: BuildRuntime, system: ProfileBuildSystem) -> Fixture {
    workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project with spaces");
    std::fs::create_dir_all(project.join("components/parser")).unwrap();
    std::fs::create_dir_all(project.join("include")).unwrap();
    std::fs::write(project.join("components/parser/a.c"), "int a;").unwrap();
    std::fs::write(
        project.join(if system == ProfileBuildSystem::CMake {
            "components/parser/CMakeLists.txt"
        } else {
            "components/parser/Makefile"
        }),
        "# marker\n",
    )
    .unwrap();
    let runtime = Arc::new(runtime);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("store.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::new(runtime.clone(), None).with_store(store);
    let profile = service
        .save_build_profile(SaveBuildProfileRequest {
            project: project.display().to_string(),
            component_root: "components/parser".into(),
            build_system: system,
            compile_database_path: "build/parser/compile_commands.json".into(),
            cmake_definitions: if system == ProfileBuildSystem::CMake {
                [
                    ("BUILD_TESTING".into(), "OFF".into()),
                    ("BUILD_SHARED_LIBS".into(), "ON".into()),
                ]
                .into()
            } else {
                std::collections::BTreeMap::new()
            },
            dependencies: vec![],
        })
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        project,
        service,
        runtime,
        profile,
    }
}
impl Fixture {
    fn request(&self) -> RunBuildPlanRequest {
        RunBuildPlanRequest {
            project: self.project.display().to_string(),
            expected_profile_sha256: self.profile.profile_sha256.clone(),
        }
    }
    async fn history(&self) -> Vec<hf_storage::BuildDiagnosisRecord> {
        self.service
            .build_diagnosis_history(&self.project, 100)
            .await
            .unwrap()
    }
}
#[tokio::test]
async fn diagnosis_probes_empty_mounts_and_retains_needs_build_without_build_execution() {
    let f = fixture(BuildRuntime::new(), ProfileBuildSystem::Make).await;
    let d = f.service.diagnose_build(&f.project).await.unwrap();
    assert_eq!(d.profile_state, BuildProfileState::NeedsBuild);
    assert!(d.plan.is_some());
    assert!(f.runtime.builds().is_empty());
    let calls = f.runtime.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    for c in calls {
        assert!(c.empty);
        assert!(c.cwd.starts_with(workspace()));
        assert_eq!(
            c.opts.image.as_deref(),
            Some(f.profile.sandbox_image_id.as_str())
        );
        assert_eq!(c.opts.network_mode, SandboxNetworkMode::None);
        assert!(c.opts.extra_mounts.is_empty());
        assert_eq!(
            &c.argv[..4],
            [
                "/bin/sh",
                "-c",
                "command -v \"$1\" >/dev/null",
                "oxfuzz-command-probe"
            ]
        );
    }
    assert_eq!(f.history().await[0].diagnosis, d);
}
#[tokio::test]
async fn cmake_uses_exact_options_whole_snapshot_component_workdir_and_selected_publication() {
    let f = fixture(BuildRuntime::new(), ProfileBuildSystem::CMake).await;
    let result = f.service.run_build_plan(f.request()).await.unwrap();
    assert_eq!(result.status, BuildTerminalStatus::Succeeded);
    assert!(result.build_context.is_some());
    let calls = f.runtime.builds();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].argv,
        [
            "cmake",
            "-S",
            ".",
            "-B",
            "../../build/parser",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DBUILD_SHARED_LIBS=ON",
            "-DBUILD_TESTING=OFF"
        ]
    );
    assert_eq!(
        calls[0].opts.workdir.as_deref(),
        Some("/work/components/parser")
    );
    assert_eq!(
        calls[0].opts.image.as_deref(),
        Some(f.profile.sandbox_image_id.as_str())
    );
    assert!(calls[0].cwd.starts_with(workspace()));
    assert!(!calls[0].cwd.exists());
    let path = f.project.join("build/parser/compile_commands.json");
    let raw = std::fs::read_to_string(path).unwrap();
    assert!(!raw.contains("/work"));
    let entries = hf_discovery::build_context::parse_compile_database(&raw).unwrap();
    assert_eq!(entries.len(), 1);
    let root = Path::new(&f.profile.project_root);
    assert_eq!(entries[0].directory, root.join("components/parser"));
    assert_eq!(entries[0].file, root.join("components/parser/a.c"));
    assert_eq!(
        entries[0].arguments,
        [
            "cc".to_owned(),
            format!("-I{}/include", root.display()),
            "-DSELECTED=1".to_owned(),
            "-std=c11".to_owned(),
            "-c".to_owned(),
            "a.c".to_owned(),
        ]
    );
    assert!(!f.project.join(".oxfuzz-build").exists());
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        result.status
    );
}
#[tokio::test]
async fn make_creates_output_directory_then_runs_bear_and_stops_on_first_failure() {
    for exit_code in [0, 7] {
        let mut runtime = BuildRuntime::new();
        runtime.exit_code = exit_code;
        let f = fixture(runtime, ProfileBuildSystem::Make).await;
        let result = f.service.run_build_plan(f.request()).await.unwrap();
        let calls = f.runtime.builds();
        assert_eq!(calls[0].argv, ["mkdir", "-p", "--", "../../build/parser"]);
        if exit_code == 0 {
            assert_eq!(
                calls[1].argv,
                [
                    "bear",
                    "--output",
                    "../../build/parser/compile_commands.json",
                    "--",
                    "make",
                    "-B"
                ]
            );
            assert_eq!(result.status, BuildTerminalStatus::Succeeded);
        } else {
            assert_eq!(calls.len(), 1);
            assert_eq!(result.status, BuildTerminalStatus::StepFailed);
            assert_eq!(
                f.history().await[0]
                    .diagnosis
                    .terminal
                    .as_ref()
                    .unwrap()
                    .step_index,
                Some(0)
            );
        }
    }
}
#[tokio::test]
async fn terminal_failure_output_is_utf8_safe_bounded_and_persisted() {
    for termination in [
        CommandTermination::Completed,
        CommandTermination::TimedOut,
        CommandTermination::Cancelled,
    ] {
        let mut runtime = BuildRuntime::new();
        runtime.exit_code = 2;
        runtime.termination = termination;
        runtime.output = "é\n\"".repeat(40000);
        let f = fixture(runtime, ProfileBuildSystem::Make).await;
        let result = f.service.run_build_plan(f.request()).await.unwrap();
        let records = f.history().await;
        let record = &records[0];
        let terminal = record.diagnosis.terminal.as_ref().unwrap();
        assert_eq!(
            result.status,
            match termination {
                CommandTermination::Completed => BuildTerminalStatus::StepFailed,
                CommandTermination::TimedOut => BuildTerminalStatus::TimedOut,
                CommandTermination::Cancelled => BuildTerminalStatus::Cancelled,
            }
        );
        assert!(terminal.output_truncated);
        assert!(!terminal.stdout.is_empty());
        assert!(serde_json::to_vec(&record.diagnosis).unwrap().len() <= 65536);
        assert_eq!(f.runtime.builds().len(), 1);
    }
}
#[tokio::test]
async fn artifact_is_required_and_must_parse_into_usable_context() {
    for (artifact, expected) in [
        (None, BuildTerminalStatus::ArtifactMissing),
        (Some("[]".into()), BuildTerminalStatus::ArtifactInvalid),
        (Some("{bad".into()), BuildTerminalStatus::ArtifactInvalid),
        (
            Some(
                serde_json::json!([{"directory":"/work", "file":"a.c", "arguments":[]}])
                    .to_string(),
            ),
            BuildTerminalStatus::ArtifactInvalid,
        ),
    ] {
        let mut runtime = BuildRuntime::new();
        runtime.artifact = artifact;
        let f = fixture(runtime, ProfileBuildSystem::CMake).await;
        assert_eq!(
            f.service.run_build_plan(f.request()).await.unwrap().status,
            expected
        );
        assert!(!f
            .project
            .join("build/parser/compile_commands.json")
            .exists());
        assert_eq!(
            f.history().await[0]
                .diagnosis
                .terminal
                .as_ref()
                .unwrap()
                .status,
            expected
        );
    }
}
#[tokio::test]
async fn expected_digest_mismatch_precedes_authorization_and_is_retained() {
    let mut f = fixture(BuildRuntime::new(), ProfileBuildSystem::CMake).await;
    f.service = f.service.with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy {
            auto_allow_max: hf_guardrails::RiskTier::Low,
            deny_at: Some(hf_guardrails::RiskTier::Low),
        },
        Arc::new(hf_guardrails::DenyAll),
    ));
    let mut request = f.request();
    request.expected_profile_sha256 = "a".repeat(64);
    let error = f.service.run_build_plan(request).await.unwrap_err();
    assert!(error.to_string().contains("profile"));
    assert!(!error.to_string().contains("guardrail"));
    assert!(f.runtime.calls.lock().unwrap().is_empty());
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        BuildTerminalStatus::ProfileChanged
    );
    assert!(f
        .service
        .run_build_plan(f.request())
        .await
        .unwrap_err()
        .to_string()
        .contains("guardrail"));
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        BuildTerminalStatus::Denied
    );
    assert!(f.runtime.builds().is_empty());
}
#[tokio::test]
async fn clearing_profile_during_pending_build_retains_captured_output_and_refuses_publication() {
    let mut runtime = BuildRuntime::new();
    runtime.pause = true;
    runtime.output = "old build output".into();
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    let run = f.service.run_build_plan(f.request());
    let change = async {
        f.runtime.entered.notified().await;
        f.service.clear_build_profile(&f.project).await.unwrap();
        f.runtime.resume.notify_one();
    };
    let (outcome, ()) = tokio::join!(run, change);
    assert!(outcome.unwrap_err().to_string().contains("profile"));
    assert!(!f
        .project
        .join("build/parser/compile_commands.json")
        .exists());
    let history = f.history().await;
    assert_eq!(
        history[0].profile_sha256.as_ref(),
        Some(&f.profile.profile_sha256)
    );
    let terminal = history[0].diagnosis.terminal.as_ref().unwrap();
    assert_eq!(terminal.status, BuildTerminalStatus::ProfileChanged);
    assert!(terminal.stdout.contains("old build output"));
}
#[tokio::test]
async fn marker_and_live_image_changes_are_stale_without_probes() {
    for image in [false, true] {
        let f = fixture(BuildRuntime::new(), ProfileBuildSystem::CMake).await;
        if image {
            *f.runtime.image.lock().unwrap() = format!("sha256:{}", "a".repeat(64));
        } else {
            std::fs::write(
                f.project.join("components/parser/CMakeLists.txt"),
                "changed",
            )
            .unwrap();
        }
        assert_eq!(
            f.service
                .diagnose_build(&f.project)
                .await
                .unwrap()
                .profile_state,
            BuildProfileState::Stale
        );
        assert!(f.runtime.calls.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn missing_dependency_is_invalid_but_runtime_failure_is_an_error_with_history() {
    let mut runtime = BuildRuntime::new();
    runtime.probe_missing = Some("bear".into());
    let f = fixture(runtime, ProfileBuildSystem::Make).await;
    let d = f.service.diagnose_build(&f.project).await.unwrap();
    assert_eq!(d.profile_state, BuildProfileState::Invalid);
    assert!(d.reasons.iter().any(|r| r.contains("bear")));
    assert!(d.plan.is_none());
    let mut runtime = BuildRuntime::new();
    runtime.runtime_error = true;
    let f = fixture(runtime, ProfileBuildSystem::Make).await;
    assert!(f.service.diagnose_build(&f.project).await.is_err());
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        BuildTerminalStatus::RuntimeFailed
    );
}
#[tokio::test]
async fn configured_database_is_authoritative_and_invalid_data_never_falls_back() {
    let f = fixture(BuildRuntime::new(), ProfileBuildSystem::CMake).await;
    let legacy = serde_json::json!([{"directory":f.profile.project_root,"file":"a.c","arguments":["cc","-DLEGACY=1","-c","a.c"]}]);
    std::fs::write(f.project.join("compile_commands.json"), legacy.to_string()).unwrap();
    assert!(f
        .service
        .resolve_build_context(&f.project)
        .await
        .unwrap()
        .is_none());
    std::fs::create_dir_all(f.project.join("build/parser")).unwrap();
    std::fs::write(f.project.join("build/parser/compile_commands.json"), "{bad").unwrap();
    assert!(f.service.resolve_build_context(&f.project).await.is_err());
    assert_eq!(
        f.service
            .diagnose_build(&f.project)
            .await
            .unwrap()
            .profile_state,
        BuildProfileState::Invalid
    );
    f.service.clear_build_profile(&f.project).await.unwrap();
    assert_eq!(
        f.service
            .resolve_build_context(&f.project)
            .await
            .unwrap()
            .unwrap()
            .defines,
        ["-DLEGACY=1"]
    );
}

#[tokio::test]
async fn a_simple_valid_database_needs_no_extra_flags() {
    let f = fixture(BuildRuntime::new(), ProfileBuildSystem::Make).await;
    std::fs::create_dir_all(f.project.join("build/parser")).unwrap();
    let document = serde_json::json!([{"directory": f.profile.project_root, "file":"components/parser/a.c", "arguments":["cc","-c","components/parser/a.c"]}]);
    std::fs::write(
        f.project.join("build/parser/compile_commands.json"),
        document.to_string(),
    )
    .unwrap();
    let diagnosis = f.service.diagnose_build(&f.project).await.unwrap();
    assert_eq!(diagnosis.profile_state, BuildProfileState::Ready);
    let context = f
        .service
        .resolve_build_context(&f.project)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.entry_count, 1);
    assert!(context.is_empty());
}

#[tokio::test]
async fn existing_selected_database_is_not_evidence_that_this_build_produced_an_artifact() {
    let mut runtime = BuildRuntime::new();
    runtime.artifact = None;
    let mut f = fixture(runtime, ProfileBuildSystem::CMake).await;
    let path = "components/parser/compile_commands.json";
    let old = serde_json::json!([{"directory":f.profile.project_root,"file":"a.c","arguments":["cc","-DOLD=1","-c","a.c"]}]).to_string();
    std::fs::write(f.project.join(path), &old).unwrap();
    f.profile = f
        .service
        .save_build_profile(SaveBuildProfileRequest {
            project: f.project.display().to_string(),
            component_root: f.profile.component_root.clone(),
            build_system: f.profile.build_system,
            compile_database_path: path.into(),
            cmake_definitions: f.profile.cmake_definitions.clone(),
            dependencies: vec![],
        })
        .await
        .unwrap();
    assert_eq!(
        f.service.run_build_plan(f.request()).await.unwrap().status,
        BuildTerminalStatus::ArtifactMissing
    );
    assert_eq!(std::fs::read_to_string(f.project.join(path)).unwrap(), old);
}
#[tokio::test]
async fn build_runtime_failure_is_retained_as_failed() {
    let mut runtime = BuildRuntime::new();
    runtime.fail_build = true;
    runtime.output = "directory step completed".into();
    let f = fixture(runtime, ProfileBuildSystem::Make).await;
    assert!(f.service.run_build_plan(f.request()).await.is_err());
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        BuildTerminalStatus::RuntimeFailed
    );
    let history = f.history().await;
    let terminal = history[0].diagnosis.terminal.as_ref().unwrap();
    assert_eq!(terminal.step_index, Some(1));
    assert_eq!(terminal.exit_code, None);
    assert!(terminal.stdout.contains("directory step completed"));
}

/// A manual fixture maps the production tag lookup to the separately built task
/// image. Every command still uses the captured immutable ID in `DockerRuntime`.
struct FixtureDocker {
    runtime: hf_runtime::docker::DockerRuntime,
    image: String,
}
#[async_trait]
impl RuntimeAdapter for FixtureDocker {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        self.runtime.resolve_image_reference(&self.image).await
    }
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.runtime.run_command(cmd, cwd, limits).await
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        self.runtime.run_command_opts(cmd, cwd, limits, opts).await
    }
    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        self.runtime.write_file(path, content).await
    }
    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        self.runtime.read_file(path).await
    }
}
#[tokio::test]
#[ignore = "requires separately built HF_BUILD_DOCTOR_TEST_IMAGE and a local Docker daemon"]
async fn real_docker_make_fixture_produces_and_retains_the_selected_database() {
    let image = std::env::var("HF_BUILD_DOCTOR_TEST_IMAGE").expect("explicit task image required");
    let runtime = Arc::new(FixtureDocker {
        runtime: hf_runtime::docker::DockerRuntime::new(
            hf_runtime::RuntimeConfig::default(),
            workspace(),
        ),
        image,
    });
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join("components/parser")).unwrap();
    std::fs::write(
        project.join("components/parser/Makefile"),
        "all: a.o\na.o: a.c\n\tcc -c a.c -o a.o\n",
    )
    .unwrap();
    std::fs::write(
        project.join("components/parser/a.c"),
        "int sum(int a, int b) { return a + b; }\n",
    )
    .unwrap();
    let service = ServiceContainer::new(runtime.clone(), None).with_store(Arc::new(
        hf_storage::Store::connect(dir.path().join("store.db"))
            .await
            .unwrap(),
    ));
    let profile = service
        .save_build_profile(SaveBuildProfileRequest {
            project: project.display().to_string(),
            component_root: "components/parser".into(),
            build_system: ProfileBuildSystem::Make,
            compile_database_path: "build/parser/compile_commands.json".into(),
            cmake_definitions: std::collections::BTreeMap::new(),
            dependencies: vec![],
        })
        .await
        .unwrap();
    let probes = tempfile::tempdir_in(workspace()).unwrap();
    for tool in ["bear", "cmake", "make", "pkg-config"] {
        let result = runtime
            .run_command_opts(
                &[tool.into(), "--version".into()],
                probes.path(),
                &ResourceLimits {
                    max_mem_mb: 256,
                    max_cpus: 1,
                    max_duration_secs: 30,
                    ..ResourceLimits::default()
                },
                &SandboxOptions {
                    image: Some(profile.sandbox_image_id.clone()),
                    network_mode: SandboxNetworkMode::None,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .require_completed("advertised toolchain")
            .unwrap();
        assert_eq!(result.exit_code, 0);
        println!("tool={tool} stdout={}", result.stdout.trim());
    }
    assert_eq!(
        service
            .diagnose_build(&project)
            .await
            .unwrap()
            .profile_state,
        BuildProfileState::NeedsBuild
    );
    let outcome = service
        .run_build_plan(RunBuildPlanRequest {
            project: project.display().to_string(),
            expected_profile_sha256: profile.profile_sha256.clone(),
        })
        .await
        .unwrap();
    println!(
        "image={} status={:?} steps={} terminal={:?}",
        profile.sandbox_image_id, outcome.status, outcome.steps_run, outcome.diagnosis.terminal
    );
    assert_eq!(outcome.status, BuildTerminalStatus::Succeeded);
    assert_eq!(outcome.steps_run, 2);
    let context = outcome.build_context.unwrap();
    assert!(context.entry_count > 0);
    assert!(context.is_empty(), "ordinary cc -c needs no extra flags");
    assert_eq!(
        service
            .diagnose_build(&project)
            .await
            .unwrap()
            .profile_state,
        BuildProfileState::Ready
    );
    println!(
        "database={}",
        std::fs::read_to_string(project.join("build/parser/compile_commands.json")).unwrap()
    );
    assert!(!project.join("components/parser/a.o").exists());
    service
        .save_build_profile(SaveBuildProfileRequest {
            project: project.display().to_string(),
            component_root: profile.component_root.clone(),
            build_system: profile.build_system,
            compile_database_path: profile.compile_database_path.clone(),
            cmake_definitions: std::collections::BTreeMap::new(),
            dependencies: vec![hf_service::BuildDependency {
                kind: hf_service::BuildDependencyKind::Command,
                name: "oxfuzz-fixture-command-does-not-exist".into(),
            }],
        })
        .await
        .unwrap();
    let missing = service.diagnose_build(&project).await;
    if missing.is_err() {
        let history = service.build_diagnosis_history(&project, 1).await.unwrap();
        println!(
            "missing_command_terminal={:?}",
            history[0].diagnosis.terminal
        );
    }
    let missing = missing.unwrap();
    println!(
        "missing_command_state={:?} reasons={:?}",
        missing.profile_state, missing.reasons
    );
    assert_eq!(missing.profile_state, BuildProfileState::Invalid);
}

#[tokio::test]
async fn normalization_rewrites_only_execution_path_prefixes_and_preserves_other_text() {
    let mut runtime = BuildRuntime::new();
    runtime.artifact = Some(serde_json::json!([{"directory":"/work/components/parser", "file":"/work/components/parser/a.c", "command":"cc -I/work/include -DNOTE=prefix/work/value -c a.c", "note":"literal /work/ text"}]).to_string());
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    assert_eq!(
        f.service.run_build_plan(f.request()).await.unwrap().status,
        BuildTerminalStatus::Succeeded
    );
    let raw =
        std::fs::read_to_string(f.project.join("build/parser/compile_commands.json")).unwrap();
    assert!(raw.contains("-DNOTE=prefix/work/value"));
    assert!(raw.contains("literal /work/ text"));
    assert!(!raw.contains("-I/work/include"));
}

#[tokio::test]
async fn cancelled_and_timed_out_probes_are_retained_without_missing_dependency_results() {
    for (termination, status) in [
        (
            CommandTermination::Cancelled,
            BuildTerminalStatus::Cancelled,
        ),
        (CommandTermination::TimedOut, BuildTerminalStatus::TimedOut),
    ] {
        let mut runtime = BuildRuntime::new();
        runtime.probe_termination = termination;
        let f = fixture(runtime, ProfileBuildSystem::Make).await;
        assert!(f.service.diagnose_build(&f.project).await.is_err());
        let history = f.history().await;
        assert_eq!(
            history[0].diagnosis.terminal.as_ref().unwrap().status,
            status
        );
        assert!(history[0].diagnosis.dependency_statuses.is_empty());
        assert!(f.runtime.builds().is_empty());
    }
}
#[tokio::test]
async fn dependency_modules_use_fixed_pkg_config_argv() {
    let mut f = fixture(BuildRuntime::new(), ProfileBuildSystem::Make).await;
    f.profile = f
        .service
        .save_build_profile(SaveBuildProfileRequest {
            project: f.project.display().to_string(),
            component_root: f.profile.component_root.clone(),
            build_system: f.profile.build_system,
            compile_database_path: f.profile.compile_database_path.clone(),
            cmake_definitions: f.profile.cmake_definitions.clone(),
            dependencies: vec![hf_service::BuildDependency {
                kind: hf_service::BuildDependencyKind::PkgConfig,
                name: "zlib".into(),
            }],
        })
        .await
        .unwrap();
    let d = f.service.diagnose_build(&f.project).await.unwrap();
    assert_eq!(d.profile_state, BuildProfileState::NeedsBuild);
    let calls = f.runtime.calls.lock().unwrap();
    assert_eq!(
        calls.last().unwrap().argv,
        ["pkg-config", "--exists", "zlib"]
    );
    assert_eq!(calls.len(), 5);
    assert!(calls.iter().all(|call| call.empty));
}
#[tokio::test]
async fn saving_a_changed_profile_during_build_preserves_both_current_and_old_evidence() {
    let mut runtime = BuildRuntime::new();
    runtime.pause = true;
    runtime.output = "captured output".into();
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    let run = f.service.run_build_plan(f.request());
    let change = async {
        f.runtime.entered.notified().await;
        let saved = f
            .service
            .save_build_profile(SaveBuildProfileRequest {
                project: f.project.display().to_string(),
                component_root: f.profile.component_root.clone(),
                build_system: f.profile.build_system,
                compile_database_path: "new/output/compile_commands.json".into(),
                cmake_definitions: f.profile.cmake_definitions.clone(),
                dependencies: vec![],
            })
            .await
            .unwrap();
        f.runtime.resume.notify_one();
        saved
    };
    let (outcome, saved) = tokio::join!(run, change);
    assert!(outcome.is_err());
    assert_eq!(
        f.service.build_profile(&f.project).await.unwrap().unwrap(),
        saved
    );
    let history = f.history().await;
    assert_eq!(history[0].diagnosis.profile.as_ref(), Some(&f.profile));
    assert_eq!(
        history[0].diagnosis.plan.as_ref().unwrap().profile_sha256,
        f.profile.profile_sha256
    );
    assert!(history[0]
        .diagnosis
        .terminal
        .as_ref()
        .unwrap()
        .stdout
        .contains("captured output"));
    assert!(!f.project.join("new/output/compile_commands.json").exists());
    assert!(!f
        .project
        .join("build/parser/compile_commands.json")
        .exists());
}
#[cfg(unix)]
#[tokio::test]
async fn source_symlinks_are_refused_before_build_dispatch() {
    let f = fixture(BuildRuntime::new(), ProfileBuildSystem::CMake).await;
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), f.project.join("linked")).unwrap();
    assert!(f
        .service
        .run_build_plan(f.request())
        .await
        .unwrap_err()
        .to_string()
        .contains("symbolic link"));
    assert!(f.runtime.builds().is_empty());
    assert_eq!(
        f.history().await[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .status,
        BuildTerminalStatus::RuntimeFailed
    );
}

#[tokio::test]
async fn retained_output_fits_the_envelope_near_profile_capacity() {
    let mut runtime = BuildRuntime::new();
    runtime.exit_code = 3;
    runtime.output = "é\n\"".repeat(40000);
    let mut f = fixture(runtime, ProfileBuildSystem::Make).await;
    let mut low = 0;
    let mut high = 500;
    while low + 1 < high {
        let count = i32::midpoint(low, high);
        let dependencies = (0..count)
            .map(|index| hf_service::BuildDependency {
                kind: hf_service::BuildDependencyKind::Command,
                name: format!("dep{index:04}{}", "x".repeat(57)),
            })
            .collect();
        let result = f
            .service
            .save_build_profile(SaveBuildProfileRequest {
                project: f.project.display().to_string(),
                component_root: f.profile.component_root.clone(),
                build_system: f.profile.build_system,
                compile_database_path: f.profile.compile_database_path.clone(),
                cmake_definitions: f.profile.cmake_definitions.clone(),
                dependencies,
            })
            .await;
        match result {
            Ok(saved) => {
                low = count;
                f.profile = saved;
            }
            Err(error) => {
                assert!(error.to_string().contains("capacity"));
                high = count;
            }
        }
    }
    let outcome = f.service.run_build_plan(f.request()).await.unwrap();
    assert_eq!(outcome.status, BuildTerminalStatus::StepFailed);
    let history = f.history().await;
    let size = serde_json::to_vec(&history[0].diagnosis).unwrap().len();
    assert!(size > 40000 && size <= 65536, "encoded envelope: {size}");
    assert!(
        history[0]
            .diagnosis
            .terminal
            .as_ref()
            .unwrap()
            .output_truncated
    );
    assert!(!history[0]
        .diagnosis
        .terminal
        .as_ref()
        .unwrap()
        .stdout
        .is_empty());
}

#[tokio::test]
async fn cmake_command_database_preserves_safe_includes_with_spaced_host_and_include_paths() {
    let mut runtime = BuildRuntime::new();
    runtime.artifact = Some(serde_json::json!([{"directory":"/work/components/parser", "file":"/work/components/parser/a.c", "command":r#"cc -I/work/include -I"/work/my include" -c a.c"#, "note":"unchanged"}]).to_string());
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    std::fs::create_dir_all(f.project.join("my include")).unwrap();
    let outcome = f.service.run_build_plan(f.request()).await.unwrap();
    let context = outcome.build_context.unwrap();
    let root = std::fs::canonicalize(&f.project).unwrap();
    assert_eq!(
        context.include_dirs,
        [root.join("include"), root.join("my include")]
    );
    let raw: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(f.project.join("build/parser/compile_commands.json")).unwrap(),
    )
    .unwrap();
    assert!(raw[0].get("command").is_none());
    assert_eq!(
        raw[0]["arguments"][2],
        format!("-I{}/my include", root.display())
    );
    assert_eq!(raw[0]["note"], "unchanged");
    assert_eq!(
        f.service
            .resolve_build_context(&f.project)
            .await
            .unwrap()
            .unwrap()
            .include_dirs,
        context.include_dirs
    );
}

#[tokio::test]
async fn command_lookup_diagnostics_are_runtime_failures_even_with_exit_127() {
    let mut runtime = BuildRuntime::new();
    runtime.probe_missing = Some("bear".into());
    runtime.probe_stderr = "could not execute sandbox shell".into();
    let f = fixture(runtime, ProfileBuildSystem::Make).await;
    assert!(f.service.diagnose_build(&f.project).await.is_err());
    let history = f.history().await;
    let terminal = history[0].diagnosis.terminal.as_ref().unwrap();
    assert_eq!(terminal.status, BuildTerminalStatus::RuntimeFailed);
    assert_eq!(terminal.exit_code, Some(127));
    assert!(terminal.stderr.contains("sandbox shell"));
    assert!(history[0].diagnosis.dependency_statuses.is_empty());
}

async fn mutate_profile_while_image_resolution_is_pending(f: &Fixture, clear: bool) {
    f.runtime.image_entered.notified().await;
    if clear {
        f.service.clear_build_profile(&f.project).await.unwrap();
    } else {
        f.service
            .save_build_profile(SaveBuildProfileRequest {
                project: f.project.display().to_string(),
                component_root: f.profile.component_root.clone(),
                build_system: f.profile.build_system,
                compile_database_path: "changed/compile_commands.json".into(),
                cmake_definitions: f.profile.cmake_definitions.clone(),
                dependencies: f.profile.dependencies.clone(),
            })
            .await
            .unwrap();
    }
    f.runtime.image_resume.notify_one();
}

async fn assert_image_resolution_race(
    pause_call: usize,
    system: ProfileBuildSystem,
    clear: bool,
    deny: bool,
) {
    let mut runtime = BuildRuntime::new();
    // Save resolves call 1; assessment resolves call 2; current checks resolve
    // call 3 before authorization, call 4 before step 0, and call 5 before step 1.
    runtime.pause_image_call = pause_call;
    runtime.output = "completed mkdir output".into();
    let mut f = fixture(runtime, system).await;
    if deny {
        f.service = f.service.with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy {
                auto_allow_max: hf_guardrails::RiskTier::Low,
                deny_at: Some(hf_guardrails::RiskTier::Low),
            },
            Arc::new(hf_guardrails::DenyAll),
        ));
    }
    let run = f.service.run_build_plan(f.request());
    let mutation = mutate_profile_while_image_resolution_is_pending(&f, clear);
    let (outcome, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(run, mutation)
    })
    .await
    .expect("image gate must be reached and resumed");
    let error = outcome.unwrap_err();
    assert!(error.to_string().contains("profile"));
    let calls = f.runtime.builds();
    if pause_call == 5 {
        assert_eq!(calls.len(), 1, "Bear must not start after profile mutation");
        assert_eq!(calls[0].argv[0], "mkdir");
    } else {
        assert!(
            calls.is_empty(),
            "no build step may start after profile mutation"
        );
    }
    let history = f.history().await;
    let evidence = &history[0].diagnosis;
    assert_eq!(evidence.profile.as_ref(), Some(&f.profile));
    assert_eq!(
        evidence.plan.as_ref().unwrap().profile_sha256,
        f.profile.profile_sha256
    );
    assert_eq!(
        evidence.plan.as_ref().unwrap().sandbox_image_id,
        f.profile.sandbox_image_id
    );
    let terminal = evidence.terminal.as_ref().unwrap();
    assert_eq!(terminal.status, BuildTerminalStatus::ProfileChanged);
    if pause_call == 5 {
        assert_eq!(terminal.stdout, "completed mkdir output");
    }
    assert!(!f
        .project
        .join("build/parser/compile_commands.json")
        .exists());
}

#[tokio::test]
async fn image_resolution_race_before_authorization_rechecks_save_and_clear() {
    for clear in [false, true] {
        assert_image_resolution_race(3, ProfileBuildSystem::CMake, clear, true).await;
    }
}

#[tokio::test]
async fn image_resolution_race_before_first_step_rechecks_save_and_clear() {
    for clear in [false, true] {
        assert_image_resolution_race(4, ProfileBuildSystem::CMake, clear, false).await;
    }
}

#[tokio::test]
async fn image_resolution_race_before_second_step_stops_bear_and_keeps_prior_output() {
    for clear in [false, true] {
        assert_image_resolution_race(5, ProfileBuildSystem::Make, clear, false).await;
    }
}

fn padded_compile_database(bytes: usize) -> String {
    let mut document = serde_json::json!([{
        "directory":"/work/components/parser", "file":"/work/components/parser/a.c",
        "arguments":["cc", "-DNEW=1", "-c", "a.c"], "padding":"",
    }]);
    let base_bytes = document.to_string().len();
    document[0]["padding"] = serde_json::Value::String("x".repeat(bytes - base_bytes));
    let raw = document.to_string();
    assert_eq!(raw.len(), bytes);
    raw
}

fn install_prior_database(f: &Fixture) -> (PathBuf, String) {
    let path = f.project.join(&f.profile.compile_database_path);
    let raw = serde_json::json!([{"directory":f.profile.project_root, "file":"a.c", "arguments":["cc", "-DOLD=1", "-c", "a.c"]}]).to_string();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &raw).unwrap();
    (path, raw)
}

#[tokio::test]
async fn normalized_database_over_reader_limit_is_retained_invalid_without_replacing_prior_output()
{
    // The production reader permits at most 64 MiB. Compact input fits by one
    // byte; pretty formatting and rewritten host prefixes make output larger.
    const READER_LIMIT_BYTES: usize = 64 * 1024 * 1024;
    let raw = padded_compile_database(READER_LIMIT_BYTES - 1);
    assert!(raw.len() < READER_LIMIT_BYTES);
    let mut runtime = BuildRuntime::new();
    runtime.artifact = Some(raw);
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    let (path, previous) = install_prior_database(&f);
    let outcome = f.service.run_build_plan(f.request()).await.unwrap();
    assert_eq!(outcome.status, BuildTerminalStatus::ArtifactInvalid);
    assert!(outcome.build_context.is_none());
    assert_eq!(outcome.diagnosis.profile_state, BuildProfileState::Invalid);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), previous);
    let history = f.history().await;
    assert_eq!(history[0].status, hf_storage::BuildDiagnosisStatus::Failed);
    assert_eq!(history[0].diagnosis.profile.as_ref(), Some(&f.profile));
    assert_eq!(
        history[0].diagnosis.profile_state,
        BuildProfileState::Invalid
    );
    let terminal = history[0].diagnosis.terminal.as_ref().unwrap();
    assert_eq!(terminal.status, BuildTerminalStatus::ArtifactInvalid);
    assert!(terminal
        .failure_message
        .as_ref()
        .unwrap()
        .contains("67108864"));
    assert_eq!(
        f.service
            .resolve_build_context(&f.project)
            .await
            .unwrap()
            .unwrap()
            .defines,
        ["-DOLD=1"]
    );
    assert_eq!(
        f.service
            .diagnose_build(&f.project)
            .await
            .unwrap()
            .profile_state,
        BuildProfileState::Ready
    );
}

#[tokio::test]
async fn normalized_database_within_reader_limit_replaces_prior_output_and_is_ready() {
    let mut runtime = BuildRuntime::new();
    runtime.artifact = Some(padded_compile_database(4096));
    let f = fixture(runtime, ProfileBuildSystem::CMake).await;
    let (path, previous) = install_prior_database(&f);
    let outcome = f.service.run_build_plan(f.request()).await.unwrap();
    assert_eq!(outcome.status, BuildTerminalStatus::Succeeded);
    assert_eq!(outcome.diagnosis.profile_state, BuildProfileState::Ready);
    let normalized = std::fs::read_to_string(path).unwrap();
    assert_ne!(normalized, previous);
    assert!(normalized.len() <= 64 * 1024 * 1024);
    assert_eq!(
        f.service
            .resolve_build_context(&f.project)
            .await
            .unwrap()
            .unwrap()
            .defines,
        ["-DNEW=1"]
    );
    assert_eq!(
        f.service
            .diagnose_build(&f.project)
            .await
            .unwrap()
            .profile_state,
        BuildProfileState::Ready
    );
}
