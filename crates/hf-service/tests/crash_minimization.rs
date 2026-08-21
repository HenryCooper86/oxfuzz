//! Crash minimization stays inside the run-owned sandbox evidence boundary.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum MinimizeOutcome {
    Success,
    TimedOut,
}

struct MinimizeRuntime {
    outcome: MinimizeOutcome,
    commands: Mutex<Vec<Vec<String>>>,
    minimize_options: Mutex<Vec<SandboxOptions>>,
}

impl MinimizeRuntime {
    fn new(outcome: MinimizeOutcome) -> Self {
        Self {
            outcome,
            commands: Mutex::new(Vec::new()),
            minimize_options: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RuntimeAdapter for MinimizeRuntime {
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
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        options: &SandboxOptions,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        self.commands.lock().unwrap().push(cmd.to_vec());
        if cmd.first().is_some_and(|part| part.starts_with("casr-")) {
            return Err(hf_core::error::ClassifiedError::Sandbox(
                "CASR unavailable in test".to_owned(),
            ));
        }
        if let Some(output) = cmd
            .iter()
            .find_map(|part| part.strip_prefix("-exact_artifact_path="))
        {
            self.minimize_options.lock().unwrap().push(options.clone());
            if matches!(self.outcome, MinimizeOutcome::Success) {
                let mount = options
                    .extra_mounts
                    .iter()
                    .find(|mount| output.starts_with(&mount.container_path))
                    .expect("minimized output uses the writable derived-artifact mount");
                let relative = output
                    .strip_prefix(&mount.container_path)
                    .unwrap()
                    .trim_start_matches('/');
                let host_output = mount.host_path.join(relative);
                std::fs::write(host_output, b"x").unwrap();
            }
            return Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: match self.outcome {
                    MinimizeOutcome::Success => CommandTermination::Completed,
                    MinimizeOutcome::TimedOut => CommandTermination::TimedOut,
                },
            });
        }

        Ok(CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 parse_input".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
    target: TargetCandidate,
    run: hf_storage::RunRecord,
    original: PathBuf,
    store: Arc<hf_storage::Store>,
}

async fn fixture(name: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    common::install_managed_workspace("oxfuzz_crash_minimization_tests");
    let project = root.path().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    let target = TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: project.clone(),
        language: TargetLanguage::C,
        symbol: "parse_input".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("parse.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "test".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    };
    let harness = hf_core::harness::Harness {
        id: uuid::Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return n && d[0]; }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: hf_core::harness::BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_input"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: hf_core::harness::HarnessStatus::Promoted,
        smoke_run: None,
    };
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(1)),
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        }),
        chrono::Utc::now(),
    );
    run.status = hf_storage::RunStatus::Done;
    run.ended_at = Some(chrono::Utc::now());
    run.evidence_dir = Some(format!("runs/{}/out", run.id));

    let workspace = hf_service::workspace_dir(&project, &target.symbol);
    let input_dir = workspace
        .join("runs")
        .join(run.id.to_string())
        .join("input");
    let output_dir = workspace.join("runs").join(run.id.to_string()).join("out");
    std::fs::create_dir_all(&input_dir).unwrap();
    std::fs::create_dir_all(&output_dir).unwrap();
    let binary = input_dir.join("harness");
    std::fs::write(&binary, b"immutable run binary").unwrap();
    run.binary_rev = Some(format!("{:x}", Sha256::digest(b"immutable run binary")));
    let original = output_dir.join("crash-original");
    std::fs::write(&original, b"crashing input that should become smaller").unwrap();
    let original = std::fs::canonicalize(original).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("service.db"))
            .await
            .unwrap(),
    );
    store
        .upsert_target(&target, chrono::Utc::now())
        .await
        .unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();

    Fixture {
        root,
        project,
        target,
        run,
        original,
        store,
    }
}

#[tokio::test]
async fn triage_persists_verified_run_owned_minimized_artifact() {
    let fixture = fixture("minimize-success").await;
    let runtime = Arc::new(MinimizeRuntime::new(MinimizeOutcome::Success));
    let service =
        ServiceContainer::new(runtime.clone(), None).with_store(Arc::clone(&fixture.store));

    let crashes = service
        .triage_run(&fixture.project, &fixture.target.symbol, fixture.run.id)
        .await
        .unwrap();

    assert_eq!(crashes.len(), 1);
    assert!(crashes[0].minimized);
    assert_eq!(std::fs::read(&crashes[0].input_path).unwrap(), b"x");
    assert!(crashes[0].input_path.starts_with(
        std::fs::canonicalize(hf_service::workspace_dir(
            &fixture.project,
            &fixture.target.symbol,
        ))
        .unwrap()
        .join("runs")
        .join(fixture.run.id.to_string())
        .join("triage/minimized")
    ));
    assert_eq!(
        std::fs::read(&fixture.original).unwrap(),
        b"crashing input that should become smaller"
    );
    let persisted = fixture
        .store
        .list_crashes_by_run(fixture.run.id)
        .await
        .unwrap();
    assert_eq!(persisted.len(), 1);
    assert!(persisted[0].minimized);

    let options = runtime.minimize_options.lock().unwrap();
    assert_eq!(options.len(), 1);
    assert!(options[0].workspace_read_only);
    assert_eq!(
        options[0].network_mode,
        hf_core::runtime::SandboxNetworkMode::None
    );
    assert_eq!(options[0].extra_mounts.len(), 1);
    assert!(!options[0].extra_mounts[0].read_only);
}

#[tokio::test]
async fn triage_timeout_keeps_original_crash_unminimized() {
    let fixture = fixture("minimize-timeout").await;
    let runtime = Arc::new(MinimizeRuntime::new(MinimizeOutcome::TimedOut));
    let service = ServiceContainer::new(runtime, None).with_store(Arc::clone(&fixture.store));

    let crashes = service
        .triage_run(&fixture.project, &fixture.target.symbol, fixture.run.id)
        .await
        .unwrap();

    assert_eq!(crashes.len(), 1);
    assert!(!crashes[0].minimized);
    assert_eq!(crashes[0].input_path, fixture.original);
    assert_eq!(
        std::fs::read(&fixture.original).unwrap(),
        b"crashing input that should become smaller"
    );
    let minimized_dir = hf_service::workspace_dir(&fixture.project, &fixture.target.symbol)
        .join("runs")
        .join(fixture.run.id.to_string())
        .join("triage/minimized");
    assert!(!minimized_dir.exists() || std::fs::read_dir(minimized_dir).unwrap().next().is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn triage_rejects_symlinked_minimization_output_directory() {
    use std::os::unix::fs::symlink;

    let fixture = fixture("minimize-symlink").await;
    let runtime = Arc::new(MinimizeRuntime::new(MinimizeOutcome::Success));
    let service =
        ServiceContainer::new(runtime.clone(), None).with_store(Arc::clone(&fixture.store));
    let triage_dir = hf_service::workspace_dir(&fixture.project, &fixture.target.symbol)
        .join("runs")
        .join(fixture.run.id.to_string())
        .join("triage");
    std::fs::create_dir_all(&triage_dir).unwrap();
    let outside = fixture.root.path().join("outside-minimized");
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, triage_dir.join("minimized")).unwrap();

    let crashes = service
        .triage_run(&fixture.project, &fixture.target.symbol, fixture.run.id)
        .await
        .unwrap();

    assert_eq!(crashes.len(), 1);
    assert!(!crashes[0].minimized);
    assert_eq!(crashes[0].input_path, fixture.original);
    assert!(std::fs::read_dir(outside).unwrap().next().is_none());
    assert!(runtime.minimize_options.lock().unwrap().is_empty());
}
