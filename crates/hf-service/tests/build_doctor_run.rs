//! Build Doctor execution contract.
//!
//! Running a plan runs the project's own build system, which is untrusted code.
//! It must be authorized, must run only through `hf-runtime`, and must prove the
//! artifact appeared rather than trusting an exit code.

#![cfg(feature = "build-doctor")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
};
use hf_service::build_doctor::{BuildPlanRunStatus, BuildSystem};
use hf_service::{RunBuildPlanRequest, ServiceContainer};

/// A runtime double that records commands and optionally writes the database.
struct BuildRuntime {
    calls: Mutex<Vec<Vec<String>>>,
    exit_code: i32,
    write_artifact: Option<PathBuf>,
}

impl BuildRuntime {
    fn new(exit_code: i32, write_artifact: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            exit_code,
            write_artifact,
        })
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RuntimeAdapter for BuildRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        ImmutableImageReference::from_sha256_id(format!("sha256:{}", "f".repeat(64))).map(Some)
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls.lock().unwrap().push(cmd.to_vec());
        if self.exit_code == 0 {
            if let Some(relative) = &self.write_artifact {
                let path = cwd.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                // A real database references paths inside the project, which is
                // what the build-context allowlist requires.
                let root = cwd.display();
                std::fs::write(
                    path,
                    format!(
                        r#"[{{"directory":"{root}","file":"{root}/a.c","arguments":["clang","-I{root}/include","-std=c11","-c","{root}/a.c"]}}]"#
                    ),
                )
                .unwrap();
            }
        }
        Ok(CommandResult {
            exit_code: self.exit_code,
            stdout: String::new(),
            stderr: if self.exit_code == 0 {
                String::new()
            } else {
                "CMake Error: could not find CMakeLists.txt".to_owned()
            },
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        std::fs::read_to_string(path).map_err(|error| ClassifiedError::Sandbox(error.to_string()))
    }
}

fn cmake_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("CMakeLists.txt"), b"project(p)\n").unwrap();
    std::fs::write(dir.path().join("a.c"), b"int main(void){return 0;}\n").unwrap();
    std::fs::create_dir_all(dir.path().join("include")).unwrap();
    dir
}

fn request(project: &Path) -> RunBuildPlanRequest {
    RunBuildPlanRequest {
        project: project.display().to_string(),
        build_system: BuildSystem::CMake,
    }
}

#[tokio::test]
async fn a_successful_run_executes_the_plan_in_the_sandbox_and_resolves_the_database() {
    let project = cmake_project();
    let runtime = BuildRuntime::new(
        0,
        Some(PathBuf::from(".oxfuzz-build/compile_commands.json")),
    );
    let container = ServiceContainer::new(runtime.clone(), None);

    let outcome = container
        .run_build_plan(request(project.path()))
        .await
        .expect("a supported plan runs");

    assert_eq!(outcome.status, BuildPlanRunStatus::Succeeded);
    assert!(
        outcome.build_context.is_some(),
        "a successful run resolves the database it produced"
    );

    // Every step went through the sandbox, as a fixed argument vector.
    let calls = runtime.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][0], "cmake");
    assert!(calls[0]
        .iter()
        .any(|arg| arg == "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"));
}

#[tokio::test]
async fn a_failing_step_stops_the_run_and_retains_its_index_exit_code_and_output() {
    let project = cmake_project();
    let runtime = BuildRuntime::new(1, None);
    let container = ServiceContainer::new(runtime.clone(), None);

    let outcome = container
        .run_build_plan(request(project.path()))
        .await
        .expect("a failed build is a result, not an error");

    assert_eq!(outcome.status, BuildPlanRunStatus::StepFailed);
    let failure = outcome.failed_step.expect("the failing step is retained");
    assert_eq!(failure.index, 0);
    assert_eq!(failure.exit_code, 1);
    assert!(
        failure.output.contains("CMake Error"),
        "the step's output is retained: {}",
        failure.output
    );
    assert!(outcome.build_context.is_none());
}

#[tokio::test]
async fn every_step_succeeding_without_the_artifact_is_a_failure_not_a_success() {
    let project = cmake_project();
    // Exit code zero, but the plan's expected artifact never appears.
    let runtime = BuildRuntime::new(0, None);
    let container = ServiceContainer::new(runtime.clone(), None);

    let outcome = container
        .run_build_plan(request(project.path()))
        .await
        .expect("a missing artifact is a result, not an error");

    assert_eq!(outcome.status, BuildPlanRunStatus::ArtifactMissing);
    assert!(
        outcome.build_context.is_none(),
        "command success is not evidence that the artifact appeared"
    );
}

#[tokio::test]
async fn a_build_system_the_image_cannot_run_is_refused_without_executing_anything() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("Makefile"), b"all:\n\ttrue\n").unwrap();
    let runtime = BuildRuntime::new(0, None);
    let container = ServiceContainer::new(runtime.clone(), None);

    let error = container
        .run_build_plan(RunBuildPlanRequest {
            project: project.path().display().to_string(),
            build_system: BuildSystem::Make,
        })
        .await
        .expect_err("an unsupported build system has no plan to run");
    assert!(
        error.to_string().contains("bear"),
        "the refusal names the missing tool: {error}"
    );
    assert!(runtime.calls().is_empty(), "nothing executed");
}

#[tokio::test]
async fn running_a_project_build_requires_guardrail_authorization() {
    use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};

    let project = cmake_project();
    let runtime = BuildRuntime::new(
        0,
        Some(PathBuf::from(".oxfuzz-build/compile_commands.json")),
    );
    let container = ServiceContainer::new(runtime.clone(), None).with_guardrails(Guardrails::new(
        GuardrailPolicy {
            auto_allow_max: RiskTier::Low,
            deny_at: Some(RiskTier::Low),
        },
        Arc::new(DenyAll),
    ));

    let error = container
        .run_build_plan(request(project.path()))
        .await
        .expect_err("a denied action never runs the project's build");
    assert!(
        error.to_string().contains("guardrail"),
        "the refusal names the guardrail: {error}"
    );
    assert!(runtime.calls().is_empty(), "nothing executed");
}
