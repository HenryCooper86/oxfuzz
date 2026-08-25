//! Diagnose a project's build system and plan a sandboxed compile-database run.
//!
//! Missing compile context is the largest source of first-draft harness build
//! failures. The container's build-context resolver consumes a
//! `compile_commands.json` when a project ships one and records that generating
//! one belongs behind `hf-runtime` and a guardrail action. This module supplies
//! the diagnosis and the plan; execution lives on [`crate::ServiceContainer`].
//!
//! Detection is read-only and cites the marker files it found. A plan is
//! emitted only when the pinned sandbox image can actually run it: a plan that
//! would fail in the sandbox teaches an operator nothing about the real gap.
//!
//! See `docs/design/build-doctor-design.md`.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Tool that would observe a Make or Autotools build to produce a compile
/// database. Absent from the pinned sandbox image.
pub const MISSING_TOOL_BEAR: &str = "bear";

/// oxfuzz-owned build directory. Separate from any `build/` the project
/// maintains, so running a plan never clobbers the operator's own build tree.
pub const OXFUZZ_BUILD_DIR: &str = ".oxfuzz-build";

/// A build system oxfuzz can recognize from a project's root marker files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildSystem {
    // The derived snake_case form of `CMake` is `c_make`, which is not what any
    // operator or wire consumer expects.
    #[serde(rename = "cmake")]
    CMake,
    Meson,
    Autotools,
    Make,
    Bazel,
    Cargo,
    /// No marker matched. Never a guess.
    Unknown,
}

/// What oxfuzz can do about a detected build system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildSystemStatus {
    /// The project already resolves usable build context. No plan is needed.
    Ready,
    /// A compile database can be produced with tools in the pinned image.
    Supported,
    /// Detected, but the tool that would generate a database is absent from the
    /// pinned image. The missing tool is named and no plan is emitted.
    UnsupportedInImage,
    /// This language path does not consume a compile database.
    NotNeeded,
    /// No marker matched.
    Unknown,
}

/// One step of a build plan: a fixed argument vector, never a shell string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildPlanStep {
    /// Exact argument vector. No value is interpolated from project content.
    pub argv: Vec<String>,
    /// Working directory, relative to the project root.
    pub working_dir: String,
    /// What this step is for, in operator-facing terms.
    pub purpose: String,
}

/// An ordered, reviewable plan that would produce a compile database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildPlan {
    pub steps: Vec<BuildPlanStep>,
    /// Artifact the plan is expected to produce, relative to the project root.
    /// Command success is not evidence that this appeared.
    pub expected_artifact: String,
}

/// One detected build system and what oxfuzz can do about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildSystemDiagnosis {
    pub build_system: BuildSystem,
    pub status: BuildSystemStatus,
    /// Marker files found at the project root, as evidence for the detection.
    pub markers: Vec<String>,
    /// The tool the pinned image lacks, when the status is
    /// `unsupported_in_image`.
    pub missing_tool: Option<String>,
    /// Emitted only for `supported`.
    pub plan: Option<BuildPlan>,
}

/// Marker files per build system, in the order they are reported. A project
/// matching several is reported as several: the first entry generates the
/// others' inputs, so it is the one that produces compile context.
const MARKERS: [(BuildSystem, &[&str]); 6] = [
    (BuildSystem::CMake, &["CMakeLists.txt"]),
    (BuildSystem::Meson, &["meson.build"]),
    (
        BuildSystem::Bazel,
        &[
            "WORKSPACE",
            "WORKSPACE.bazel",
            "MODULE.bazel",
            "BUILD.bazel",
        ],
    ),
    (BuildSystem::Cargo, &["Cargo.toml"]),
    (
        BuildSystem::Autotools,
        &["configure.ac", "configure.in", "Makefile.am"],
    ),
    (BuildSystem::Make, &["Makefile", "makefile", "GNUmakefile"]),
];

/// Detect the project's build systems and diagnose each one.
///
/// Reads the project root only: a marker in a subdirectory belongs to a
/// component, not to the project under test. Executes nothing.
#[must_use]
pub fn detect_build_systems(project: &Path) -> Vec<BuildSystemDiagnosis> {
    let ready = has_usable_build_context(project);
    let mut found: Vec<BuildSystemDiagnosis> = Vec::new();
    for (build_system, markers) in MARKERS {
        let present: Vec<String> = markers
            .iter()
            .filter(|marker| is_root_file(project, marker))
            .map(|marker| (*marker).to_owned())
            .collect();
        if present.is_empty() {
            continue;
        }
        found.push(diagnose(build_system, present, ready, project));
    }
    if found.is_empty() {
        found.push(BuildSystemDiagnosis {
            build_system: BuildSystem::Unknown,
            status: BuildSystemStatus::Unknown,
            markers: Vec::new(),
            missing_tool: None,
            plan: None,
        });
    }
    found
}

fn diagnose(
    build_system: BuildSystem,
    markers: Vec<String>,
    ready: bool,
    project: &Path,
) -> BuildSystemDiagnosis {
    // A project that already resolves usable build context needs no plan,
    // whichever build system produced that database.
    if ready && !matches!(build_system, BuildSystem::Cargo) {
        return BuildSystemDiagnosis {
            build_system,
            status: BuildSystemStatus::Ready,
            markers,
            missing_tool: None,
            plan: None,
        };
    }
    let (status, missing_tool, plan) = match build_system {
        BuildSystem::CMake => (
            BuildSystemStatus::Supported,
            None,
            Some(cmake_plan(project)),
        ),
        // Make and Autotools need a build observer to record a database, and
        // the pinned image has none.
        BuildSystem::Make | BuildSystem::Autotools => (
            BuildSystemStatus::UnsupportedInImage,
            Some(MISSING_TOOL_BEAR.to_owned()),
            None,
        ),
        BuildSystem::Meson => (
            BuildSystemStatus::UnsupportedInImage,
            Some("meson".to_owned()),
            None,
        ),
        BuildSystem::Bazel => (
            BuildSystemStatus::UnsupportedInImage,
            Some("bazel".to_owned()),
            None,
        ),
        // Rust harnesses build through cargo-fuzz against the staged crate.
        BuildSystem::Cargo => (BuildSystemStatus::NotNeeded, None, None),
        BuildSystem::Unknown => (BuildSystemStatus::Unknown, None, None),
    };
    BuildSystemDiagnosis {
        build_system,
        status,
        markers,
        missing_tool,
        plan,
    }
}

/// A configure-only `CMake` step: it generates the database without building the
/// project.
fn cmake_plan(_project: &Path) -> BuildPlan {
    BuildPlan {
        steps: vec![BuildPlanStep {
            argv: vec![
                "cmake".to_owned(),
                "-S".to_owned(),
                ".".to_owned(),
                "-B".to_owned(),
                OXFUZZ_BUILD_DIR.to_owned(),
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".to_owned(),
            ],
            working_dir: ".".to_owned(),
            purpose: "Configure the project so CMake writes a compile database".to_owned(),
        }],
        expected_artifact: format!("{OXFUZZ_BUILD_DIR}/compile_commands.json"),
    }
}

/// Whether a regular file with this exact name sits at the project root.
fn is_root_file(project: &Path, name: &str) -> bool {
    project
        .join(name)
        .symlink_metadata()
        .is_ok_and(|meta| meta.is_file())
}

/// Whether the project already ships a compile database in one of the places
/// the existing resolver looks.
fn has_usable_build_context(project: &Path) -> bool {
    [
        "compile_commands.json",
        "build/compile_commands.json",
        "out/compile_commands.json",
    ]
    .iter()
    .any(|relative| is_root_relative_file(project, relative))
}

fn is_root_relative_file(project: &Path, relative: &str) -> bool {
    project
        .join(relative)
        .symlink_metadata()
        .is_ok_and(|meta| meta.is_file())
}

/// Request to run a diagnosed build plan in the sandbox.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunBuildPlanRequest {
    pub project: String,
    pub build_system: BuildSystem,
}

/// How a plan run ended. Command success alone is never success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildPlanRunStatus {
    /// Every step exited zero and the expected artifact resolved.
    Succeeded,
    /// A step exited non-zero; later steps were not attempted.
    StepFailed,
    /// Every step exited zero, but the expected artifact never appeared.
    ArtifactMissing,
}

/// The step that stopped a run, retained for the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedBuildStep {
    pub index: usize,
    pub exit_code: i32,
    /// Captured output, bounded.
    pub output: String,
}

/// Durable-enough result of one plan run.
#[derive(Debug, Clone, Serialize)]
pub struct BuildPlanRunOutcome {
    pub status: BuildPlanRunStatus,
    pub build_system: BuildSystem,
    pub steps_run: usize,
    pub failed_step: Option<FailedBuildStep>,
    /// Resolved only when the artifact actually appeared and parsed.
    pub build_context: Option<hf_core::build::BuildContext>,
}

/// Bound on retained step output, so a verbose build cannot flood a record.
const MAX_STEP_OUTPUT_BYTES: usize = 8 * 1024;

impl crate::container::ServiceContainer {
    /// Diagnose a project's build systems. Reads the project root and executes
    /// nothing.
    ///
    /// # Errors
    /// Returns a classified error when the project path cannot be resolved.
    pub fn diagnose_build(
        &self,
        project: &std::path::Path,
    ) -> Result<Vec<BuildSystemDiagnosis>, hf_core::error::ClassifiedError> {
        let root = crate::container::canonical_project_root(project)?;
        Ok(detect_build_systems(&root))
    }

    /// Run a diagnosed build plan through `hf-runtime`.
    ///
    /// Runs the project's own build system, which is untrusted code: the run is
    /// guardrail-authorized, executes only in the sandbox, and proves the
    /// expected artifact appeared rather than trusting an exit code.
    ///
    /// # Errors
    /// Returns a classified error when the project cannot be resolved, the
    /// requested build system was not detected or has no runnable plan, or the
    /// guardrail denies the action. A build that runs and fails is an outcome,
    /// not an error.
    pub async fn run_build_plan(
        &self,
        req: RunBuildPlanRequest,
    ) -> Result<BuildPlanRunOutcome, hf_core::error::ClassifiedError> {
        use hf_core::error::ClassifiedError;

        let root = crate::container::canonical_project_root(std::path::Path::new(&req.project))?;
        let diagnosis = detect_build_systems(&root)
            .into_iter()
            .find(|entry| entry.build_system == req.build_system)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "build system {:?} was not detected in this project",
                    req.build_system
                ))
            })?;
        let Some(plan) = diagnosis.plan.clone() else {
            return Err(ClassifiedError::Validation(match &diagnosis.missing_tool {
                Some(tool) => format!(
                    "the pinned sandbox image cannot run this project's {:?} build: {tool} is not installed",
                    req.build_system
                ),
                None => format!(
                    "build system {:?} has no plan to run (status {:?})",
                    req.build_system, diagnosis.status
                ),
            }));
        };

        self.authorize_recorded(
            hf_guardrails::Action::RunProjectBuild {
                build_system: build_system_id(req.build_system).to_owned(),
            },
            "run_build_plan",
            Some(&root),
        )
        .await
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

        let runtime = self.runtime_adapter().clone();
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 600,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let opts = hf_core::runtime::SandboxOptions::default();

        let mut steps_run = 0usize;
        for (index, step) in plan.steps.iter().enumerate() {
            let cwd = root.join(&step.working_dir);
            let result = runtime
                .as_ref()
                .run_command_opts(&step.argv, &cwd, &limits, &opts)
                .await?;
            steps_run += 1;
            let completed = result.termination == hf_core::runtime::CommandTermination::Completed;
            if !completed || result.exit_code != 0 {
                let mut output = format!("{}\n{}", result.stdout, result.stderr);
                output.truncate(MAX_STEP_OUTPUT_BYTES);
                return Ok(BuildPlanRunOutcome {
                    status: BuildPlanRunStatus::StepFailed,
                    build_system: req.build_system,
                    steps_run,
                    failed_step: Some(FailedBuildStep {
                        index,
                        exit_code: result.exit_code,
                        output: output.trim().to_owned(),
                    }),
                    build_context: None,
                });
            }
        }

        // The artifact is the evidence, not the exit status.
        let artifact = root.join(&plan.expected_artifact);
        if !artifact.symlink_metadata().is_ok_and(|meta| meta.is_file()) {
            return Ok(BuildPlanRunOutcome {
                status: BuildPlanRunStatus::ArtifactMissing,
                build_system: req.build_system,
                steps_run,
                failed_step: None,
                build_context: None,
            });
        }
        let build_context = self.resolve_build_context(&root).unwrap_or(None);
        Ok(BuildPlanRunOutcome {
            status: if build_context.is_some() {
                BuildPlanRunStatus::Succeeded
            } else {
                // The file appeared but yielded nothing a compiler can use, so
                // the run did not achieve what it was for.
                BuildPlanRunStatus::ArtifactMissing
            },
            build_system: req.build_system,
            steps_run,
            failed_step: None,
            build_context,
        })
    }
}

/// Stable lowercase identifier, matching the serde wire form.
#[must_use]
pub const fn build_system_id(build_system: BuildSystem) -> &'static str {
    match build_system {
        BuildSystem::CMake => "cmake",
        BuildSystem::Meson => "meson",
        BuildSystem::Autotools => "autotools",
        BuildSystem::Make => "make",
        BuildSystem::Bazel => "bazel",
        BuildSystem::Cargo => "cargo",
        BuildSystem::Unknown => "unknown",
    }
}
