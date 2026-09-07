//! Execute the captured reviewed profile and retain every terminal result.
use super::diagnosis::{evidence, fail, fit, terminal};
use super::{
    normalize_compile_database, publish_compile_database, stage_project_snapshot,
    BuildPlanRunOutcome, BuildProfileState, BuildProfileView, BuildStagingGuard, ClassifiedError,
    Path, ProfileBuildSystem, ProjectBuildDiagnosis, RunBuildPlanRequest,
};
use crate::build_profiles::{
    check_build_profile, marker_digest, profile_build_plan, validate_project_path,
};
use hf_core::runtime::{CommandTermination, ResourceLimits, SandboxNetworkMode, SandboxOptions};
use hf_storage::{BuildDiagnosisOperation, BuildTerminalStatus};

impl crate::ServiceContainer {
    /// Run the exact saved profile after current checks and human authorization.
    /// Terminal evidence retains the captured identity even if save/clear races execution.
    pub async fn run_build_plan(
        &self,
        request: RunBuildPlanRequest,
    ) -> Result<BuildPlanRunOutcome, ClassifiedError> {
        let root = crate::container::canonical_project_root(Path::new(&request.project))?;
        let mut evidence = evidence(None, BuildDiagnosisOperation::Build);
        evidence.terminal = Some(terminal(BuildTerminalStatus::RuntimeFailed));
        let mut steps_run = 0;
        let result = async {
            let profile = self.build_profile(&root).await?.ok_or_else(|| {
                ClassifiedError::Validation(
                    "save a build profile before running a project build".into(),
                )
            })?;
            evidence.profile = Some(profile.clone());
            evidence.plan = Some(profile_build_plan(&profile));
            if request.expected_profile_sha256 != profile.profile_sha256 {
                let error = ClassifiedError::Validation(
                    "expected build profile digest does not match current saved profile".into(),
                );
                fail(&mut evidence, BuildTerminalStatus::ProfileChanged, &error);
                return Err(error);
            }
            self.assess_build_profile(&root, &mut evidence).await?;
            if !matches!(
                evidence.profile_state,
                BuildProfileState::Ready | BuildProfileState::NeedsBuild
            ) {
                let error = ClassifiedError::Validation(format!(
                    "build profile is {:?}: {}",
                    evidence.profile_state,
                    evidence.reasons.join("; ")
                ));
                fail(&mut evidence, BuildTerminalStatus::ProfileChanged, &error);
                return Err(error);
            }
            if let Err(error) = self.revalidate_build_profile(&root, &profile).await {
                fail(&mut evidence, BuildTerminalStatus::ProfileChanged, &error);
                return Err(error);
            }
            if let Err(error) = self
                .authorize_recorded(
                    hf_guardrails::Action::RunProjectBuild {
                        build_system: match profile.build_system {
                            ProfileBuildSystem::CMake => "cmake",
                            ProfileBuildSystem::Make => "make",
                        }
                        .into(),
                    },
                    "run_build_plan",
                    Some(&root),
                )
                .await
            {
                let error = ClassifiedError::Validation(error.to_string());
                fail(&mut evidence, BuildTerminalStatus::Denied, &error);
                return Err(error);
            }
            self.execute_profile_build(&root, &profile, &mut evidence, &mut steps_run)
                .await
        }
        .await;
        if let Err(error) = &result {
            let status =
                evidence
                    .terminal
                    .as_ref()
                    .map_or(
                        BuildTerminalStatus::RuntimeFailed,
                        |terminal| match terminal.status {
                            BuildTerminalStatus::Succeeded => BuildTerminalStatus::RuntimeFailed,
                            status => status,
                        },
                    );
            fail(&mut evidence, status, error);
        }
        self.retain_build_evidence(&root, &mut evidence).await?;
        let context = result?;
        let profile = evidence
            .profile
            .as_ref()
            .ok_or_else(|| ClassifiedError::Internal("completed build has no profile".into()))?;
        let status = evidence
            .terminal
            .as_ref()
            .ok_or_else(|| {
                ClassifiedError::Internal("completed build has no terminal result".into())
            })?
            .status;
        Ok(BuildPlanRunOutcome {
            status,
            build_system: profile.build_system,
            steps_run,
            build_context: context,
            diagnosis: evidence,
        })
    }
    async fn revalidate_build_profile(
        &self,
        root: &Path,
        captured: &BuildProfileView,
    ) -> Result<(), ClassifiedError> {
        let image = self
            .runtime_adapter()
            .resolve_image_reference(&captured.sandbox_image_tag)
            .await?
            .ok_or_else(|| {
                ClassifiedError::Sandbox("build requires immutable image resolution".into())
            })?;
        if image.reference() != captured.sandbox_image_id {
            return Err(ClassifiedError::Validation(
                "build profile sandbox image changed".into(),
            ));
        }
        // Image resolution may suspend while a profile is saved or cleared.
        // Current-profile admission must be the final awaited read before use.
        let current = self.build_profile(root).await?.ok_or_else(|| {
            ClassifiedError::Validation("build profile was cleared during the operation".into())
        })?;
        if current.profile_sha256 != captured.profile_sha256 {
            return Err(ClassifiedError::Validation(
                "build profile changed during the operation".into(),
            ));
        }
        let settings = crate::config::effective_build_profile_settings()
            .map_err(ClassifiedError::Validation)?;
        let stale = check_build_profile(captured, &settings)?;
        if !stale.is_empty() {
            return Err(ClassifiedError::Validation(format!(
                "build profile is stale: {}",
                stale.join("; ")
            )));
        }
        Ok(())
    }
    async fn execute_profile_build(
        &self,
        root: &Path,
        profile: &BuildProfileView,
        evidence: &mut ProjectBuildDiagnosis,
        steps_run: &mut usize,
    ) -> Result<Option<hf_core::build::BuildContext>, ClassifiedError> {
        let _lease = self.acquire_workspace_operation().await?;
        let staging = crate::container::build_doctor_staging_dir(root, uuid::Uuid::new_v4())?;
        let _cleanup = BuildStagingGuard {
            path: staging.clone(),
        };
        stage_project_snapshot(root, &staging)?;
        if marker_digest(&staging, &profile.marker_path)? != profile.marker_sha256 {
            let error =
                ClassifiedError::Validation("selected build marker changed while staging".into());
            fail(evidence, BuildTerminalStatus::ProfileChanged, &error);
            return Err(error);
        }
        let existing =
            validate_project_path(&staging, &profile.compile_database_path, false, true)?;
        match std::fs::remove_file(existing) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ClassifiedError::Internal(format!(
                    "remove previous staged compile database: {error}"
                )))
            }
        }
        let plan = profile_build_plan(profile);
        let limits = ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 600,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let options = SandboxOptions {
            image: Some(profile.sandbox_image_id.clone()),
            workdir: Some(if profile.component_root == "." {
                "/work".into()
            } else {
                format!("/work/{}", profile.component_root)
            }),
            network_mode: SandboxNetworkMode::None,
            ..SandboxOptions::default()
        };
        for (index, step) in plan.steps.iter().enumerate() {
            if let Err(error) = self.revalidate_build_profile(root, profile).await {
                fail(evidence, BuildTerminalStatus::ProfileChanged, &error);
                return Err(error);
            }
            let terminal = evidence
                .terminal
                .as_mut()
                .ok_or_else(|| ClassifiedError::Internal("build terminal missing".into()))?;
            terminal.step_index = Some(index);
            terminal.exit_code = None;
            terminal.status = BuildTerminalStatus::RuntimeFailed;
            let result = self
                .runtime_adapter()
                .run_command_opts(&step.argv, &staging, &limits, &options)
                .await?;
            *steps_run += 1;
            let terminal = evidence
                .terminal
                .as_mut()
                .ok_or_else(|| ClassifiedError::Internal("build terminal missing".into()))?;
            terminal.step_index = Some(index);
            terminal.exit_code =
                (result.termination == CommandTermination::Completed).then_some(result.exit_code);
            terminal.stdout.push_str(&result.stdout);
            terminal.stderr.push_str(&result.stderr);
            terminal.status = match result.termination {
                CommandTermination::TimedOut => BuildTerminalStatus::TimedOut,
                CommandTermination::Cancelled => BuildTerminalStatus::Cancelled,
                CommandTermination::Completed if result.exit_code != 0 => {
                    BuildTerminalStatus::StepFailed
                }
                CommandTermination::Completed => BuildTerminalStatus::Succeeded,
            };
            let success = terminal.status == BuildTerminalStatus::Succeeded;
            fit(evidence)?;
            if !success {
                return Ok(None);
            }
        }
        let artifact = validate_project_path(&staging, &profile.compile_database_path, false, true);
        let artifact = match artifact {
            Ok(path) => path,
            Err(error) => {
                fail(evidence, BuildTerminalStatus::ArtifactInvalid, &error);
                return Ok(None);
            }
        };
        match std::fs::symlink_metadata(&artifact) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fail(
                    evidence,
                    BuildTerminalStatus::ArtifactMissing,
                    &ClassifiedError::Validation(
                        "build did not produce the configured compile database".into(),
                    ),
                );
                return Ok(None);
            }
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect built database: {error}"
                )))
            }
            Ok(_) => {}
        }
        let (normalized, context) = match normalize_compile_database(&artifact, &staging, root) {
            Ok(result) => result,
            Err(error) => {
                fail(evidence, BuildTerminalStatus::ArtifactInvalid, &error);
                return Ok(None);
            }
        };
        if let Err(error) = self.revalidate_build_profile(root, profile).await {
            fail(evidence, BuildTerminalStatus::ProfileChanged, &error);
            return Err(error);
        }
        // This is the final current-profile read before synchronous publication.
        // No runtime or provider await may occur between this check and replacement.
        let current = self.build_profile(root).await?;
        if current
            .as_ref()
            .is_none_or(|current| current.profile_sha256 != profile.profile_sha256)
        {
            let error = ClassifiedError::Validation(
                "build profile changed before database publication".into(),
            );
            fail(evidence, BuildTerminalStatus::ProfileChanged, &error);
            return Err(error);
        }
        publish_compile_database(root, &profile.compile_database_path, &normalized)?;
        evidence.profile_state = BuildProfileState::Ready;
        Ok(Some(context))
    }
}
