//! Diagnosis probes and durable evidence fitting.
use super::{
    is_root_file, BuildDependencyKind, BuildDependencyStatus, BuildProfileState, BuildProfileView,
    BuildStagingGuard, BuildSystem, ClassifiedError, Path, ProjectBuildDiagnosis,
};
use crate::build_profiles::{
    check_build_profile, profile_build_plan, required_build_dependencies, BUILD_SYSTEM_MARKERS,
};
use hf_core::runtime::{CommandTermination, ResourceLimits, SandboxNetworkMode, SandboxOptions};
use hf_storage::{
    BuildDiagnosisOperation, BuildDiagnosisRecord, BuildDiagnosisStatus, BuildSystemEvidence,
    BuildTerminalEvidence, BuildTerminalStatus, DetectedBuildStatus,
};

pub(super) fn evidence(
    profile: Option<BuildProfileView>,
    operation: BuildDiagnosisOperation,
) -> ProjectBuildDiagnosis {
    ProjectBuildDiagnosis {
        schema_version: 1,
        operation,
        plan: profile.as_ref().map(profile_build_plan),
        profile,
        detected: Vec::new(),
        profile_state: BuildProfileState::Unconfigured,
        dependency_statuses: Vec::new(),
        reasons: Vec::new(),
        legacy_build_context_available: false,
        terminal: None,
    }
}
pub(super) fn terminal(status: BuildTerminalStatus) -> BuildTerminalEvidence {
    BuildTerminalEvidence {
        status,
        step_index: None,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        output_truncated: false,
        failure_code: None,
        failure_message: None,
    }
}
pub(super) fn fail(
    evidence: &mut ProjectBuildDiagnosis,
    status: BuildTerminalStatus,
    error: &ClassifiedError,
) {
    if evidence.operation == BuildDiagnosisOperation::Build
        && status == BuildTerminalStatus::ArtifactInvalid
    {
        evidence.profile_state = BuildProfileState::Invalid;
    }
    let terminal = evidence.terminal.get_or_insert_with(|| terminal(status));
    terminal.status = status;
    terminal.failure_code = Some(format!("{status:?}"));
    terminal.failure_message = Some(error.to_string());
}
/// Limit retained text without ever slicing a UTF-8 code point.
pub(super) fn truncate(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}
pub(super) fn fit(evidence: &mut ProjectBuildDiagnosis) -> Result<(), ClassifiedError> {
    let mut reason_budget = 4096;
    evidence.reasons.retain_mut(|reason| {
        if reason_budget == 0 {
            return false;
        }
        if truncate(reason, reason_budget.min(512)) {
            reason.push_str(" [truncated]");
        }
        reason_budget = reason_budget.saturating_sub(reason.len());
        true
    });
    if let Some(terminal) = &mut evidence.terminal {
        terminal.output_truncated |= truncate(&mut terminal.stdout, 8192);
        terminal.output_truncated |= truncate(&mut terminal.stderr, 8192);
        if let Some(message) = &mut terminal.failure_message {
            if truncate(message, 1024) {
                message.push_str(" [truncated]");
            }
        }
    }
    // Save reserved a combined encoded details budget. Fit the actual JSON,
    // including escaping, instead of truncating an already serialized record.
    while crate::build_profiles::evidence::build_diagnosis_remaining_bytes(evidence).is_err() {
        let mut reduced = false;
        if let Some(terminal) = &mut evidence.terminal {
            let stdout_limit = terminal.stdout.len() / 2;
            let stderr_limit = terminal.stderr.len() / 2;
            reduced |= truncate(&mut terminal.stdout, stdout_limit);
            reduced |= truncate(&mut terminal.stderr, stderr_limit);
            terminal.output_truncated |= reduced;
        }
        if !reduced && !evidence.reasons.is_empty() {
            evidence.reasons.pop();
            reduced = true;
        }
        if !reduced {
            return crate::build_profiles::evidence::build_diagnosis_remaining_bytes(evidence)
                .map(|_| ());
        }
    }
    Ok(())
}
pub(super) fn detected(project: &Path, component: &str) -> Vec<BuildSystemEvidence> {
    let mut systems = Vec::new();
    for (build_system, markers) in BUILD_SYSTEM_MARKERS {
        let markers: Vec<_> = markers
            .iter()
            .filter(|name| is_root_file(&project.join(component), name))
            .map(|name| {
                if component == "." {
                    (*name).into()
                } else {
                    format!("{component}/{name}")
                }
            })
            .collect();
        if markers.is_empty() {
            continue;
        }
        let status = match build_system {
            BuildSystem::CMake | BuildSystem::Make => DetectedBuildStatus::Supported,
            BuildSystem::Cargo => DetectedBuildStatus::NotNeeded,
            _ => DetectedBuildStatus::UnsupportedInImage,
        };
        systems.push(BuildSystemEvidence {
            build_system,
            status,
            markers,
            missing_tool: None,
        });
    }
    if systems.is_empty() {
        systems.push(BuildSystemEvidence {
            build_system: BuildSystem::Unknown,
            status: DetectedBuildStatus::Unknown,
            markers: Vec::new(),
            missing_tool: None,
        });
    }
    systems
}
impl crate::ServiceContainer {
    pub(super) async fn retain_build_evidence(
        &self,
        root: &Path,
        evidence: &mut ProjectBuildDiagnosis,
    ) -> Result<(), ClassifiedError> {
        fit(evidence)?;
        let status = match evidence.terminal.as_ref().map(|terminal| terminal.status) {
            Some(BuildTerminalStatus::Cancelled) => BuildDiagnosisStatus::Cancelled,
            None | Some(BuildTerminalStatus::Succeeded) => BuildDiagnosisStatus::Succeeded,
            Some(_) => BuildDiagnosisStatus::Failed,
        };
        self.store()
            .ok_or_else(|| {
                ClassifiedError::Internal("build diagnosis storage is unavailable".into())
            })?
            .append_build_diagnosis(&BuildDiagnosisRecord {
                id: uuid::Uuid::new_v4(),
                project_root: root.to_string_lossy().into_owned(),
                profile_sha256: evidence.profile.as_ref().map(|p| p.profile_sha256.clone()),
                status,
                diagnosis: evidence.clone(),
                created_at: chrono::Utc::now(),
            })
            .await
            .map_err(|error| ClassifiedError::Internal(format!("retain build diagnosis: {error}")))
    }
    /// Diagnose saved assumptions and prerequisites without executing project code.
    /// Persists the exact returned evidence, or the runtime failure, before return.
    pub async fn diagnose_build(
        &self,
        project: &Path,
    ) -> Result<ProjectBuildDiagnosis, ClassifiedError> {
        let root = crate::container::canonical_project_root(project)?;
        let mut evidence = evidence(None, BuildDiagnosisOperation::Diagnose);
        let result = async {
            evidence.profile = self.build_profile(&root).await?;
            self.assess_build_profile(&root, &mut evidence).await
        }
        .await;
        if let Err(error) = &result {
            let status = evidence
                .terminal
                .as_ref()
                .map_or(BuildTerminalStatus::RuntimeFailed, |terminal| {
                    terminal.status
                });
            fail(&mut evidence, status, error);
        }
        self.retain_build_evidence(&root, &mut evidence).await?;
        result?;
        Ok(evidence)
    }
    /// Return retained operation evidence, newest first. Limits must be 1–100.
    pub async fn build_diagnosis_history(
        &self,
        project: &Path,
        limit: usize,
    ) -> Result<Vec<BuildDiagnosisRecord>, ClassifiedError> {
        if !(1..=hf_storage::MAX_BUILD_DIAGNOSIS_HISTORY).contains(&limit) {
            return Err(ClassifiedError::Validation(format!(
                "build diagnosis history limit must be between 1 and {}",
                hf_storage::MAX_BUILD_DIAGNOSIS_HISTORY
            )));
        }
        let root = crate::container::canonical_project_root(project)?;
        self.store()
            .ok_or_else(|| {
                ClassifiedError::Internal("build diagnosis storage is unavailable".into())
            })?
            .build_diagnosis_history(&root.to_string_lossy(), limit)
            .await
            .map_err(|error| {
                ClassifiedError::Internal(format!("read build diagnosis history: {error}"))
            })
    }
    pub(super) async fn assess_build_profile(
        &self,
        root: &Path,
        evidence: &mut ProjectBuildDiagnosis,
    ) -> Result<(), ClassifiedError> {
        let Some(profile) = evidence.profile.clone() else {
            evidence.detected = detected(root, ".");
            evidence.legacy_build_context_available =
                crate::container::build_context::resolve_project_build_context(root)?.is_some();
            return Ok(());
        };
        evidence.plan = Some(profile_build_plan(&profile));
        let settings = crate::config::effective_build_profile_settings()
            .map_err(ClassifiedError::Validation)?;
        let reasons = match check_build_profile(&profile, &settings) {
            Ok(reasons) => reasons,
            Err(ClassifiedError::Validation(reason)) => {
                evidence.profile_state = BuildProfileState::Invalid;
                evidence.reasons.push(reason);
                if evidence.operation == BuildDiagnosisOperation::Diagnose {
                    evidence.plan = None;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        evidence.detected = detected(root, &profile.component_root);
        if reasons.is_empty() {
            let image = self
                .runtime_adapter()
                .resolve_image_reference(&profile.sandbox_image_tag)
                .await?
                .ok_or_else(|| {
                    ClassifiedError::Sandbox(
                        "build diagnosis requires an immutable sandbox image identity".into(),
                    )
                })?;
            if image.reference() == profile.sandbox_image_id {
                self.probe_build_dependencies(root, &profile, evidence)
                    .await?;
                if evidence
                    .dependency_statuses
                    .iter()
                    .any(|status| !status.available)
                {
                    evidence.profile_state = BuildProfileState::Invalid;
                } else {
                    match crate::container::build_context::resolve_profile_build_context(&profile) {
                        Ok(Some(_)) => evidence.profile_state = BuildProfileState::Ready,
                        Ok(None) => evidence.profile_state = BuildProfileState::NeedsBuild,
                        Err(ClassifiedError::Validation(reason)) => {
                            evidence.profile_state = BuildProfileState::Invalid;
                            evidence.reasons.push(reason);
                        }
                        Err(error) => return Err(error),
                    }
                }
            } else {
                evidence.profile_state = BuildProfileState::Stale;
                evidence
                    .reasons
                    .push("sandbox image identity changed; review and save the profile".into());
            }
        } else {
            evidence.profile_state = BuildProfileState::Stale;
            evidence.reasons = reasons;
        }
        if matches!(
            evidence.profile_state,
            BuildProfileState::Invalid | BuildProfileState::Stale
        ) && evidence.operation == BuildDiagnosisOperation::Diagnose
        {
            evidence.plan = None;
        }
        Ok(())
    }
    async fn probe_build_dependencies(
        &self,
        root: &Path,
        profile: &BuildProfileView,
        evidence: &mut ProjectBuildDiagnosis,
    ) -> Result<(), ClassifiedError> {
        let _lease = self.acquire_workspace_operation().await?;
        let staging = crate::container::build_doctor_staging_dir(root, uuid::Uuid::new_v4())?;
        let _cleanup = BuildStagingGuard {
            path: staging.clone(),
        };
        let options = SandboxOptions {
            image: Some(profile.sandbox_image_id.clone()),
            network_mode: SandboxNetworkMode::None,
            ..SandboxOptions::default()
        };
        let limits = ResourceLimits {
            max_mem_mb: 256,
            max_cpus: 1,
            max_duration_secs: 30,
            ..ResourceLimits::default()
        };
        for dependency in required_build_dependencies(profile) {
            if dependency.kind == BuildDependencyKind::PkgConfig
                && evidence.dependency_statuses.iter().any(|status| {
                    status.dependency.kind == BuildDependencyKind::Command
                        && status.dependency.name == "pkg-config"
                        && !status.available
                })
            {
                evidence.reasons.push(format!(
                    "missing pkg-config prerequisite for module {}",
                    dependency.name
                ));
                evidence.dependency_statuses.push(BuildDependencyStatus {
                    dependency,
                    available: false,
                });
                continue;
            }
            let argv = match dependency.kind {
                BuildDependencyKind::Command => vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "command -v \"$1\" >/dev/null".into(),
                    "oxfuzz-command-probe".into(),
                    dependency.name.clone(),
                ],
                BuildDependencyKind::PkgConfig => vec![
                    "pkg-config".into(),
                    "--exists".into(),
                    dependency.name.clone(),
                ],
            };
            let result = self
                .runtime_adapter()
                .run_command_opts(&argv, &staging, &limits, &options)
                .await?;
            // dash returns 127 for an absent `command -v` target; bash returns
            // 1. A shell/runtime diagnostic is not an absent dependency.
            let missing = match dependency.kind {
                BuildDependencyKind::Command => {
                    matches!(result.exit_code, 1 | 127)
                        && result.stdout.is_empty()
                        && result.stderr.is_empty()
                }
                BuildDependencyKind::PkgConfig => result.exit_code == 1,
            };
            if result.termination != CommandTermination::Completed
                || (result.exit_code != 0 && !missing)
            {
                let status = match result.termination {
                    CommandTermination::Cancelled => BuildTerminalStatus::Cancelled,
                    CommandTermination::TimedOut => BuildTerminalStatus::TimedOut,
                    CommandTermination::Completed => BuildTerminalStatus::RuntimeFailed,
                };
                let mut terminal = terminal(status);
                terminal.stdout = result.stdout;
                terminal.stderr = result.stderr;
                terminal.exit_code = (result.termination == CommandTermination::Completed)
                    .then_some(result.exit_code);
                evidence.terminal = Some(terminal);
                return Err(ClassifiedError::Sandbox(format!(
                    "dependency probe failed for {}",
                    dependency.name
                )));
            }
            let available = result.exit_code == 0;
            if !available {
                evidence.reasons.push(format!(
                    "missing {:?} dependency: {}",
                    dependency.kind, dependency.name
                ));
            }
            evidence.dependency_statuses.push(BuildDependencyStatus {
                dependency,
                available,
            });
        }
        Ok(())
    }
}
