//! Service admission, sandbox ownership, and durable Clang evidence publication.
use super::{project_identity::canonical_project_root, workspace, ServiceContainer};
use crate::clang_analysis::{
    inputs::resolve_units,
    snapshot::{capture, digest, invalid, InputFingerprint},
    ClangAnalysisSettings, StartClangAnalysisRequest,
};
use hf_core::{
    error::ClassifiedError,
    runtime::{CommandTermination, ResourceLimits, SandboxMount, SandboxOptions},
};
use hf_guardrails::Action;
use hf_storage::{ClangOperationRecord, ClangOperationState as State, ClangResultRecord};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(crate) struct ClangActive {
    cancel: CancellationToken,
    done: tokio::sync::Notify,
    finished: AtomicBool,
}
#[derive(Default)]
pub(crate) struct ClangCoordinator {
    active: tokio::sync::Mutex<BTreeMap<Uuid, Arc<ClangActive>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    request: StartClangAnalysisRequest,
    settings: ClangAnalysisSettings,
    database: PathBuf,
    profile_sha256: Option<String>,
    image_id: String,
    target_files: Vec<String>,
}

fn operation_relative(project: &Path, id: Uuid) -> PathBuf {
    PathBuf::from(super::project_slug(project))
        .join(".service")
        .join("clang-analysis")
        .join(id.to_string())
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, ClassifiedError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| invalid(e.to_string()))?;
    if !meta.file_type().is_file() || meta.len() > max as u64 {
        return Err(invalid("input is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| invalid(e.to_string()))?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| invalid(e.to_string()))?;
    if bytes.len() > max {
        return Err(invalid("input byte limit"));
    }
    Ok(bytes)
}

fn capture_inputs(
    admission: &Admission,
    source: Option<&Path>,
) -> Result<(InputFingerprint, serde_json::Value), ClassifiedError> {
    let project = &admission.request.project;
    let limits = admission.settings.resolve().map_err(invalid)?;
    let database_path = crate::build_profiles::validate_project_path(
        project,
        admission
            .database
            .to_str()
            .ok_or_else(|| invalid("invalid database path"))?,
        false,
        false,
    )?;
    let database = read_bounded(&database_path, 64 * 1024 * 1024)?;
    let database_sha = digest(&database);
    let text = std::str::from_utf8(&database).map_err(|e| invalid(e.to_string()))?;
    let entries = hf_discovery::build_context::parse_compile_database(text)
        .map_err(|e| invalid(e.to_string()))?;
    let scope = admission
        .settings
        .scope_file
        .as_ref()
        .map(|relative| {
            let path = crate::build_profiles::validate_project_path(
                project,
                relative
                    .to_str()
                    .ok_or_else(|| invalid("invalid scope path"))?,
                false,
                false,
            )?;
            read_bounded(&path, 1024 * 1024)
        })
        .transpose()?;
    let units = resolve_units(
        &entries,
        project,
        &database_sha,
        scope.as_deref(),
        limits.max_translation_units,
    )?;
    if admission.settings.scope_file.is_some() {
        crate::clang_analysis::inputs::validate_scope_selection(&units, &admission.target_files)?;
    }
    let request = serde_json::json!({"schema_version":1,"max_functions":limits.max_functions,"max_calls":limits.max_calls,"max_output_bytes":limits.max_output_bytes,"units":units});
    let files = capture(project, source, limits.max_snapshot_bytes)?;
    let database_relative = hf_core::runtime::posix_relative(&admission.database);
    if files.get(&database_relative) != Some(&database_sha) {
        return Err(invalid("database changed during snapshot"));
    }
    let fingerprint = InputFingerprint {
        schema_version: 1,
        files,
        database_sha256: database_sha,
        profile_sha256: admission.profile_sha256.clone(),
        scope_sha256: scope.as_deref().map(digest),
        request_sha256: digest(&serde_json::to_vec(&request).map_err(|e| invalid(e.to_string()))?),
    };
    Ok((fingerprint, request))
}

impl ServiceContainer {
    /// Start an explicitly authorized compiler analysis operation and retain its admission.
    ///
    /// # Errors
    /// Refuses missing storage, unsupported languages, unsafe inputs, or denied analysis.
    #[tracing::instrument(skip(self, request), fields(operation = "clang_analysis"))]
    pub async fn start_clang_analysis(
        &self,
        mut request: StartClangAnalysisRequest,
    ) -> Result<ClangOperationRecord, ClassifiedError> {
        let store = self
            .store()
            .cloned()
            .ok_or_else(|| invalid("analysis requires the persistent service store"))?;
        if !matches!(
            request.language,
            hf_core::target::TargetLanguage::C | hf_core::target::TargetLanguage::Cpp
        ) {
            return Err(invalid("unsupported language"));
        }
        request.project = canonical_project_root(&request.project)?;
        self.authorize_recorded(
            Action::AnalyzeSource {
                analyzer: "clang".into(),
            },
            "clang_analysis",
            Some(&request.project),
        )
        .await?;
        let settings = crate::config::effective_clang_analysis_settings().map_err(invalid)?;
        let limits = settings.resolve().map_err(invalid)?;
        let mut candidates: Vec<_> = store
            .list_all_targets()
            .await?
            .into_iter()
            .filter(|c| c.project_root == request.project && c.language == request.language)
            .collect();
        candidates.sort_by(|a, b| {
            b.fit_score.total_cmp(&a.fit_score).then_with(|| {
                (a.relative_file(), &a.symbol, a.id).cmp(&(b.relative_file(), &b.symbol, b.id))
            })
        });
        if request.target_ids.is_empty() {
            request.target_ids = candidates
                .iter()
                .take(limits.max_targets)
                .map(|c| c.id)
                .collect();
        }
        if request.target_ids.is_empty()
            || request.target_ids.len() > limits.max_targets
            || request
                .target_ids
                .iter()
                .any(|id| !candidates.iter().any(|c| &c.id == id))
        {
            return Err(invalid(
                "selected targets do not belong to the persisted project inventory",
            ));
        }
        let profile = self.build_profile(&request.project).await?;
        let (database, profile_sha256, image) = if let Some(profile) = profile {
            let configuration =
                crate::config::effective_build_profile_settings().map_err(invalid)?;
            if !crate::build_profiles::check_build_profile(&profile, &configuration)?.is_empty() {
                return Err(invalid("saved build profile is stale"));
            }
            (
                PathBuf::from(profile.compile_database_path),
                Some(profile.profile_sha256),
                profile.sandbox_image_tag,
            )
        } else {
            let database = super::build_context::COMPILE_DATABASE_PATHS
                .iter()
                .find(|p| request.project.join(p).exists())
                .ok_or_else(|| invalid("compile database missing"))?;
            (PathBuf::from(database), None, settings.image.clone())
        };
        let image = self
            .runtime_adapter()
            .resolve_image_reference(&image)
            .await?
            .ok_or_else(|| invalid("immutable sandbox image unavailable"))?;
        let target_files = candidates
            .iter()
            .filter(|candidate| request.target_ids.contains(&candidate.id))
            .map(|candidate| {
                hf_core::runtime::posix_relative(Path::new(&candidate.relative_file()))
            })
            .collect();
        let admission = Admission {
            target_files,
            request,
            settings,
            database,
            profile_sha256,
            image_id: image.reference().to_owned(),
        };
        let lease = self.acquire_workspace_operation().await?;
        let workspace_root = workspace::prepare_configured_workspace_root()?;
        if workspace_root.starts_with(&admission.request.project) {
            return Err(invalid(
                "analysis workspace must be outside the analyzed project",
            ));
        }
        let id = Uuid::new_v4();
        let operation_root = workspace::ensure_workspace_directory(
            &workspace_root,
            &operation_relative(&admission.request.project, id),
        )?;
        let owner = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(operation_root.join("owner.lock"))
            .map_err(|e| invalid(e.to_string()))?;
        owner.lock().map_err(|e| invalid(e.to_string()))?;
        let record = ClangOperationRecord {
            id,
            project_root: admission.request.project.to_string_lossy().into_owned(),
            language: admission.request.language.as_str().into(),
            state: State::Staging,
            request_json: serde_json::to_string(&admission).map_err(|e| invalid(e.to_string()))?,
            started_at: chrono::Utc::now().to_rfc3339(),
            ended_at: None,
            failure: None,
        };
        store.create_clang_operation(&record).await?;
        let active = Arc::new(ClangActive {
            cancel: CancellationToken::new(),
            done: tokio::sync::Notify::new(),
            finished: AtomicBool::new(false),
        });
        self.clang.active.lock().await.insert(id, active.clone());
        let service = self.clone();
        tokio::spawn(async move {
            let operation_lease = lease;
            let operation_owner = owner;
            let outcome = service
                .execute_clang(id, &admission, &operation_root, &active.cancel)
                .await;
            if let Err(error) = outcome {
                tracing::error!(operation_id=%id,%error,"Clang operation failed");
                match store.clang_operation(id).await {
                    Ok(Some(current)) if !current.state.terminal() => {
                        let state = if active.cancel.is_cancelled()
                            && !matches!(error, ClassifiedError::Sandbox(_))
                        {
                            State::Cancelled
                        } else {
                            State::Failed
                        };
                        if let Err(save) = store
                            .advance_clang_operation(
                                id,
                                current.state,
                                state,
                                Some("analysis_failed"),
                            )
                            .await
                        {
                            tracing::error!(%save,"could not retain Clang failure");
                        }
                    }
                    Ok(_) => {}
                    Err(save) => tracing::error!(%save,"could not read Clang failure state"),
                }
            }
            drop(operation_owner);
            drop(operation_lease);
            active.finished.store(true, Ordering::Release);
            active.done.notify_waiters();
            service.clang.active.lock().await.remove(&id);
        });
        Ok(record)
    }

    async fn execute_clang(
        &self,
        id: Uuid,
        admission: &Admission,
        root: &Path,
        cancel: &CancellationToken,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store()
            .ok_or_else(|| invalid("persistent store unavailable"))?;
        let source = root.join("source");
        let input = root.join("input");
        let output = root.join("output");
        for path in [&source, &input, &output] {
            std::fs::create_dir(path).map_err(|e| invalid(e.to_string()))?;
        }
        let captured = admission.clone();
        let destination = source.clone();
        let (fingerprint, request) =
            tokio::task::spawn_blocking(move || capture_inputs(&captured, Some(&destination)))
                .await
                .map_err(|e| invalid(e.to_string()))??;
        if cancel.is_cancelled() {
            return Err(invalid("cancelled"));
        }
        std::fs::write(
            input.join("request.json"),
            serde_json::to_vec(&request).map_err(|e| invalid(e.to_string()))?,
        )
        .map_err(|e| invalid(e.to_string()))?;
        store
            .advance_clang_operation(id, State::Staging, State::Analyzing, None)
            .await?;
        let resolved = admission.settings.resolve().map_err(invalid)?;
        let limits = ResourceLimits {
            max_mem_mb: resolved.memory_mb,
            max_cpus: resolved.cpus,
            max_duration_secs: resolved.timeout_secs,
            ..ResourceLimits::default()
        };
        let options = SandboxOptions {
            image: Some(admission.image_id.clone()),
            extra_mounts: vec![
                SandboxMount::read_only(source, "/work/source"),
                SandboxMount::read_only(input, "/work/input"),
                SandboxMount::writable(output.clone(), "/work/output"),
            ],
            workspace_read_only: true,
            max_file_size_bytes: Some(resolved.max_output_bytes as u64),
            max_pids: Some(128),
            ..SandboxOptions::default()
        };
        let result = self
            .runtime_adapter()
            .run_command_streaming_opts(
                &["/usr/local/bin/oxfuzz-clang-analyze".into()],
                root,
                &limits,
                &options,
                cancel,
                &|_| {},
            )
            .await?;
        if result.termination == CommandTermination::Cancelled {
            return Err(invalid("cancelled"));
        }
        let result = result.require_completed("Clang analysis")?;
        if result.exit_code != 0 {
            return Err(invalid("helper failed to parse selected build"));
        }
        if cancel.is_cancelled() {
            return Err(invalid("cancelled"));
        }
        store
            .advance_clang_operation(id, State::Analyzing, State::Validating, None)
            .await?;
        let bytes = read_bounded(&output.join("index.json"), resolved.max_output_bytes)?;
        let index = hf_discovery::clang_analysis::normalize_index(&bytes, &resolved)
            .map_err(|e| invalid(e.to_string()))?;
        let major = index
            .clang_version
            .split_whitespace()
            .find(|part| part.as_bytes().first().is_some_and(u8::is_ascii_digit))
            .and_then(|version| version.split('.').next());
        if major != Some("18") {
            return Err(invalid("unsupported Clang major"));
        }
        let expected_units: Vec<crate::clang_analysis::inputs::UnitRequest> =
            serde_json::from_value(request["units"].clone()).map_err(|e| invalid(e.to_string()))?;
        if index.units.len() != expected_units.len()
            || index.units.iter().any(|u| {
                !expected_units.iter().any(|expected| {
                    u.id == expected.id && u.file == expected.file && u.scope == expected.scope
                })
            })
        {
            return Err(invalid("helper output units do not match request"));
        }
        if admission.settings.scope_file.is_some() {
            let candidates = store.list_all_targets().await?;
            for target_id in &admission.request.target_ids {
                let candidate = candidates
                    .iter()
                    .find(|candidate| {
                        candidate.id == *target_id
                            && candidate.project_root == admission.request.project
                            && candidate.language == admission.request.language
                    })
                    .ok_or_else(|| invalid("scoped target no longer exists"))?;
                if !matches!(
                    hf_discovery::clang_analysis::associate_target(&index, candidate),
                    hf_core::clang_analysis::ClangTargetAssociation::Exact(_)
                ) {
                    return Err(invalid(
                        "selected target definition is unavailable or ambiguous in declared scope",
                    ));
                }
            }
        }
        let captured = admission.clone();
        let (current, _) = tokio::task::spawn_blocking(move || capture_inputs(&captured, None))
            .await
            .map_err(|e| invalid(e.to_string()))??;
        if current != fingerprint {
            return Err(invalid("source inputs changed during analysis"));
        }
        if cancel.is_cancelled() {
            return Err(invalid("cancelled"));
        }
        let inputs_json =
            serde_json::to_string(&fingerprint).map_err(|e| invalid(e.to_string()))?;
        store
            .publish_clang_result(&ClangResultRecord {
                operation_id: id,
                project_root: admission.request.project.to_string_lossy().into_owned(),
                input_sha256: digest(inputs_json.as_bytes()),
                image_id: admission.image_id.clone(),
                inputs_json,
                index,
            })
            .await?;
        Ok(())
    }

    /// Read durable status without restarting an operation.
    pub async fn clang_analysis_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<ClangOperationRecord>, ClassifiedError> {
        Ok(self
            .store()
            .ok_or_else(|| invalid("persistent store unavailable"))?
            .clang_operation(id)
            .await?)
    }
    /// Read the normalized immutable result of one successful operation.
    pub async fn clang_analysis_result(
        &self,
        id: Uuid,
    ) -> Result<Option<ClangResultRecord>, ClassifiedError> {
        Ok(self
            .store()
            .ok_or_else(|| invalid("persistent store unavailable"))?
            .clang_result(id)
            .await?)
    }
    /// Cancel and wait for completed teardown, then return retained terminal status.
    pub async fn cancel_clang_analysis(
        &self,
        id: Uuid,
    ) -> Result<Option<ClangOperationRecord>, ClassifiedError> {
        let active = self.clang.active.lock().await.get(&id).cloned();
        if let Some(active) = active {
            active.cancel.cancel();
            loop {
                let notified = active.done.notified();
                if active.finished.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        }
        self.clang_analysis_operation(id).await
    }
}

impl ServiceContainer {
    /// Resolve and retain one exact current model-visible semantic section.
    pub(super) async fn retained_clang_context(
        &self,
        project: &Path,
        target: &hf_core::target::TargetCandidate,
    ) -> Result<Option<String>, ClassifiedError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        let project = canonical_project_root(project)?;
        let Some(result) = store
            .latest_clang_result_for_target(&project.to_string_lossy(), target.id, target.language)
            .await?
        else {
            return Ok(None);
        };
        let operation = store
            .clang_operation(result.operation_id)
            .await?
            .ok_or_else(|| invalid("analysis owner record unavailable"))?;
        let admission: Admission =
            serde_json::from_str(&operation.request_json).map_err(|e| invalid(e.to_string()))?;
        if !admission.request.target_ids.contains(&target.id) {
            return Ok(None);
        }
        let settings = crate::config::effective_clang_analysis_settings().map_err(invalid)?;
        let profile = self.build_profile(&project).await?;
        let (profile_sha, image) = profile
            .as_ref()
            .map_or((None, settings.image.as_str()), |p| {
                (Some(p.profile_sha256.clone()), p.sandbox_image_tag.as_str())
            });
        if profile_sha != admission.profile_sha256
            || settings.scope_file != admission.settings.scope_file
        {
            tracing::warn!(operation_id=%operation.id,"stale Clang profile or scope excluded");
            return Ok(None);
        }
        let image = match self.runtime_adapter().resolve_image_reference(image).await {
            Ok(Some(image)) => image,
            Ok(None) => {
                tracing::warn!("Clang evidence excluded because image identity is unavailable");
                return Ok(None);
            }
            Err(error) => {
                tracing::warn!(%error,"Clang evidence excluded because the analysis image is unavailable");
                return Ok(None);
            }
        };
        if image.reference() != result.image_id {
            tracing::warn!("stale Clang image excluded");
            return Ok(None);
        }
        let captured = admission.clone();
        let current = match tokio::task::spawn_blocking(move || capture_inputs(&captured, None))
            .await
            .map_err(|e| invalid(e.to_string()))?
        {
            Ok((fingerprint, _)) => fingerprint,
            Err(error) => {
                tracing::warn!(%error,"stale or unavailable Clang inputs excluded");
                return Ok(None);
            }
        };
        if digest(result.inputs_json.as_bytes()) != result.input_sha256 {
            return Err(invalid("retained input fingerprint corrupted"));
        }
        let previous: InputFingerprint =
            serde_json::from_str(&result.inputs_json).map_err(|e| invalid(e.to_string()))?;
        if current != previous {
            tracing::warn!(operation_id=%operation.id,"stale Clang source evidence excluded");
            return Ok(None);
        }
        let limits = settings.resolve().map_err(invalid)?;
        let target_snapshot = target.clone();
        let retained_index = result.index;
        let rendered =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, ClassifiedError> {
                let normalized = hf_discovery::clang_analysis::normalize_index(
                    &serde_json::to_vec(&retained_index).map_err(|e| invalid(e.to_string()))?,
                    &limits,
                )
                .map_err(|e| invalid(e.to_string()))?;
                let context = hf_discovery::clang_analysis::target_context(
                    &normalized,
                    &target_snapshot,
                    &limits,
                )
                .map_err(|e| invalid(e.to_string()))?;
                if !matches!(
                    context.association,
                    hf_core::clang_analysis::ClangTargetAssociation::Exact(_)
                ) {
                    tracing::warn!("Clang target association unavailable or ambiguous");
                    return Ok(None);
                }
                Ok(Some(
                    hf_prompt::render_clang_context(&context, limits.max_context_bytes)
                        .map_err(|e| invalid(e.to_string()))?,
                ))
            })
            .await
            .map_err(|e| invalid(e.to_string()))??;
        let Some(rendered) = rendered else {
            return Ok(None);
        };
        store
            .append_harness_clang_context(&hf_storage::HarnessClangContextRecord {
                id: Uuid::new_v4(),
                operation_id: result.operation_id,
                project_root: project.to_string_lossy().into_owned(),
                target_id: target.id,
                renderer_version: 1,
                rendered: rendered.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
            })
            .await?;
        Ok(Some(rendered))
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[tokio::test]
    async fn recovery_preserves_a_live_owner_and_interrupts_an_abandoned_operation() {
        let root = tempfile::tempdir().unwrap();
        let store = hf_storage::Store::connect(root.path().join("state.db"))
            .await
            .unwrap();
        let id = Uuid::new_v4();
        let operation = root
            .path()
            .join(operation_relative(Path::new("/fixture"), id));
        std::fs::create_dir_all(&operation).unwrap();
        let owner = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(operation.join("owner.lock"))
            .unwrap();
        owner.lock().unwrap();
        store
            .create_clang_operation(&ClangOperationRecord {
                id,
                project_root: "/fixture".into(),
                language: "c".into(),
                state: State::Staging,
                request_json: "{}".into(),
                started_at: chrono::Utc::now().to_rfc3339(),
                ended_at: None,
                failure: None,
            })
            .await
            .unwrap();
        recover_clang_operations(&store, root.path()).await.unwrap();
        assert_eq!(
            store.clang_operation(id).await.unwrap().unwrap().state,
            State::Staging
        );
        drop(owner);
        recover_clang_operations(&store, root.path()).await.unwrap();
        assert_eq!(
            store.clang_operation(id).await.unwrap().unwrap().state,
            State::Interrupted
        );
    }
}

pub(super) async fn recover_clang_operations(
    store: &hf_storage::Store,
    root: &Path,
) -> Result<(), ClassifiedError> {
    for id in store.active_clang_operation_ids().await? {
        let Some(operation) = store.clang_operation(id).await? else {
            continue;
        };
        let path = root
            .join(operation_relative(Path::new(&operation.project_root), id))
            .join("owner.lock");
        let owner = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(invalid(error.to_string())),
        };
        if let Some(file) = &owner {
            match file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => continue,
                Err(std::fs::TryLockError::Error(error)) => return Err(invalid(error.to_string())),
            }
        }
        store.interrupt_clang_operation(id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod executor_tests {
    use super::*;
    use hf_core::runtime::{CommandResult, ImmutableImageReference, LineSink, RuntimeAdapter};
    #[derive(Clone, Copy)]
    enum Mode {
        Success,
        Timeout,
        BadJson,
        UnsupportedVersion,
        Nonzero,
        Cancel,
        TeardownFailure,
    }
    struct ControlledRuntime {
        mode: Mode,
        started: tokio::sync::Notify,
        image_available: AtomicBool,
    }
    #[async_trait::async_trait]
    impl RuntimeAdapter for ControlledRuntime {
        async fn run_command(
            &self,
            _: &[String],
            _: &Path,
            _: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            Err(invalid("unprofiled execution refused"))
        }
        async fn resolve_image_reference(
            &self,
            _: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            if !self.image_available.load(Ordering::Acquire) {
                return Err(ClassifiedError::Sandbox("image unavailable".into()));
            }
            Ok(Some(ImmutableImageReference::from_sha256_id(format!(
                "sha256:{}",
                "a".repeat(64)
            ))?))
        }
        async fn run_command_streaming_opts(
            &self,
            cmd: &[String],
            cwd: &Path,
            _: &ResourceLimits,
            opts: &SandboxOptions,
            cancel: &CancellationToken,
            _: &LineSink<'_>,
        ) -> Result<CommandResult, ClassifiedError> {
            assert_eq!(cmd, ["/usr/local/bin/oxfuzz-clang-analyze"]);
            assert!(
                opts.workspace_read_only && !opts.relax_hardening && opts.capabilities.is_empty()
            );
            assert_eq!(
                opts.network_mode,
                hf_core::runtime::SandboxNetworkMode::None
            );
            assert_eq!(
                opts.image.as_deref(),
                Some(format!("sha256:{}", "a".repeat(64)).as_str())
            );
            assert!(opts
                .extra_mounts
                .iter()
                .filter(|m| !m.read_only)
                .all(|m| m.container_path == "/work/output"));
            self.started.notify_one();
            if matches!(self.mode, Mode::Cancel | Mode::TeardownFailure) {
                cancel.cancelled().await;
                if matches!(self.mode, Mode::TeardownFailure) {
                    return Err(ClassifiedError::Sandbox("forced teardown failed".into()));
                }
                return Ok(CommandResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    workspace: cwd.to_owned(),
                    termination: CommandTermination::Cancelled,
                });
            }
            let request: serde_json::Value =
                serde_json::from_slice(&std::fs::read(cwd.join("input/request.json")).unwrap())
                    .unwrap();
            let unit = &request["units"][0];
            let id = unit["id"].as_str().unwrap();
            let version = if matches!(self.mode, Mode::UnsupportedVersion) {
                "118.1.3"
            } else {
                "18.1.3"
            };
            let output = serde_json::json!({"schema_version":1,"clang_version":version,"helper_sha256":"b".repeat(64),
                "units":[{"id":id,"file":"a.c","scope":unit["scope"]}],
                "functions":[{"id":format!("{id}:parse"),"unit":id,"usr":"parse","name":"parse","location":{"file":"a.c","line":1,"column":1},"declarations":[],"result_type":"int","parameters":[{"name":"x","type_name":"int"}],"variadic":false,"linkage":"external","access":"none","method_kind":"function","definition":true}],"calls":[]});
            let bytes = if matches!(self.mode, Mode::BadJson) {
                b"{bad json".to_vec()
            } else {
                serde_json::to_vec(&output).unwrap()
            };
            std::fs::write(cwd.join("output/index.json"), bytes).unwrap();
            Ok(CommandResult {
                exit_code: i32::from(matches!(self.mode, Mode::Nonzero)),
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_owned(),
                termination: if matches!(self.mode, Mode::Timeout) {
                    CommandTermination::TimedOut
                } else {
                    CommandTermination::Completed
                },
            })
        }
        async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
            std::fs::write(path, content).map_err(|e| invalid(e.to_string()))
        }
        async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
            std::fs::read_to_string(path).map_err(|e| invalid(e.to_string()))
        }
    }
    struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Environment {
        fn set(values: &[(&'static str, &Path)]) -> Self {
            let old = values
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();
            for (key, value) in values {
                std::env::set_var(key, value);
            }
            Self(old)
        }
    }
    impl Drop for Environment {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[tokio::test]
    async fn executor_publishes_only_completed_valid_output_and_awaits_cancel_teardown() {
        let _gate = ServiceContainer::workspace_environment_test_gate()
            .lock()
            .await;
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let config = root.path().join("config");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&config).unwrap();
        std::fs::write(config.join("oxfuzz.toml"), "").unwrap();
        std::fs::write(project.join("a.c"), "int parse(int x){return x;}").unwrap();
        std::fs::write(project.join("compile_commands.json"),serde_json::json!([{"directory":project,"file":"a.c","arguments":["clang","-c","a.c"]}]).to_string()).unwrap();
        let workspace = root.path().join("workspace");
        let _environment =
            Environment::set(&[("HF_WORKSPACE_DIR", &workspace), ("HF_CONFIG_DIR", &config)]);
        let store = Arc::new(
            hf_storage::Store::connect(root.path().join("state.db"))
                .await
                .unwrap(),
        );
        let inventory = hf_discovery::discover(&project, hf_core::target::TargetLanguage::C)
            .await
            .unwrap();
        store
            .save_inventory(&inventory, chrono::Utc::now())
            .await
            .unwrap();
        for mode in [
            Mode::Success,
            Mode::Timeout,
            Mode::BadJson,
            Mode::UnsupportedVersion,
            Mode::Nonzero,
            Mode::Cancel,
            Mode::TeardownFailure,
        ] {
            let runtime = Arc::new(ControlledRuntime {
                mode,
                started: tokio::sync::Notify::new(),
                image_available: AtomicBool::new(true),
            });
            let service = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
            let operation = service
                .start_clang_analysis(StartClangAnalysisRequest {
                    project: project.clone(),
                    language: hf_core::target::TargetLanguage::C,
                    target_ids: vec![],
                })
                .await
                .unwrap();
            runtime.started.notified().await;
            let final_state = if matches!(mode, Mode::Cancel | Mode::TeardownFailure) {
                assert!(service.delete_project(&project).await.is_err());
                assert!(store.clang_operation(operation.id).await.unwrap().is_some());
                service
                    .cancel_clang_analysis(operation.id)
                    .await
                    .unwrap()
                    .unwrap()
            } else {
                let mut result = None;
                for _ in 0..1000 {
                    let state = service
                        .clang_analysis_operation(operation.id)
                        .await
                        .unwrap()
                        .unwrap();
                    if state.state.terminal() {
                        result = Some(state);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                result.expect("analysis did not reach terminal state")
            };
            let expected = if matches!(mode, Mode::Success) {
                State::Done
            } else if matches!(mode, Mode::Cancel) {
                State::Cancelled
            } else {
                State::Failed
            };
            assert_eq!(final_state.state, expected);
            if matches!(mode, Mode::Success) {
                assert!(
                    workspace::project_workspace_dir(&project)
                        .join(".service/clang-analysis")
                        .join(operation.id.to_string())
                        .is_dir(),
                    "analysis artifacts must be owned by project cleanup"
                );
                assert!(service
                    .retained_clang_context(&project, &inventory.candidates[0])
                    .await
                    .unwrap()
                    .is_some());
                runtime.image_available.store(false, Ordering::Release);
                assert!(service
                    .retained_clang_context(&project, &inventory.candidates[0])
                    .await
                    .unwrap()
                    .is_none());
            }

            assert_eq!(
                service
                    .clang_analysis_result(operation.id)
                    .await
                    .unwrap()
                    .is_some(),
                matches!(mode, Mode::Success)
            );
        }

        std::fs::write(
            project.join("not_compiled.h"),
            "int header_parse(int x){return x;}",
        )
        .unwrap();
        let updated = hf_discovery::discover(&project, hf_core::target::TargetLanguage::C)
            .await
            .unwrap();
        store
            .save_inventory(&updated, chrono::Utc::now())
            .await
            .unwrap();
        let header_target = updated
            .candidates
            .iter()
            .find(|c| c.symbol == "header_parse")
            .unwrap();
        let database = std::fs::read(project.join("compile_commands.json")).unwrap();
        let entries = hf_discovery::build_context::parse_compile_database(
            std::str::from_utf8(&database).unwrap(),
        )
        .unwrap();
        let units = resolve_units(
            &entries,
            &std::fs::canonicalize(&project).unwrap(),
            &digest(&database),
            None,
            1024,
        )
        .unwrap();
        std::fs::write(project.join("scope.json"),serde_json::json!({"schema_version":1,"name":"library","compile_database_sha256":digest(&database),"units":[{"file":"a.c","invocation_sha256":units[0].id}]}).to_string()).unwrap();
        std::fs::write(
            config.join("oxfuzz.toml"),
            "[clang_analysis]\nscope_file='scope.json'\n",
        )
        .unwrap();
        let runtime = Arc::new(ControlledRuntime {
            mode: Mode::Success,
            started: tokio::sync::Notify::new(),
            image_available: AtomicBool::new(true),
        });
        let service = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
        let operation = service
            .start_clang_analysis(StartClangAnalysisRequest {
                project: project.clone(),
                language: hf_core::target::TargetLanguage::C,
                target_ids: vec![header_target.id],
            })
            .await
            .unwrap();
        runtime.started.notified().await;
        let mut terminal = None;
        for _ in 0..1000 {
            let record = service
                .clang_analysis_operation(operation.id)
                .await
                .unwrap()
                .unwrap();
            if record.state.terminal() {
                terminal = Some(record.state);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(terminal, Some(State::Failed));
        assert!(service
            .clang_analysis_result(operation.id)
            .await
            .unwrap()
            .is_none());
        service.cancel_clang_analysis(operation.id).await.unwrap();
        let project_workspace = workspace::project_workspace_dir(&project);
        assert!(project_workspace.is_dir());
        service.delete_project(&project).await.unwrap();
        assert!(!project_workspace.exists());
        assert!(project.join("a.c").is_file());
        assert!(store.clang_operation(operation.id).await.unwrap().is_none());
    }
}
