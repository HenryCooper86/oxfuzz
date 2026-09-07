//! Per-attempt compilation evidence and shared configured-project admission.
use super::build_context::{
    read_bounded_build_bytes, read_compile_database_text, COMPILE_DATABASE_PATHS,
};
use super::{canonical_project_root, PersistenceAvailability, ServiceContainer};
use crate::BuildProfileView;
use chrono::Utc;
use hf_core::{
    build::BuildContext, error::ClassifiedError, harness::Harness,
    runtime::ImmutableImageReference, target::TargetLanguage,
};
use hf_storage::{BuildDiagnosisStatus, BuildProfileState, HarnessBuildInputsRecord, Store};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub(super) struct CapturedBuildInputs {
    pub record: HarnessBuildInputsRecord,
    pub flags: Vec<String>,
    pub context: Option<BuildContext>,
    profile: Option<BuildProfileView>,
    // Keep the single bounded byte buffer alive through the attempted compile.
    _database: Option<String>,
}

impl CapturedBuildInputs {
    pub fn stage_marker(&self, workspace: &Path) -> Result<(), ClassifiedError> {
        let Some(profile) = &self.profile else {
            return Ok(());
        };
        let root = Path::new(&profile.project_root);
        let source =
            crate::build_profiles::validate_project_path(root, &profile.marker_path, false, false)?;
        let bytes = read_bounded_build_bytes(&source)?;
        if super::harness::sha256_hex(&bytes) != profile.marker_sha256 {
            return Err(stale("selected marker changed before staging"));
        }
        let root = canonical_project_root(workspace)?;
        let destination =
            crate::build_profiles::validate_project_path(&root, &profile.marker_path, false, true)?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ClassifiedError::Internal(format!("stage marker directory: {e}")))?;
        }
        crate::build_profiles::validate_project_path(&root, &profile.marker_path, false, true)?;
        std::fs::write(&destination, bytes)
            .map_err(|e| ClassifiedError::Internal(format!("stage build marker: {e}")))?;
        if super::staging::sha256_file(&destination)? != profile.marker_sha256 {
            return Err(stale("staged marker does not match profile"));
        }
        Ok(())
    }
}

fn stale(reason: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!(
        "Stale build inputs: {reason}; harness must be rebuilt and requalified"
    ))
}

#[derive(Serialize)]
struct InputDigest<'a> {
    schema_version: u32,
    profile_sha256: Option<&'a str>,
    compile_database_sha256: Option<&'a str>,
    compile_flags_sha256: &'a str,
    sandbox_image_id: &'a str,
}

impl ServiceContainer {
    pub(super) fn compilation_store(&self) -> Result<&Store, ClassifiedError> {
        let store = self.store.as_deref().ok_or_else(|| {
            ClassifiedError::Validation(
                "new harness compilation requires the persistent service store".into(),
            )
        })?;
        if store.pool().is_closed() {
            return Err(ClassifiedError::Storage(
                "persistent service store is closed".into(),
            ));
        }
        Ok(store)
    }

    pub(super) async fn configured_build_profile(
        &self,
        project: &Path,
    ) -> Result<Option<BuildProfileView>, ClassifiedError> {
        if self.persistence_availability() == PersistenceAvailability::NotConfigured {
            Ok(None)
        } else {
            self.build_profile(project).await
        }
    }

    async fn require_retained_build_diagnosis(
        &self,
        profile: &BuildProfileView,
    ) -> Result<(), ClassifiedError> {
        let records = self
            .compilation_store()?
            .build_diagnosis_history(&profile.project_root, 100)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        let required = crate::build_profiles::required_build_dependencies(profile);
        let ready = records.iter().any(|record| {
            record.status == BuildDiagnosisStatus::Succeeded
                && record.profile_sha256.as_deref() == Some(profile.profile_sha256.as_str())
                && record.diagnosis.profile_state == BuildProfileState::Ready
                && record.diagnosis.profile.as_ref().is_some_and(|saved| {
                    saved.profile_sha256 == profile.profile_sha256
                        && saved.sandbox_image_id == profile.sandbox_image_id
                })
                && required.iter().all(|dependency| {
                    record
                        .diagnosis
                        .dependency_statuses
                        .iter()
                        .any(|status| &status.dependency == dependency && status.available)
                })
        });
        if !ready {
            return Err(ClassifiedError::Validation("build_diagnosis_unavailable: diagnose the current configured build before harness operations".into()));
        }
        Ok(())
    }

    pub(super) async fn capture_harness_build_inputs(
        &self,
        project: &Path,
        language: TargetLanguage,
        live: bool,
    ) -> Result<CapturedBuildInputs, ClassifiedError> {
        let root = canonical_project_root(project)?;
        let mut profile = self.configured_build_profile(&root).await?;
        let image = if live {
            let tag = profile
                .as_ref()
                .map_or(hf_runtime::SANDBOX_IMAGE, |p| p.sandbox_image_tag.as_str());
            let image = self
                .runtime
                .resolve_image_reference(tag)
                .await?
                .ok_or_else(|| {
                    ClassifiedError::Validation("sandbox immutable image is unavailable".into())
                })?;
            let current = self.configured_build_profile(&root).await?;
            if current.as_ref().map(|p| &p.profile_sha256)
                != profile.as_ref().map(|p| &p.profile_sha256)
            {
                return Err(stale("profile changed during image resolution"));
            }
            profile = current;
            image
        } else {
            let saved = profile.as_ref().ok_or_else(|| {
                ClassifiedError::Internal("read-only capture requires a configured profile".into())
            })?;
            ImmutableImageReference::from_sha256_id(&saved.sandbox_image_id)?
        };
        if let Some(profile) = &profile {
            let settings = crate::config::effective_build_profile_settings()
                .map_err(ClassifiedError::Validation)?;
            let reasons = crate::build_profiles::check_build_profile(profile, &settings)?;
            if !reasons.is_empty() {
                return Err(stale(&reasons.join("; ")));
            }
            if image.reference() != profile.sandbox_image_id {
                return Err(stale("sandbox image identity changed"));
            }
            self.require_retained_build_diagnosis(profile).await?;
        }
        let path = selected_database(&root, profile.as_ref())?;
        let database = path
            .as_ref()
            .map(|path| read_compile_database_text(path))
            .transpose()?;
        let context = database
            .as_ref()
            .map(|json| {
                let entries = hf_discovery::build_context::parse_compile_database(json)
                    .map_err(|e| ClassifiedError::Validation(e.to_string()))?;
                if profile.is_some() && entries.is_empty() {
                    return Err(ClassifiedError::Validation(
                        "configured compile database contains no entries".into(),
                    ));
                }
                Ok(hf_discovery::build_context::extract_build_context(
                    &entries, &root,
                ))
            })
            .transpose()?;
        if profile.is_some() && context.is_none() {
            return Err(ClassifiedError::Validation(
                "NeedsBuild: configured compile database is absent".into(),
            ));
        }
        let flags = if language == TargetLanguage::Rust {
            Vec::new()
        } else {
            context
                .as_ref()
                .map(|context| {
                    hf_discovery::build_context::staged_compile_flags(context, &root, "/work")
                })
                .unwrap_or_default()
        };
        let context = context.filter(|context| profile.is_some() || !context.is_empty());
        let profile_sha256 = profile.as_ref().map(|p| p.profile_sha256.clone());
        let compile_database_sha256 = database
            .as_ref()
            .map(|json| super::harness::sha256_hex(json.as_bytes()));
        let compile_flags_sha256 = super::harness::sha256_hex(
            &serde_json::to_vec(&flags)
                .map_err(|e| ClassifiedError::Internal(format!("serialize compile flags: {e}")))?,
        );
        let serialized = serde_json::to_vec(&InputDigest {
            schema_version: 1,
            profile_sha256: profile_sha256.as_deref(),
            compile_database_sha256: compile_database_sha256.as_deref(),
            compile_flags_sha256: &compile_flags_sha256,
            sandbox_image_id: image.reference(),
        })
        .map_err(|e| ClassifiedError::Internal(format!("serialize build inputs: {e}")))?;
        Ok(CapturedBuildInputs {
            record: HarnessBuildInputsRecord {
                harness_id: uuid::Uuid::new_v4(),
                project_root: root.to_string_lossy().into_owned(),
                profile_sha256,
                compile_database_sha256,
                compile_flags_sha256,
                sandbox_image_id: image.reference().to_owned(),
                build_input_sha256: super::harness::sha256_hex(&serialized),
                created_at: Utc::now(),
            },
            flags,
            context,
            profile,
            _database: database,
        })
    }

    pub(super) async fn admit_harness_build(
        &self,
        project: &Path,
        language: TargetLanguage,
    ) -> Result<(), ClassifiedError> {
        if self.configured_build_profile(project).await?.is_some() {
            self.capture_harness_build_inputs(project, language, true)
                .await?;
        }
        Ok(())
    }

    /// The caller retains its workspace operation lease across corpus work.
    pub(super) async fn verify_corpus_build_inputs(
        &self,
        project: &Path,
        target: &str,
        engine: hf_core::engine::EngineKind,
        operation: &str,
    ) -> Result<(), ClassifiedError> {
        if self.configured_build_profile(project).await?.is_none() {
            return Ok(());
        }
        let _revision = self.acquire_target_revision(project, target).await?;
        let harness = self.active_harness_locked(project, target, engine).await?;
        self.verify_harness_build_inputs(project, &harness, true)
            .await
            .map_err(|error| corpus_input_error(operation, error))
    }

    pub(super) async fn verify_harness_dispatch_image(
        &self,
        project: &Path,
        harness: &Harness,
        image: Option<&str>,
    ) -> Result<(), ClassifiedError> {
        if self.configured_build_profile(project).await?.is_none() {
            return Ok(());
        }
        self.verify_harness_build_inputs(project, harness, true)
            .await?;
        let inputs = self
            .compilation_store()?
            .harness_build_inputs(harness.id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| stale("configured harness has no input record"))?;
        if image != Some(inputs.sandbox_image_id.as_str()) {
            return Err(stale("dispatched image does not match compilation"));
        }
        Ok(())
    }

    pub(super) async fn configured_harness_image(
        &self,
        project: &Path,
        harness: &Harness,
    ) -> Result<Option<String>, ClassifiedError> {
        if self.configured_build_profile(project).await?.is_none() {
            return Ok(None);
        }
        self.verify_harness_build_inputs(project, harness, true)
            .await?;
        self.compilation_store()?
            .harness_build_inputs(harness.id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .map(|inputs| Some(inputs.sandbox_image_id))
            .ok_or_else(|| stale("configured harness has no input record"))
    }

    pub(super) async fn persist_harness_promotion(
        &self,
        project: &Path,
        harness: &Harness,
        kind: hf_storage::HarnessApprovalKind,
        source: &str,
        binary: &str,
    ) -> Result<(), ClassifiedError> {
        let root = canonical_project_root(project)?;
        let profile = self.configured_build_profile(&root).await?;
        self.verify_harness_build_inputs(&root, harness, true)
            .await?;
        let store = self.compilation_store()?;
        let inputs = store
            .harness_build_inputs(harness.id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        store
            .promote_harness_with_approval_and_build_identity(
                harness,
                kind,
                source,
                binary,
                Utc::now(),
                &hf_storage::ExpectedHarnessBuildIdentity {
                    project_root: root.to_str().ok_or_else(|| {
                        ClassifiedError::Validation("project root must be UTF-8".into())
                    })?,
                    profile_sha256: profile
                        .as_ref()
                        .map(|profile| profile.profile_sha256.as_str()),
                    build_input_sha256: inputs
                        .as_ref()
                        .map(|inputs| inputs.build_input_sha256.as_str()),
                },
            )
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(())
    }

    pub(super) async fn verify_harness_build_inputs(
        &self,
        project: &Path,
        harness: &Harness,
        live: bool,
    ) -> Result<(), ClassifiedError> {
        if self.configured_build_profile(project).await?.is_none() {
            return Ok(());
        }
        let captured = self
            .capture_harness_build_inputs(project, harness.language, live)
            .await
            .map_err(|error| match error {
                ClassifiedError::Validation(message)
                    if !message.contains("build_diagnosis_unavailable")
                        && !message.contains("rebuilt and requalified") =>
                {
                    stale(&message)
                }
                error => error,
            })?;
        let saved = self
            .compilation_store()?
            .harness_build_inputs(harness.id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| stale("configured harness has no retained input record"))?;
        if saved.project_root != captured.record.project_root
            || saved.build_input_sha256 != captured.record.build_input_sha256
        {
            return Err(stale(
                "profile, database, flags or image no longer match compilation",
            ));
        }
        Ok(())
    }
}

fn selected_database(
    root: &Path,
    profile: Option<&BuildProfileView>,
) -> Result<Option<PathBuf>, ClassifiedError> {
    if let Some(profile) = profile {
        let path = crate::build_profiles::validate_project_path(
            root,
            &profile.compile_database_path,
            false,
            true,
        )?;
        return match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ClassifiedError::Validation(format!(
                "inspect configured compile database: {error}"
            ))),
        };
    }
    if !cfg!(feature = "build-context") {
        return Ok(None);
    }
    for relative in COMPILE_DATABASE_PATHS {
        let path = root.join(relative);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return Ok(Some(crate::build_profiles::validate_project_path(
                    root, relative, false, false,
                )?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect compile database: {e}"
                )))
            }
        }
    }
    Ok(None)
}

pub(super) fn corpus_input_error(operation: &str, error: ClassifiedError) -> ClassifiedError {
    match error {
        ClassifiedError::Validation(message) => {
            ClassifiedError::Validation(format!("{operation}: {message}"))
        }
        error => error,
    }
}
