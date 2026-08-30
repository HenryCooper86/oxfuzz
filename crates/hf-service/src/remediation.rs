//! Service-owned remediation handoff assembly and atomic draft export.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_crash::remediation::{
    RemediationBinding, RemediationHandoff, RemediationVerificationSpec,
    REMEDIATION_VERIFICATION_SPEC_VERSION,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::container::ServiceContainer;
use crate::evidence::{read_run_crash_file, CampaignEvidencePricing};

const DEFAULT_REMEDIATION_FOLLOW_UP_SECS: u64 = 60;
const REMEDIATION_REPLAY_TIMEOUT_SECS: u64 = 30;
const MAX_REMEDIATION_REGRESSION_CASES: usize = 256;

/// Reusable output of [`ServiceContainer::prepare_remediation_draft`]: the
/// unverified handoff plus the durable identity a Patch-to-Proof operation
/// record needs (project root, target) and the reproducer bytes for export.
pub(crate) struct RemediationDraftParts {
    pub handoff: RemediationHandoff,
    pub reproducer: Vec<u8>,
    #[cfg(feature = "patch-to-proof")]
    pub project_root: String,
    #[cfg(feature = "patch-to-proof")]
    pub target: String,
}

impl ServiceContainer {
    /// Assemble a visibly unverified remediation contract without writing it.
    ///
    /// # Errors
    /// Returns a classified error for incomplete evidence, an unknown finding,
    /// invalid patch content, or changed reproducer bytes.
    pub async fn remediation_draft(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        patch: &str,
        pricing: CampaignEvidencePricing,
    ) -> Result<RemediationHandoff, ClassifiedError> {
        Ok(self
            .prepare_remediation_draft(
                run_id,
                finding_id,
                patch,
                pricing,
                DEFAULT_REMEDIATION_FOLLOW_UP_SECS,
            )
            .await?
            .handoff)
    }

    /// Export a bounded remediation candidate whose status is explicitly
    /// `draft`. This method performs no patch application and accepts no
    /// caller-supplied verification booleans.
    ///
    /// The completed directory contains `remediation.json`, `PATCH.diff`, the
    /// exact `reproducer`, and `REMEDIATION.md`.
    ///
    /// # Errors
    /// Returns a classified error for incomplete evidence, an unknown finding,
    /// invalid patch content, changed reproducer bytes, or a destination that
    /// cannot be published without overwriting existing data.
    pub async fn export_remediation_draft(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        patch: &str,
        destination: &Path,
        pricing: CampaignEvidencePricing,
    ) -> Result<RemediationHandoff, ClassifiedError> {
        let parts = self
            .prepare_remediation_draft(
                run_id,
                finding_id,
                patch,
                pricing,
                DEFAULT_REMEDIATION_FOLLOW_UP_SECS,
            )
            .await?;
        write_draft_bundle_atomic(destination, &parts.handoff, &parts.reproducer)?;
        Ok(parts.handoff)
    }

    pub(crate) async fn prepare_remediation_draft(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        patch: &str,
        pricing: CampaignEvidencePricing,
        follow_up_fuzz_seconds: u64,
    ) -> Result<RemediationDraftParts, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.prepare_remediation_draft_locked(
            run_id,
            finding_id,
            patch,
            pricing,
            follow_up_fuzz_seconds,
        )
        .await
    }

    async fn prepare_remediation_draft_locked(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        patch: &str,
        pricing: CampaignEvidencePricing,
        follow_up_fuzz_seconds: u64,
    ) -> Result<RemediationDraftParts, ClassifiedError> {
        let managed_workspace_root = crate::container::initialize_workspace_root()?;
        let manifest = self
            .campaign_evidence_manifest_locked(run_id, pricing)
            .await?;
        let finding = manifest
            .body
            .findings
            .iter()
            .find(|finding| finding.crash_id == finding_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {finding_id} does not belong to run {run_id}"
                ))
            })?;
        if !finding.minimized {
            return Err(ClassifiedError::Validation(
                "remediation handoff requires a minimized reproducer".to_owned(),
            ));
        }
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("remediation export requires persistent storage".to_owned())
        })?;
        let crash = store
            .list_crashes_by_run(run_id)
            .await?
            .into_iter()
            .find(|crash| crash.id == finding_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("finding {finding_id} was not found"))
            })?;
        let run = store
            .get_run(run_id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation(format!("run {run_id} was not found")))?;
        let run_config = run.config.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run has no retained configuration".to_owned())
        })?;
        let (reproducer, reproducer_sha256) = read_run_crash_file(
            &managed_workspace_root,
            Path::new(&run.project_root),
            &manifest.body.target,
            run_id,
            &crash.input_path,
        )?;
        if reproducer_sha256 != finding.reproducer_sha256 {
            return Err(ClassifiedError::Validation(
                "crash reproducer changed after evidence assembly".to_owned(),
            ));
        }

        let patch_sha256 = hex::encode(Sha256::digest(patch.as_bytes()));
        let verification_spec = resolve_remediation_verification_spec(
            run_config,
            &patch_sha256,
            follow_up_fuzz_seconds,
        )?;
        let verification_spec_sha256 = verification_spec
            .sha256()
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let handoff = RemediationHandoff::draft(RemediationBinding {
            finding_id,
            run_id,
            source_revision_sha256: manifest.body.source_revision.clone(),
            patch_sha256,
            patch: patch.to_owned(),
            reproducer_sha256,
            harness_sha256: manifest.body.harness_sha256.clone(),
            original_binary_sha256: manifest.body.binary_sha256.clone(),
            sandbox_image_sha256: manifest.body.sandbox_image_sha256.clone(),
            evidence_manifest_sha256: manifest.manifest_sha256.clone(),
            regression_corpus_sha256: manifest.body.corpus_sha256.clone(),
            verification_spec_sha256,
            verification_spec,
        })
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

        Ok(RemediationDraftParts {
            handoff,
            reproducer,
            #[cfg(feature = "patch-to-proof")]
            project_root: run.project_root.clone(),
            #[cfg(feature = "patch-to-proof")]
            target: manifest.body.target.clone(),
        })
    }
}

fn resolve_remediation_verification_spec(
    run: &hf_core::engine::FuzzRunConfig,
    patch_sha256: &str,
    follow_up_fuzz_seconds: u64,
) -> Result<RemediationVerificationSpec, ClassifiedError> {
    let seed =
        u64::from_str_radix(patch_sha256.get(..16).unwrap_or_default(), 16).map_err(|error| {
            ClassifiedError::Validation(format!("derive remediation seed: {error}"))
        })?;
    let spec = RemediationVerificationSpec {
        schema_version: REMEDIATION_VERIFICATION_SPEC_VERSION,
        engine: run.engine,
        replay_timeout_secs: REMEDIATION_REPLAY_TIMEOUT_SECS,
        max_regression_cases: MAX_REMEDIATION_REGRESSION_CASES,
        follow_up_fuzz_seconds,
        max_mem_mb: run.max_mem_mb,
        max_cpus: run.max_cpus,
        seed,
    };
    spec.sha256()
        .map(|_| spec)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))
}

fn write_draft_bundle_atomic(
    destination: &Path,
    handoff: &RemediationHandoff,
    reproducer: &[u8],
) -> Result<PathBuf, ClassifiedError> {
    if destination.file_name().is_none() {
        return Err(ClassifiedError::Validation(
            "remediation destination must name a bundle directory".to_owned(),
        ));
    }
    match std::fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(ClassifiedError::Validation(format!(
                "remediation destination already exists: {}",
                destination.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ClassifiedError::Storage(format!(
                "inspect remediation destination {}: {error}",
                destination.display()
            )));
        }
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        ClassifiedError::Storage(format!(
            "inspect remediation parent {}: {error}",
            parent.display()
        ))
    })?;
    if !parent_metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "remediation parent is not a directory: {}",
            parent.display()
        )));
    }
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle");
    let temporary = parent.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    std::fs::create_dir(&temporary).map_err(|error| {
        ClassifiedError::Storage(format!(
            "create temporary remediation bundle {}: {error}",
            temporary.display()
        ))
    })?;

    let result = (|| {
        let json = serde_json::to_vec_pretty(handoff).map_err(|error| {
            ClassifiedError::Internal(format!("serialize remediation handoff: {error}"))
        })?;
        write_new(&temporary.join("remediation.json"), &json)?;
        write_new(
            &temporary.join("PATCH.diff"),
            handoff.binding.patch.as_bytes(),
        )?;
        write_new(&temporary.join("reproducer"), reproducer)?;
        write_new(
            &temporary.join("REMEDIATION.md"),
            render_summary(handoff).as_bytes(),
        )?;
        sync_directory(&temporary)?;
        if std::fs::symlink_metadata(destination).is_ok() {
            return Err(ClassifiedError::Validation(format!(
                "remediation destination appeared during export: {}",
                destination.display()
            )));
        }
        std::fs::rename(&temporary, destination).map_err(|error| {
            ClassifiedError::Storage(format!(
                "publish remediation bundle {}: {error}",
                destination.display()
            ))
        })?;
        sync_directory(parent)?;
        Ok(destination.to_path_buf())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), ClassifiedError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            ClassifiedError::Storage(format!(
                "create remediation artifact {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(contents).map_err(|error| {
        ClassifiedError::Storage(format!(
            "write remediation artifact {}: {error}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        ClassifiedError::Storage(format!(
            "sync remediation artifact {}: {error}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ClassifiedError> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            ClassifiedError::Storage(format!(
                "sync remediation directory {}: {error}",
                path.display()
            ))
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ClassifiedError> {
    Ok(())
}

fn render_summary(handoff: &RemediationHandoff) -> String {
    format!(
        "# Remediation handoff\n\n\
         Status: `draft`\n\n\
         This patch candidate is not verified. Review it, then use the guarded \
         sandbox verification workflow before making any verification claim.\n\n\
         - Finding: `{}`\n\
         - Source SHA-256: `{}`\n\
         - Patch SHA-256: `{}`\n\
         - Reproducer SHA-256: `{}`\n\
         - Evidence manifest SHA-256: `{}`\n",
        handoff.binding.finding_id,
        handoff.binding.source_revision_sha256,
        handoff.binding.patch_sha256,
        handoff.binding.reproducer_sha256,
        handoff.binding.evidence_manifest_sha256,
    )
}

#[cfg(test)]
mod workspace_lease_tests {
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use uuid::Uuid;

    use crate::container::ServiceContainer;
    use crate::evidence::CampaignEvidencePricing;

    fn install_workspace() {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        let root = ROOT.get_or_init(|| {
            let root = std::env::temp_dir().join(format!("oxfuzz-remediation-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let canonical = std::fs::canonicalize(&root).unwrap();
            std::fs::write(
                canonical.join(".oxfuzz-workspace.json"),
                serde_json::to_vec(&serde_json::json!({
                    "application": "oxfuzz",
                    "version": 1,
                    "canonical_root": canonical,
                }))
                .unwrap(),
            )
            .unwrap();
            canonical
        });
        std::env::set_var("HF_WORKSPACE_DIR", root);
    }

    #[tokio::test]
    async fn remediation_draft_locked_completes_with_a_queued_cleanup_writer() {
        let _environment = ServiceContainer::workspace_environment_test_gate()
            .lock()
            .await;
        install_workspace();
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("remediation.db"))
                .await
                .unwrap(),
        );
        let container = ServiceContainer::stubbed().with_store(store);
        let lease = container.acquire_workspace_operation().await.unwrap();
        let gate = ServiceContainer::workspace_test_operation_gate();
        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let _ = waiting_tx.send(());
            let _cleanup = gate.write_owned().await;
        });
        waiting_rx.await.unwrap();
        tokio::task::yield_now().await;

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            container.prepare_remediation_draft_locked(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "--- a/parser.c\n+++ b/parser.c\n",
                CampaignEvidencePricing {
                    compute_usd_per_hour: 1.0,
                    model_cost_usd: 0.0,
                },
                60,
            ),
        )
        .await
        .expect("already-locked remediation assembly must not reacquire the workspace lease");
        let error = match result {
            Ok(_) => panic!("the missing run must remain a validation failure"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("was not found"));

        drop(lease);
        writer.await.unwrap();
    }
}
