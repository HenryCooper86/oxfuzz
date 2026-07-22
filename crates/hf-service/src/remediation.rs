//! Service-owned remediation handoff assembly and atomic draft export.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_crash::remediation::{RemediationBinding, RemediationHandoff};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::container::ServiceContainer;
use crate::evidence::{read_regular_file_bounded, CampaignEvidencePricing};

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
        let (handoff, _) = self
            .prepare_remediation_draft(run_id, finding_id, patch, pricing)
            .await?;
        Ok(handoff)
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
        let (handoff, reproducer) = self
            .prepare_remediation_draft(run_id, finding_id, patch, pricing)
            .await?;
        write_draft_bundle_atomic(destination, &handoff, &reproducer)?;
        Ok(handoff)
    }

    async fn prepare_remediation_draft(
        &self,
        run_id: Uuid,
        finding_id: Uuid,
        patch: &str,
        pricing: CampaignEvidencePricing,
    ) -> Result<(RemediationHandoff, Vec<u8>), ClassifiedError> {
        let manifest = self.campaign_evidence_manifest(run_id, pricing).await?;
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
        let (reproducer, reproducer_sha256) = read_regular_file_bounded(&crash.input_path)?;
        if reproducer_sha256 != finding.reproducer_sha256 {
            return Err(ClassifiedError::Validation(
                "crash reproducer changed after evidence assembly".to_owned(),
            ));
        }

        let handoff = RemediationHandoff::draft(RemediationBinding {
            finding_id,
            source_revision_sha256: manifest.body.source_revision.clone(),
            patch_sha256: hex::encode(Sha256::digest(patch.as_bytes())),
            patch: patch.to_owned(),
            reproducer_sha256,
            harness_sha256: manifest.body.harness_sha256.clone(),
            binary_sha256: manifest.body.binary_sha256.clone(),
            evidence_manifest_sha256: manifest.manifest_sha256.clone(),
        })
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

        Ok((handoff, reproducer))
    }
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
