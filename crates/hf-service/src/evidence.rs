//! Canonical, proof-carrying campaign evidence manifests.
//!
//! The types in this module are read-only evidence. They do not execute a run,
//! authorize an action, or mutate campaign state.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::path::Path;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::Sanitizer;
use hf_runtime::SANDBOX_IMAGE;
use hf_storage::{HarnessApprovalKind, RunKind, RunRecord, RunStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::container::ServiceContainer;

/// Current evidence-manifest schema.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 2;

/// Lifecycle captured in a proof-carrying manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRunStatus {
    /// Run is still active and therefore cannot produce a final manifest.
    Running,
    /// Run completed successfully.
    Done,
    /// Run terminated with an error but retained terminal evidence.
    Failed,
    /// Run was explicitly cancelled and retained terminal evidence.
    Cancelled,
}

impl EvidenceRunStatus {
    const fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// Normalized run configuration bound into a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRunConfig {
    /// Requested execution duration.
    pub duration_secs: u64,
    /// Sandbox memory ceiling.
    pub max_mem_mb: u64,
    /// Sandbox CPU ceiling.
    pub max_cpus: u32,
    /// Stable sanitizer identifier.
    pub sanitizer: String,
    /// Deterministic engine seed, when supported.
    pub seed: Option<u64>,
    /// Stable, key-sorted environment.
    pub environment: BTreeMap<String, String>,
    /// Exact engine arguments in dispatch order.
    pub extra_args: Vec<String>,
}

/// Human promotion evidence bound to the exact harness bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceApproval {
    /// Durable approval id.
    pub approval_id: Uuid,
    /// Approved harness id.
    pub harness_id: Uuid,
    /// Approved harness-source digest.
    pub source_sha256: String,
    /// Smoke-qualified binary digest.
    pub binary_sha256: String,
    /// Stable approval kind.
    pub kind: String,
    /// RFC3339 approval timestamp.
    pub approved_at: String,
}

/// Coverage totals bound to a campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCoverage {
    /// Peak comparable source edges.
    pub edges: u64,
    /// Edge delta against the comparable baseline.
    pub delta_edges: i64,
}

/// One crash and its immutable reproducer identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFinding {
    /// Durable crash id.
    pub crash_id: Uuid,
    /// Normalized stack signature digest.
    pub stack_signature: String,
    /// Exact raw or minimized reproducer digest.
    pub reproducer_sha256: String,
    /// Whether the bound input is the minimized artifact.
    pub minimized: bool,
}

/// Attributable campaign economics.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EvidenceCost {
    /// Operator-priced sandbox compute cost.
    pub compute_cost_usd: f64,
    /// Attributable model cost.
    pub model_cost_usd: f64,
}

/// Operator-provided rates used to attribute campaign cost without inventing
/// a cloud-vendor billing dependency.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CampaignEvidencePricing {
    /// Price of one hour of sandbox compute.
    pub compute_usd_per_hour: f64,
    /// Model cost already attributed to this run by the provider ledger.
    pub model_cost_usd: f64,
}

/// Canonical body covered by `manifest_sha256`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceManifestBody {
    /// Version of this serialization contract.
    pub schema_version: u32,
    /// Stable manifest id.
    pub manifest_id: Uuid,
    /// RFC3339 assembly timestamp.
    pub generated_at: String,
    /// Shareable project display name, not a host path.
    pub project: String,
    /// Target symbol.
    pub target: String,
    /// Durable run id.
    pub run_id: Uuid,
    /// Terminal run state.
    pub status: EvidenceRunStatus,
    /// Fuzz engine.
    pub engine: EngineKind,
    /// Normalized run settings.
    pub run_config: EvidenceRunConfig,
    /// Target-source or repository revision digest.
    pub source_revision: String,
    /// Approved harness-source SHA-256.
    pub harness_sha256: String,
    /// Staged binary SHA-256.
    pub binary_sha256: String,
    /// Comparison-context SHA-256.
    pub comparison_context_sha256: String,
    /// Canonical starting-corpus SHA-256.
    pub corpus_sha256: String,
    /// Pinned sandbox image reference.
    pub sandbox_image: String,
    /// Resolved sandbox image SHA-256.
    pub sandbox_image_sha256: String,
    /// Explicit human promotion provenance.
    pub approval: EvidenceApproval,
    /// Source-coverage evidence.
    pub coverage: EvidenceCoverage,
    /// Stable crash/reproducer list.
    pub findings: Vec<EvidenceFinding>,
    /// Attributable economics.
    pub cost: EvidenceCost,
}

/// A body plus its canonical SHA-256 identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceManifest {
    /// Canonical manifest body.
    pub body: EvidenceManifestBody,
    /// Lowercase SHA-256 of the canonical body.
    pub manifest_sha256: String,
}

/// Evidence construction or verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// Unsupported schema version.
    #[error("unsupported evidence schema")]
    UnsupportedSchema,
    /// Required identifier or text field is missing.
    #[error("evidence contains an empty required field")]
    EmptyField,
    /// A SHA-256 field is malformed.
    #[error("evidence contains a malformed SHA-256 digest")]
    InvalidDigest,
    /// Run is not terminal.
    #[error("a running campaign cannot produce a final evidence manifest")]
    NonTerminalRun,
    /// Approval does not name the manifest's exact harness and binary.
    #[error("approval does not match the exact harness and binary")]
    ApprovalMismatch,
    /// Cost is negative or non-finite.
    #[error("evidence cost must be finite and non-negative")]
    InvalidCost,
    /// A crash id appears more than once.
    #[error("evidence contains a duplicate finding")]
    DuplicateFinding,
    /// Canonical serialization failed.
    #[error("evidence could not be serialized canonically")]
    Serialization,
    /// Retained digest does not cover the current body.
    #[error("evidence manifest digest mismatch")]
    DigestMismatch,
}

impl EvidenceManifest {
    /// Validate, normalize, and digest one evidence body.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] if required provenance is incomplete or invalid.
    pub fn new(mut body: EvidenceManifestBody) -> Result<Self, EvidenceError> {
        body.findings.sort_by_key(|finding| finding.crash_id);
        validate_body(&body)?;
        let manifest_sha256 = body_digest(&body)?;
        Ok(Self {
            body,
            manifest_sha256,
        })
    }

    /// Revalidate the body and verify its retained digest.
    ///
    /// # Errors
    /// Returns [`EvidenceError::DigestMismatch`] after any covered mutation.
    pub fn verify(&self) -> Result<(), EvidenceError> {
        validate_body(&self.body)?;
        if body_digest(&self.body)? == self.manifest_sha256 {
            Ok(())
        } else {
            Err(EvidenceError::DigestMismatch)
        }
    }
}

impl ServiceContainer {
    /// Assemble a final, digest-covered evidence manifest entirely from
    /// durable campaign, approval, target, and finding records.
    ///
    /// This is deliberately fail-closed: incomplete provenance, active runs,
    /// changed reproducers, and mismatched promotion evidence cannot produce a
    /// shareable final manifest.
    ///
    /// # Errors
    /// Returns a classified error when the run is missing, non-terminal, or
    /// lacks any required proof component.
    pub async fn campaign_evidence_manifest(
        &self,
        run_id: Uuid,
        pricing: CampaignEvidencePricing,
    ) -> Result<EvidenceManifest, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.campaign_evidence_manifest_locked(run_id, pricing)
            .await
    }

    pub(crate) async fn campaign_evidence_manifest_locked(
        &self,
        run_id: Uuid,
        pricing: CampaignEvidencePricing,
    ) -> Result<EvidenceManifest, ClassifiedError> {
        let managed_workspace_root = crate::container::initialize_workspace_root()?;
        validate_pricing(pricing)?;
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("campaign evidence requires persistent storage".to_owned())
        })?;
        let run = store
            .get_run(run_id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation(format!("run {run_id} was not found")))?;
        let status = evidence_status(run.status)?;
        if run.kind != RunKind::Campaign {
            return Err(ClassifiedError::Validation(
                "qualification smoke runs cannot produce campaign evidence".to_owned(),
            ));
        }
        let config = run.config.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run has no retained configuration".to_owned())
        })?;
        if config.engine != run.engine {
            return Err(ClassifiedError::Validation(
                "retained run engine does not match its configuration".to_owned(),
            ));
        }
        let duration = config.duration.ok_or_else(|| {
            ClassifiedError::Validation("run has no finite duration budget".to_owned())
        })?;
        if duration.is_zero() {
            return Err(ClassifiedError::Validation(
                "run duration budget must be positive".to_owned(),
            ));
        }

        let harness = store.get_harness(config.harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness {} referenced by run was not found",
                config.harness_id
            ))
        })?;
        let target = store
            .list_targets(&run.project_root)
            .await?
            .into_iter()
            .find(|candidate| candidate.id == harness.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "target {} referenced by harness was not found",
                    harness.target_id
                ))
            })?;

        let harness_sha256 = required_digest(run.harness_rev.as_deref(), "harness revision")?;
        let binary_sha256 = required_digest(run.binary_rev.as_deref(), "binary revision")?;
        let comparison_context_sha256 =
            required_digest(run.context_rev.as_deref(), "comparison context")?;
        let source_revision = required_digest(run.source_rev.as_deref(), "source revision")?;
        let corpus_sha256 = required_digest(run.corpus_rev.as_deref(), "corpus revision")?;
        let sandbox_image_sha256 = required_exact_sandbox_digest(run.sandbox_rev.as_deref())?;
        let approval = store
            .harness_approval(config.harness_id, harness_sha256, binary_sha256)
            .await?
            .ok_or_else(|| {
                ClassifiedError::Validation(
                    "run has no approval for its exact harness and binary revisions".to_owned(),
                )
            })?;

        let findings = store
            .list_crashes_by_run(run.id)
            .await?
            .into_iter()
            .map(|crash| {
                let (_, reproducer_sha256) = read_run_crash_file(
                    &managed_workspace_root,
                    Path::new(&run.project_root),
                    &target.symbol,
                    run.id,
                    &crash.input_path,
                )?;
                let stack_signature = if is_sha256(&crash.stack_signature) {
                    crash.stack_signature
                } else {
                    digest_stack_signature(&crash.stack_signature)
                };
                Ok(EvidenceFinding {
                    crash_id: crash.id,
                    stack_signature,
                    reproducer_sha256,
                    minimized: crash.minimized,
                })
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;

        let ended_at = run.ended_at.ok_or_else(|| {
            ClassifiedError::Validation("terminal run has no completion timestamp".to_owned())
        })?;
        if ended_at < run.started_at {
            return Err(ClassifiedError::Validation(
                "run completion predates its start".to_owned(),
            ));
        }
        let elapsed_ms = (ended_at - run.started_at).num_milliseconds().max(0) as f64;
        let compute_cost_usd = elapsed_ms * pricing.compute_usd_per_hour / 3_600_000.0;
        let environment = config.env.iter().cloned().collect::<BTreeMap<_, _>>();
        if environment.len() != config.env.len() {
            return Err(ClassifiedError::Validation(
                "run environment contains duplicate keys".to_owned(),
            ));
        }
        let delta_edges = comparable_coverage_delta(store, &run, harness.target_id).await?;

        EvidenceManifest::new(EvidenceManifestBody {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            manifest_id: Uuid::new_v5(&run.id, b"oxfuzz-evidence-manifest-v2"),
            generated_at: ended_at.to_rfc3339(),
            project: project_display_name(&run.project_root),
            target: target.symbol,
            run_id: run.id,
            status,
            engine: run.engine,
            run_config: EvidenceRunConfig {
                duration_secs: duration.as_secs(),
                max_mem_mb: config.max_mem_mb,
                max_cpus: config.max_cpus,
                sanitizer: sanitizer_name(config.sanitizer).to_owned(),
                seed: config.seed,
                environment,
                extra_args: config.extra_args.clone(),
            },
            source_revision: source_revision.to_owned(),
            harness_sha256: harness_sha256.to_owned(),
            binary_sha256: binary_sha256.to_owned(),
            comparison_context_sha256: comparison_context_sha256.to_owned(),
            corpus_sha256: corpus_sha256.to_owned(),
            sandbox_image: SANDBOX_IMAGE.to_owned(),
            sandbox_image_sha256: sandbox_image_sha256.to_owned(),
            approval: EvidenceApproval {
                approval_id: approval.id,
                harness_id: approval.harness_id,
                source_sha256: approval.source_sha256,
                binary_sha256: approval.binary_sha256,
                kind: approval_kind_name(approval.approval_kind).to_owned(),
                approved_at: approval.approved_at.to_rfc3339(),
            },
            coverage: EvidenceCoverage {
                edges: run.edges.unwrap_or(0),
                delta_edges,
            },
            findings,
            cost: EvidenceCost {
                compute_cost_usd,
                model_cost_usd: pricing.model_cost_usd,
            },
        })
        .map_err(|error| ClassifiedError::Validation(error.to_string()))
    }
}

fn validate_pricing(pricing: CampaignEvidencePricing) -> Result<(), ClassifiedError> {
    if !pricing.compute_usd_per_hour.is_finite()
        || pricing.compute_usd_per_hour < 0.0
        || !pricing.model_cost_usd.is_finite()
        || pricing.model_cost_usd < 0.0
    {
        return Err(ClassifiedError::Validation(
            "campaign evidence pricing must be finite and non-negative".to_owned(),
        ));
    }
    Ok(())
}

fn evidence_status(status: RunStatus) -> Result<EvidenceRunStatus, ClassifiedError> {
    match status {
        RunStatus::Done => Ok(EvidenceRunStatus::Done),
        RunStatus::Failed => Ok(EvidenceRunStatus::Failed),
        RunStatus::Cancelled => Ok(EvidenceRunStatus::Cancelled),
        RunStatus::Pending | RunStatus::Running => Err(ClassifiedError::Validation(
            "a non-terminal run cannot produce final campaign evidence".to_owned(),
        )),
    }
}

fn required_digest<'a>(value: Option<&'a str>, label: &str) -> Result<&'a str, ClassifiedError> {
    value
        .filter(|digest| is_sha256(digest))
        .ok_or_else(|| ClassifiedError::Validation(format!("run has no valid {label} SHA-256")))
}

fn required_exact_sandbox_digest(value: Option<&str>) -> Result<&str, ClassifiedError> {
    let digest =
        value.and_then(|value| value.strip_prefix(crate::container::EXACT_DOCKER_IMAGE_REV_PREFIX));
    required_digest(digest, "exact sandbox image revision")
}

fn approval_kind_name(kind: HarnessApprovalKind) -> &'static str {
    match kind {
        HarnessApprovalKind::CleanSmoke => "clean_smoke",
        HarnessApprovalKind::KnownFindings => "known_findings",
    }
}

const fn sanitizer_name(sanitizer: Sanitizer) -> &'static str {
    match sanitizer {
        Sanitizer::None => "none",
        Sanitizer::Address => "address",
        Sanitizer::Undefined => "undefined",
        Sanitizer::Memory => "memory",
        Sanitizer::Thread => "thread",
    }
}

fn project_display_name(project_root: &str) -> String {
    Path::new(project_root)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("project")
        .to_owned()
}

async fn comparable_coverage_delta(
    store: &hf_storage::Store,
    run: &RunRecord,
    target_id: Uuid,
) -> Result<i64, ClassifiedError> {
    let mut baseline = None;
    for prior in store.list_runs(Some(&run.project_root)).await? {
        if prior.id == run.id
            || prior.started_at >= run.started_at
            || prior.status != RunStatus::Done
            || prior.kind != RunKind::Campaign
            || prior.engine != run.engine
            || prior.context_rev != run.context_rev
        {
            continue;
        }
        let Some(config) = prior.config.as_ref() else {
            continue;
        };
        let Some(prior_harness) = store.get_harness(config.harness_id).await? else {
            continue;
        };
        if prior_harness.target_id == target_id {
            baseline = prior.edges;
            break;
        }
    }
    let current = i128::from(run.edges.unwrap_or(0));
    let previous = i128::from(baseline.unwrap_or(0));
    Ok(i64::try_from(current - previous).unwrap_or({
        if current >= previous {
            i64::MAX
        } else {
            i64::MIN
        }
    }))
}

pub(crate) fn read_run_crash_file(
    managed_workspace_root: &Path,
    project: &Path,
    target: &str,
    run_id: Uuid,
    recorded_path: &Path,
) -> Result<(Vec<u8>, String), ClassifiedError> {
    let configured_workspace_root = crate::container::workspace_root();
    let configured_run_root = crate::container::workspace_dir(project, target)
        .join("runs")
        .join(run_id.to_string());
    let run_relative = configured_run_root
        .strip_prefix(&configured_workspace_root)
        .map_err(|_| {
            ClassifiedError::Validation("approved run root escapes managed workspace".to_owned())
        })?;
    let crash_relative = recorded_path
        .strip_prefix(&configured_run_root)
        .map_err(|_| {
            ClassifiedError::Validation(format!(
                "crash reproducer escapes its approved run root: {}",
                recorded_path.display()
            ))
        })?;
    read_regular_file_bounded(
        managed_workspace_root,
        run_relative,
        crash_relative,
        recorded_path,
    )
}

fn read_regular_file_bounded(
    managed_workspace_root: &Path,
    run_relative: &Path,
    crash_relative: &Path,
    display_path: &Path,
) -> Result<(Vec<u8>, String), ClassifiedError> {
    let file = open_regular_file_beneath(
        managed_workspace_root,
        run_relative,
        crash_relative,
        display_path,
    )?;
    read_open_file_snapshot(file, display_path)
}

#[cfg(unix)]
fn open_regular_file_beneath(
    managed_workspace_root: &Path,
    run_relative: &Path,
    crash_relative: &Path,
    display_path: &Path,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let components = run_relative
        .components()
        .chain(crash_relative.components())
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(ClassifiedError::Validation(format!(
                "crash reproducer has an unsafe path component: {}",
                display_path.display()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, parents) = components.split_last().ok_or_else(|| {
        ClassifiedError::Validation(format!(
            "crash reproducer must be below its approved run root: {}",
            display_path.display()
        ))
    })?;

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(managed_workspace_root, directory_flags, Mode::empty()).map_err(|error| {
        ClassifiedError::Validation(format!(
            "open managed workspace root {} without following links: {error}",
            managed_workspace_root.display()
        ))
    })?;
    let mut directory = File::from(root);
    for component in parents {
        let next =
            openat(&directory, *component, directory_flags, Mode::empty()).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "open crash reproducer directory beneath {}: {error}",
                    managed_workspace_root.display()
                ))
            })?;
        directory = File::from(next);
    }

    let file = openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        ClassifiedError::Validation(format!(
            "open crash reproducer {} without following links: {error}",
            display_path.display()
        ))
    })?;
    Ok(File::from(file))
}

#[cfg(not(unix))]
fn open_regular_file_beneath(
    _managed_workspace_root: &Path,
    _run_relative: &Path,
    _crash_relative: &Path,
    _display_path: &Path,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "proof-carrying evidence reads require descriptor-relative filesystem access".to_owned(),
    ))
}

fn read_open_file_snapshot(
    mut file: File,
    path: &Path,
) -> Result<(Vec<u8>, String), ClassifiedError> {
    let maximum = hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes;
    let before = file.metadata().map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect open crash reproducer {}: {error}",
            path.display()
        ))
    })?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(ClassifiedError::Validation(format!(
            "crash reproducer must be a regular file no larger than {maximum} bytes"
        )));
    }

    let read_bounded = |file: &mut File| -> Result<Vec<u8>, ClassifiedError> {
        let mut data = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
        file.take(maximum + 1)
            .read_to_end(&mut data)
            .map_err(|error| {
                ClassifiedError::Validation(format!(
                    "read crash reproducer {}: {error}",
                    path.display()
                ))
            })?;
        if data.len() as u64 > maximum {
            return Err(ClassifiedError::Validation(format!(
                "crash reproducer exceeds {maximum} bytes"
            )));
        }
        Ok(data)
    };
    let data = read_bounded(&mut file)?;
    file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
        ClassifiedError::Validation(format!(
            "rewind crash reproducer {}: {error}",
            path.display()
        ))
    })?;
    let repeated = read_bounded(&mut file)?;
    let after = file.metadata().map_err(|error| {
        ClassifiedError::Validation(format!(
            "reinspect open crash reproducer {}: {error}",
            path.display()
        ))
    })?;
    if data != repeated || before.len() != data.len() as u64 || !stable_file(&before, &after) {
        return Err(ClassifiedError::Validation(
            "crash reproducer changed during verification".to_owned(),
        ));
    }
    let digest = hex::encode(Sha256::digest(&data));
    Ok((data, digest))
}

#[cfg(unix)]
fn stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn stable_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn digest_stack_signature(signature: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"oxfuzz-stack-signature-v1\0");
    hasher.update(signature.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_body(body: &EvidenceManifestBody) -> Result<(), EvidenceError> {
    if body.schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(EvidenceError::UnsupportedSchema);
    }
    if !body.status.is_terminal() {
        return Err(EvidenceError::NonTerminalRun);
    }
    if [
        body.generated_at.as_str(),
        body.project.as_str(),
        body.target.as_str(),
        body.run_config.sanitizer.as_str(),
        body.sandbox_image.as_str(),
        body.approval.kind.as_str(),
        body.approval.approved_at.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(EvidenceError::EmptyField);
    }
    let required_digests = [
        body.source_revision.as_str(),
        body.harness_sha256.as_str(),
        body.binary_sha256.as_str(),
        body.comparison_context_sha256.as_str(),
        body.corpus_sha256.as_str(),
        body.sandbox_image_sha256.as_str(),
        body.approval.source_sha256.as_str(),
        body.approval.binary_sha256.as_str(),
    ];
    if required_digests.iter().any(|value| !is_sha256(value))
        || body.findings.iter().any(|finding| {
            !is_sha256(&finding.stack_signature) || !is_sha256(&finding.reproducer_sha256)
        })
    {
        return Err(EvidenceError::InvalidDigest);
    }
    if body.approval.source_sha256 != body.harness_sha256
        || body.approval.binary_sha256 != body.binary_sha256
    {
        return Err(EvidenceError::ApprovalMismatch);
    }
    if !body.cost.compute_cost_usd.is_finite()
        || body.cost.compute_cost_usd < 0.0
        || !body.cost.model_cost_usd.is_finite()
        || body.cost.model_cost_usd < 0.0
    {
        return Err(EvidenceError::InvalidCost);
    }
    if body
        .findings
        .windows(2)
        .any(|pair| pair[0].crash_id == pair[1].crash_id)
    {
        return Err(EvidenceError::DuplicateFinding);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod file_read_tests {
    use super::{read_regular_file_bounded, required_exact_sandbox_digest};
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::symlink;
    use std::path::Path;

    #[test]
    fn bounded_read_accepts_a_nested_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("run/out");
        std::fs::create_dir_all(&directory).unwrap();
        let artifact = directory.join("crash");
        std::fs::write(&artifact, b"crash bytes").unwrap();

        let (bytes, digest) = read_regular_file_bounded(
            root.path(),
            Path::new("run"),
            Path::new("out/crash"),
            &artifact,
        )
        .unwrap();

        assert_eq!(bytes, b"crash bytes");
        assert_eq!(digest, hex::encode(Sha256::digest(b"crash bytes")));
    }

    #[test]
    fn bounded_read_rejects_an_intermediate_symlink_inside_the_run_root() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("run/real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("crash"), b"crash bytes").unwrap();
        symlink(&real, root.path().join("run/alias")).unwrap();
        let artifact = root.path().join("run/alias/crash");

        let error = read_regular_file_bounded(
            root.path(),
            Path::new("run"),
            Path::new("alias/crash"),
            &artifact,
        )
        .unwrap_err();

        assert!(error.to_string().contains("crash reproducer"));
    }

    #[test]
    fn bounded_read_rejects_a_symlinked_run_root_ancestor() {
        let managed = tempfile::tempdir().unwrap();
        let real = managed.path().join("real");
        let run_root = real.join("runs/run-id");
        std::fs::create_dir_all(run_root.join("out")).unwrap();
        std::fs::write(run_root.join("out/crash"), b"crash bytes").unwrap();
        symlink(&real, managed.path().join("project")).unwrap();
        let redirected_run_root = managed.path().join("project/runs/run-id");

        let artifact = redirected_run_root.join("out/crash");
        let error = read_regular_file_bounded(
            managed.path(),
            Path::new("project/runs/run-id"),
            Path::new("out/crash"),
            &artifact,
        )
        .unwrap_err();

        assert!(error.to_string().contains("crash reproducer"));
    }

    #[test]
    fn exact_sandbox_digest_rejects_legacy_untagged_values() {
        let legacy = "a".repeat(64);
        assert!(required_exact_sandbox_digest(Some(&legacy)).is_err());

        let exact = format!("docker-image-id-sha256:{legacy}");
        assert_eq!(required_exact_sandbox_digest(Some(&exact)).unwrap(), legacy);
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        primitive => primitive,
    }
}

fn body_digest(body: &EvidenceManifestBody) -> Result<String, EvidenceError> {
    let value = serde_json::to_value(body).map_err(|_| EvidenceError::Serialization)?;
    let bytes =
        serde_json::to_vec(&canonicalize(value)).map_err(|_| EvidenceError::Serialization)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
