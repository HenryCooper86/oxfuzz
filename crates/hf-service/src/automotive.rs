//! Service-owned automotive protocol orchestration.

use std::collections::{BTreeSet, HashMap};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use hf_automotive::{
    AnalyzeCaptureRequest, ArtifactRef, AutomotiveRequest, CapabilityRequest, LiveMonitorRequest,
    MutationRequest, OperationLimits, ReplayPlanRequest, ReplayRequest, ResponseEnvelope,
    SchemaEnvelope, UdsScanRequest, Validate,
};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    ImmutableImageReference, ResourceLimits, SandboxCapability, SandboxMount, SandboxNetworkMode,
    SandboxOptions,
};
use hf_guardrails::Action;
use hf_storage::{
    AutomotiveOperationRecord, AutomotiveOperationStatus, AutomotiveStateCorpusRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::config::{AutomotivePhysicalBenchSettings, AutomotiveSettings};
use crate::container::{
    ensure_workspace_directory, initialize_workspace_root_at, project_workspace_dir_at,
};
use crate::ServiceContainer;

pub use hf_automotive::{
    AutomotiveMode, AutomotiveProtocol, AutomotiveResult, ModeConfig, ReplayPlan, StateSignature,
};

const SIDECAR_INPUT_ROOT: &str = "/work/inputs";
const SIDECAR_OUTPUT_ROOT: &str = "/work/output";
const REQUEST_EVIDENCE_FILE: &str = "request.jsonl";
const MAX_REQUEST_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_PROMOTION_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const APPROVAL_MAX_AGE: Duration = Duration::minutes(15);
const DANGEROUS_UDS_SERVICES: &[u8] = &[
    0x11, 0x27, 0x28, 0x2e, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3d, 0x85,
];

/// Human approval evidence bound to an exact physical-bench request scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomotiveApprovalEvidence {
    /// Correlation id copied into the physical [`ModeConfig`].
    pub approval_id: String,
    /// Operator identity or local desktop attribution.
    pub approved_by: String,
    /// Time approval was recorded.
    pub approved_at: DateTime<Utc>,
    /// SHA-256 over the exact command, limits, and physical allowlists.
    pub scope_sha256: String,
    /// Immutable sidecar image content digest included in the approved scope.
    pub sidecar_image_sha256: String,
}

/// High-level service operation. Filesystem paths remain outside the pure
/// `hf-automotive` contract and are replaced with opaque artifact references
/// before JSONL serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum AutomotiveCommand {
    /// Inspect the pinned sidecar build.
    Capabilities,
    /// Decode an immutable PCAP capture.
    AnalyzeCapture {
        /// Decoder protocol.
        protocol: AutomotiveProtocol,
        /// Host capture selected by the operator; staged before execution.
        capture_path: PathBuf,
    },
    /// Generate a deterministic field-aware mutation corpus.
    GenerateMutations {
        /// Protocol whose fields constrain mutation.
        protocol: AutomotiveProtocol,
        /// Immutable seed artifact selected by the operator.
        source_path: PathBuf,
        /// Deterministic reproduction seed.
        deterministic_seed: u64,
        /// Number of requested cases.
        mutation_count: u32,
        /// Source media type (`application/octet-stream` or supported JSON).
        media_type: String,
    },
    /// Build a deterministic replay plan from a decoded transcript artifact.
    BuildReplayPlan {
        /// Transcript protocol.
        protocol: AutomotiveProtocol,
        /// Immutable transcript JSON selected by the operator.
        source_path: PathBuf,
        /// Intended later execution mode.
        target_mode: AutomotiveMode,
        /// Deterministic reproduction seed.
        deterministic_seed: u64,
    },
    /// Execute a service-validated replay plan.
    ExecuteReplay {
        /// Exact virtual or physical interface configuration.
        mode: ModeConfig,
        /// Typed plan to execute.
        plan: ReplayPlan,
    },
    /// Perform a bounded, read-only live capture ("monitor"/sniffer).
    LiveMonitor {
        /// Exact virtual or physical interface configuration.
        mode: ModeConfig,
        /// Protocol decoder for captured frames.
        protocol: AutomotiveProtocol,
    },
    /// Perform a read-only UDS ECU/service discovery scan.
    ScanUds {
        /// Exact virtual or physical interface configuration.
        mode: ModeConfig,
        /// Protocol decoder (typically UDS).
        protocol: AutomotiveProtocol,
        /// Request arbitration ids to probe.
        request_ids: Vec<u32>,
        /// Read-only diagnostic service ids to probe.
        services: Vec<u8>,
    },
}

impl AutomotiveCommand {
    fn protocol(&self) -> Option<AutomotiveProtocol> {
        match self {
            Self::Capabilities => None,
            Self::AnalyzeCapture { protocol, .. }
            | Self::GenerateMutations { protocol, .. }
            | Self::BuildReplayPlan { protocol, .. }
            | Self::LiveMonitor { protocol, .. }
            | Self::ScanUds { protocol, .. } => Some(*protocol),
            Self::ExecuteReplay { plan, .. } => Some(plan.protocol),
        }
    }

    fn execution_mode(&self) -> AutomotiveMode {
        match self {
            Self::ExecuteReplay { mode, .. }
            | Self::LiveMonitor { mode, .. }
            | Self::ScanUds { mode, .. } => mode.mode(),
            Self::Capabilities
            | Self::AnalyzeCapture { .. }
            | Self::GenerateMutations { .. }
            | Self::BuildReplayPlan { .. } => AutomotiveMode::OfflinePcap,
        }
    }

    fn operation_name(&self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::AnalyzeCapture { .. } => "analyze_capture",
            Self::GenerateMutations { .. } => "generate_mutations",
            Self::BuildReplayPlan { .. } => "build_replay_plan",
            Self::ExecuteReplay { .. } => "execute_replay",
            Self::LiveMonitor { .. } => "live_monitor",
            Self::ScanUds { .. } => "scan_uds",
        }
    }
}

/// One service-owned automotive operation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomotiveOperationRequest {
    /// Project to which evidence belongs.
    pub project_root: PathBuf,
    /// Operation and its typed inputs.
    pub command: AutomotiveCommand,
    /// Mandatory scoped evidence for physical-bench execution.
    pub approval: Option<AutomotiveApprovalEvidence>,
}

/// Successful retained automotive operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomotiveOperationOutcome {
    /// Service-owned durable operation id.
    pub operation_id: Uuid,
    /// Validated sidecar result.
    pub result: AutomotiveResult,
    /// Canonical sidecar transcript digest, when one was produced.
    pub transcript_sha256: Option<String>,
    /// Workspace-relative retained evidence directory.
    pub artifact_dir: String,
}

/// Public, redacted history item for one retained automotive operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomotiveOperationSummary {
    /// Service-owned operation identifier.
    pub id: Uuid,
    /// Canonical project root associated with the evidence.
    pub project_root: String,
    /// Stable operation name.
    pub operation: String,
    /// Stable execution mode.
    pub mode: String,
    /// Primary protocol, when selected.
    pub protocol: Option<String>,
    /// Durable lifecycle state.
    pub status: AutomotiveOperationStatus,
    /// Admission timestamp.
    pub started_at: DateTime<Utc>,
    /// Terminal timestamp, when available.
    pub ended_at: Option<DateTime<Utc>>,
    /// Canonical transcript digest, when produced.
    pub transcript_sha256: Option<String>,
    /// Workspace-relative retained evidence directory.
    pub artifact_dir: String,
    /// Redacted terminal failure, when present.
    pub error: Option<String>,
    /// Validated protocol-state observations retained from the typed result.
    pub state_signatures: Vec<StateSignature>,
    /// Artifact selectors this operation's evidence can promote into the
    /// protocol-state corpus, ready to be handed back verbatim as
    /// [`AutomotiveStatePromotionRequest::artifact`].
    ///
    /// A caller browsing retained history has only this summary, so without it
    /// there is no way to name a valid artifact. Naming one is necessary but
    /// not sufficient: promotion also requires one of `state_signatures` and a
    /// successfully completed operation, both of which it revalidates.
    pub promotable_artifacts: Vec<AutomotiveStateArtifactSource>,
}

/// Service-owned artifact selector for protocol-state corpus promotion.
///
/// Callers choose only an operation-local identifier, never a host path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "location", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutomotiveStateArtifactSource {
    /// Immutable artifact staged as operation input.
    Input {
        /// Safe single-component artifact identifier.
        artifact_id: String,
    },
    /// Sidecar output referenced by the validated operation result.
    Output {
        /// Safe single-component artifact identifier.
        artifact_id: String,
    },
}

impl AutomotiveStateArtifactSource {
    fn directory(&self) -> &'static str {
        match self {
            Self::Input { .. } => "inputs",
            Self::Output { .. } => "output",
        }
    }

    fn artifact_id(&self) -> &str {
        match self {
            Self::Input { artifact_id } | Self::Output { artifact_id } => artifact_id,
        }
    }
}

/// Request to retain an operation artifact for one observed protocol state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomotiveStatePromotionRequest {
    /// Canonicalized project association checked against the source operation.
    pub project_root: PathBuf,
    /// Completed operation that observed the requested state.
    pub source_operation_id: Uuid,
    /// Exact validated state signature retained by that operation.
    pub state_signature: StateSignature,
    /// Input or validated output artifact to copy into the state corpus.
    pub artifact: AutomotiveStateArtifactSource,
}

/// Public, redacted protocol-state corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomotiveStateCorpusEntry {
    /// Canonical project root associated with the evidence.
    pub project_root: String,
    /// Protocol whose state was observed.
    pub protocol: AutomotiveProtocol,
    /// Canonical state signature digest; observations remain in operation evidence.
    pub state_digest: String,
    /// SHA-256 of the retained artifact bytes.
    pub artifact_sha256: String,
    /// Completed operation that supplied the evidence.
    pub source_operation_id: Uuid,
    /// Workspace-relative, digest-addressed retained path.
    pub artifact_path: String,
    /// Time the first identical promotion was persisted.
    pub created_at: DateTime<Utc>,
}

struct PreparedInput {
    artifact: ArtifactRef,
    bytes: Vec<u8>,
}

struct PreparedOperation {
    project_root: PathBuf,
    command: AutomotiveCommand,
    domain_request: AutomotiveRequest,
    input: Option<PreparedInput>,
    mode: AutomotiveMode,
    protocol: Option<AutomotiveProtocol>,
    operation_name: &'static str,
    approval: Option<AutomotiveApprovalEvidence>,
    execution_config: Option<String>,
}

impl ServiceContainer {
    /// Execute an automotive operation using the current persisted operator
    /// policy. Every sidecar call uses `hf-runtime`; no host Python is invoked.
    ///
    /// # Errors
    /// Returns a validation, guardrail, storage, or sandbox error without
    /// executing when any preflight condition is unmet.
    pub async fn execute_automotive(
        &self,
        request: AutomotiveOperationRequest,
    ) -> Result<AutomotiveOperationOutcome, ClassifiedError> {
        let settings =
            crate::config::effective_automotive_settings().map_err(ClassifiedError::Validation)?;
        let workspace = crate::workspace_root();
        self.execute_automotive_with_context(request, settings, &workspace)
            .await
    }

    /// List redacted automotive operation history for one canonical project.
    ///
    /// # Errors
    /// Returns an error for an invalid project, limit, unavailable store, or
    /// malformed retained typed result.
    pub async fn list_automotive_operations(
        &self,
        project_root: &Path,
        limit: u32,
    ) -> Result<Vec<AutomotiveOperationSummary>, ClassifiedError> {
        if !(1..=200).contains(&limit) {
            return Err(ClassifiedError::Validation(
                "automotive operation history limit must be within 1..=200".to_owned(),
            ));
        }
        let project_root = std::fs::canonicalize(project_root).map_err(|error| {
            ClassifiedError::Validation(format!(
                "resolve automotive project {}: {error}",
                project_root.display()
            ))
        })?;
        if !std::fs::metadata(&project_root).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(ClassifiedError::Validation(
                "automotive project root must be a directory".to_owned(),
            ));
        }
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive operations require durable evidence storage".to_owned(),
            )
        })?;
        store
            .automotive_operations(&project_root.display().to_string(), limit)
            .await?
            .into_iter()
            .map(operation_summary)
            .collect()
    }

    /// Load one redacted automotive operation by its service-owned id.
    ///
    /// # Errors
    /// Returns an error for an unavailable store or malformed retained result.
    pub async fn automotive_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<AutomotiveOperationSummary>, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive operations require durable evidence storage".to_owned(),
            )
        })?;
        store
            .automotive_operation(operation_id)
            .await?
            .map(operation_summary)
            .transpose()
    }

    /// Promote one verified operation artifact into the protocol-state corpus.
    ///
    /// This corpus records protocol novelty only; it does not update source
    /// coverage, engine corpora, or coverage-regression baselines.
    ///
    /// # Errors
    /// Returns an error unless the source operation completed successfully,
    /// retained the exact validated state signature, owns the selected regular
    /// artifact, and every source/destination path remains below the managed
    /// workspace root.
    pub async fn promote_automotive_state_artifact(
        &self,
        request: AutomotiveStatePromotionRequest,
    ) -> Result<AutomotiveStateCorpusEntry, ClassifiedError> {
        let workspace = crate::workspace_root();
        self.promote_automotive_state_artifact_with_context(request, &workspace)
            .await
    }

    /// List redacted protocol-state corpus entries for one canonical project.
    ///
    /// # Errors
    /// Returns an error for an invalid project or limit, unavailable storage,
    /// or malformed retained data.
    pub async fn list_automotive_state_corpus(
        &self,
        project_root: &Path,
        limit: u32,
    ) -> Result<Vec<AutomotiveStateCorpusEntry>, ClassifiedError> {
        if !(1..=200).contains(&limit) {
            return Err(ClassifiedError::Validation(
                "automotive state corpus limit must be within 1..=200".to_owned(),
            ));
        }
        let project_root = canonical_project_root(project_root)?;
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive state corpus requires durable evidence storage".to_owned(),
            )
        })?;
        store
            .automotive_state_corpus(&project_root.display().to_string(), limit)
            .await?
            .into_iter()
            .map(state_corpus_entry)
            .collect()
    }

    /// Compose a project-level automotive campaign report from retained
    /// evidence, optionally appending a grounded provider interpretation.
    ///
    /// `language` selects the report's prose. Every technical token -- evidence
    /// citations, pipeline stage identifiers, protocol, bus, ECU and adapter
    /// names, digests, paths and figures -- is byte-identical in either
    /// language, so a reader of one rendering can be pointed at a line of the
    /// other.
    ///
    /// The deterministic fact sheet is always authoritative and remains
    /// available when no provider is configured or provider validation fails.
    /// This operation never invokes the automotive sidecar or contacts an
    /// interface.
    ///
    /// # Errors
    /// Returns an error for invalid project/configuration, unavailable storage,
    /// or malformed retained evidence.
    pub async fn generate_automotive_report(
        &self,
        project_root: &Path,
        include_ai: bool,
        language: crate::report::ReportLanguage,
    ) -> Result<crate::automotive_report::AutomotiveCampaignReport, ClassifiedError> {
        let settings =
            crate::config::effective_automotive_settings().map_err(ClassifiedError::Validation)?;
        self.generate_automotive_report_with_settings(project_root, include_ai, &settings, language)
            .await
    }

    async fn generate_automotive_report_with_settings(
        &self,
        project_root: &Path,
        include_ai: bool,
        settings: &AutomotiveSettings,
        language: crate::report::ReportLanguage,
    ) -> Result<crate::automotive_report::AutomotiveCampaignReport, ClassifiedError> {
        use crate::automotive_report::{
            append_ai_interpretation, render_automotive_report, AutomotiveCampaignReport,
            AutomotiveLabels, AutomotiveReportAiStatus, AutomotiveReportData,
            AutomotiveReportSafetyPosture,
        };

        let project_root = canonical_project_root(project_root)?;
        let project_root_text = project_root.display().to_string();
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive reporting requires durable evidence storage".to_owned(),
            )
        })?;
        let operations = store
            .automotive_operations(&project_root_text, 200)
            .await?
            .into_iter()
            .map(report_operation)
            .collect::<Result<Vec<_>, _>>()?;
        let state_corpus = store
            .automotive_state_corpus(&project_root_text, 200)
            .await?
            .into_iter()
            .map(state_corpus_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let generated_at = Utc::now().to_rfc3339();
        let project_name = project_root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("project")
            .to_owned();
        let data = AutomotiveReportData {
            generated_at: generated_at.clone(),
            project_name: project_name.clone(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            safety: AutomotiveReportSafetyPosture::from_settings(settings),
            operations,
            state_corpus,
        };
        let metrics = data.metrics();
        // Everything downstream resolves from this one value: the deterministic
        // render, the two prompts, the validation of what the model returns and
        // the advisory notice above it. Splitting it would let the prompts ask
        // for one language while validation required another, which rejects
        // every interpretation and falls back without saying why.
        let labels = AutomotiveLabels::for_language(language);
        let facts = render_automotive_report(&data, &labels);
        let mut markdown = facts.clone();
        let mut ai_model = None;
        let ai_status = if !include_ai {
            AutomotiveReportAiStatus::NotRequested
        } else if data.operations.is_empty() {
            AutomotiveReportAiStatus::NotApplicable
        } else if let Some(pool) = self.provider_pool() {
            match self
                .compose_automotive_report_interpretation(&pool, &facts, &data, language)
                .await
            {
                Ok((interpretation, model)) => {
                    markdown = append_ai_interpretation(&facts, &interpretation, &model, &labels);
                    ai_model = Some(model);
                    AutomotiveReportAiStatus::Applied
                }
                Err(error) => {
                    tracing::warn!(
                        "automotive AI report composition failed, retaining fact sheet: {error}"
                    );
                    AutomotiveReportAiStatus::Fallback
                }
            }
        } else {
            AutomotiveReportAiStatus::NotConfigured
        };

        Ok(AutomotiveCampaignReport {
            generated_at,
            project_name,
            ai_status,
            ai_model,
            operation_count: metrics.operation_count,
            failed_operation_count: metrics.failed_operation_count,
            unique_state_count: metrics.unique_state_count,
            promoted_state_count: metrics.promoted_state_count,
            markdown,
        })
    }

    async fn compose_automotive_report_interpretation(
        &self,
        pool: &std::sync::Arc<dyn hf_core::provider::ProviderPool>,
        facts: &str,
        data: &crate::automotive_report::AutomotiveReportData,
        language: crate::report::ReportLanguage,
    ) -> Result<(String, String), ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;

        // One language value reaches the prompts and the validation of what
        // comes back. Asking for one language's headings while requiring
        // another's rejects every interpretation the model returns and falls
        // back to the deterministic report without saying why.
        let messages = vec![
            Message::system(crate::automotive_report::automotive_report_system_prompt(
                language,
            )),
            Message::user(crate::automotive_report::automotive_report_user_prompt(
                facts, data, language,
            )),
        ];
        let response = pool
            .chat_completion(
                &ChatRequest::from_messages(messages),
                &RouteRequest::with_tags(&["reasoning", "security", "general"]),
            )
            .await?;
        self.diagnostics()
            .record("automotive_report", &response.model, &response.usage)
            .await;
        let interpretation = response.text().trim();
        crate::automotive_report::validate_ai_interpretation(interpretation, data, language)
            .map_err(ClassifiedError::Provider)?;
        Ok((interpretation.to_owned(), response.model))
    }

    async fn promote_automotive_state_artifact_with_context(
        &self,
        request: AutomotiveStatePromotionRequest,
        workspace: &Path,
    ) -> Result<AutomotiveStateCorpusEntry, ClassifiedError> {
        request
            .state_signature
            .validate()
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        validate_artifact_identifier(request.artifact.artifact_id())?;
        let project_root = canonical_project_root(&request.project_root)?;
        // Promotion copies an artifact into the project's retained corpus and
        // persists a row, so it is authorized as the corpus filesystem
        // operation it is. This sits in the executor rather than the public
        // wrapper: `_with_context` is what actually performs the copy, and a
        // guard the direct caller can step around is not a guard
        // (AGENTS.md 2.19).
        self.authorize_recorded(
            hf_guardrails::Action::CorpusOp,
            "automotive_state_promote",
            Some(&project_root),
        )
        .await
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let project_root_text = project_root.display().to_string();
        let store = self.store().cloned().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive state corpus requires durable evidence storage".to_owned(),
            )
        })?;
        let operation = store
            .automotive_operation(request.source_operation_id)
            .await?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "automotive source operation {} was not found",
                    request.source_operation_id
                ))
            })?;
        let retained_result = validate_promotion_operation(
            &operation,
            &project_root_text,
            &request.state_signature,
            &request.artifact,
        )?;

        let _workspace_lease = self.acquire_workspace_operation_at(workspace).await?;
        let workspace = initialize_workspace_root_at(workspace)?;
        let project_dir = project_workspace_dir_at(&workspace, &project_root);
        let project_relative = project_dir.strip_prefix(&workspace).map_err(|_| {
            ClassifiedError::Internal("automotive project workspace escaped its root".to_owned())
        })?;
        let expected_operation_relative = project_relative
            .join(".service")
            .join("automotive")
            .join(operation.id.to_string());
        if Path::new(&operation.artifact_dir) != expected_operation_relative {
            return Err(ClassifiedError::Storage(format!(
                "automotive operation {} has an invalid retained artifact directory",
                operation.id
            )));
        }
        let source_directory_relative =
            expected_operation_relative.join(request.artifact.directory());
        let operation_directory =
            resolve_existing_workspace_directory(&workspace, &expected_operation_relative)?;
        let source_directory =
            resolve_existing_workspace_directory(&workspace, &source_directory_relative)?;
        let source = resolve_regular_artifact(&source_directory, request.artifact.artifact_id())?;
        let (artifact_sha256, artifact_size) = digest_regular_file(&source)?;
        let input_artifact = match &request.artifact {
            AutomotiveStateArtifactSource::Input { .. } => {
                Some(retained_request_input(&operation_directory, &operation)?)
            }
            AutomotiveStateArtifactSource::Output { .. } => None,
        };
        validate_selected_artifact(
            &retained_result,
            &request.artifact,
            &artifact_sha256,
            artifact_size,
            input_artifact.as_ref(),
        )?;

        let protocol = request.state_signature.protocol;
        let protocol_name = protocol_id(protocol);
        let state_digest = request.state_signature.digest.as_str();
        if let Some(existing) = store
            .automotive_state_corpus_entry(
                &project_root_text,
                protocol_name,
                state_digest,
                &artifact_sha256,
            )
            .await?
        {
            verify_retained_corpus_artifact(&workspace, &existing)?;
            return state_corpus_entry(existing);
        }

        let destination_relative = project_relative
            .join(".service")
            .join("automotive")
            .join("state-corpus")
            .join(protocol_name)
            .join(state_digest);
        let destination_directory = ensure_workspace_directory(&workspace, &destination_relative)?;
        let destination = destination_directory.join(&artifact_sha256);
        copy_verified_create_new(&source, &destination, &artifact_sha256, artifact_size)?;
        let artifact_path = destination
            .strip_prefix(&workspace)
            .map_err(|_| {
                ClassifiedError::Internal(
                    "automotive state corpus destination escaped its workspace".to_owned(),
                )
            })?
            .to_string_lossy()
            .into_owned();
        let persisted = store
            .record_automotive_state_corpus(&AutomotiveStateCorpusRecord {
                project_root: project_root_text,
                protocol: protocol_name.to_owned(),
                state_digest: state_digest.to_owned(),
                artifact_sha256,
                source_operation_id: operation.id,
                artifact_path,
                created_at: Utc::now(),
            })
            .await?;
        verify_retained_corpus_artifact(&workspace, &persisted)?;
        state_corpus_entry(persisted)
    }

    async fn execute_automotive_with_context(
        &self,
        request: AutomotiveOperationRequest,
        settings: AutomotiveSettings,
        workspace: &Path,
    ) -> Result<AutomotiveOperationOutcome, ClassifiedError> {
        let mut prepared = preflight(request, &settings)?;
        let store = self.store().cloned().ok_or_else(|| {
            ClassifiedError::Storage(
                "automotive operations require durable evidence storage".to_owned(),
            )
        })?;
        // Fail fast with an actionable message when the sidecar image has not
        // been built, instead of a raw Docker "no such image" from the sandbox --
        // and, crucially, BEFORE authorizing or claiming a single-use
        // physical-bench approval, so a missing image never burns an approval.
        if !self
            .runtime_adapter()
            .image_present(&settings.sidecar_image)
            .await
        {
            return Err(missing_sidecar_image_error(&settings.sidecar_image));
        }
        let sidecar_image = self
            .runtime_adapter()
            .resolve_image_reference(&settings.sidecar_image)
            .await?
            .ok_or_else(|| missing_sidecar_image_error(&settings.sidecar_image))?;
        validate_resolved_image_approval(&prepared, &settings, sidecar_image.sha256())?;
        prepared.execution_config = build_execution_config(
            &prepared.command,
            prepared.approval.as_ref(),
            &settings,
            &operation_limits(&settings)?,
            sidecar_image.sha256(),
        )?;
        self.authorize_recorded(
            action_for(&prepared, &settings, sidecar_image.sha256()),
            "automotive_operation",
            Some(&prepared.project_root),
        )
        .await?;

        let _workspace_lease = self.acquire_workspace_operation_at(workspace).await?;
        let workspace = initialize_workspace_root_at(workspace)?;
        let operation_id = Uuid::new_v4();

        // Single-use physical-bench approval: a human approval authorizes at most
        // one real transmission. Atomically claim it before any workspace setup
        // or bus access, so a repeated or concurrent execution reusing the same
        // approval within its freshness window is rejected here rather than
        // firing a second time on the vehicle. Claiming before the operation
        // record is inserted means a rejected duplicate leaves no spurious row;
        // fail-closed -- a claimed approval whose operation later errors requires
        // a fresh approval (no auto-retry against real hardware).
        if prepared.mode == AutomotiveMode::PhysicalBench {
            // Fail closed: a physical-bench operation must never reach execution
            // without approval evidence to claim. preflight guarantees this, but the
            // single-use gate does not depend on that invariant holding.
            let approval = prepared.approval.as_ref().ok_or_else(|| {
                ClassifiedError::Validation(
                    "physical automotive bench operation reached execution without approval \
                     evidence"
                        .to_owned(),
                )
            })?;
            let claimed_at = Utc::now();
            validate_resolved_image_approval_at(
                &prepared,
                &settings,
                sidecar_image.sha256(),
                claimed_at,
            )?;
            let claimed = store
                .consume_automotive_approval(
                    &approval.approval_id,
                    &approval.scope_sha256,
                    operation_id,
                    &prepared.project_root.display().to_string(),
                    claimed_at,
                )
                .await?;
            if !claimed {
                return Err(ClassifiedError::Validation(
                    "physical automotive bench approval has already been used; each \
                     physical transmission requires a fresh human approval"
                        .to_owned(),
                ));
            }
        }

        let project_dir = project_workspace_dir_at(&workspace, &prepared.project_root);
        let project_relative = project_dir.strip_prefix(&workspace).map_err(|_| {
            ClassifiedError::Internal("automotive project workspace escaped its root".to_owned())
        })?;
        let operation_relative = project_relative
            .join(".service")
            .join("automotive")
            .join(operation_id.to_string());
        let operation_dir = ensure_workspace_directory(&workspace, &operation_relative)?;
        let input_dir = ensure_workspace_directory(&operation_dir, Path::new("inputs"))?;
        let output_dir = ensure_workspace_directory(&operation_dir, Path::new("output"))?;
        if let Some(input) = &prepared.input {
            stage_input(&input_dir, input)?;
        }

        let request_id = operation_id.to_string();
        let envelope = SchemaEnvelope::new(&request_id, prepared.domain_request.clone());
        envelope
            .validate()
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let mut encoded = serde_json::to_vec(&envelope).map_err(|error| {
            ClassifiedError::Internal(format!("serialize automotive request: {error}"))
        })?;
        encoded.push(b'\n');
        let request_hash = sha256_bytes(&encoded);
        retain_request_evidence(&operation_dir, &encoded)?;
        let artifact_dir = operation_relative.to_string_lossy().into_owned();
        let approval_json = prepared
            .approval
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| {
                ClassifiedError::Internal(format!("serialize automotive approval: {error}"))
            })?;
        let record = AutomotiveOperationRecord {
            id: operation_id,
            project_root: prepared.project_root.display().to_string(),
            operation: prepared.operation_name.to_owned(),
            mode: mode_id(prepared.mode).to_owned(),
            protocol: prepared.protocol.map(protocol_id).map(str::to_owned),
            status: AutomotiveOperationStatus::Running,
            started_at: Utc::now(),
            ended_at: None,
            request_hash,
            transcript_hash: None,
            artifact_dir: artifact_dir.clone(),
            approval_json,
            result_json: None,
            error: None,
        };
        store.insert_automotive_operation(&record).await?;

        let limits = runtime_limits(&settings, &prepared);
        let options = sandbox_options(
            &settings,
            &prepared,
            &sidecar_image,
            &input_dir,
            &output_dir,
            encoded,
        );
        let command = vec![
            "python3".to_owned(),
            "-m".to_owned(),
            "oxfuzz_scapy_automotive".to_owned(),
        ];
        let result = self
            .runtime_adapter()
            .run_command_opts(&command, &operation_dir, &limits, &options)
            .await;
        let response = match result {
            Ok(result) => match result.require_completed("automotive sidecar") {
                Ok(result) if matches!(result.exit_code, 0 | 1) => {
                    parse_response(&result.stdout, &request_id).and_then(|response| {
                        if result.exit_code == 1 && response.ok {
                            Err(ClassifiedError::Sandbox(
                                "automotive sidecar returned success with failure exit status"
                                    .to_owned(),
                            ))
                        } else {
                            Ok(response)
                        }
                    })
                }
                Ok(result) => Err(ClassifiedError::Sandbox(format!(
                    "automotive sidecar exited with status {}: {}",
                    result.exit_code,
                    result.stderr.trim()
                ))),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                persist_failure(&store, operation_id, &error).await;
                return Err(error);
            }
        };
        let result = match response.result {
            Some(result) if response.ok => result,
            _ => {
                let message = response.error.map_or_else(
                    || "automotive sidecar returned no result".to_owned(),
                    |error| format!("{}: {}", serde_json_string(&error.code), error.message),
                );
                let error = ClassifiedError::Validation(message);
                persist_failure(&store, operation_id, &error).await;
                return Err(error);
            }
        };
        retain_failure(
            &store,
            operation_id,
            require_matching_result(&prepared.domain_request, &result),
        )
        .await?;
        retain_failure(
            &store,
            operation_id,
            verify_result_artifacts(&output_dir, &result, settings.limits.max_output_bytes),
        )
        .await?;
        let result_json = retain_failure(
            &store,
            operation_id,
            serde_json::to_string(&result).map_err(|error| {
                ClassifiedError::Internal(format!("serialize automotive result: {error}"))
            }),
        )
        .await?;
        let transcript_sha256 = response
            .transcript_sha256
            .as_ref()
            .map(|digest| digest.as_str().to_owned());
        store
            .complete_automotive_operation(
                operation_id,
                AutomotiveOperationStatus::Done,
                Utc::now(),
                transcript_sha256.as_deref(),
                Some(&result_json),
                None,
            )
            .await?;
        Ok(AutomotiveOperationOutcome {
            operation_id,
            result,
            transcript_sha256,
            artifact_dir,
        })
    }
}

fn operation_summary(
    record: AutomotiveOperationRecord,
) -> Result<AutomotiveOperationSummary, ClassifiedError> {
    let retained = retained_operation_result(&record)?;
    let state_signatures = retained
        .as_ref()
        .map_or_else(Vec::new, |result| result_state_signatures(result).to_vec());
    let promotable_artifacts = promotable_artifacts(&record, retained.as_ref());
    Ok(AutomotiveOperationSummary {
        id: record.id,
        project_root: record.project_root,
        operation: record.operation,
        mode: record.mode,
        protocol: record.protocol,
        status: record.status,
        started_at: record.started_at,
        ended_at: record.ended_at,
        transcript_sha256: record.transcript_hash,
        artifact_dir: record.artifact_dir,
        // Redact absolute host/workspace paths: this summary is a "redacted history
        // item" returned over the REST API, and execution-phase failures can embed
        // absolute artifact paths.
        error: record
            .error
            .as_deref()
            .map(crate::automotive_report::shareable_error),
        state_signatures,
        promotable_artifacts,
    })
}

/// The artifact selectors promotion accepts for one retained operation.
///
/// The staged input is named by the operation kind through the same
/// `operation_input_artifact_id` map promotion validates against, and the
/// outputs come from the retained typed result. Both are operation-local
/// identifiers; the digest and size each one must still match live in the
/// operation's own evidence, and promotion rereads them from there.
///
/// Empty for an operation with no retained result: there is nothing to promote
/// from a run that never produced one.
fn promotable_artifacts(
    record: &AutomotiveOperationRecord,
    result: Option<&AutomotiveResult>,
) -> Vec<AutomotiveStateArtifactSource> {
    let Some(result) = result else {
        return Vec::new();
    };
    let mut artifacts: Vec<AutomotiveStateArtifactSource> =
        operation_input_artifact_id(&record.operation)
            .map(|artifact_id| AutomotiveStateArtifactSource::Input {
                artifact_id: artifact_id.to_owned(),
            })
            .into_iter()
            .collect();
    artifacts.extend(result_output_artifacts(result).into_iter().map(|artifact| {
        AutomotiveStateArtifactSource::Output {
            artifact_id: artifact.artifact_id.clone(),
        }
    }));
    artifacts
}

fn report_operation(
    record: AutomotiveOperationRecord,
) -> Result<crate::automotive_report::AutomotiveReportOperation, ClassifiedError> {
    for (field, digest) in [
        ("request", Some(record.request_hash.as_str())),
        ("transcript", record.transcript_hash.as_deref()),
    ] {
        if let Some(digest) = digest {
            validate_retained_digest(field, record.id, digest)?;
        }
    }
    let artifact_dir = Path::new(&record.artifact_dir);
    if artifact_dir.is_absolute()
        || !artifact_dir
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Storage(format!(
            "automotive operation {} has an invalid retained artifact directory",
            record.id
        )));
    }
    let retained_result = retained_operation_result(&record)?;
    let state_signatures = retained_result
        .as_ref()
        .map_or_else(Vec::new, |result| result_state_signatures(result).to_vec());
    let result_summary = retained_result.as_ref().map(automotive_result_summary);
    let result_complete = retained_result.as_ref().map(automotive_result_complete);
    Ok(crate::automotive_report::AutomotiveReportOperation {
        id: record.id,
        operation: record.operation,
        mode: record.mode,
        protocol: record.protocol,
        status: record.status,
        started_at: record.started_at,
        ended_at: record.ended_at,
        request_sha256: record.request_hash,
        transcript_sha256: record.transcript_hash,
        artifact_dir: record.artifact_dir,
        error: record.error,
        state_signatures,
        result_summary,
        result_complete,
    })
}

fn retained_operation_result(
    record: &AutomotiveOperationRecord,
) -> Result<Option<AutomotiveResult>, ClassifiedError> {
    let Some(retained) = record.result_json.as_deref() else {
        return Ok(None);
    };
    let result: AutomotiveResult = serde_json::from_str(retained).map_err(|error| {
        ClassifiedError::Storage(format!(
            "automotive operation {} has malformed retained result: {error}",
            record.id
        ))
    })?;
    result.validate().map_err(|error| {
        ClassifiedError::Storage(format!(
            "automotive operation {} has invalid retained result: {error}",
            record.id
        ))
    })?;
    Ok(Some(result))
}

fn automotive_result_summary(result: &AutomotiveResult) -> String {
    match result {
        AutomotiveResult::Capabilities(capabilities) => format!(
            "adapter {} {}; {} protocol(s), {} mode(s), {} capability/capabilities",
            capabilities.adapter_name,
            capabilities.adapter_version,
            capabilities.protocols.len(),
            capabilities.modes.len(),
            capabilities.capabilities.len()
        ),
        AutomotiveResult::CaptureAnalysis(analysis) => format!(
            "{} decoded event(s); {} protocol-state signature(s)",
            analysis.event_count,
            analysis.state_signatures.len()
        ),
        AutomotiveResult::Mutations(mutations) => format!(
            "{} deterministic mutation(s); {} retained artifact(s)",
            mutations.generated,
            mutations.artifacts.len()
        ),
        AutomotiveResult::ReplayPlan(plan) => format!(
            "{} typed replay step(s); target mode {}; deterministic seed {}",
            plan.steps.len(),
            mode_id(plan.mode),
            plan.deterministic_seed
        ),
        AutomotiveResult::Replay(replay) => format!(
            "{} of {} replay event(s) executed; {}; {} protocol-state signature(s)",
            replay.executed_events,
            replay.planned_events,
            if replay.completed {
                "complete"
            } else {
                "partial"
            },
            replay.state_signatures.len()
        ),
        AutomotiveResult::UdsScan(scan) => format!(
            "{} discovered ECU(s) on {}",
            scan.ecus.len(),
            mode_id(scan.mode)
        ),
    }
}

fn automotive_result_complete(result: &AutomotiveResult) -> bool {
    match result {
        AutomotiveResult::Replay(replay) => replay.completed,
        AutomotiveResult::Capabilities(_)
        | AutomotiveResult::CaptureAnalysis(_)
        | AutomotiveResult::Mutations(_)
        | AutomotiveResult::ReplayPlan(_)
        | AutomotiveResult::UdsScan(_) => true,
    }
}

fn validate_retained_digest(
    field: &str,
    operation_id: Uuid,
    digest: &str,
) -> Result<(), ClassifiedError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ClassifiedError::Storage(format!(
            "automotive operation {operation_id} has an invalid retained {field} digest"
        )))
    }
}

fn canonical_project_root(project_root: &Path) -> Result<PathBuf, ClassifiedError> {
    let canonical = std::fs::canonicalize(project_root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve automotive project {}: {error}",
            project_root.display()
        ))
    })?;
    if !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(ClassifiedError::Validation(
            "automotive project root must be a directory".to_owned(),
        ));
    }
    Ok(canonical)
}

fn validate_promotion_operation(
    operation: &AutomotiveOperationRecord,
    project_root: &str,
    state_signature: &StateSignature,
    artifact: &AutomotiveStateArtifactSource,
) -> Result<AutomotiveResult, ClassifiedError> {
    if operation.status != AutomotiveOperationStatus::Done || operation.ended_at.is_none() {
        return Err(ClassifiedError::Validation(format!(
            "automotive source operation {} is not completed",
            operation.id
        )));
    }
    if operation.project_root != project_root {
        return Err(ClassifiedError::Validation(
            "automotive source operation belongs to a different project".to_owned(),
        ));
    }
    let expected_protocol = protocol_id(state_signature.protocol);
    if operation.protocol.as_deref() != Some(expected_protocol) {
        return Err(ClassifiedError::Validation(
            "automotive state protocol does not match the source operation".to_owned(),
        ));
    }
    let retained = operation.result_json.as_deref().ok_or_else(|| {
        ClassifiedError::Storage(format!(
            "completed automotive operation {} has no retained result",
            operation.id
        ))
    })?;
    let result: AutomotiveResult = serde_json::from_str(retained).map_err(|error| {
        ClassifiedError::Storage(format!(
            "automotive operation {} has malformed retained result: {error}",
            operation.id
        ))
    })?;
    result.validate().map_err(|error| {
        ClassifiedError::Storage(format!(
            "automotive operation {} has invalid retained result: {error}",
            operation.id
        ))
    })?;
    if !result_state_signatures(&result).contains(state_signature) {
        return Err(ClassifiedError::Validation(
            "requested state signature was not observed by the source operation".to_owned(),
        ));
    }
    match artifact {
        AutomotiveStateArtifactSource::Input { artifact_id } => {
            let expected = operation_input_artifact_id(&operation.operation).ok_or_else(|| {
                ClassifiedError::Validation(
                    "source operation did not retain an input artifact".to_owned(),
                )
            })?;
            if artifact_id != expected {
                return Err(ClassifiedError::Validation(
                    "input artifact identifier does not belong to the source operation".to_owned(),
                ));
            }
        }
        AutomotiveStateArtifactSource::Output { artifact_id } => {
            if result_output_artifact(&result, artifact_id).is_none() {
                return Err(ClassifiedError::Validation(
                    "output artifact identifier is not referenced by the source result".to_owned(),
                ));
            }
        }
    }
    Ok(result)
}

fn result_state_signatures(result: &AutomotiveResult) -> &[StateSignature] {
    match result {
        AutomotiveResult::CaptureAnalysis(result) => &result.state_signatures,
        AutomotiveResult::Replay(result) => &result.state_signatures,
        AutomotiveResult::Capabilities(_)
        | AutomotiveResult::Mutations(_)
        | AutomotiveResult::ReplayPlan(_)
        | AutomotiveResult::UdsScan(_) => &[],
    }
}

/// Every output artifact one typed result references, in result order.
///
/// The single home for "which outputs does this result own": both the
/// promotable-artifact listing and the by-id lookup promotion validates with
/// read it, so a caller can never be offered a selector that validation would
/// then reject (AGENTS.md 2.18).
fn result_output_artifacts(result: &AutomotiveResult) -> Vec<&ArtifactRef> {
    match result {
        AutomotiveResult::CaptureAnalysis(result) => vec![&result.transcript],
        AutomotiveResult::UdsScan(result) => vec![&result.transcript],
        AutomotiveResult::Mutations(result) => result.artifacts.iter().collect(),
        AutomotiveResult::Capabilities(_)
        | AutomotiveResult::ReplayPlan(_)
        | AutomotiveResult::Replay(_) => Vec::new(),
    }
}

fn result_output_artifact<'a>(
    result: &'a AutomotiveResult,
    artifact_id: &str,
) -> Option<&'a ArtifactRef> {
    result_output_artifacts(result)
        .into_iter()
        .find(|artifact| artifact.artifact_id == artifact_id)
}

fn operation_input_artifact_id(operation: &str) -> Option<&'static str> {
    match operation {
        "analyze_capture" => Some("capture.pcap"),
        "generate_mutations" => Some("mutation-seed"),
        "build_replay_plan" => Some("transcript.json"),
        _ => None,
    }
}

fn retained_request_input(
    operation_directory: &Path,
    operation: &AutomotiveOperationRecord,
) -> Result<ArtifactRef, ClassifiedError> {
    let request_path = resolve_regular_artifact(operation_directory, REQUEST_EVIDENCE_FILE)?;
    let (bytes, digest) = read_verified_regular_file(&request_path, MAX_REQUEST_EVIDENCE_BYTES)?;
    if digest != operation.request_hash {
        return Err(ClassifiedError::Storage(format!(
            "automotive operation {} request evidence does not match its retained hash",
            operation.id
        )));
    }
    let envelope: SchemaEnvelope<AutomotiveRequest> =
        serde_json::from_slice(&bytes).map_err(|error| {
            ClassifiedError::Storage(format!(
                "automotive operation {} has malformed request evidence: {error}",
                operation.id
            ))
        })?;
    envelope.validate().map_err(|error| {
        ClassifiedError::Storage(format!(
            "automotive operation {} has invalid request evidence: {error}",
            operation.id
        ))
    })?;
    if envelope.request_id != operation.id.to_string() {
        return Err(ClassifiedError::Storage(format!(
            "automotive operation {} request evidence has the wrong correlation id",
            operation.id
        )));
    }
    let input = match envelope.payload {
        AutomotiveRequest::AnalyzeCapture(request) => Some(request.capture),
        AutomotiveRequest::GenerateMutations(request) => Some(request.source),
        AutomotiveRequest::BuildReplayPlan(request) => Some(request.source),
        AutomotiveRequest::Capabilities(_)
        | AutomotiveRequest::ExecuteReplay(_)
        | AutomotiveRequest::LiveMonitor(_)
        | AutomotiveRequest::ScanUds(_) => None,
    }
    .ok_or_else(|| {
        ClassifiedError::Storage(format!(
            "automotive operation {} request evidence has no input artifact",
            operation.id
        ))
    })?;
    let expected_id = operation_input_artifact_id(&operation.operation).ok_or_else(|| {
        ClassifiedError::Storage(format!(
            "automotive operation {} does not admit an input artifact",
            operation.id
        ))
    })?;
    if input.artifact_id != expected_id {
        return Err(ClassifiedError::Storage(format!(
            "automotive operation {} request input does not match its operation kind",
            operation.id
        )));
    }
    Ok(input)
}

fn validate_selected_artifact(
    result: &AutomotiveResult,
    source: &AutomotiveStateArtifactSource,
    digest: &str,
    size: u64,
    input_artifact: Option<&ArtifactRef>,
) -> Result<(), ClassifiedError> {
    let expected = match source {
        AutomotiveStateArtifactSource::Input { artifact_id } => {
            let expected = input_artifact.ok_or_else(|| {
                ClassifiedError::Storage(
                    "automotive source operation has no verified request input".to_owned(),
                )
            })?;
            if expected.artifact_id != *artifact_id {
                return Err(ClassifiedError::Validation(
                    "input artifact is not referenced by the retained request".to_owned(),
                ));
            }
            expected
        }
        AutomotiveStateArtifactSource::Output { artifact_id } => {
            result_output_artifact(result, artifact_id).ok_or_else(|| {
                ClassifiedError::Validation(
                    "output artifact is not referenced by the retained result".to_owned(),
                )
            })?
        }
    };
    if expected.sha256 != digest || expected.size_bytes != size {
        return Err(ClassifiedError::Validation(format!(
            "{} artifact no longer matches its retained digest and size",
            source.directory()
        )));
    }
    Ok(())
}

fn validate_artifact_identifier(artifact_id: &str) -> Result<(), ClassifiedError> {
    let mut bytes = artifact_id.bytes();
    let starts_safely = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if artifact_id.is_empty()
        || artifact_id.len() > 128
        || !starts_safely
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || Path::new(artifact_id).components().count() != 1
    {
        return Err(ClassifiedError::Validation(
            "automotive artifact identifier must be a safe single component".to_owned(),
        ));
    }
    Ok(())
}

fn resolve_existing_workspace_directory(
    workspace: &Path,
    relative: &Path,
) -> Result<PathBuf, ClassifiedError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "automotive workspace path is unsafe: {}",
            relative.display()
        )));
    }
    let root = std::fs::canonicalize(workspace).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve automotive workspace {}: {error}",
            workspace.display()
        ))
    })?;
    let mut current = root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("workspace path was validated")
        };
        current.push(name);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect automotive workspace directory {}: {error}",
                current.display()
            ))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(ClassifiedError::Validation(format!(
                "automotive workspace path is not a regular directory: {}",
                current.display()
            )));
        }
    }
    let resolved = std::fs::canonicalize(&current).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve automotive workspace directory {}: {error}",
            current.display()
        ))
    })?;
    if !resolved.starts_with(&root) || resolved != current {
        return Err(ClassifiedError::Validation(
            "automotive workspace directory escaped its managed root".to_owned(),
        ));
    }
    Ok(resolved)
}

fn resolve_regular_artifact(
    directory: &Path,
    artifact_id: &str,
) -> Result<PathBuf, ClassifiedError> {
    validate_artifact_identifier(artifact_id)?;
    let candidate = directory.join(artifact_id);
    let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect automotive operation artifact {}: {error}",
            candidate.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(
            "automotive operation artifact is not a regular file".to_owned(),
        ));
    }
    let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve automotive operation artifact {}: {error}",
            candidate.display()
        ))
    })?;
    if resolved != candidate || !resolved.starts_with(directory) {
        return Err(ClassifiedError::Validation(
            "automotive operation artifact escaped its retained directory".to_owned(),
        ));
    }
    Ok(resolved)
}

fn digest_regular_file(path: &Path) -> Result<(String, u64), ClassifiedError> {
    let before = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect automotive artifact {}: {error}",
            path.display()
        ))
    })?;
    if !before.file_type().is_file() || before.len() > MAX_PROMOTION_ARTIFACT_BYTES {
        return Err(ClassifiedError::Validation(format!(
            "automotive artifact must be a regular file no larger than {MAX_PROMOTION_ARTIFACT_BYTES} bytes"
        )));
    }
    let mut file = std::fs::File::open(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "open automotive artifact {}: {error}",
            path.display()
        ))
    })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(ClassifiedError::Validation(
            "automotive artifact changed before verification".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            ClassifiedError::Validation(format!(
                "read automotive artifact {}: {error}",
                path.display()
            ))
        })?;
        if count == 0 {
            break;
        }
        observed = observed.checked_add(count as u64).ok_or_else(|| {
            ClassifiedError::Validation("automotive artifact size overflowed".to_owned())
        })?;
        if observed > MAX_PROMOTION_ARTIFACT_BYTES {
            return Err(ClassifiedError::Validation(format!(
                "automotive artifact exceeds {MAX_PROMOTION_ARTIFACT_BYTES} bytes"
            )));
        }
        hasher.update(&buffer[..count]);
    }
    let after = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "reinspect automotive artifact {}: {error}",
            path.display()
        ))
    })?;
    if !after.file_type().is_file() || before.len() != observed || after.len() != observed {
        return Err(ClassifiedError::Validation(
            "automotive artifact changed during verification".to_owned(),
        ));
    }
    Ok((format!("{:x}", hasher.finalize()), observed))
}

fn read_verified_regular_file(
    path: &Path,
    maximum: u64,
) -> Result<(Vec<u8>, String), ClassifiedError> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        ClassifiedError::Storage(format!(
            "open retained automotive evidence {}: {error}",
            path.display()
        ))
    })?;
    let before = file.metadata().map_err(|error| {
        ClassifiedError::Storage(format!(
            "inspect retained automotive evidence {}: {error}",
            path.display()
        ))
    })?;
    if !before.is_file() || before.len() > maximum {
        return Err(ClassifiedError::Storage(format!(
            "retained automotive evidence must be a regular file no larger than {maximum} bytes"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ClassifiedError::Storage(format!(
                "read retained automotive evidence {}: {error}",
                path.display()
            ))
        })?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let after = file.metadata().map_err(|error| {
        ClassifiedError::Storage(format!(
            "reinspect retained automotive evidence {}: {error}",
            path.display()
        ))
    })?;
    if observed > maximum || before.len() != observed || after.len() != observed {
        return Err(ClassifiedError::Storage(
            "retained automotive evidence changed while it was read".to_owned(),
        ));
    }
    let digest = sha256_bytes(&bytes);
    Ok((bytes, digest))
}

fn copy_verified_create_new(
    source: &Path,
    destination: &Path,
    expected_digest: &str,
    expected_size: u64,
) -> Result<(), ClassifiedError> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => return verify_file_digest(destination, expected_digest, expected_size),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ClassifiedError::Internal(format!(
                "inspect automotive state corpus destination {}: {error}",
                destination.display()
            )));
        }
    }
    let parent = destination.parent().ok_or_else(|| {
        ClassifiedError::Internal("automotive corpus destination has no parent".to_owned())
    })?;
    let temporary = parent.join(format!(".promotion-{}.tmp", Uuid::new_v4()));
    let copy_result = (|| {
        let mut input = std::fs::File::open(source).map_err(|error| {
            ClassifiedError::Validation(format!(
                "open automotive promotion source {}: {error}",
                source.display()
            ))
        })?;
        if !input.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return Err(ClassifiedError::Validation(
                "automotive promotion source is not a regular file".to_owned(),
            ));
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                ClassifiedError::Internal(format!(
                    "create automotive promotion temporary file {}: {error}",
                    temporary.display()
                ))
            })?;
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = input.read(&mut buffer).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "read automotive promotion source {}: {error}",
                    source.display()
                ))
            })?;
            if count == 0 {
                break;
            }
            copied = copied.checked_add(count as u64).ok_or_else(|| {
                ClassifiedError::Validation("automotive promotion size overflowed".to_owned())
            })?;
            if copied > expected_size {
                return Err(ClassifiedError::Validation(
                    "automotive promotion source changed during copy".to_owned(),
                ));
            }
            hasher.update(&buffer[..count]);
            output.write_all(&buffer[..count]).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "write automotive promotion temporary file {}: {error}",
                    temporary.display()
                ))
            })?;
        }
        output.sync_all().map_err(|error| {
            ClassifiedError::Internal(format!(
                "sync automotive promotion temporary file {}: {error}",
                temporary.display()
            ))
        })?;
        let copied_digest = format!("{:x}", hasher.finalize());
        if copied != expected_size || copied_digest != expected_digest {
            return Err(ClassifiedError::Validation(
                "automotive promotion source changed during copy".to_owned(),
            ));
        }
        match std::fs::hard_link(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_file_digest(destination, expected_digest, expected_size)
            }
            Err(error) => Err(ClassifiedError::Internal(format!(
                "publish automotive state corpus artifact {}: {error}",
                destination.display()
            ))),
        }
    })();
    if let Err(error) = std::fs::remove_file(&temporary) {
        if error.kind() != std::io::ErrorKind::NotFound && copy_result.is_ok() {
            return Err(ClassifiedError::Internal(format!(
                "remove automotive promotion temporary file {}: {error}",
                temporary.display()
            )));
        }
    }
    copy_result
}

fn verify_file_digest(
    path: &Path,
    expected_digest: &str,
    expected_size: u64,
) -> Result<(), ClassifiedError> {
    let (digest, size) = digest_regular_file(path)?;
    if digest != expected_digest || size != expected_size {
        return Err(ClassifiedError::Validation(
            "existing automotive state corpus artifact does not match its digest".to_owned(),
        ));
    }
    Ok(())
}

fn verify_retained_corpus_artifact(
    workspace: &Path,
    record: &AutomotiveStateCorpusRecord,
) -> Result<(), ClassifiedError> {
    let relative = Path::new(&record.artifact_path);
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Storage(
            "retained automotive state corpus path is not workspace-relative".to_owned(),
        ));
    }
    let parent = relative.parent().ok_or_else(|| {
        ClassifiedError::Storage(
            "retained automotive state corpus path has no directory".to_owned(),
        )
    })?;
    let file_name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ClassifiedError::Storage(
                "retained automotive state corpus path has no safe filename".to_owned(),
            )
        })?;
    let directory = resolve_existing_workspace_directory(workspace, parent)?;
    let path = resolve_regular_artifact(&directory, file_name)?;
    let (digest, _) = digest_regular_file(&path)?;
    if digest != record.artifact_sha256 {
        return Err(ClassifiedError::Storage(
            "retained automotive state corpus artifact digest is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn state_corpus_entry(
    record: AutomotiveStateCorpusRecord,
) -> Result<AutomotiveStateCorpusEntry, ClassifiedError> {
    let protocol = serde_json::from_value(serde_json::Value::String(record.protocol.clone()))
        .map_err(|error| {
            ClassifiedError::Storage(format!(
                "retained automotive state corpus protocol is invalid: {error}"
            ))
        })?;
    for (field, digest) in [
        ("state", record.state_digest.as_str()),
        ("artifact", record.artifact_sha256.as_str()),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ClassifiedError::Storage(format!(
                "retained automotive {field} digest is invalid"
            )));
        }
    }
    let artifact_path = Path::new(&record.artifact_path);
    if artifact_path.is_absolute()
        || !artifact_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Storage(
            "retained automotive state corpus path is invalid".to_owned(),
        ));
    }
    Ok(AutomotiveStateCorpusEntry {
        project_root: record.project_root,
        protocol,
        state_digest: record.state_digest,
        artifact_sha256: record.artifact_sha256,
        source_operation_id: record.source_operation_id,
        artifact_path: record.artifact_path,
        created_at: record.created_at,
    })
}

fn preflight(
    request: AutomotiveOperationRequest,
    settings: &AutomotiveSettings,
) -> Result<PreparedOperation, ClassifiedError> {
    settings.validate().map_err(ClassifiedError::Validation)?;
    if !settings.enabled {
        return Err(ClassifiedError::Validation(
            "automotive Scapy support is disabled in Settings".to_owned(),
        ));
    }
    let project_root = std::fs::canonicalize(&request.project_root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve automotive project {}: {error}",
            request.project_root.display()
        ))
    })?;
    if !std::fs::metadata(&project_root).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(ClassifiedError::Validation(
            "automotive project root must be a directory".to_owned(),
        ));
    }
    if let Some(protocol) = request.command.protocol() {
        require_protocol(settings, protocol)?;
    }
    let mode = request.command.execution_mode();
    require_mode(settings, mode)?;
    let limits = operation_limits(settings)?;
    let operation_name = request.command.operation_name();
    let protocol = request.command.protocol();
    let mut input = None;
    let domain_request = match &request.command {
        AutomotiveCommand::Capabilities => AutomotiveRequest::Capabilities(CapabilityRequest {}),
        AutomotiveCommand::AnalyzeCapture {
            protocol,
            capture_path,
        } => {
            let prepared = read_input(
                capture_path,
                "capture.pcap",
                "application/vnd.tcpdump.pcap",
                settings.limits.max_input_bytes,
            )?;
            let artifact = prepared.artifact.clone();
            input = Some(prepared);
            AutomotiveRequest::AnalyzeCapture(AnalyzeCaptureRequest {
                protocol: *protocol,
                capture: artifact,
                limits,
            })
        }
        AutomotiveCommand::GenerateMutations {
            protocol,
            source_path,
            deterministic_seed,
            mutation_count,
            media_type,
        } => {
            let prepared = read_input(
                source_path,
                "mutation-seed",
                media_type,
                settings.limits.max_input_bytes,
            )?;
            let artifact = prepared.artifact.clone();
            input = Some(prepared);
            AutomotiveRequest::GenerateMutations(MutationRequest {
                protocol: *protocol,
                source: artifact,
                deterministic_seed: *deterministic_seed,
                mutation_count: *mutation_count,
                limits,
            })
        }
        AutomotiveCommand::BuildReplayPlan {
            protocol,
            source_path,
            target_mode,
            deterministic_seed,
        } => {
            require_mode(settings, *target_mode)?;
            let prepared = read_input(
                source_path,
                "transcript.json",
                "application/vnd.oxfuzz.automotive-transcript+json",
                settings.limits.max_input_bytes,
            )?;
            let artifact = prepared.artifact.clone();
            input = Some(prepared);
            AutomotiveRequest::BuildReplayPlan(ReplayPlanRequest {
                protocol: *protocol,
                source: artifact,
                target_mode: *target_mode,
                deterministic_seed: *deterministic_seed,
                limits,
            })
        }
        AutomotiveCommand::ExecuteReplay { mode, plan } => {
            validate_replay_policy(mode, plan, request.approval.as_ref(), settings, &limits)?;
            AutomotiveRequest::ExecuteReplay(ReplayRequest {
                mode: mode.clone(),
                plan: plan.clone(),
                limits,
            })
        }
        AutomotiveCommand::LiveMonitor { mode, protocol } => {
            validate_live_monitor_policy(mode, settings)?;
            AutomotiveRequest::LiveMonitor(LiveMonitorRequest {
                protocol: *protocol,
                mode: mode.clone(),
                limits,
            })
        }
        AutomotiveCommand::ScanUds {
            mode,
            request_ids,
            services,
            ..
        } => {
            validate_uds_scan_policy(mode, services, settings)?;
            AutomotiveRequest::ScanUds(UdsScanRequest {
                mode: mode.clone(),
                request_ids: request_ids.clone(),
                services: services.clone(),
                limits,
            })
        }
    };
    domain_request
        .validate()
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    Ok(PreparedOperation {
        project_root,
        command: request.command,
        domain_request,
        input,
        mode,
        protocol,
        operation_name,
        approval: request.approval,
        execution_config: None,
    })
}

fn operation_limits(settings: &AutomotiveSettings) -> Result<OperationLimits, ClassifiedError> {
    Ok(OperationLimits {
        max_events: settings.limits.max_packets,
        max_payload_bytes: u32::try_from(settings.limits.max_payload_bytes).map_err(|_| {
            ClassifiedError::Validation(
                "automotive max payload does not fit the sidecar contract".to_owned(),
            )
        })?,
        max_duration_ms: settings.limits.max_duration_secs.saturating_mul(1000),
        max_rate_per_second: settings.limits.max_rate_per_second,
    })
}

fn read_input(
    path: &Path,
    artifact_id: &str,
    media_type: &str,
    maximum: u64,
) -> Result<PreparedInput, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect automotive input {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        return Err(ClassifiedError::Validation(format!(
            "automotive input must be a regular file no larger than {maximum} bytes"
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        ClassifiedError::Validation(format!("read automotive input {}: {error}", path.display()))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(ClassifiedError::Validation(
            "automotive input changed while it was read".to_owned(),
        ));
    }
    Ok(PreparedInput {
        artifact: ArtifactRef {
            artifact_id: artifact_id.to_owned(),
            sha256: sha256_bytes(&bytes),
            media_type: media_type.to_owned(),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        },
        bytes,
    })
}

/// The actionable error returned when the automotive sidecar image is not
/// available locally: it names the missing image and how to build it.
fn missing_sidecar_image_error(image: &str) -> ClassifiedError {
    ClassifiedError::Sandbox(format!(
        "automotive sidecar image '{image}' is not available. Build it with \
         ./scripts/build-scapy-sidecar.sh and ensure Docker is running, then retry \
         (or set automotive.sidecar_image to an already-built image)."
    ))
}

fn stage_input(directory: &Path, input: &PreparedInput) -> Result<(), ClassifiedError> {
    let destination = directory.join(&input.artifact.artifact_id);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "create staged automotive input {}: {error}",
                destination.display()
            ))
        })?;
    file.write_all(&input.bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "write staged automotive input {}: {error}",
                destination.display()
            ))
        })?;
    Ok(())
}

fn retain_request_evidence(directory: &Path, encoded: &[u8]) -> Result<(), ClassifiedError> {
    let path = directory.join(REQUEST_EVIDENCE_FILE);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "create automotive request evidence {}: {error}",
                path.display()
            ))
        })?;
    file.write_all(encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "write automotive request evidence {}: {error}",
                path.display()
            ))
        })?;
    Ok(())
}

fn runtime_limits(settings: &AutomotiveSettings, prepared: &PreparedOperation) -> ResourceLimits {
    let mut env = HashMap::from([
        (
            "OXFUZZ_SCAPY_INPUT_ROOT".to_owned(),
            SIDECAR_INPUT_ROOT.to_owned(),
        ),
        (
            "OXFUZZ_SCAPY_OUTPUT_ROOT".to_owned(),
            SIDECAR_OUTPUT_ROOT.to_owned(),
        ),
    ]);
    if let Some(config) = &prepared.execution_config {
        env.insert(
            "OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON".to_owned(),
            config.clone(),
        );
    }
    ResourceLimits {
        max_mem_mb: settings.limits.max_mem_mb,
        max_cpus: settings.limits.max_cpus,
        max_duration_secs: settings.limits.max_duration_secs,
        env,
        ptrace: false,
    }
}

fn sandbox_options(
    settings: &AutomotiveSettings,
    prepared: &PreparedOperation,
    sidecar_image: &ImmutableImageReference,
    input_dir: &Path,
    output_dir: &Path,
    stdin: Vec<u8>,
) -> SandboxOptions {
    let (network_mode, capabilities) = match prepared.mode {
        AutomotiveMode::OfflinePcap => (SandboxNetworkMode::None, Vec::new()),
        AutomotiveMode::VirtualCan => (
            SandboxNetworkMode::None,
            vec![SandboxCapability::NetAdmin, SandboxCapability::NetRaw],
        ),
        AutomotiveMode::PhysicalBench => {
            (SandboxNetworkMode::Host, vec![SandboxCapability::NetRaw])
        }
    };
    SandboxOptions {
        extra_mounts: vec![
            SandboxMount::read_only(input_dir.to_path_buf(), SIDECAR_INPUT_ROOT),
            SandboxMount::writable(output_dir.to_path_buf(), SIDECAR_OUTPUT_ROOT),
        ],
        image: Some(sidecar_image.reference().to_owned()),
        network_mode,
        workdir: Some("/work".to_owned()),
        relax_hardening: false,
        capabilities,
        stdin: Some(stdin),
        workspace_read_only: true,
        max_file_size_bytes: Some(settings.limits.max_output_bytes),
        ..SandboxOptions::default()
    }
}

fn parse_response(stdout: &str, request_id: &str) -> Result<ResponseEnvelope, ClassifiedError> {
    let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().ok_or_else(|| {
        ClassifiedError::Sandbox("automotive sidecar returned no JSONL response".to_owned())
    })?;
    if lines.next().is_some() {
        return Err(ClassifiedError::Sandbox(
            "automotive sidecar returned more than one JSONL response".to_owned(),
        ));
    }
    let response: ResponseEnvelope = serde_json::from_str(line).map_err(|error| {
        ClassifiedError::Sandbox(format!("invalid automotive sidecar response: {error}"))
    })?;
    response
        .validate()
        .map_err(|error| ClassifiedError::Sandbox(error.to_string()))?;
    if response.request_id != request_id {
        return Err(ClassifiedError::Sandbox(
            "automotive sidecar response correlation id does not match".to_owned(),
        ));
    }
    Ok(response)
}

fn require_matching_result(
    request: &AutomotiveRequest,
    result: &AutomotiveResult,
) -> Result<(), ClassifiedError> {
    let matches = matches!(
        (request, result),
        (
            AutomotiveRequest::Capabilities(_),
            AutomotiveResult::Capabilities(_)
        ) | (
            // Both an offline analysis and a live monitor yield a capture analysis.
            AutomotiveRequest::AnalyzeCapture(_) | AutomotiveRequest::LiveMonitor(_),
            AutomotiveResult::CaptureAnalysis(_)
        ) | (
            AutomotiveRequest::GenerateMutations(_),
            AutomotiveResult::Mutations(_)
        ) | (
            AutomotiveRequest::BuildReplayPlan(_),
            AutomotiveResult::ReplayPlan(_)
        ) | (
            AutomotiveRequest::ExecuteReplay(_),
            AutomotiveResult::Replay(_)
        ) | (AutomotiveRequest::ScanUds(_), AutomotiveResult::UdsScan(_))
    );
    if matches {
        Ok(())
    } else {
        Err(ClassifiedError::Sandbox(
            "automotive sidecar result does not match the requested operation".to_owned(),
        ))
    }
}

fn verify_result_artifacts(
    output_dir: &Path,
    result: &AutomotiveResult,
    maximum: u64,
) -> Result<(), ClassifiedError> {
    let artifacts = match result {
        AutomotiveResult::CaptureAnalysis(analysis) => std::slice::from_ref(&analysis.transcript),
        AutomotiveResult::UdsScan(scan) => std::slice::from_ref(&scan.transcript),
        AutomotiveResult::Mutations(mutations) => mutations.artifacts.as_slice(),
        AutomotiveResult::Capabilities(_)
        | AutomotiveResult::ReplayPlan(_)
        | AutomotiveResult::Replay(_) => &[],
    };
    let mut expected = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut aggregate_bytes = 0_u64;
    let entries = std::fs::read_dir(output_dir).map_err(|error| {
        ClassifiedError::Sandbox(format!("inspect automotive output directory: {error}"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ClassifiedError::Sandbox(format!("inspect automotive output entry: {error}"))
        })?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| {
            ClassifiedError::Sandbox(format!("inspect automotive output entry: {error}"))
        })?;
        if !metadata.file_type().is_file() {
            return Err(ClassifiedError::Sandbox(
                "automotive output directory contains a non-regular entry".to_owned(),
            ));
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or_else(|| {
            ClassifiedError::Sandbox(
                "automotive output directory contains a non-UTF-8 artifact".to_owned(),
            )
        })?;
        if !expected.remove(file_name) {
            return Err(ClassifiedError::Sandbox(
                "automotive output directory contains an unreferenced artifact".to_owned(),
            ));
        }
        aggregate_bytes = aggregate_bytes.checked_add(metadata.len()).ok_or_else(|| {
            ClassifiedError::Sandbox("automotive output aggregate size overflowed".to_owned())
        })?;
        if aggregate_bytes > maximum {
            return Err(ClassifiedError::Sandbox(format!(
                "automotive output aggregate exceeds {maximum} bytes"
            )));
        }
    }
    if !expected.is_empty() {
        return Err(ClassifiedError::Sandbox(
            "automotive result references a missing output artifact".to_owned(),
        ));
    }
    for artifact in artifacts {
        let path = output_dir.join(&artifact.artifact_id);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            ClassifiedError::Sandbox(format!(
                "inspect automotive output artifact {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(ClassifiedError::Sandbox(
                "automotive output artifact is not a regular file".to_owned(),
            ));
        }
        if metadata.len() != artifact.size_bytes {
            return Err(ClassifiedError::Sandbox(
                "automotive output artifact does not match its declared size".to_owned(),
            ));
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            ClassifiedError::Sandbox(format!("read automotive output artifact: {error}"))
        })?;
        if sha256_bytes(&bytes) != artifact.sha256 {
            return Err(ClassifiedError::Sandbox(
                "automotive output artifact digest does not match".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn persist_failure(store: &hf_storage::Store, operation_id: Uuid, error: &ClassifiedError) {
    if let Err(storage_error) = store
        .complete_automotive_operation(
            operation_id,
            AutomotiveOperationStatus::Failed,
            Utc::now(),
            None,
            None,
            Some(&error.to_string()),
        )
        .await
    {
        tracing::error!(%operation_id, %storage_error, "failed to persist automotive failure");
    }
}

async fn retain_failure<T>(
    store: &hf_storage::Store,
    operation_id: Uuid,
    result: Result<T, ClassifiedError>,
) -> Result<T, ClassifiedError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            persist_failure(store, operation_id, &error).await;
            Err(error)
        }
    }
}

fn action_for(
    prepared: &PreparedOperation,
    settings: &AutomotiveSettings,
    sidecar_image_sha256: &str,
) -> Action {
    match prepared.mode {
        AutomotiveMode::OfflinePcap => Action::AutomotiveOffline {
            operation: prepared.operation_name.to_owned(),
        },
        AutomotiveMode::VirtualCan => Action::AutomotiveVirtualCan {
            protocol: prepared.protocol.map_or("unknown", protocol_id).to_owned(),
            duration_secs: settings.limits.max_duration_secs,
        },
        AutomotiveMode::PhysicalBench => {
            let interface = match &prepared.domain_request {
                AutomotiveRequest::ExecuteReplay(ReplayRequest {
                    mode: ModeConfig::PhysicalBench { interface, .. },
                    ..
                }) => interface.clone(),
                _ => "unknown".to_owned(),
            };
            Action::AutomotivePhysicalBench {
                interface,
                protocol: prepared.protocol.map_or("unknown", protocol_id).to_owned(),
                duration_secs: settings.limits.max_duration_secs,
                sidecar_image_sha256: sidecar_image_sha256.to_owned(),
            }
        }
    }
}

fn require_protocol(
    settings: &AutomotiveSettings,
    protocol: AutomotiveProtocol,
) -> Result<(), ClassifiedError> {
    if settings
        .allowed_protocols
        .iter()
        .any(|allowed| allowed == protocol_id(protocol))
    {
        Ok(())
    } else {
        Err(ClassifiedError::Validation(format!(
            "automotive protocol '{}' is disabled in Settings",
            protocol_id(protocol)
        )))
    }
}

fn require_mode(
    settings: &AutomotiveSettings,
    mode: AutomotiveMode,
) -> Result<(), ClassifiedError> {
    if settings
        .allowed_modes
        .iter()
        .any(|allowed| allowed == mode_id(mode))
    {
        Ok(())
    } else {
        Err(ClassifiedError::Validation(format!(
            "automotive mode '{}' is disabled in Settings",
            mode_id(mode)
        )))
    }
}

fn validate_replay_policy(
    mode: &ModeConfig,
    plan: &ReplayPlan,
    approval: Option<&AutomotiveApprovalEvidence>,
    settings: &AutomotiveSettings,
    limits: &OperationLimits,
) -> Result<(), ClassifiedError> {
    plan.validate()
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    match mode {
        ModeConfig::OfflinePcap => Err(ClassifiedError::Validation(
            "offline capture mode cannot execute a replay".to_owned(),
        )),
        ModeConfig::VirtualCan { interface } => {
            if !settings
                .virtual_interfaces
                .iter()
                .any(|allowed| allowed == interface)
            {
                return Err(ClassifiedError::Validation(format!(
                    "virtual CAN interface '{interface}' is not allowlisted"
                )));
            }
            Ok(())
        }
        ModeConfig::PhysicalBench {
            interface,
            approval_id,
        } => validate_physical_policy(
            interface,
            approval_id,
            plan,
            approval,
            &settings.physical_bench,
            limits,
            None,
        ),
    }
}

/// Validate a live-monitor request. This is a read-only capture, so it needs no
/// arbitration-id/service allowlists (nothing is transmitted). Physical-bench
/// live capture is deferred until it has a purpose-built approval scope (the
/// replay approval scope hashes a plan, which a live capture does not have), so
/// only virtual CAN is admitted here.
fn validate_live_monitor_policy(
    mode: &ModeConfig,
    settings: &AutomotiveSettings,
) -> Result<(), ClassifiedError> {
    match mode {
        ModeConfig::OfflinePcap => Err(ClassifiedError::Validation(
            "offline capture mode cannot run a live monitor".to_owned(),
        )),
        ModeConfig::VirtualCan { interface } => {
            if settings
                .virtual_interfaces
                .iter()
                .any(|allowed| allowed == interface)
            {
                Ok(())
            } else {
                Err(ClassifiedError::Validation(format!(
                    "virtual CAN interface '{interface}' is not allowlisted"
                )))
            }
        }
        ModeConfig::PhysicalBench { .. } => Err(ClassifiedError::Validation(
            "physical-bench live monitor is not yet supported; use a virtual CAN interface"
                .to_owned(),
        )),
    }
}

/// Diagnostic service ids a discovery scan may probe. These are read-only and
/// non-actuating: `TesterPresent` (0x3E), `DiagnosticSessionControl` (0x10 --
/// the sidecar only ever probes the default session), `ReadDataByIdentifier`
/// (0x22), `ReadDTCInformation` (0x19), and `ReadEcuIdentification` (0x1A).
/// Every state-changing, actuating, security, memory, or programming service is
/// denied so a scan can never reset, unlock, write, flash, or actuate an ECU.
const READ_ONLY_UDS_SERVICES: &[u8] = &[0x3E, 0x10, 0x22, 0x19, 0x1A];

/// Validate a UDS discovery scan. Read-only by construction: only virtual CAN is
/// admitted (physical bench is deferred, as for the live monitor) and every
/// probed service id must be on the read-only discovery allowlist.
fn validate_uds_scan_policy(
    mode: &ModeConfig,
    services: &[u8],
    settings: &AutomotiveSettings,
) -> Result<(), ClassifiedError> {
    match mode {
        ModeConfig::OfflinePcap => {
            return Err(ClassifiedError::Validation(
                "offline capture mode cannot run a UDS scan".to_owned(),
            ));
        }
        ModeConfig::VirtualCan { interface } => {
            if !settings
                .virtual_interfaces
                .iter()
                .any(|allowed| allowed == interface)
            {
                return Err(ClassifiedError::Validation(format!(
                    "virtual CAN interface '{interface}' is not allowlisted"
                )));
            }
        }
        ModeConfig::PhysicalBench { .. } => {
            return Err(ClassifiedError::Validation(
                "physical-bench UDS scan is not yet supported; use a virtual CAN interface"
                    .to_owned(),
            ));
        }
    }
    if let Some(denied) = services
        .iter()
        .find(|sid| !READ_ONLY_UDS_SERVICES.contains(sid))
    {
        return Err(ClassifiedError::Validation(format!(
            "UDS scan service 0x{denied:02X} is not a read-only discovery service and is denied"
        )));
    }
    Ok(())
}

fn validate_physical_policy(
    interface: &str,
    approval_id: &str,
    plan: &ReplayPlan,
    approval: Option<&AutomotiveApprovalEvidence>,
    policy: &AutomotivePhysicalBenchSettings,
    limits: &OperationLimits,
    sidecar_image_sha256: Option<&str>,
) -> Result<(), ClassifiedError> {
    validate_physical_policy_at(
        interface,
        approval_id,
        plan,
        approval,
        policy,
        limits,
        PhysicalApprovalContext {
            sidecar_image_sha256,
            now: Utc::now(),
        },
    )
}

#[derive(Clone, Copy)]
struct PhysicalApprovalContext<'a> {
    sidecar_image_sha256: Option<&'a str>,
    now: DateTime<Utc>,
}

fn validate_physical_policy_at(
    interface: &str,
    approval_id: &str,
    plan: &ReplayPlan,
    approval: Option<&AutomotiveApprovalEvidence>,
    policy: &AutomotivePhysicalBenchSettings,
    limits: &OperationLimits,
    context: PhysicalApprovalContext<'_>,
) -> Result<(), ClassifiedError> {
    if !policy.enabled || !policy.interfaces.iter().any(|allowed| allowed == interface) {
        return Err(ClassifiedError::Validation(
            "physical automotive bench interface is disabled or not allowlisted".to_owned(),
        ));
    }
    let (arbitration_ids, services) = replay_allowlists(plan)?;
    if !arbitration_ids
        .iter()
        .all(|id| policy.arbitration_ids.contains(id))
    {
        return Err(ClassifiedError::Validation(
            "replay contains a non-allowlisted arbitration id".to_owned(),
        ));
    }
    if !services
        .iter()
        .all(|service| policy.uds_services.contains(service))
    {
        return Err(ClassifiedError::Validation(
            "replay contains a non-allowlisted UDS service".to_owned(),
        ));
    }
    if !policy.allow_dangerous_services
        && services
            .iter()
            .any(|service| DANGEROUS_UDS_SERVICES.contains(service))
    {
        return Err(ClassifiedError::Validation(
            "replay contains a dangerous UDS service denied by policy".to_owned(),
        ));
    }
    let approval = approval.ok_or_else(|| {
        ClassifiedError::Validation("physical automotive bench approval is required".to_owned())
    })?;
    if approval.approval_id != approval_id
        || approval.approval_id.trim().is_empty()
        || approval.approved_by.trim().is_empty()
    {
        return Err(ClassifiedError::Validation(
            "physical automotive bench approval evidence is invalid".to_owned(),
        ));
    }
    validate_approval_freshness_at(approval, context.now)?;
    if let Some(sidecar_image_sha256) = context.sidecar_image_sha256 {
        if approval.sidecar_image_sha256 != sidecar_image_sha256 {
            return Err(ClassifiedError::Validation(
                "physical automotive bench approval image identity does not match".to_owned(),
            ));
        }
        let expected = approval_scope_hash(interface, plan, policy, limits, sidecar_image_sha256)?;
        if approval.scope_sha256 != expected {
            return Err(ClassifiedError::Validation(
                "physical automotive bench approval scope does not match".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_approval_freshness_at(
    approval: &AutomotiveApprovalEvidence,
    now: DateTime<Utc>,
) -> Result<(), ClassifiedError> {
    if approval.approved_at > now + Duration::minutes(1)
        || now.signed_duration_since(approval.approved_at) > APPROVAL_MAX_AGE
    {
        return Err(ClassifiedError::Validation(
            "physical automotive bench approval has expired".to_owned(),
        ));
    }
    Ok(())
}

fn validate_resolved_image_approval(
    prepared: &PreparedOperation,
    settings: &AutomotiveSettings,
    sidecar_image_sha256: &str,
) -> Result<(), ClassifiedError> {
    validate_resolved_image_approval_at(prepared, settings, sidecar_image_sha256, Utc::now())
}

fn validate_resolved_image_approval_at(
    prepared: &PreparedOperation,
    settings: &AutomotiveSettings,
    sidecar_image_sha256: &str,
    now: DateTime<Utc>,
) -> Result<(), ClassifiedError> {
    if let AutomotiveCommand::ExecuteReplay {
        mode: ModeConfig::PhysicalBench {
            interface,
            approval_id,
        },
        plan,
    } = &prepared.command
    {
        validate_physical_policy_at(
            interface,
            approval_id,
            plan,
            prepared.approval.as_ref(),
            &settings.physical_bench,
            &operation_limits(settings)?,
            PhysicalApprovalContext {
                sidecar_image_sha256: Some(sidecar_image_sha256),
                now,
            },
        )?;
    }
    Ok(())
}

/// The byte at `index` of a lowercase-hex payload, if present.
fn payload_byte(payload_hex: &str, index: usize) -> Option<u8> {
    let start = index * 2;
    payload_hex
        .get(start..start + 2)
        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
}

/// The UDS service a physical send actually puts on the wire, derived from the
/// payload bytes -- never the spoofable `service` metadata field -- and aware of
/// ISO-TP single-frame framing, where byte 0 is the PCI (`0x0L`, length 1..=7)
/// and the service is byte 1. For any other first byte the service is byte 0.
///
/// This is deliberately protocol-label-independent: a dangerous UDS request must
/// not evade the denylist by being labelled `can`/`iso_tp`/etc., and the service
/// byte must not be confused with the ISO-TP PCI. Returns `None` only for an
/// undecodable/too-short payload.
fn wire_uds_service(payload_hex: &str) -> Option<u8> {
    let first = payload_byte(payload_hex, 0)?;
    if first & 0xf0 == 0x00 && (1..=7).contains(&(first & 0x0f)) {
        // ISO-TP single frame: the service follows the PCI byte.
        payload_byte(payload_hex, 1)
    } else {
        Some(first)
    }
}

fn replay_allowlists(plan: &ReplayPlan) -> Result<(BTreeSet<u32>, BTreeSet<u8>), ClassifiedError> {
    let mut arbitration_ids = BTreeSet::new();
    let mut services = BTreeSet::new();
    for step in &plan.steps {
        if step.action != hf_automotive::ReplayAction::Send {
            continue;
        }
        let arbitration = step
            .message
            .fields
            .get("arbitration_id")
            .and_then(|value| parse_integer(value))
            .ok_or_else(|| {
                ClassifiedError::Validation(
                    "every transmitted automotive message needs an arbitration_id field".to_owned(),
                )
            })?;
        if arbitration > 0x1fff_ffff {
            return Err(ClassifiedError::Validation(
                "automotive arbitration id is out of range".to_owned(),
            ));
        }
        arbitration_ids.insert(arbitration);
        // Derive the service for EVERY transmitted frame regardless of protocol
        // label, from the wire bytes (framing-aware), so the service allowlist and
        // dangerous-service denylist cannot be evaded by relabelling the protocol
        // or by hiding the service behind the ISO-TP PCI byte.
        let service = wire_uds_service(&step.message.payload_hex).ok_or_else(|| {
            ClassifiedError::Validation(
                "every transmitted automotive frame needs a decodable service byte".to_owned(),
            )
        })?;
        services.insert(service);
    }
    Ok((arbitration_ids, services))
}

fn build_execution_config(
    command: &AutomotiveCommand,
    approval: Option<&AutomotiveApprovalEvidence>,
    settings: &AutomotiveSettings,
    limits: &OperationLimits,
    sidecar_image_sha256: &str,
) -> Result<Option<String>, ClassifiedError> {
    let (mode, protocol, plan): (&ModeConfig, AutomotiveProtocol, Option<&ReplayPlan>) =
        match command {
            AutomotiveCommand::ExecuteReplay { mode, plan } => (mode, plan.protocol, Some(plan)),
            AutomotiveCommand::LiveMonitor { mode, protocol }
            | AutomotiveCommand::ScanUds { mode, protocol, .. } => (mode, *protocol, None),
            _ => return Ok(None),
        };
    // Plan-derived send allowlists (validated as a side effect). A live monitor
    // has no plan and transmits nothing, so its send allowlists are empty.
    let (plan_arbitration_ids, plan_services) = match plan {
        Some(plan) => replay_allowlists(plan)?,
        None => (BTreeSet::new(), BTreeSet::new()),
    };
    let (physical_enabled, interface, interface_allowlist) = match mode {
        ModeConfig::OfflinePcap => (false, None, Vec::new()),
        ModeConfig::VirtualCan { interface } => (
            false,
            Some(interface.clone()),
            settings.virtual_interfaces.clone(),
        ),
        ModeConfig::PhysicalBench { interface, .. } => (
            settings.physical_bench.enabled,
            Some(interface.clone()),
            settings.physical_bench.interfaces.clone(),
        ),
    };
    // For physical bench, the config allowlists are the FULL approved policy, not the
    // plan's own ids/services. The sidecar both validates each frame against these and
    // recomputes the approval scope hash from them (`physical_replay_scope_sha256`), so
    // they must match `approval_scope_hash` (which hashes the policy) -- otherwise the
    // single-use approval is consumed and the sidecar then rejects on a scope mismatch,
    // and the sidecar is not an independent policy check. Other modes carry the
    // plan-derived sets (there is no physical policy allowlist for them).
    let (arbitration_id_allowlist, service_allowlist): (Vec<u32>, Vec<u8>) =
        if let AutomotiveCommand::ScanUds {
            request_ids,
            services,
            ..
        } = command
        {
            // A scan carries its already read-only-validated probe sets so the
            // sidecar enforces the same request-id and service allowlists.
            let mut ids = request_ids.clone();
            ids.sort_unstable();
            ids.dedup();
            let mut svc = services.clone();
            svc.sort_unstable();
            svc.dedup();
            (ids, svc)
        } else {
            match mode {
                ModeConfig::PhysicalBench { .. } => {
                    let mut arbitration = settings.physical_bench.arbitration_ids.clone();
                    arbitration.sort_unstable();
                    arbitration.dedup();
                    let mut uds = settings.physical_bench.uds_services.clone();
                    uds.sort_unstable();
                    uds.dedup();
                    (arbitration, uds)
                }
                _ => (
                    plan_arbitration_ids.iter().copied().collect(),
                    plan_services.iter().copied().collect(),
                ),
            }
        };
    let mut value = serde_json::json!({
        "mode": mode_id(mode.mode()),
        "protocol": protocol_id(protocol),
        "physical_enabled": physical_enabled,
        "interface_allowlist": interface_allowlist,
        "arbitration_id_allowlist": arbitration_id_allowlist,
        "service_allowlist": service_allowlist,
        "allow_dangerous_services": settings.physical_bench.allow_dangerous_services,
        "limits": limits,
        "sidecar_image_sha256": sidecar_image_sha256,
    });
    if let Some(interface) = interface {
        value["interface"] = serde_json::Value::String(interface);
    }
    if let Some(approval) = approval {
        value["approval"] = serde_json::to_value(approval).map_err(|error| {
            ClassifiedError::Internal(format!("serialize automotive approval: {error}"))
        })?;
    }
    serde_json::to_string(&value).map(Some).map_err(|error| {
        ClassifiedError::Internal(format!("serialize automotive execution policy: {error}"))
    })
}

fn approval_scope_hash(
    interface: &str,
    plan: &ReplayPlan,
    policy: &AutomotivePhysicalBenchSettings,
    limits: &OperationLimits,
    sidecar_image_sha256: &str,
) -> Result<String, ClassifiedError> {
    let mut arbitration_ids = policy.arbitration_ids.clone();
    arbitration_ids.sort_unstable();
    arbitration_ids.dedup();
    let mut uds_services = policy.uds_services.clone();
    uds_services.sort_unstable();
    uds_services.dedup();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "interface": interface,
        "plan": plan,
        "limits": limits,
        "arbitration_ids": arbitration_ids,
        "uds_services": uds_services,
        "allow_dangerous_services": policy.allow_dangerous_services,
        "sidecar_image_sha256": sidecar_image_sha256,
    }))
    .map_err(|error| {
        ClassifiedError::Internal(format!("serialize automotive approval scope: {error}"))
    })?;
    Ok(sha256_bytes(&bytes))
}

fn parse_integer(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

fn protocol_id(protocol: AutomotiveProtocol) -> &'static str {
    match protocol {
        AutomotiveProtocol::Can => "can",
        AutomotiveProtocol::CanFd => "can_fd",
        AutomotiveProtocol::IsoTp => "iso_tp",
        AutomotiveProtocol::Uds => "uds",
        AutomotiveProtocol::Gmlan => "gmlan",
        AutomotiveProtocol::SomeIp => "some_ip",
        AutomotiveProtocol::SomeIpSd => "some_ip_sd",
        AutomotiveProtocol::DoIp => "do_ip",
        AutomotiveProtocol::Obd => "obd",
        AutomotiveProtocol::Ccp => "ccp",
        AutomotiveProtocol::Xcp => "xcp",
        AutomotiveProtocol::BmwHsfz => "bmw_hsfz",
        AutomotiveProtocol::SecOc => "sec_oc",
    }
}

fn mode_id(mode: AutomotiveMode) -> &'static str {
    match mode {
        AutomotiveMode::OfflinePcap => "offline_pcap",
        AutomotiveMode::VirtualCan => "virtual_can",
        AutomotiveMode::PhysicalBench => "physical_bench",
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn serde_json_string(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::Utc;
    use hf_automotive::{
        ArtifactRef, AutomotiveError, AutomotiveErrorCode, AutomotiveMode, AutomotiveProtocol,
        AutomotiveResult, CaptureAnalysisResult, ModeConfig, MutationResult, OperationLimits,
        ProtocolMessage, ReplayAction, ReplayPlan, ReplayResult, ReplayStep, ResponseEnvelope,
        Sha256Digest, StateSignature, UdsEcu, UdsScanResult, UdsService,
    };
    use hf_core::error::ClassifiedError;
    use hf_core::provider::{
        ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
        ProviderStatus, RouteRequest,
    };
    use hf_core::runtime::{
        CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
        SandboxCapability, SandboxNetworkMode, SandboxOptions,
    };
    use hf_core::types::{ProviderId, TokenUsage};
    use hf_storage::Store;
    use uuid::Uuid;

    use super::{
        approval_scope_hash, build_execution_config, operation_limits, sha256_bytes,
        validate_approval_freshness_at, validate_physical_policy, verify_result_artifacts,
        wire_uds_service, AutomotiveApprovalEvidence, AutomotiveCommand,
        AutomotiveOperationRequest, AutomotiveStateArtifactSource, AutomotiveStatePromotionRequest,
        APPROVAL_MAX_AGE, REQUEST_EVIDENCE_FILE,
    };
    use crate::automotive_report::AutomotiveReportAiStatus;
    use crate::config::AutomotiveSettings;
    use crate::ServiceContainer;

    const IMMUTABLE_SIDECAR_SHA256: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMMUTABLE_SIDECAR_IMAGE: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn physical_approval_freshness_is_checked_again_at_claim_time() {
        let first_check = Utc::now();
        let approval = AutomotiveApprovalEvidence {
            approval_id: "approval-near-expiry".to_owned(),
            approved_by: "operator".to_owned(),
            approved_at: first_check - APPROVAL_MAX_AGE + chrono::Duration::seconds(1),
            scope_sha256: "a".repeat(64),
            sidecar_image_sha256: IMMUTABLE_SIDECAR_SHA256.to_owned(),
        };

        validate_approval_freshness_at(&approval, first_check)
            .expect("approval is initially fresh");
        let error =
            validate_approval_freshness_at(&approval, first_check + chrono::Duration::seconds(2))
                .expect_err("approval must expire while waiting for final authorization");
        assert!(error.to_string().contains("expired"), "{error}");
    }

    #[derive(Default)]
    struct RecordingRuntime {
        calls: Mutex<Vec<(Vec<String>, ResourceLimits, SandboxOptions)>>,
        response: Mutex<Option<ResponseEnvelope>>,
        output_artifacts: Vec<(String, Vec<u8>)>,
        exit_code: i32,
        /// When set, `image_present` reports the sidecar image as absent, so the
        /// automotive guard fails fast before any sandbox run.
        image_missing: bool,
    }

    impl RecordingRuntime {
        fn with_response(response: &ResponseEnvelope) -> Self {
            Self {
                response: Mutex::new(Some(response.clone())),
                ..Self::default()
            }
        }

        /// A runtime that reports the sidecar image as not built.
        fn with_missing_image() -> Self {
            Self {
                image_missing: true,
                ..Self::default()
            }
        }

        fn with_response_and_output(
            response: &ResponseEnvelope,
            artifact: &ArtifactRef,
            bytes: &[u8],
        ) -> Self {
            Self {
                response: Mutex::new(Some(response.clone())),
                output_artifacts: vec![(artifact.artifact_id.clone(), bytes.to_vec())],
                ..Self::default()
            }
        }

        fn with_response_and_exit(response: &ResponseEnvelope, exit_code: i32) -> Self {
            Self {
                response: Mutex::new(Some(response.clone())),
                exit_code,
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<(Vec<String>, ResourceLimits, SandboxOptions)> {
            self.calls.lock().unwrap().clone()
        }
    }

    /// A pool that answers with fixed content and records the request it was
    /// handed, so a test can assert what the model was actually asked for.
    ///
    /// Recording is not optional decoration. Without it nothing observes
    /// `automotive_report_system_prompt` or `automotive_report_user_prompt`, and
    /// both can be hardcoded to English with the whole suite green -- which asks
    /// the model in English while validating against Chinese headings, discards
    /// every interpretation and reports a silent `Fallback`.
    struct ReportPool {
        content: String,
        captured: Mutex<Vec<hf_core::types::Message>>,
    }

    impl ReportPool {
        fn new(content: impl Into<String>) -> Self {
            Self {
                content: content.into(),
                captured: Mutex::new(Vec::new()),
            }
        }

        /// The recorded content for one role, or `None` when the pool was never
        /// called -- so a silent fallback cannot masquerade as a pass.
        fn message(&self, role: hf_core::types::Role) -> Option<String> {
            self.captured
                .lock()
                .unwrap()
                .iter()
                .find(|message| message.role == role)
                .map(|message| message.content.clone())
        }
    }

    #[async_trait]
    impl ProviderPool for ReportPool {
        async fn chat_completion(
            &self,
            request: &ChatRequest,
            _route: &RouteRequest,
        ) -> Result<ChatResponse, ProviderError> {
            self.captured.lock().unwrap().clone_from(&request.messages);
            Ok(ChatResponse {
                id: "automotive-report-test".to_owned(),
                model: "grounded-test-model".to_owned(),
                content: Some(self.content.clone()),
                reasoning_content: None,
                tool_calls: Vec::new(),
                usage: TokenUsage::default(),
                finish_reason: FinishReason::Stop,
                raw_request: None,
                raw_response: None,
                provider_id: None,
                generated_images: Vec::new(),
            })
        }

        async fn chat_completion_stream(
            &self,
            _request: &ChatRequest,
            _route: &RouteRequest,
        ) -> Result<ChatStreamResponse, ProviderError> {
            Err(ProviderError::Other {
                message: "streaming is not used for automotive reports".to_owned(),
            })
        }

        fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

        async fn provider_statuses(&self) -> Vec<ProviderStatus> {
            Vec::new()
        }

        async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

        async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[async_trait]
    impl RuntimeAdapter for RecordingRuntime {
        async fn image_present(&self, _image: &str) -> bool {
            !self.image_missing
        }

        async fn resolve_image_reference(
            &self,
            _image: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            if self.image_missing {
                return Ok(None);
            }
            ImmutableImageReference::from_sha256_id(IMMUTABLE_SIDECAR_IMAGE).map(Some)
        }

        async fn run_command(
            &self,
            _cmd: &[String],
            _cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            panic!("automotive operations must use an explicit sandbox profile")
        }

        async fn run_command_opts(
            &self,
            cmd: &[String],
            cwd: &Path,
            limits: &ResourceLimits,
            options: &SandboxOptions,
        ) -> Result<CommandResult, ClassifiedError> {
            self.calls
                .lock()
                .unwrap()
                .push((cmd.to_vec(), limits.clone(), options.clone()));
            for (artifact_id, bytes) in &self.output_artifacts {
                std::fs::write(cwd.join("output").join(artifact_id), bytes).unwrap();
            }
            let request_id = options
                .stdin
                .as_deref()
                .and_then(|input| serde_json::from_slice::<serde_json::Value>(input).ok())
                .and_then(|value| value["request_id"].as_str().map(str::to_owned));
            let stdout = self
                .response
                .lock()
                .unwrap()
                .clone()
                .map(|mut response| {
                    if let Some(request_id) = request_id {
                        response.request_id = request_id;
                    }
                    format!("{}\n", serde_json::to_string(&response).unwrap())
                })
                .unwrap_or_default();
            Ok(CommandResult {
                exit_code: self.exit_code,
                stdout,
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            })
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            panic!("service stages automotive evidence before sandbox launch")
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            panic!("service validates automotive evidence after sandbox completion")
        }
    }

    async fn service(
        runtime: Arc<RecordingRuntime>,
        root: &Path,
    ) -> (ServiceContainer, Arc<Store>) {
        let store = Arc::new(Store::connect(root.join("automotive.db")).await.unwrap());
        (
            ServiceContainer::new(runtime, None).with_store(Arc::clone(&store)),
            store,
        )
    }

    fn project_fixture(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let project = root.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let capture = project.join("diagnostic.pcap");
        std::fs::write(&capture, b"bounded synthetic pcap fixture").unwrap();
        (project, capture)
    }

    fn transcript_fixture() -> (Sha256Digest, ArtifactRef, Vec<u8>) {
        let bytes = b"canonical automotive transcript".to_vec();
        let digest = Sha256Digest::parse(sha256_bytes(&bytes)).unwrap();
        let artifact = ArtifactRef {
            artifact_id: "canonical-transcript.json".to_owned(),
            sha256: digest.as_str().to_owned(),
            media_type: "application/vnd.oxfuzz.automotive-transcript+json".to_owned(),
            size_bytes: u64::try_from(bytes.len()).unwrap(),
        };
        (digest, artifact, bytes)
    }

    async fn completed_analysis_with_state(
        root: &Path,
    ) -> (
        ServiceContainer,
        Arc<Store>,
        std::path::PathBuf,
        std::path::PathBuf,
        Uuid,
        StateSignature,
    ) {
        let (project, capture) = project_fixture(root);
        let workspace = root.join("workspace");
        let (transcript, transcript_artifact, transcript_bytes) = transcript_fixture();
        let state = StateSignature::from_observations(
            AutomotiveProtocol::Uds,
            BTreeMap::from([("session".to_owned(), "extended".to_owned())]),
        )
        .unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::CaptureAnalysis(CaptureAnalysisResult {
                protocol: AutomotiveProtocol::Uds,
                event_count: 1,
                transcript: transcript_artifact.clone(),
                transcript_hash: transcript.clone(),
                state_signatures: vec![state.clone()],
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response_and_output(
            &response,
            &transcript_artifact,
            &transcript_bytes,
        ));
        let (service, store) = service(runtime, root).await;
        let outcome = service
            .execute_automotive_with_context(
                AutomotiveOperationRequest {
                    project_root: project.clone(),
                    command: AutomotiveCommand::AnalyzeCapture {
                        protocol: AutomotiveProtocol::Uds,
                        capture_path: capture,
                    },
                    approval: None,
                },
                AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                &workspace,
            )
            .await
            .unwrap();
        (
            service,
            store,
            project,
            workspace,
            outcome.operation_id,
            state,
        )
    }

    fn uds_replay_plan(mode: AutomotiveMode) -> ReplayPlan {
        ReplayPlan {
            protocol: AutomotiveProtocol::Uds,
            mode,
            deterministic_seed: 7,
            steps: vec![ReplayStep {
                sequence: 0,
                delay_micros: 0,
                action: ReplayAction::Send,
                message: ProtocolMessage {
                    protocol: AutomotiveProtocol::Uds,
                    payload_hex: "221234".to_owned(),
                    fields: BTreeMap::from([
                        ("arbitration_id".to_owned(), "0x7e0".to_owned()),
                        ("service".to_owned(), "0x22".to_owned()),
                    ]),
                },
            }],
        }
    }

    fn enable_physical_bench(settings: &mut AutomotiveSettings) {
        settings.allowed_modes.push("physical_bench".to_owned());
        settings.limits.max_packets = 1_000;
        settings.physical_bench.enabled = true;
        settings.physical_bench.interfaces = vec!["can0".to_owned()];
        settings.physical_bench.arbitration_ids = vec![0x7e0];
        settings.physical_bench.uds_services = vec![0x22];
    }

    #[tokio::test]
    async fn campaign_report_is_composed_from_retained_service_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (service, store, project, _, operation_id, _) =
            completed_analysis_with_state(temp.path()).await;
        let failed_id = Uuid::new_v4();
        let started_at = Utc::now();
        store
            .insert_automotive_operation(&hf_storage::AutomotiveOperationRecord {
                id: failed_id,
                project_root: std::fs::canonicalize(&project)
                    .unwrap()
                    .display()
                    .to_string(),
                operation: "execute_replay".to_owned(),
                mode: "virtual_can".to_owned(),
                protocol: Some("uds".to_owned()),
                status: hf_storage::AutomotiveOperationStatus::Running,
                started_at,
                ended_at: None,
                request_hash: "12".repeat(32),
                transcript_hash: None,
                artifact_dir: format!("project/.service/automotive/{failed_id}"),
                approval_json: None,
                result_json: None,
                error: None,
            })
            .await
            .unwrap();
        store
            .complete_automotive_operation(
                failed_id,
                hf_storage::AutomotiveOperationStatus::Failed,
                started_at,
                None,
                None,
                Some("virtual replay transcript failed validation"),
            )
            .await
            .unwrap();

        let report = service
            .generate_automotive_report_with_settings(
                &project,
                false,
                &AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                crate::report::ReportLanguage::En,
            )
            .await
            .unwrap();

        assert_eq!(report.ai_status, AutomotiveReportAiStatus::NotRequested);
        assert_eq!(report.operation_count, 2);
        assert_eq!(report.failed_operation_count, 1);
        assert_eq!(report.unique_state_count, 1);
        assert!(report.markdown.contains(&format!("[OP:{operation_id}]")));
        assert!(report.markdown.contains(&format!("[OP:{failed_id}]")));
        assert!(report
            .markdown
            .contains("virtual replay transcript failed validation"));
        assert!(!report.markdown.contains(&project.display().to_string()));
    }

    #[tokio::test]
    async fn campaign_report_appends_only_grounded_ai_interpretation() {
        let temp = tempfile::tempdir().unwrap();
        let (service, _, project, _, operation_id, _) =
            completed_analysis_with_state(temp.path()).await;
        let interpretation = format!(
            "### Evidence-backed interpretation\nThe offline analysis retained validated state evidence \
             [OP:{operation_id}].\n\n### Hypotheses\nNo hypothesis is asserted.\n\n### Missing \
             evidence\nNo virtual replay is retained.\n\n### Recommended next actions\nReview the \
             captured states before deterministic mutation [OP:{operation_id}]."
        );
        let service = service.with_provider_pool(Arc::new(ReportPool::new(interpretation)));

        let report = service
            .generate_automotive_report_with_settings(
                &project,
                true,
                &AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                crate::report::ReportLanguage::En,
            )
            .await
            .unwrap();

        assert_eq!(report.ai_status, AutomotiveReportAiStatus::Applied);
        assert_eq!(report.ai_model.as_deref(), Some("grounded-test-model"));
        assert!(report.markdown.contains("## AI-Assisted Interpretation"));
        assert!(report
            .markdown
            .contains("Retained evidence and service validation"));
    }

    #[tokio::test]
    async fn campaign_report_falls_back_when_ai_invents_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (service, _, project, _, _, _) = completed_analysis_with_state(temp.path()).await;
        let service = service.with_provider_pool(Arc::new(ReportPool::new(
            "### Evidence-backed interpretation\nInvented evidence \
             [OP:00000000-0000-0000-0000-000000000001].\n\n### Hypotheses\nNone.\n\n\
             ### Missing evidence\nNone.\n\n### Recommended next actions\nNone.",
        )));

        let report = service
            .generate_automotive_report_with_settings(
                &project,
                true,
                &AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                crate::report::ReportLanguage::En,
            )
            .await
            .unwrap();

        assert_eq!(report.ai_status, AutomotiveReportAiStatus::Fallback);
        assert_eq!(report.ai_model, None);
        assert!(!report.markdown.contains("## AI-Assisted Interpretation"));
        assert!(report.markdown.contains("## Evidence Manifest"));
    }

    #[tokio::test]
    async fn the_requested_language_reaches_the_deterministic_renderer() {
        // The whole point of the branch: a caller can now choose. Asserted on
        // the document's own title rather than on any label, so the assertion
        // fails if the parameter stops reaching `AutomotiveLabels::for_language`
        // even though the label set itself is correct.
        let temp = tempfile::tempdir().unwrap();
        let (service, _, project, _, operation_id, _) =
            completed_analysis_with_state(temp.path()).await;
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let chinese = service
            .generate_automotive_report_with_settings(
                &project,
                false,
                &settings,
                crate::report::ReportLanguage::Zh,
            )
            .await
            .unwrap();
        assert!(
            chinese.markdown.starts_with("# 汽车协议模糊测试活动报告："),
            "the requested language must reach the renderer: {}",
            chinese.markdown
        );
        assert!(!chinese
            .markdown
            .contains("Automotive Fuzzing Campaign Report"));
        // The evidence citation is a technical token: byte-identical either way.
        assert!(chinese.markdown.contains(&format!("[OP:{operation_id}]")));

        let english = service
            .generate_automotive_report_with_settings(
                &project,
                false,
                &settings,
                crate::report::ReportLanguage::En,
            )
            .await
            .unwrap();
        assert!(
            english
                .markdown
                .starts_with("# Automotive Fuzzing Campaign Report: "),
            "the English rendering must not move: {}",
            english.markdown
        );
        assert!(english.markdown.contains(&format!("[OP:{operation_id}]")));
    }

    #[tokio::test]
    async fn a_chinese_campaign_report_accepts_and_frames_a_chinese_interpretation() {
        // One language value has to reach the prompts, the validation of what
        // comes back and the advisory notice around it. Asking for Chinese while
        // validating against English headings would discard this interpretation
        // and report `Fallback` without saying why, so the status is asserted
        // alongside the Chinese framing.
        let temp = tempfile::tempdir().unwrap();
        let (service, _, project, _, operation_id, _) =
            completed_analysis_with_state(temp.path()).await;
        let service = service.with_provider_pool(Arc::new(ReportPool::new(format!(
            "### 基于证据的解读\n离线分析保留了经过校验的状态证据 [OP:{operation_id}]。\n\n\
             ### 假设\n不作任何假设。\n\n\
             ### 缺失的证据\n未保留任何虚拟重放。\n\n\
             ### 建议的后续行动\n在进行确定性变异之前先复核已捕获的状态 [OP:{operation_id}]。"
        ))));

        let report = service
            .generate_automotive_report_with_settings(
                &project,
                true,
                &AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                crate::report::ReportLanguage::Zh,
            )
            .await
            .unwrap();

        assert_eq!(report.ai_status, AutomotiveReportAiStatus::Applied);
        assert_eq!(report.ai_model.as_deref(), Some("grounded-test-model"));
        assert!(
            report.markdown.contains("## AI 辅助解读"),
            "{}",
            report.markdown
        );
        assert!(
            report
                .markdown
                .contains("任何情况下均以保留的证据和服务校验为准"),
            "the advisory notice must reach the reader in the report's language: {}",
            report.markdown
        );
        assert!(!report.markdown.contains("## AI-Assisted Interpretation"));
    }

    #[tokio::test]
    async fn the_settings_resolving_entry_point_carries_the_language_through() {
        // `generate_automotive_report` resolves the operator policy and then
        // delegates. That delegation is its own call site, and every assertion
        // above is on the method it delegates to, so a hardcoded language there
        // would go unnoticed.
        let temp = tempfile::tempdir().unwrap();
        let (service, _, project, _, _, _) = completed_analysis_with_state(temp.path()).await;

        let chinese = service
            .generate_automotive_report(&project, false, crate::report::ReportLanguage::Zh)
            .await
            .unwrap();
        assert!(
            chinese.markdown.starts_with("# 汽车协议模糊测试活动报告："),
            "{}",
            chinese.markdown
        );

        let default = service
            .generate_automotive_report(&project, false, crate::report::ReportLanguage::default())
            .await
            .unwrap();
        assert!(
            default
                .markdown
                .starts_with("# Automotive Fuzzing Campaign Report: "),
            "{}",
            default.markdown
        );
    }

    /// Drive the report's provider path in `language` and return the (system,
    /// user) prompts the model was actually handed.
    async fn captured_automotive_report_prompts(
        root: &Path,
        language: crate::report::ReportLanguage,
    ) -> (String, String) {
        let (service, _, project, _, _, _) =
            completed_analysis_with_state(&root.join(format!("prompt_{language:?}"))).await;
        let pool = Arc::new(ReportPool::new("interpretation content is irrelevant here"));
        let service = service.with_provider_pool(Arc::clone(&pool) as Arc<dyn ProviderPool>);
        service
            .generate_automotive_report_with_settings(
                &project,
                true,
                &AutomotiveSettings {
                    enabled: true,
                    ..AutomotiveSettings::default()
                },
                language,
            )
            .await
            .unwrap();
        (
            pool.message(hf_core::types::Role::System)
                .expect("the provider pool must have been asked to compose the interpretation"),
            pool.message(hf_core::types::Role::User)
                .expect("the provider pool must have been asked to compose the interpretation"),
        )
    }

    #[tokio::test]
    async fn the_report_asks_the_model_for_the_requested_language() {
        // The two prompt builders are the only uses of `language` that produce
        // no visible difference in a successful report, so nothing else can see
        // them severed. Asking in English while validating against Chinese
        // headings discards every interpretation and reports a silent
        // `Fallback` -- the exact failure this work exists to prevent, reached
        // from the other side.
        let temp = tempfile::tempdir().unwrap();

        let (zh_system, zh_user) =
            captured_automotive_report_prompts(temp.path(), crate::report::ReportLanguage::Zh)
                .await;
        assert!(
            zh_system.contains("You write the interpretation in Simplified Chinese"),
            "the system prompt does not ask for Chinese: {zh_system}"
        );
        assert!(
            zh_user.contains("Write the entire interpretation in Simplified Chinese"),
            "the user prompt does not ask for Chinese: {zh_user}"
        );
        // The Chinese arm's token rule, as one contiguous phrase that exists
        // only in that block: a translated citation no longer matches the
        // retained evidence it names.
        assert!(
            zh_user.contains(
                "never translated or \
                 transliterated: the evidence citations `[OP:<uuid>]`, `[STATE:<sha256>]` and \
                 `[TRANSCRIPT:<sha256>]`"
            ),
            "the user prompt does not pin the untranslatable citations: {zh_user}"
        );
        // And the four headings requested are the Chinese ones the validator
        // will require.
        assert!(zh_user.contains("### 基于证据的解读"), "{zh_user}");

        let (en_system, en_user) =
            captured_automotive_report_prompts(temp.path(), crate::report::ReportLanguage::En)
                .await;

        // The negative half is not optional: without it a pool that hardcoded
        // `Zh` at both sites would satisfy everything above.
        assert!(
            !en_system.contains("Simplified Chinese"),
            "the English system prompt leaked a language instruction: {en_system}"
        );
        assert!(
            !en_user.contains("Simplified Chinese"),
            "the English user prompt leaked a language instruction: {en_user}"
        );
        assert!(
            !en_user.contains("transliterated"),
            "the English user prompt leaked the Chinese token rule: {en_user}"
        );
        assert!(
            en_user.contains("### Evidence-backed interpretation"),
            "{en_user}"
        );
    }

    #[tokio::test]
    async fn disabled_policy_rejects_before_workspace_or_runtime_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let (project, capture) = project_fixture(temp.path());
        let workspace = temp.path().join("missing-workspace");
        let runtime = Arc::new(RecordingRuntime::default());
        let (service, store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project.clone(),
            command: AutomotiveCommand::AnalyzeCapture {
                protocol: AutomotiveProtocol::Uds,
                capture_path: capture,
            },
            approval: None,
        };

        // Exercise the disabled path explicitly: the master switch defaults to
        // enabled now, so opt this fixture out to prove rejection happens before
        // any workspace or runtime mutation.
        let disabled = AutomotiveSettings {
            enabled: false,
            ..AutomotiveSettings::default()
        };
        let error = service
            .execute_automotive_with_context(request, disabled, &workspace)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("disabled"));
        assert!(runtime.calls().is_empty());
        assert!(!workspace.exists());
        assert!(store
            .automotive_operations(&project.display().to_string(), 10)
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_sidecar_image_error_is_actionable() {
        let msg = super::missing_sidecar_image_error("oxfuzz/scapy-automotive:2.7.0").to_string();
        assert!(
            msg.contains("oxfuzz/scapy-automotive:2.7.0"),
            "names the image: {msg}"
        );
        assert!(
            msg.contains("build-scapy-sidecar.sh"),
            "points at the build script: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_sidecar_image_fails_fast_before_running_the_operation() {
        let temp = tempfile::tempdir().unwrap();
        let (project, capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        // The runtime reports the sidecar image as absent and carries no scripted
        // response, so had the guard not fired the sandbox run would surface a
        // different parse error -- the actionable build message below is therefore
        // proof the guard failed fast before any sandbox run.
        let (service, _store) = service(
            Arc::new(RecordingRuntime::with_missing_image()),
            temp.path(),
        )
        .await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::AnalyzeCapture {
                protocol: AutomotiveProtocol::Uds,
                capture_path: capture,
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        // The operation must error with the actionable build message, which only
        // the pre-sandbox guard produces.
        let msg = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .expect_err("a missing sidecar image must be an error")
            .to_string();
        assert!(
            msg.contains("build-scapy-sidecar.sh"),
            "actionable message: {msg}"
        );
    }

    #[tokio::test]
    async fn missing_sidecar_image_does_not_burn_a_physical_bench_approval() {
        // The headline guarantee: the image-present probe runs BEFORE the
        // single-use physical-bench approval is claimed, so a missing sidecar
        // image fails the operation without spending the operator's one-shot
        // approval. A later attempt with the image built must still be able to
        // spend that same approval. Both attempts share one evidence store; if the
        // guard fired after the claim (or not at all), the first attempt would burn
        // the approval and the second would be rejected as already used.
        let temp = tempfile::tempdir().unwrap();
        let (project, _) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let transcript = Sha256Digest::parse("ef".repeat(32)).unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::Replay(ReplayResult {
                protocol: AutomotiveProtocol::Uds,
                mode: AutomotiveMode::PhysicalBench,
                planned_events: 1,
                executed_events: 1,
                transcript_hash: transcript.clone(),
                state_signatures: Vec::new(),
                completed: true,
            }),
            Some(transcript),
        );
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);
        let plan = uds_replay_plan(AutomotiveMode::PhysicalBench);
        let limits = operation_limits(&settings).unwrap();
        let approval_id = "approval-image-guard".to_owned();
        let make_request = || {
            let approval = AutomotiveApprovalEvidence {
                approval_id: approval_id.clone(),
                approved_by: "desktop-operator".to_owned(),
                approved_at: chrono::Utc::now(),
                scope_sha256: approval_scope_hash(
                    "can0",
                    &plan,
                    &settings.physical_bench,
                    &limits,
                    IMMUTABLE_SIDECAR_SHA256,
                )
                .unwrap(),
                sidecar_image_sha256: IMMUTABLE_SIDECAR_SHA256.to_owned(),
            };
            AutomotiveOperationRequest {
                project_root: project.clone(),
                command: AutomotiveCommand::ExecuteReplay {
                    mode: ModeConfig::PhysicalBench {
                        interface: "can0".to_owned(),
                        approval_id: approval_id.clone(),
                    },
                    plan: plan.clone(),
                },
                approval: Some(approval),
            }
        };

        // First attempt: the sidecar image is not built. The operation fails with
        // the actionable message before the approval can be claimed.
        let missing = Arc::new(RecordingRuntime::with_missing_image());
        let (svc_missing, _) = service(Arc::clone(&missing), temp.path()).await;
        let err = svc_missing
            .execute_automotive_with_context(make_request(), settings.clone(), &workspace)
            .await
            .expect_err("a missing sidecar image must fail the operation");
        assert!(
            err.to_string().contains("build-scapy-sidecar.sh"),
            "actionable message: {err}"
        );

        // Second attempt against the SAME evidence store, now with the image built:
        // the approval was never spent, so this transmission is authorized and
        // fires exactly once.
        let ready = Arc::new(RecordingRuntime::with_response(&response));
        let (svc_ready, _) = service(Arc::clone(&ready), temp.path()).await;
        svc_ready
            .execute_automotive_with_context(make_request(), settings.clone(), &workspace)
            .await
            .expect("the unspent approval authorizes the replay once the image exists");
        assert_eq!(
            ready.calls().len(),
            1,
            "the transmission fired on the still-valid approval"
        );
    }

    #[tokio::test]
    async fn offline_capture_is_staged_and_sent_over_bounded_jsonl_in_a_hardened_profile() {
        let temp = tempfile::tempdir().unwrap();
        let (project, capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let (transcript, transcript_artifact, transcript_bytes) = transcript_fixture();
        let state = StateSignature::from_observations(
            AutomotiveProtocol::Uds,
            BTreeMap::from([("session".to_owned(), "default".to_owned())]),
        )
        .unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::CaptureAnalysis(CaptureAnalysisResult {
                protocol: AutomotiveProtocol::Uds,
                event_count: 1,
                transcript: transcript_artifact.clone(),
                transcript_hash: transcript.clone(),
                state_signatures: vec![state.clone()],
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response_and_output(
            &response,
            &transcript_artifact,
            &transcript_bytes,
        ));
        let (service, store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project.clone(),
            command: AutomotiveCommand::AnalyzeCapture {
                protocol: AutomotiveProtocol::Uds,
                capture_path: capture.clone(),
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let outcome = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap();

        assert!(matches!(
            outcome.result,
            AutomotiveResult::CaptureAnalysis(_)
        ));
        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (command, limits, options) = &calls[0];
        assert_eq!(command, &["python3", "-m", "oxfuzz_scapy_automotive"]);
        assert_eq!(limits.max_mem_mb, 1024);
        assert_eq!(
            limits
                .env
                .get("OXFUZZ_SCAPY_INPUT_ROOT")
                .map(String::as_str),
            Some("/work/inputs")
        );
        assert_eq!(
            limits
                .env
                .get("OXFUZZ_SCAPY_OUTPUT_ROOT")
                .map(String::as_str),
            Some("/work/output")
        );
        assert!(!limits
            .env
            .contains_key("OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON"));
        assert_eq!(options.network_mode, SandboxNetworkMode::None);
        assert!(options.capabilities.is_empty());
        assert_eq!(options.image.as_deref(), Some(IMMUTABLE_SIDECAR_IMAGE));
        assert!(options.workspace_read_only);
        let input = String::from_utf8(options.stdin.clone().expect("JSONL stdin")).unwrap();
        assert!(input.ends_with('\n'));
        assert!(input.contains(r#""operation":"analyze_capture""#));
        assert!(input.contains(r#""artifact_id":"capture.pcap""#));
        assert!(!input.contains("/work/inputs"));
        assert!(!input.contains(&capture.display().to_string()));
        let record = store
            .automotive_operation(outcome.operation_id)
            .await
            .unwrap()
            .expect("durable operation");
        assert_eq!(record.status, hf_storage::AutomotiveOperationStatus::Done);
        assert!(record.transcript_hash.is_some());
        assert!(record.ended_at.is_some());
        let summaries = service
            .list_automotive_operations(&project, 10)
            .await
            .unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].state_signatures, vec![state]);
        let public_json = serde_json::to_value(&summaries[0]).unwrap();
        assert!(public_json.get("request_hash").is_none());
        assert!(public_json.get("approval_json").is_none());
        assert!(public_json.get("result_json").is_none());
        assert!(workspace.exists());
    }

    #[tokio::test]
    async fn live_monitor_virtual_can_dispatches_with_a_policy_in_a_hardened_profile() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let (transcript, transcript_artifact, transcript_bytes) = transcript_fixture();
        let state = StateSignature::from_observations(
            AutomotiveProtocol::Can,
            BTreeMap::from([("arbitration_id".to_owned(), "291".to_owned())]),
        )
        .unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::CaptureAnalysis(CaptureAnalysisResult {
                protocol: AutomotiveProtocol::Can,
                event_count: 2,
                transcript: transcript_artifact.clone(),
                transcript_hash: transcript.clone(),
                state_signatures: vec![state],
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response_and_output(
            &response,
            &transcript_artifact,
            &transcript_bytes,
        ));
        let (service, _store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::LiveMonitor {
                mode: ModeConfig::VirtualCan {
                    interface: "vcan0".to_owned(),
                },
                protocol: AutomotiveProtocol::Can,
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let outcome = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap();

        assert!(matches!(
            outcome.result,
            AutomotiveResult::CaptureAnalysis(_)
        ));
        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (_, limits, options) = &calls[0];
        // Virtual CAN: no network, but NetAdmin+NetRaw to bring up and read vcan.
        assert_eq!(options.network_mode, SandboxNetworkMode::None);
        assert_eq!(
            options.capabilities,
            vec![SandboxCapability::NetAdmin, SandboxCapability::NetRaw]
        );
        // A live operation carries an execution policy for a virtual interface.
        let config = limits
            .env
            .get("OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON")
            .expect("execution config");
        assert!(config.contains("\"mode\":\"virtual_can\""));
        assert!(config.contains("\"physical_enabled\":false"));
        // The JSONL request dispatches the live_monitor operation.
        let stdin = String::from_utf8(options.stdin.clone().expect("JSONL stdin")).unwrap();
        assert!(stdin.contains(r#""operation":"live_monitor""#));
    }

    #[tokio::test]
    async fn live_monitor_rejects_physical_bench_for_now() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let runtime = Arc::new(RecordingRuntime::default());
        let (service, _store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::LiveMonitor {
                mode: ModeConfig::PhysicalBench {
                    interface: "can0".to_owned(),
                    approval_id: "approval-1".to_owned(),
                },
                protocol: AutomotiveProtocol::Can,
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        // Physical-bench live monitor must be rejected before any runtime call --
        // whether by the mode allowlist or the live-monitor policy, it never
        // reaches the sandbox.
        service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap_err();
        assert!(runtime.calls().is_empty());
    }

    #[tokio::test]
    async fn uds_scan_denies_dangerous_services_before_any_runtime_call() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let runtime = Arc::new(RecordingRuntime::default());
        let (service, _store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::ScanUds {
                mode: ModeConfig::VirtualCan {
                    interface: "vcan0".to_owned(),
                },
                protocol: AutomotiveProtocol::Uds,
                request_ids: vec![0x7E0],
                // 0x27 SecurityAccess is a dangerous, non-read-only service.
                services: vec![0x22, 0x27],
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let error = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("0x27"));
        assert!(runtime.calls().is_empty());
    }

    #[tokio::test]
    async fn uds_scan_virtual_can_dispatches_read_only_service_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let (transcript, transcript_artifact, transcript_bytes) = transcript_fixture();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::UdsScan(UdsScanResult {
                mode: AutomotiveMode::VirtualCan,
                ecus: vec![UdsEcu {
                    request_id: 0x7E0,
                    response_id: 0x7E8,
                    services: vec![UdsService {
                        sid: 0x22,
                        supported: true,
                        nrc: None,
                    }],
                }],
                transcript: transcript_artifact.clone(),
                transcript_hash: transcript.clone(),
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response_and_output(
            &response,
            &transcript_artifact,
            &transcript_bytes,
        ));
        let (service, _store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::ScanUds {
                mode: ModeConfig::VirtualCan {
                    interface: "vcan0".to_owned(),
                },
                protocol: AutomotiveProtocol::Uds,
                request_ids: vec![0x7E0],
                services: vec![0x3E, 0x22],
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let outcome = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap();

        assert!(matches!(outcome.result, AutomotiveResult::UdsScan(_)));
        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (_, limits, options) = &calls[0];
        assert_eq!(options.network_mode, SandboxNetworkMode::None);
        assert_eq!(
            options.capabilities,
            vec![SandboxCapability::NetAdmin, SandboxCapability::NetRaw]
        );
        let config = limits
            .env
            .get("OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON")
            .expect("execution config");
        // The read-only services are carried (sorted) as the sidecar-enforced
        // allowlist: 0x22=34, 0x3E=62.
        assert!(config.contains("\"service_allowlist\":[34,62]"));
        let stdin = String::from_utf8(options.stdin.clone().expect("JSONL stdin")).unwrap();
        assert!(stdin.contains(r#""operation":"scan_uds""#));
    }

    #[tokio::test]
    async fn physical_bench_requires_policy_and_scoped_approval_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let runtime = Arc::new(RecordingRuntime::default());
        let (service, _) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::ExecuteReplay {
                mode: ModeConfig::PhysicalBench {
                    interface: "can0".to_owned(),
                    approval_id: "approval-missing-evidence".to_owned(),
                },
                plan: uds_replay_plan(AutomotiveMode::PhysicalBench),
            },
            approval: None,
        };
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);

        let error = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("approval"));
        assert!(runtime.calls().is_empty());
        assert!(!workspace.exists());
    }

    #[tokio::test]
    async fn virtual_replay_uses_only_the_isolated_vcan_runtime_profile() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let transcript = Sha256Digest::parse("cd".repeat(32)).unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::Replay(ReplayResult {
                protocol: AutomotiveProtocol::Uds,
                mode: AutomotiveMode::VirtualCan,
                planned_events: 1,
                executed_events: 1,
                transcript_hash: transcript.clone(),
                state_signatures: Vec::new(),
                completed: true,
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response(&response));
        let (service, _) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::ExecuteReplay {
                mode: ModeConfig::VirtualCan {
                    interface: "vcan0".to_owned(),
                },
                plan: uds_replay_plan(AutomotiveMode::VirtualCan),
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap();

        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (_, limits, options) = &calls[0];
        assert_eq!(options.network_mode, SandboxNetworkMode::None);
        assert_eq!(
            options.capabilities,
            vec![SandboxCapability::NetAdmin, SandboxCapability::NetRaw]
        );
        let execution = limits
            .env
            .get("OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON")
            .expect("service-owned execution policy");
        assert!(execution.contains(r#""mode":"virtual_can""#));
        assert!(execution.contains(r#""interface":"vcan0""#));
        assert!(!execution.contains(r#""physical_enabled":true"#));
    }

    #[tokio::test]
    async fn approved_physical_replay_uses_exact_host_profile_and_scope() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let transcript = Sha256Digest::parse("ef".repeat(32)).unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::Replay(ReplayResult {
                protocol: AutomotiveProtocol::Uds,
                mode: AutomotiveMode::PhysicalBench,
                planned_events: 1,
                executed_events: 1,
                transcript_hash: transcript.clone(),
                state_signatures: Vec::new(),
                completed: true,
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response(&response));
        let (service, _) = service(Arc::clone(&runtime), temp.path()).await;
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);
        let plan = uds_replay_plan(AutomotiveMode::PhysicalBench);
        let limits = operation_limits(&settings).unwrap();
        let approval_id = "approval-exact-scope".to_owned();
        let substituted_image_sha256 = "b".repeat(64);
        let substituted_approval = AutomotiveApprovalEvidence {
            approval_id: approval_id.clone(),
            approved_by: "desktop-operator".to_owned(),
            approved_at: chrono::Utc::now(),
            scope_sha256: approval_scope_hash(
                "can0",
                &plan,
                &settings.physical_bench,
                &limits,
                &substituted_image_sha256,
            )
            .unwrap(),
            sidecar_image_sha256: substituted_image_sha256,
        };
        let mismatch = service
            .execute_automotive_with_context(
                AutomotiveOperationRequest {
                    project_root: project.clone(),
                    command: AutomotiveCommand::ExecuteReplay {
                        mode: ModeConfig::PhysicalBench {
                            interface: "can0".to_owned(),
                            approval_id: approval_id.clone(),
                        },
                        plan: plan.clone(),
                    },
                    approval: Some(substituted_approval),
                },
                settings.clone(),
                &workspace,
            )
            .await
            .expect_err("approval for a substituted sidecar image must be rejected");
        assert!(
            mismatch.to_string().contains("image identity"),
            "{mismatch}"
        );
        assert!(
            runtime.calls().is_empty(),
            "image mismatch must fail before sandbox execution"
        );

        let approval = AutomotiveApprovalEvidence {
            approval_id: approval_id.clone(),
            approved_by: "desktop-operator".to_owned(),
            approved_at: chrono::Utc::now(),
            scope_sha256: approval_scope_hash(
                "can0",
                &plan,
                &settings.physical_bench,
                &limits,
                IMMUTABLE_SIDECAR_SHA256,
            )
            .unwrap(),
            sidecar_image_sha256: IMMUTABLE_SIDECAR_SHA256.to_owned(),
        };
        let request = AutomotiveOperationRequest {
            project_root: project,
            command: AutomotiveCommand::ExecuteReplay {
                mode: ModeConfig::PhysicalBench {
                    interface: "can0".to_owned(),
                    approval_id,
                },
                plan,
            },
            approval: Some(approval),
        };

        service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap();

        let calls = runtime.calls();
        assert_eq!(calls.len(), 1);
        let (_, limits, options) = &calls[0];
        assert_eq!(options.network_mode, SandboxNetworkMode::Host);
        assert_eq!(options.capabilities, vec![SandboxCapability::NetRaw]);
        assert_eq!(options.image.as_deref(), Some(IMMUTABLE_SIDECAR_IMAGE));
        let execution = limits
            .env
            .get("OXFUZZ_SCAPY_EXECUTION_CONFIG_JSON")
            .expect("service-owned execution policy");
        assert!(execution.contains(r#""mode":"physical_bench""#));
        assert!(execution.contains(r#""physical_enabled":true"#));
        assert!(execution.contains("approval-exact-scope"));
    }

    #[tokio::test]
    async fn physical_approval_is_single_use_and_cannot_authorize_a_second_transmission() {
        let temp = tempfile::tempdir().unwrap();
        let (project, _) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let transcript = Sha256Digest::parse("ef".repeat(32)).unwrap();
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::Replay(ReplayResult {
                protocol: AutomotiveProtocol::Uds,
                mode: AutomotiveMode::PhysicalBench,
                planned_events: 1,
                executed_events: 1,
                transcript_hash: transcript.clone(),
                state_signatures: Vec::new(),
                completed: true,
            }),
            Some(transcript),
        );
        let runtime = Arc::new(RecordingRuntime::with_response(&response));
        let (service, _) = service(Arc::clone(&runtime), temp.path()).await;
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);
        let plan = uds_replay_plan(AutomotiveMode::PhysicalBench);
        let limits = operation_limits(&settings).unwrap();
        let approval_id = "approval-single-use".to_owned();
        // A helper to build a fresh request carrying the SAME approval evidence:
        // the operator scripts a second execution with the one approval.
        let make_request = || {
            let approval = AutomotiveApprovalEvidence {
                approval_id: approval_id.clone(),
                approved_by: "desktop-operator".to_owned(),
                approved_at: chrono::Utc::now(),
                scope_sha256: approval_scope_hash(
                    "can0",
                    &plan,
                    &settings.physical_bench,
                    &limits,
                    IMMUTABLE_SIDECAR_SHA256,
                )
                .unwrap(),
                sidecar_image_sha256: IMMUTABLE_SIDECAR_SHA256.to_owned(),
            };
            AutomotiveOperationRequest {
                project_root: project.clone(),
                command: AutomotiveCommand::ExecuteReplay {
                    mode: ModeConfig::PhysicalBench {
                        interface: "can0".to_owned(),
                        approval_id: approval_id.clone(),
                    },
                    plan: plan.clone(),
                },
                approval: Some(approval),
            }
        };

        // First execution consumes the approval and runs the sidecar.
        service
            .execute_automotive_with_context(make_request(), settings.clone(), &workspace)
            .await
            .expect("first physical replay is authorized");
        assert_eq!(runtime.calls().len(), 1, "the first transmission fired");

        // A second execution reusing the same approval is rejected before any
        // further bus access -- the approval is single-use.
        let err = service
            .execute_automotive_with_context(make_request(), settings.clone(), &workspace)
            .await
            .expect_err("the reused approval must be rejected");
        assert!(
            err.to_string().contains("already been used"),
            "unexpected error: {err}"
        );
        assert_eq!(
            runtime.calls().len(),
            1,
            "no second transmission fired on the reused approval"
        );
    }

    #[test]
    fn wire_service_is_framing_aware_and_protocol_independent() {
        // ISO-TP single frame: byte 0 is the PCI (0x02 = length 2), the service is
        // byte 1 (0x11 = ECU reset), NOT the PCI byte.
        assert_eq!(wire_uds_service("0211"), Some(0x11));
        // A non-single-frame first byte is itself the service.
        assert_eq!(wire_uds_service("221234"), Some(0x22));
        assert_eq!(wire_uds_service("11"), Some(0x11));
        // Looks like a single-frame PCI but no service byte follows.
        assert_eq!(wire_uds_service("03"), None);
    }

    #[test]
    fn dangerous_service_is_denied_even_when_the_plan_is_labelled_non_uds() {
        // A CAN-labelled plan that frames a dangerous UDS service (ECU reset) must be
        // rejected: the denylist is protocol-label independent and ISO-TP framing aware,
        // so it cannot be evaded by mislabelling the protocol or hiding the service
        // behind the PCI byte.
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);
        settings.physical_bench.uds_services = vec![0x11]; // allowlisted, but...
        settings.physical_bench.allow_dangerous_services = false; // ...denylist wins
        let plan = ReplayPlan {
            protocol: AutomotiveProtocol::Can,
            mode: AutomotiveMode::PhysicalBench,
            deterministic_seed: 1,
            steps: vec![ReplayStep {
                sequence: 0,
                delay_micros: 0,
                action: ReplayAction::Send,
                message: ProtocolMessage {
                    protocol: AutomotiveProtocol::Can,
                    payload_hex: "0211".to_owned(),
                    fields: BTreeMap::from([("arbitration_id".to_owned(), "0x7e0".to_owned())]),
                },
            }],
        };
        let limits = operation_limits(&settings).unwrap();
        let err = validate_physical_policy(
            "can0",
            "id",
            &plan,
            None,
            &settings.physical_bench,
            &limits,
            Some(IMMUTABLE_SIDECAR_SHA256),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("dangerous"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn physical_execution_config_carries_the_full_policy_allowlists() {
        // The config the sidecar validates against and scope-hashes must be the full
        // approved policy (matching approval_scope_hash), not just the plan's own ids,
        // so a plan narrower than the policy does not diverge the two scope hashes.
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        enable_physical_bench(&mut settings);
        settings.physical_bench.arbitration_ids = vec![0x7e8, 0x7e0]; // broader than the plan
        settings.physical_bench.uds_services = vec![0x3e, 0x22];
        let command = AutomotiveCommand::ExecuteReplay {
            mode: ModeConfig::PhysicalBench {
                interface: "can0".to_owned(),
                approval_id: "id".to_owned(),
            },
            plan: uds_replay_plan(AutomotiveMode::PhysicalBench), // uses only 0x7e0 / 0x22
        };
        let limits = operation_limits(&settings).unwrap();
        let cfg_json =
            build_execution_config(&command, None, &settings, &limits, IMMUTABLE_SIDECAR_SHA256)
                .unwrap()
                .unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&cfg_json).unwrap();
        assert_eq!(
            cfg["arbitration_id_allowlist"],
            serde_json::json!([0x7e0, 0x7e8])
        );
        assert_eq!(cfg["service_allowlist"], serde_json::json!([0x22, 0x3e]));
    }

    #[tokio::test]
    async fn structured_sidecar_error_on_exit_one_is_retained_and_returned() {
        let temp = tempfile::tempdir().unwrap();
        let (project, capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let response = ResponseEnvelope::failure(
            "request-placeholder",
            AutomotiveError {
                code: AutomotiveErrorCode::MalformedTranscript,
                message: "capture is malformed".to_owned(),
                field: Some("capture".to_owned()),
                retryable: false,
                details: BTreeMap::new(),
            },
            None,
        );
        let runtime = Arc::new(RecordingRuntime::with_response_and_exit(&response, 1));
        let (service, store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project.clone(),
            command: AutomotiveCommand::AnalyzeCapture {
                protocol: AutomotiveProtocol::Uds,
                capture_path: capture,
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let error = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("capture is malformed"));
        assert_eq!(runtime.calls().len(), 1);
        let canonical_project = std::fs::canonicalize(&project).unwrap();
        let records = store
            .automotive_operations(&canonical_project.display().to_string(), 10)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].status,
            hf_storage::AutomotiveOperationStatus::Failed
        );
        assert!(records[0]
            .error
            .as_deref()
            .is_some_and(|message| message.contains("capture is malformed")));
    }

    #[tokio::test]
    async fn mismatched_success_result_marks_the_reserved_operation_failed() {
        let temp = tempfile::tempdir().unwrap();
        let (project, capture) = project_fixture(temp.path());
        let workspace = temp.path().join("workspace");
        let response = ResponseEnvelope::success(
            "request-placeholder",
            AutomotiveResult::ReplayPlan(ReplayPlan {
                protocol: AutomotiveProtocol::Uds,
                mode: AutomotiveMode::VirtualCan,
                deterministic_seed: 9,
                steps: vec![ReplayStep {
                    sequence: 0,
                    delay_micros: 0,
                    action: ReplayAction::Send,
                    message: ProtocolMessage {
                        protocol: AutomotiveProtocol::Uds,
                        payload_hex: "221234".to_owned(),
                        fields: BTreeMap::new(),
                    },
                }],
            }),
            None,
        );
        let runtime = Arc::new(RecordingRuntime::with_response(&response));
        let (service, store) = service(Arc::clone(&runtime), temp.path()).await;
        let request = AutomotiveOperationRequest {
            project_root: project.clone(),
            command: AutomotiveCommand::AnalyzeCapture {
                protocol: AutomotiveProtocol::Uds,
                capture_path: capture,
            },
            approval: None,
        };
        let settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        let error = service
            .execute_automotive_with_context(request, settings, &workspace)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("does not match"));
        let canonical_project = std::fs::canonicalize(&project).unwrap();
        let records = store
            .automotive_operations(&canonical_project.display().to_string(), 10)
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].status,
            hf_storage::AutomotiveOperationStatus::Failed
        );
    }

    #[test]
    fn mutation_outputs_enforce_an_aggregate_directory_ceiling() {
        let temp = tempfile::tempdir().unwrap();
        let first = b"123456";
        let second = b"abcdef";
        std::fs::write(temp.path().join("first.bin"), first).unwrap();
        std::fs::write(temp.path().join("second.bin"), second).unwrap();
        let result = AutomotiveResult::Mutations(MutationResult {
            protocol: AutomotiveProtocol::Uds,
            generated: 2,
            transcript_hash: None,
            artifacts: vec![
                ArtifactRef {
                    artifact_id: "first.bin".to_owned(),
                    sha256: sha256_bytes(first),
                    media_type: "application/octet-stream".to_owned(),
                    size_bytes: u64::try_from(first.len()).unwrap(),
                },
                ArtifactRef {
                    artifact_id: "second.bin".to_owned(),
                    sha256: sha256_bytes(second),
                    media_type: "application/octet-stream".to_owned(),
                    size_bytes: u64::try_from(second.len()).unwrap(),
                },
            ],
        });

        let error = verify_result_artifacts(temp.path(), &result, 10).unwrap_err();

        assert!(error.to_string().contains("aggregate"));
    }

    #[test]
    fn mutation_outputs_reject_unreferenced_sidecar_files() {
        let temp = tempfile::tempdir().unwrap();
        let retained = b"retained";
        std::fs::write(temp.path().join("retained.bin"), retained).unwrap();
        std::fs::write(temp.path().join("unexpected.bin"), b"unexpected").unwrap();
        let result = AutomotiveResult::Mutations(MutationResult {
            protocol: AutomotiveProtocol::Uds,
            generated: 1,
            transcript_hash: None,
            artifacts: vec![ArtifactRef {
                artifact_id: "retained.bin".to_owned(),
                sha256: sha256_bytes(retained),
                media_type: "application/octet-stream".to_owned(),
                size_bytes: u64::try_from(retained.len()).unwrap(),
            }],
        });

        let error = verify_result_artifacts(temp.path(), &result, 1024).unwrap_err();

        assert!(error.to_string().contains("unreferenced"));
    }

    #[test]
    fn mutation_outputs_verify_declared_artifact_sizes() {
        let temp = tempfile::tempdir().unwrap();
        let retained = b"retained";
        std::fs::write(temp.path().join("retained.bin"), retained).unwrap();
        let result = AutomotiveResult::Mutations(MutationResult {
            protocol: AutomotiveProtocol::Uds,
            generated: 1,
            transcript_hash: None,
            artifacts: vec![ArtifactRef {
                artifact_id: "retained.bin".to_owned(),
                sha256: sha256_bytes(retained),
                media_type: "application/octet-stream".to_owned(),
                size_bytes: u64::try_from(retained.len() + 1).unwrap(),
            }],
        });

        let error = verify_result_artifacts(temp.path(), &result, 1024).unwrap_err();

        assert!(error.to_string().contains("declared size"));
    }

    #[test]
    fn capture_transcript_output_is_part_of_result_artifact_verification() {
        let temp = tempfile::tempdir().unwrap();
        let transcript_bytes = b"canonical automotive transcript";
        let digest = Sha256Digest::parse(sha256_bytes(transcript_bytes)).unwrap();
        let transcript = ArtifactRef {
            artifact_id: "canonical-transcript.json".to_owned(),
            sha256: digest.as_str().to_owned(),
            media_type: "application/vnd.oxfuzz.automotive-transcript+json".to_owned(),
            size_bytes: u64::try_from(transcript_bytes.len()).unwrap(),
        };
        std::fs::write(temp.path().join(&transcript.artifact_id), transcript_bytes).unwrap();
        let result = AutomotiveResult::CaptureAnalysis(CaptureAnalysisResult {
            protocol: AutomotiveProtocol::Uds,
            event_count: 1,
            transcript,
            transcript_hash: digest,
            state_signatures: Vec::new(),
        });

        verify_result_artifacts(temp.path(), &result, 1024).unwrap();
    }

    #[test]
    fn physical_approval_scope_is_stable_across_allowlist_order() {
        let mut settings = AutomotiveSettings::default();
        settings.physical_bench.arbitration_ids = vec![0x7e8, 0x7e0];
        settings.physical_bench.uds_services = vec![0x3e, 0x22];
        let limits = operation_limits(&settings).unwrap();
        let plan = uds_replay_plan(AutomotiveMode::PhysicalBench);
        let first = approval_scope_hash(
            "can0",
            &plan,
            &settings.physical_bench,
            &limits,
            IMMUTABLE_SIDECAR_SHA256,
        )
        .unwrap();
        settings.physical_bench.arbitration_ids.reverse();
        settings.physical_bench.uds_services.reverse();

        let second = approval_scope_hash(
            "can0",
            &plan,
            &settings.physical_bench,
            &limits,
            IMMUTABLE_SIDECAR_SHA256,
        )
        .unwrap();

        assert_eq!(first, second);

        let substituted_image = approval_scope_hash(
            "can0",
            &plan,
            &settings.physical_bench,
            &limits,
            "b".repeat(64).as_str(),
        )
        .unwrap();
        assert_ne!(first, substituted_image);
    }

    #[test]
    fn physical_approval_scope_matches_the_python_sidecar_fixture() {
        let mut settings = AutomotiveSettings::default();
        settings.physical_bench.arbitration_ids = vec![2016, 2024];
        settings.physical_bench.uds_services = vec![0x10, 0x22];
        let plan = ReplayPlan {
            protocol: AutomotiveProtocol::Uds,
            mode: AutomotiveMode::PhysicalBench,
            deterministic_seed: 5,
            steps: vec![
                ReplayStep {
                    sequence: 0,
                    delay_micros: 0,
                    action: ReplayAction::Send,
                    message: ProtocolMessage {
                        protocol: AutomotiveProtocol::Uds,
                        payload_hex: "221234".to_owned(),
                        fields: BTreeMap::from([("arbitration_id".to_owned(), "2016".to_owned())]),
                    },
                },
                ReplayStep {
                    sequence: 1,
                    delay_micros: 200,
                    action: ReplayAction::ExpectResponse,
                    message: ProtocolMessage {
                        protocol: AutomotiveProtocol::Uds,
                        payload_hex: "621234".to_owned(),
                        fields: BTreeMap::from([("arbitration_id".to_owned(), "2024".to_owned())]),
                    },
                },
            ],
        };
        let limits = OperationLimits {
            max_events: 20,
            max_payload_bytes: 4096,
            max_duration_ms: 10_000,
            max_rate_per_second: 20,
        };

        let digest = approval_scope_hash(
            "can0",
            &plan,
            &settings.physical_bench,
            &limits,
            IMMUTABLE_SIDECAR_SHA256,
        )
        .unwrap();

        assert_eq!(
            digest,
            "3bdff1e65d5f82ca3d332dd56fbbd322d8a51e89ccb24cbdb10bf2001534c82d"
        );
    }

    #[tokio::test]
    async fn retained_operations_name_the_artifacts_promotion_accepts() {
        // A caller promoting from history holds only an operation summary. It
        // must be able to name a valid artifact from that summary alone --
        // otherwise the promotion API exists but nothing can call it.
        let temp = tempfile::tempdir().unwrap();
        let (service, _store, project, _workspace, operation_id, _state) =
            completed_analysis_with_state(temp.path()).await;

        let operations = service
            .list_automotive_operations(&project, 10)
            .await
            .unwrap();
        let summary = operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .expect("the executed operation is retained");

        assert!(
            summary
                .promotable_artifacts
                .contains(&AutomotiveStateArtifactSource::Input {
                    artifact_id: "capture.pcap".to_owned(),
                }),
            "the staged capture must be offered: {:?}",
            summary.promotable_artifacts
        );
        assert!(
            summary
                .promotable_artifacts
                .contains(&AutomotiveStateArtifactSource::Output {
                    artifact_id: "canonical-transcript.json".to_owned(),
                }),
            "the retained transcript must be offered: {:?}",
            summary.promotable_artifacts
        );
    }

    #[tokio::test]
    async fn state_promotion_is_refused_when_the_policy_denies_a_corpus_operation() {
        // Promotion copies an artifact into the project's retained corpus and
        // persists a row, so it is a corpus filesystem operation and passes the
        // same guardrail every other one does. The denial is asserted through
        // the executor that actually performs the copy, not a wrapper a direct
        // caller could bypass (AGENTS.md 2.19).
        use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};

        let temp = tempfile::tempdir().unwrap();
        let (service, store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let denied = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&store))
            .with_guardrails(Guardrails::new(
                GuardrailPolicy {
                    auto_allow_max: RiskTier::Low,
                    deny_at: Some(RiskTier::Low),
                },
                Arc::new(DenyAll),
            ));

        let error = denied
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project.clone(),
                    source_operation_id: operation_id,
                    state_signature: state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .expect_err("a denied corpus operation must not promote");
        assert!(
            matches!(
                error,
                ClassifiedError::Validation(_) | ClassifiedError::Internal(_)
            ),
            "unexpected error kind: {error:?}"
        );
        assert!(
            service
                .list_automotive_state_corpus(&project, 20)
                .await
                .unwrap()
                .is_empty(),
            "a denied promotion must persist nothing"
        );
    }

    #[tokio::test]
    async fn state_artifact_promotion_is_verified_idempotent_and_listed() {
        let temp = tempfile::tempdir().unwrap();
        let (service, store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let request = AutomotiveStatePromotionRequest {
            project_root: project.clone(),
            source_operation_id: operation_id,
            state_signature: state.clone(),
            artifact: AutomotiveStateArtifactSource::Input {
                artifact_id: "capture.pcap".to_owned(),
            },
        };

        let first = service
            .promote_automotive_state_artifact_with_context(request.clone(), &workspace)
            .await
            .unwrap();
        let second = service
            .promote_automotive_state_artifact_with_context(request, &workspace)
            .await
            .unwrap();
        let output = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project.clone(),
                    source_operation_id: operation_id,
                    state_signature: state.clone(),
                    artifact: AutomotiveStateArtifactSource::Output {
                        artifact_id: "canonical-transcript.json".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_ne!(first.artifact_sha256, output.artifact_sha256);
        assert_eq!(first.protocol, AutomotiveProtocol::Uds);
        assert_eq!(first.state_digest, state.digest.as_str());
        assert_eq!(first.source_operation_id, operation_id);
        assert!(!Path::new(&first.artifact_path).is_absolute());
        let retained = workspace.join(&first.artifact_path);
        assert_eq!(
            std::fs::read(retained).unwrap(),
            b"bounded synthetic pcap fixture"
        );
        assert_eq!(
            std::fs::read(workspace.join(&output.artifact_path)).unwrap(),
            b"canonical automotive transcript"
        );
        let listed = service
            .list_automotive_state_corpus(&project, 20)
            .await
            .unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&first));
        assert!(listed.contains(&output));
        assert_eq!(
            store
                .automotive_state_corpus(
                    &std::fs::canonicalize(project)
                        .unwrap()
                        .display()
                        .to_string(),
                    20
                )
                .await
                .unwrap()
                .len(),
            2
        );
        let public = serde_json::to_value(first).unwrap();
        assert!(public.get("state_signature").is_none());
        assert!(public.get("observations").is_none());
        assert!(public["artifact_path"]
            .as_str()
            .is_some_and(|path| !path.starts_with('/')));
    }

    #[tokio::test]
    async fn state_artifact_promotion_rejects_unobserved_state_and_unsafe_source() {
        let temp = tempfile::tempdir().unwrap();
        let (service, store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let unknown_state = StateSignature::from_observations(
            AutomotiveProtocol::Uds,
            BTreeMap::from([("session".to_owned(), "programming".to_owned())]),
        )
        .unwrap();
        let error = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project.clone(),
                    source_operation_id: operation_id,
                    state_signature: unknown_state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("state signature"));

        let error = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project.clone(),
                    source_operation_id: operation_id,
                    state_signature: state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "../capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("artifact identifier"));
        assert!(store
            .automotive_state_corpus(
                &std::fs::canonicalize(project)
                    .unwrap()
                    .display()
                    .to_string(),
                20
            )
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn state_artifact_promotion_rejects_non_regular_operation_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let (service, _store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let operation = service
            .automotive_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        let source = workspace
            .join(operation.artifact_dir)
            .join("inputs")
            .join("capture.pcap");
        std::fs::remove_file(&source).unwrap();
        std::fs::create_dir(&source).unwrap();

        let error = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project,
                    source_operation_id: operation_id,
                    state_signature: state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("regular file"));
    }

    #[tokio::test]
    async fn state_artifact_promotion_rejects_input_changed_after_completion() {
        let temp = tempfile::tempdir().unwrap();
        let (service, _store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let operation = service
            .automotive_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        let source = workspace
            .join(operation.artifact_dir)
            .join("inputs")
            .join("capture.pcap");
        std::fs::write(&source, b"tampered capture after completion").unwrap();

        let error = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project,
                    source_operation_id: operation_id,
                    state_signature: state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("digest and size"));
    }

    #[tokio::test]
    async fn state_artifact_promotion_rejects_request_evidence_changed_after_completion() {
        let temp = tempfile::tempdir().unwrap();
        let (service, _store, project, workspace, operation_id, state) =
            completed_analysis_with_state(temp.path()).await;
        let operation = service
            .automotive_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        let request_evidence = workspace
            .join(&operation.artifact_dir)
            .join(REQUEST_EVIDENCE_FILE);
        let mut bytes = std::fs::read(&request_evidence).unwrap();
        bytes.push(b' ');
        std::fs::write(&request_evidence, bytes).unwrap();

        let error = service
            .promote_automotive_state_artifact_with_context(
                AutomotiveStatePromotionRequest {
                    project_root: project,
                    source_operation_id: operation_id,
                    state_signature: state,
                    artifact: AutomotiveStateArtifactSource::Input {
                        artifact_id: "capture.pcap".to_owned(),
                    },
                },
                &workspace,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("retained hash"));
    }
}
