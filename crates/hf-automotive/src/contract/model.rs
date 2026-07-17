use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::canonical::{Sha256Digest, StateSignature};
use super::validation::{
    bounded_metadata, lower_hex, nonempty_text, positive_bounded, safe_artifact_id,
    safe_physical_interface, safe_virtual_interface, ContractError, Validate,
    AUTOMOTIVE_SCHEMA_VERSION, MAX_DURATION_MS, MAX_EVENTS, MAX_PAYLOAD_BYTES, MAX_RATE_PER_SECOND,
};

/// Automotive protocol understood by the optional sidecar contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveProtocol {
    /// Classical Controller Area Network.
    Can,
    /// CAN with flexible data rate.
    CanFd,
    /// ISO 15765-2 transport over CAN.
    IsoTp,
    /// Unified Diagnostic Services.
    Uds,
    /// General Motors Local Area Network diagnostics.
    Gmlan,
    /// Service-oriented middleware over IP.
    SomeIp,
    /// SOME/IP service discovery.
    SomeIpSd,
    /// Diagnostics over IP.
    DoIp,
    /// On-board diagnostics.
    Obd,
    /// CAN Calibration Protocol.
    Ccp,
    /// Universal Measurement and Calibration Protocol.
    Xcp,
    /// BMW High-Speed Fahrzeugzugang framing.
    BmwHsfz,
    /// AUTOSAR Secure Onboard Communication metadata.
    SecOc,
}

impl AutomotiveProtocol {
    /// Complete stable protocol catalog for capability negotiation.
    pub const ALL: [Self; 13] = [
        Self::Can,
        Self::CanFd,
        Self::IsoTp,
        Self::Uds,
        Self::Gmlan,
        Self::SomeIp,
        Self::SomeIpSd,
        Self::DoIp,
        Self::Obd,
        Self::Ccp,
        Self::Xcp,
        Self::BmwHsfz,
        Self::SecOc,
    ];
}

/// Safety-relevant transport mode for an automotive operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveMode {
    /// Decode and plan from an immutable capture artifact.
    OfflinePcap,
    /// Use a sandbox-approved virtual CAN interface.
    VirtualCan,
    /// Use a separately approved physical bench interface.
    PhysicalBench,
}

impl AutomotiveMode {
    /// Complete stable mode catalog for capability negotiation.
    pub const ALL: [Self; 3] = [Self::OfflinePcap, Self::VirtualCan, Self::PhysicalBench];
}

/// Adapter behavior that may be advertised independently of protocol support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveCapability {
    /// Decode a bounded capture transcript.
    DecodeCapture,
    /// Generate deterministic, field-aware mutations.
    GenerateMutations,
    /// Convert messages into an explicit replay plan.
    BuildReplayPlan,
    /// Execute a plan on an approved virtual interface.
    ExecuteVirtual,
    /// Execute a plan on an explicitly approved physical bench.
    ExecutePhysical,
    /// Derive protocol-state novelty signatures.
    StateFeedback,
}

/// Concrete mode parameters supplied by the service after policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModeConfig {
    /// No live interface; inputs are staged immutable artifacts.
    OfflinePcap,
    /// A sandbox-visible virtual CAN interface name.
    VirtualCan {
        /// Validated interface identifier, for example `vcan0`.
        interface: String,
    },
    /// A physical bench interface plus service-owned approval evidence.
    PhysicalBench {
        /// Allowlisted interface identifier, for example `can0`.
        interface: String,
        /// Opaque approval record identifier; never a secret.
        approval_id: String,
    },
}

impl ModeConfig {
    /// Return the discriminant used in capabilities and replay plans.
    #[must_use]
    pub const fn mode(&self) -> AutomotiveMode {
        match self {
            Self::OfflinePcap => AutomotiveMode::OfflinePcap,
            Self::VirtualCan { .. } => AutomotiveMode::VirtualCan,
            Self::PhysicalBench { .. } => AutomotiveMode::PhysicalBench,
        }
    }
}

impl Validate for ModeConfig {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::OfflinePcap => Ok(()),
            Self::VirtualCan { interface } => safe_virtual_interface(interface),
            Self::PhysicalBench {
                interface,
                approval_id,
            } => {
                safe_physical_interface(interface)?;
                nonempty_text("mode.approval_id", approval_id)
            }
        }
    }
}

/// Hard operation bounds carried in every executable request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationLimits {
    /// Maximum decoded, generated, or replayed events.
    pub max_events: u32,
    /// Maximum decoded payload size for one event.
    pub max_payload_bytes: u32,
    /// Whole-operation wall-clock budget.
    pub max_duration_ms: u64,
    /// Maximum scheduled replay actions per second.
    pub max_rate_per_second: u32,
}

impl Validate for OperationLimits {
    fn validate(&self) -> Result<(), ContractError> {
        positive_bounded(
            "limits.max_events",
            u64::from(self.max_events),
            u64::from(MAX_EVENTS),
        )?;
        positive_bounded(
            "limits.max_payload_bytes",
            u64::from(self.max_payload_bytes),
            u64::from(MAX_PAYLOAD_BYTES),
        )?;
        positive_bounded(
            "limits.max_duration_ms",
            self.max_duration_ms,
            MAX_DURATION_MS,
        )?;
        positive_bounded(
            "limits.max_rate_per_second",
            u64::from(self.max_rate_per_second),
            u64::from(MAX_RATE_PER_SECOND),
        )
    }
}

/// Opaque reference to a service-staged artifact; host paths are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Service-owned artifact identifier.
    pub artifact_id: String,
    /// Expected immutable artifact digest.
    pub sha256: String,
    /// Media type used to select a bounded decoder.
    pub media_type: String,
    /// Immutable staged file size used for a second in-sandbox bound check.
    pub size_bytes: u64,
}

impl Validate for ArtifactRef {
    fn validate(&self) -> Result<(), ContractError> {
        safe_artifact_id(&self.artifact_id)?;
        Sha256Digest::parse(self.sha256.clone())?;
        nonempty_text("artifact.media_type", &self.media_type)?;
        if self.size_bytes == 0 {
            return Err(ContractError::InvalidField {
                field: "artifact.size_bytes",
                reason: "artifact must contain at least one byte".to_owned(),
            });
        }
        if self.size_bytes > 1024 * 1024 * 1024 {
            return Err(ContractError::LimitExceeded {
                field: "artifact.size_bytes",
                maximum: 1024 * 1024 * 1024,
                actual: self.size_bytes,
            });
        }
        let media_parts = self.media_type.split('/').collect::<Vec<_>>();
        if media_parts.len() != 2
            || media_parts.iter().any(|part| part.is_empty())
            || self.media_type.chars().any(char::is_whitespace)
        {
            return Err(ContractError::InvalidField {
                field: "artifact.media_type",
                reason: "expected a type/subtype media type".to_owned(),
            });
        }
        Ok(())
    }
}

/// Adapter capabilities returned before any operation is staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Adapter implementation name.
    pub adapter_name: String,
    /// Adapter implementation version.
    pub adapter_version: String,
    /// Envelope schemas accepted by the adapter.
    pub schema_versions: BTreeSet<u16>,
    /// Protocols available in the pinned adapter build.
    pub protocols: BTreeSet<AutomotiveProtocol>,
    /// Modes available in the current sandbox profile.
    pub modes: BTreeSet<AutomotiveMode>,
    /// Independent operation capabilities.
    pub capabilities: BTreeSet<AutomotiveCapability>,
    /// Maximum limits the adapter claims it can enforce.
    pub limits: OperationLimits,
}

impl Validate for CapabilityReport {
    fn validate(&self) -> Result<(), ContractError> {
        nonempty_text("capabilities.adapter_name", &self.adapter_name)?;
        nonempty_text("capabilities.adapter_version", &self.adapter_version)?;
        if !self.schema_versions.contains(&AUTOMOTIVE_SCHEMA_VERSION) {
            return Err(ContractError::UnsupportedSchema {
                expected: AUTOMOTIVE_SCHEMA_VERSION,
                actual: self.schema_versions.iter().next().copied().unwrap_or(0),
            });
        }
        for (field, empty) in [
            ("capabilities.protocols", self.protocols.is_empty()),
            ("capabilities.modes", self.modes.is_empty()),
            ("capabilities.operations", self.capabilities.is_empty()),
        ] {
            if empty {
                return Err(ContractError::MissingField { field });
            }
        }
        for (capability, mode, field) in [
            (
                AutomotiveCapability::ExecuteVirtual,
                AutomotiveMode::VirtualCan,
                "capabilities.execute_virtual",
            ),
            (
                AutomotiveCapability::ExecutePhysical,
                AutomotiveMode::PhysicalBench,
                "capabilities.execute_physical",
            ),
        ] {
            if self.capabilities.contains(&capability) && !self.modes.contains(&mode) {
                return Err(ContractError::InconsistentField {
                    field,
                    reason: "execution capability requires its corresponding mode".to_owned(),
                });
            }
        }
        self.limits.validate()
    }
}

/// One protocol message independent of its eventual transport implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Decoder/encoder protocol.
    pub protocol: AutomotiveProtocol,
    /// Lowercase payload bytes without separators.
    pub payload_hex: String,
    /// Bounded decoded fields used for mutation and diagnostics.
    pub fields: BTreeMap<String, String>,
}

impl Validate for ProtocolMessage {
    fn validate(&self) -> Result<(), ContractError> {
        lower_hex("message.payload_hex", &self.payload_hex, true)?;
        if self.payload_hex.len() / 2 > MAX_PAYLOAD_BYTES as usize {
            return Err(ContractError::LimitExceeded {
                field: "message.payload_hex",
                maximum: u64::from(MAX_PAYLOAD_BYTES),
                actual: (self.payload_hex.len() / 2) as u64,
            });
        }
        bounded_metadata("message.fields", &self.fields)
    }
}

/// Direction of an observed transcript event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    /// Message sent by the active endpoint.
    Transmit,
    /// Message received from the peer endpoint.
    Receive,
}

/// Canonical transcript event used for evidence hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEvent {
    /// Stable event order within the operation.
    pub sequence: u64,
    /// Decoder protocol.
    pub protocol: AutomotiveProtocol,
    /// Observed direction.
    pub direction: MessageDirection,
    /// Relative time from operation start; wall-clock time is excluded.
    pub offset_micros: u64,
    /// Lowercase payload bytes without separators.
    pub payload_hex: String,
    /// Bounded deterministic metadata.
    pub metadata: BTreeMap<String, String>,
}

impl Validate for TranscriptEvent {
    fn validate(&self) -> Result<(), ContractError> {
        lower_hex("transcript.payload_hex", &self.payload_hex, true)?;
        if self.payload_hex.len() / 2 > MAX_PAYLOAD_BYTES as usize {
            return Err(ContractError::LimitExceeded {
                field: "transcript.payload_hex",
                maximum: u64::from(MAX_PAYLOAD_BYTES),
                actual: (self.payload_hex.len() / 2) as u64,
            });
        }
        bounded_metadata("transcript.metadata", &self.metadata)
    }
}

/// Action encoded by one deterministic replay step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayAction {
    /// Transmit the message after the configured delay.
    Send,
    /// Match the next received message against the expected structure.
    ExpectResponse,
}

/// One ordered action in a replay plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Unique order identifier within the plan.
    pub sequence: u64,
    /// Delay relative to the previous step.
    pub delay_micros: u64,
    /// Send or expected-response action.
    pub action: ReplayAction,
    /// Protocol message associated with the action.
    pub message: ProtocolMessage,
}

impl Validate for ReplayStep {
    fn validate(&self) -> Result<(), ContractError> {
        self.message.validate()
    }
}

/// Deterministic, bounded plan that contains no executable command or host path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPlan {
    /// Protocol shared by every step.
    pub protocol: AutomotiveProtocol,
    /// Intended execution mode.
    pub mode: AutomotiveMode,
    /// Seed retained for exact mutation/replay reproduction.
    pub deterministic_seed: u64,
    /// Ordered send and expectation actions.
    pub steps: Vec<ReplayStep>,
}

impl Validate for ReplayPlan {
    fn validate(&self) -> Result<(), ContractError> {
        if self.mode == AutomotiveMode::OfflinePcap {
            return Err(ContractError::InvalidField {
                field: "replay.mode",
                reason: "offline capture mode cannot execute a replay plan".to_owned(),
            });
        }
        if self.steps.is_empty() {
            return Err(ContractError::MissingField {
                field: "replay.steps",
            });
        }
        if self.steps.len() > MAX_EVENTS as usize {
            return Err(ContractError::LimitExceeded {
                field: "replay.steps",
                maximum: u64::from(MAX_EVENTS),
                actual: self.steps.len() as u64,
            });
        }
        let mut sequences = BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            if !sequences.insert(step.sequence) {
                return Err(ContractError::DuplicateSequence {
                    sequence: step.sequence,
                });
            }
            if step.sequence != index as u64 {
                return Err(ContractError::InconsistentField {
                    field: "replay.steps.sequence",
                    reason: "step sequences must be contiguous and match array order".to_owned(),
                });
            }
            step.validate()?;
            if step.message.protocol != self.protocol {
                return Err(ContractError::InconsistentField {
                    field: "replay.steps.protocol",
                    reason: "every message must match the plan protocol".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Offline capture-analysis request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzeCaptureRequest {
    /// Protocol decoder selected by the service.
    pub protocol: AutomotiveProtocol,
    /// Immutable staged PCAP artifact.
    pub capture: ArtifactRef,
    /// Decode and resource bounds.
    pub limits: OperationLimits,
}

impl Validate for AnalyzeCaptureRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.capture.validate()?;
        self.limits.validate()
    }
}

/// Deterministic mutation-plan request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRequest {
    /// Protocol whose fields constrain mutation.
    pub protocol: AutomotiveProtocol,
    /// Immutable staged source artifact.
    pub source: ArtifactRef,
    /// Seed retained for exact reproduction.
    pub deterministic_seed: u64,
    /// Number of requested mutation cases.
    pub mutation_count: u32,
    /// Generation and resource bounds.
    pub limits: OperationLimits,
}

impl Validate for MutationRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.source.validate()?;
        self.limits.validate()?;
        positive_bounded(
            "mutation.mutation_count",
            u64::from(self.mutation_count),
            u64::from(self.limits.max_events),
        )
    }
}

/// Request to derive a deterministic replay plan from a staged artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPlanRequest {
    /// Protocol whose decoded fields define the plan.
    pub protocol: AutomotiveProtocol,
    /// Immutable decoded capture or mutation artifact.
    pub source: ArtifactRef,
    /// Intended future execution mode.
    pub target_mode: AutomotiveMode,
    /// Seed retained for deterministic plan construction.
    pub deterministic_seed: u64,
    /// Plan generation and resource bounds.
    pub limits: OperationLimits,
}

impl Validate for ReplayPlanRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.source.validate()?;
        self.limits.validate()?;
        if self.target_mode == AutomotiveMode::OfflinePcap {
            return Err(ContractError::InvalidField {
                field: "replay_plan.target_mode",
                reason: "a replay plan must target virtual CAN or a physical bench".to_owned(),
            });
        }
        Ok(())
    }
}

/// Replay request whose mode must agree with the embedded plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRequest {
    /// Validated offline, virtual, or physical parameters.
    pub mode: ModeConfig,
    /// Protocol-neutral replay plan.
    pub plan: ReplayPlan,
    /// Execution and resource bounds.
    pub limits: OperationLimits,
}

impl Validate for ReplayRequest {
    fn validate(&self) -> Result<(), ContractError> {
        self.mode.validate()?;
        self.plan.validate()?;
        self.limits.validate()?;
        if self.mode.mode() != self.plan.mode {
            return Err(ContractError::InconsistentField {
                field: "replay.mode",
                reason: "mode configuration does not match the replay plan".to_owned(),
            });
        }
        if self.plan.steps.len() > self.limits.max_events as usize {
            return Err(ContractError::LimitExceeded {
                field: "replay.steps",
                maximum: u64::from(self.limits.max_events),
                actual: self.plan.steps.len() as u64,
            });
        }
        let mut payload_bytes = 0_u64;
        let mut duration_micros = 0_u64;
        for step in &self.plan.steps {
            payload_bytes =
                payload_bytes.saturating_add((step.message.payload_hex.len() / 2) as u64);
            if payload_bytes > u64::from(self.limits.max_payload_bytes) {
                return Err(ContractError::LimitExceeded {
                    field: "replay.payload",
                    maximum: u64::from(self.limits.max_payload_bytes),
                    actual: payload_bytes,
                });
            }
            duration_micros = duration_micros.saturating_add(step.delay_micros);
            let maximum_duration_micros = self.limits.max_duration_ms.saturating_mul(1_000);
            if duration_micros > maximum_duration_micros {
                return Err(ContractError::LimitExceeded {
                    field: "replay.duration_micros",
                    maximum: maximum_duration_micros,
                    actual: duration_micros,
                });
            }
        }
        let rate_window_seconds = duration_micros.saturating_add(999_999) / 1_000_000;
        let rate_window_seconds = rate_window_seconds.max(1);
        let maximum_actions =
            u64::from(self.limits.max_rate_per_second).saturating_mul(rate_window_seconds);
        if self.plan.steps.len() as u64 > maximum_actions {
            return Err(ContractError::LimitExceeded {
                field: "replay.rate",
                maximum: maximum_actions,
                actual: self.plan.steps.len() as u64,
            });
        }
        // Peak-rate guard: the average check above does not bound a burst -- a plan
        // can front-load many zero-delay steps and pad the tail to keep the average
        // under the cap while blasting frames onto the bus in an instant. Enforce
        // that no 1-second sliding window over cumulative fire time contains more
        // than `max_rate_per_second` steps.
        let max_rate = u64::from(self.limits.max_rate_per_second);
        let mut fire_times: Vec<u64> = Vec::with_capacity(self.plan.steps.len());
        let mut fire = 0_u64;
        for step in &self.plan.steps {
            fire = fire.saturating_add(step.delay_micros);
            fire_times.push(fire);
        }
        let mut window_start = 0usize;
        for (index, &now) in fire_times.iter().enumerate() {
            if let Some(lower) = now.checked_sub(1_000_000) {
                while fire_times[window_start] <= lower {
                    window_start += 1;
                }
            }
            let in_window = (index - window_start + 1) as u64;
            if in_window > max_rate {
                return Err(ContractError::LimitExceeded {
                    field: "replay.peak_rate",
                    maximum: max_rate,
                    actual: in_window,
                });
            }
        }
        Ok(())
    }
}

/// Empty payload for capability negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequest {}

impl Validate for CapabilityRequest {
    fn validate(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

/// Request payload carried by a [`SchemaEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum AutomotiveRequest {
    /// Query adapter capabilities without touching an input artifact.
    Capabilities(CapabilityRequest),
    /// Decode a bounded immutable PCAP.
    AnalyzeCapture(AnalyzeCaptureRequest),
    /// Produce deterministic mutations from a staged artifact.
    GenerateMutations(MutationRequest),
    /// Derive a typed replay plan without executing it.
    BuildReplayPlan(ReplayPlanRequest),
    /// Execute an approved replay plan.
    ExecuteReplay(ReplayRequest),
}

impl Validate for AutomotiveRequest {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Capabilities(request) => request.validate(),
            Self::AnalyzeCapture(request) => request.validate(),
            Self::GenerateMutations(request) => request.validate(),
            Self::BuildReplayPlan(request) => request.validate(),
            Self::ExecuteReplay(request) => request.validate(),
        }
    }
}

/// Bounded capture-analysis result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureAnalysisResult {
    /// Decoded protocol.
    pub protocol: AutomotiveProtocol,
    /// Number of retained transcript events.
    pub event_count: u32,
    /// Immutable canonical transcript that can feed replay planning.
    pub transcript: ArtifactRef,
    /// Digest of the canonical transcript.
    pub transcript_hash: Sha256Digest,
    /// Unique protocol-state signatures observed in the capture.
    pub state_signatures: Vec<StateSignature>,
}

impl Validate for CaptureAnalysisResult {
    fn validate(&self) -> Result<(), ContractError> {
        positive_bounded(
            "analysis.event_count",
            u64::from(self.event_count),
            u64::from(MAX_EVENTS),
        )?;
        self.transcript.validate()?;
        if self.transcript.media_type != "application/vnd.hobot-fuzz.automotive-transcript+json" {
            return Err(ContractError::InvalidField {
                field: "analysis.transcript.media_type",
                reason: "expected a canonical automotive transcript artifact".to_owned(),
            });
        }
        self.transcript_hash.validate()?;
        if self.transcript.sha256 != self.transcript_hash.as_str() {
            return Err(ContractError::InconsistentField {
                field: "analysis.transcript.sha256",
                reason: "artifact digest does not match the canonical transcript digest".to_owned(),
            });
        }
        validate_states(self.protocol, &self.state_signatures)
    }
}

/// Deterministic mutation-generation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationResult {
    /// Mutated protocol.
    pub protocol: AutomotiveProtocol,
    /// Number of generated mutation cases.
    pub generated: u32,
    /// Optional canonical transcript when cases were decoded inline.
    pub transcript_hash: Option<Sha256Digest>,
    /// Immutable service-staged output artifacts.
    pub artifacts: Vec<ArtifactRef>,
}

impl Validate for MutationResult {
    fn validate(&self) -> Result<(), ContractError> {
        positive_bounded(
            "mutation.generated",
            u64::from(self.generated),
            u64::from(MAX_EVENTS),
        )?;
        if self.artifacts.is_empty() {
            return Err(ContractError::MissingField {
                field: "mutation.artifacts",
            });
        }
        if let Some(hash) = &self.transcript_hash {
            hash.validate()?;
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }
}

/// Replay execution result with deterministic evidence attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Executed protocol.
    pub protocol: AutomotiveProtocol,
    /// Executed mode.
    pub mode: AutomotiveMode,
    /// Number of actions in the approved plan.
    pub planned_events: u32,
    /// Number of actions completed before termination.
    pub executed_events: u32,
    /// Digest of the canonical observed transcript.
    pub transcript_hash: Sha256Digest,
    /// Unique protocol-state signatures observed during replay.
    pub state_signatures: Vec<StateSignature>,
    /// Whether every planned event completed normally.
    pub completed: bool,
}

impl Validate for ReplayResult {
    fn validate(&self) -> Result<(), ContractError> {
        positive_bounded(
            "replay.planned_events",
            u64::from(self.planned_events),
            u64::from(MAX_EVENTS),
        )?;
        if self.executed_events > self.planned_events {
            return Err(ContractError::InconsistentField {
                field: "replay.executed_events",
                reason: "executed count exceeds the approved plan".to_owned(),
            });
        }
        if self.completed && self.executed_events != self.planned_events {
            return Err(ContractError::InconsistentField {
                field: "replay.completed",
                reason: "completed replay must execute every planned event".to_owned(),
            });
        }
        self.transcript_hash.validate()?;
        validate_states(self.protocol, &self.state_signatures)
    }
}

/// Successful result payload carried by a [`SchemaEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum AutomotiveResult {
    /// Adapter capability report.
    Capabilities(CapabilityReport),
    /// Offline PCAP analysis.
    CaptureAnalysis(CaptureAnalysisResult),
    /// Generated mutation artifacts.
    Mutations(MutationResult),
    /// Deterministically generated replay plan.
    ReplayPlan(ReplayPlan),
    /// Virtual or physical replay outcome.
    Replay(ReplayResult),
}

impl Validate for AutomotiveResult {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Capabilities(result) => result.validate(),
            Self::CaptureAnalysis(result) => result.validate(),
            Self::Mutations(result) => result.validate(),
            Self::ReplayPlan(result) => result.validate(),
            Self::Replay(result) => result.validate(),
        }
    }
}

impl AutomotiveResult {
    fn transcript_hash(&self) -> Option<&Sha256Digest> {
        match self {
            Self::CaptureAnalysis(result) => Some(&result.transcript_hash),
            Self::Mutations(result) => result.transcript_hash.as_ref(),
            Self::Replay(result) => Some(&result.transcript_hash),
            Self::Capabilities(_) | Self::ReplayPlan(_) => None,
        }
    }
}

/// Stable machine-readable sidecar error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveErrorCode {
    /// Request failed domain validation.
    InvalidRequest,
    /// Envelope schema is unsupported.
    UnsupportedSchema,
    /// Requested protocol is unavailable.
    UnsupportedProtocol,
    /// Requested mode is unavailable.
    UnsupportedMode,
    /// Pinned adapter lacks a required operation capability.
    CapabilityUnavailable,
    /// Requested or observed data exceeded a hard limit.
    LimitExceeded,
    /// Human approval evidence is absent.
    ApprovalRequired,
    /// Service policy denied the operation.
    PolicyDenied,
    /// Adapter could not parse a transcript.
    MalformedTranscript,
    /// Sandboxed adapter reported an internal failure.
    AdapterFailure,
    /// Operation reached its time budget.
    TimedOut,
    /// Operator cancelled the operation.
    Cancelled,
}

/// Structured error payload emitted instead of a successful result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomotiveError {
    /// Stable machine-readable error code.
    pub code: AutomotiveErrorCode,
    /// Redacted human-readable explanation.
    pub message: String,
    /// Optional dotted field associated with the error.
    pub field: Option<String>,
    /// Whether retrying unchanged input may succeed.
    pub retryable: bool,
    /// Bounded, non-secret diagnostic attributes.
    pub details: BTreeMap<String, String>,
}

impl Validate for AutomotiveError {
    fn validate(&self) -> Result<(), ContractError> {
        nonempty_text("error.message", &self.message)?;
        if let Some(field) = &self.field {
            nonempty_text("error.field", field)?;
        }
        bounded_metadata("error.details", &self.details)
    }
}

/// Generic versioned JSONL message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEnvelope<T> {
    /// Contract schema version.
    pub schema_version: u16,
    /// Caller-generated correlation identifier.
    pub request_id: String,
    /// Request fields flattened beside the schema and correlation id.
    #[serde(flatten)]
    pub payload: T,
}

impl<T> SchemaEnvelope<T> {
    /// Wrap a payload in the current schema version.
    #[must_use]
    pub fn new(request_id: impl Into<String>, payload: T) -> Self {
        Self {
            schema_version: AUTOMOTIVE_SCHEMA_VERSION,
            request_id: request_id.into(),
            payload,
        }
    }
}

impl<T: Validate> Validate for SchemaEnvelope<T> {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != AUTOMOTIVE_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema {
                expected: AUTOMOTIVE_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        nonempty_text("envelope.request_id", &self.request_id)?;
        self.payload.validate()
    }
}

/// Exact JSONL response shape shared with the pinned sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    /// Contract schema version returned by the sidecar.
    pub schema_version: u16,
    /// Correlation identifier copied from the request.
    pub request_id: String,
    /// `true` when `result` is present and `error` is absent.
    pub ok: bool,
    /// Typed successful result.
    pub result: Option<AutomotiveResult>,
    /// Typed structured failure.
    pub error: Option<AutomotiveError>,
    /// Optional canonical transcript digest returned by the sidecar.
    pub transcript_sha256: Option<Sha256Digest>,
}

impl ResponseEnvelope {
    /// Build a successful response.
    #[must_use]
    pub fn success(
        request_id: impl Into<String>,
        result: AutomotiveResult,
        transcript_sha256: Option<Sha256Digest>,
    ) -> Self {
        Self {
            schema_version: AUTOMOTIVE_SCHEMA_VERSION,
            request_id: request_id.into(),
            ok: true,
            result: Some(result),
            error: None,
            transcript_sha256,
        }
    }

    /// Build a failed response, optionally retaining partial transcript evidence.
    #[must_use]
    pub fn failure(
        request_id: impl Into<String>,
        error: AutomotiveError,
        transcript_sha256: Option<Sha256Digest>,
    ) -> Self {
        Self {
            schema_version: AUTOMOTIVE_SCHEMA_VERSION,
            request_id: request_id.into(),
            ok: false,
            result: None,
            error: Some(error),
            transcript_sha256,
        }
    }
}

impl Validate for ResponseEnvelope {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != AUTOMOTIVE_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema {
                expected: AUTOMOTIVE_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        nonempty_text("response.request_id", &self.request_id)?;
        match (self.ok, &self.result, &self.error) {
            (true, Some(result), None) => {
                result.validate()?;
                if result.transcript_hash() != self.transcript_sha256.as_ref() {
                    return Err(ContractError::InconsistentField {
                        field: "response.transcript_sha256",
                        reason: "response digest must match the typed result".to_owned(),
                    });
                }
            }
            (false, None, Some(error)) => error.validate()?,
            _ => {
                return Err(ContractError::InconsistentField {
                    field: "response.ok",
                    reason: "success requires only result; failure requires only error".to_owned(),
                });
            }
        }
        if let Some(hash) = &self.transcript_sha256 {
            hash.validate()?;
        }
        Ok(())
    }
}

fn validate_states(
    protocol: AutomotiveProtocol,
    states: &[StateSignature],
) -> Result<(), ContractError> {
    let mut digests = BTreeSet::new();
    for state in states {
        state.validate()?;
        if state.protocol != protocol {
            return Err(ContractError::InconsistentField {
                field: "result.state_signatures.protocol",
                reason: "state signature protocol does not match the result".to_owned(),
            });
        }
        if !digests.insert(&state.digest) {
            return Err(ContractError::InconsistentField {
                field: "result.state_signatures",
                reason: "state signature digests must be unique".to_owned(),
            });
        }
    }
    Ok(())
}
