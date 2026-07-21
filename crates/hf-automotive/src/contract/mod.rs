//! Versioned automotive sidecar contract.

mod canonical;
mod model;
mod validation;

pub use canonical::{canonical_transcript_hash, Sha256Digest, StateSignature};
pub use model::{
    AnalyzeCaptureRequest, ArtifactRef, AutomotiveCapability, AutomotiveError, AutomotiveErrorCode,
    AutomotiveMode, AutomotiveProtocol, AutomotiveRequest, AutomotiveResult, CapabilityReport,
    CapabilityRequest, CaptureAnalysisResult, LiveMonitorRequest, MessageDirection, ModeConfig,
    MutationRequest, MutationResult, OperationLimits, ProtocolMessage, ReplayAction, ReplayPlan,
    ReplayPlanRequest, ReplayRequest, ReplayResult, ReplayStep, ResponseEnvelope, SchemaEnvelope,
    TranscriptEvent,
};
pub use validation::{ContractError, Validate, AUTOMOTIVE_SCHEMA_VERSION};
