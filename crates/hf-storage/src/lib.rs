//! hf-storage: `SQLite` storage and persistence for `oxfuzz`.
//!
//! Implements the schema in `docs/standards/DATABASE_SCHEMA.md` on top of
//! `sqlx` + `SQLite`. The [`Store`] type owns a connection pool, runs
//! forward-only migrations on connect, and exposes typed repository methods for
//! runs, targets, harnesses, crashes, and corpus entries.

mod build_profile_store;
mod store;
mod work_order_store;

pub mod checkpoint_store;
mod remediation_store;
mod retired_engine;
mod schedule_occurrence_store;
pub mod session_store;
pub mod transcript;
pub mod transcript_display;

pub use build_profile_store::{
    BuildDependency, BuildDependencyKind, BuildDependencyStatus, BuildDiagnosisEvidence,
    BuildDiagnosisOperation, BuildDiagnosisRecord, BuildDiagnosisStatus, BuildPlanEvidence,
    BuildPlanStepEvidence, BuildProfileState, BuildSystemEvidence, BuildTerminalEvidence,
    BuildTerminalStatus, DetectedBuildStatus, DetectedBuildSystem, ExpectedHarnessBuildIdentity,
    HarnessBuildContextEvidence, HarnessBuildContextRecord, HarnessBuildInputsRecord,
    ProfileBuildSystem, ProjectBuildProfileRecord, MAX_BUILD_DIAGNOSIS_HISTORY,
    MAX_BUILD_JSON_BYTES,
};
pub use checkpoint_store::SqliteChatCheckpointStore;
pub use remediation_store::{
    RemediationOperationCompletion, RemediationOperationRecord, RemediationOperationStage,
    RemediationOperationStatus,
};
pub use retired_engine::{
    validate_schedule_retirement_ids, validate_schedule_retirement_manifest,
    validate_schedule_retirement_operation_id, ScheduleRetirementHistoryProof,
    ValidatedScheduleRetirementManifest,
};
pub use schedule_occurrence_store::{
    NewScheduleOccurrence, ScheduleOccurrenceAcknowledgement, ScheduleOccurrenceInspection,
    ScheduleOccurrenceRecord, ScheduleOccurrenceReservation, ScheduleOccurrenceTransition,
    ScheduleOccurrenceTransitionResult,
};
pub use session_store::SqliteSessionStore;
pub use store::{
    AutoRevertEvent, AutomotiveOperationRecord, AutomotiveOperationStatus,
    AutomotiveStateCorpusRecord, CampaignHealthEventPageRecord, CampaignHealthEventRecord,
    CampaignHealthEvidenceRecord, GuardrailDecisionRecord, HarnessAiReviewRecord,
    HarnessApprovalKind, HarnessApprovalRecord, ProjectAutoRevert, PromotedHarness,
    RetainedHealthSample, RunKind, RunRecord, RunStatus, RunTelemetryRecord, SemgrepFindingRecord,
    SemgrepFindingSeverity, SemgrepPublication, SemgrepRunRecord, SemgrepRunStatus,
    SemgrepTargetScoreRecord, StorageError, Store, MAX_CAMPAIGN_HEALTH_EVENT_PAGE_SIZE,
    MAX_CAMPAIGN_HEALTH_SAMPLES,
};
pub use transcript::JsonlTranscriptStore;
pub use transcript_display::JsonlDisplayTranscriptStore;
pub use work_order_store::{
    HarnessWorkOrderAttemptCompletion, HarnessWorkOrderAttemptRecord, HarnessWorkOrderAttemptStage,
    HarnessWorkOrderAttemptStatus, HarnessWorkOrderRecord, HarnessWorkOrderSubmissionInsertError,
    HarnessWorkOrderSubmissionRecord, MAX_WORK_ORDER_RANK_ATTEMPTS, MAX_WORK_ORDER_SUBMISSIONS,
};
