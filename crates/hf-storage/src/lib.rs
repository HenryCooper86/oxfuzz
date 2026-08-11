//! hf-storage: `SQLite` storage and persistence for `oxfuzz`.
//!
//! Implements the schema in `docs/standards/DATABASE_SCHEMA.md` on top of
//! `sqlx` + `SQLite`. The [`Store`] type owns a connection pool, runs
//! forward-only migrations on connect, and exposes typed repository methods for
//! runs, targets, harnesses, crashes, and corpus entries.

mod store;

pub mod checkpoint_store;
mod retired_engine;
mod schedule_occurrence_store;
pub mod session_store;
pub mod transcript;
pub mod transcript_display;

pub use checkpoint_store::SqliteChatCheckpointStore;
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
    AutomotiveStateCorpusRecord, GuardrailDecisionRecord, HarnessApprovalKind,
    HarnessApprovalRecord, ProjectAutoRevert, RunKind, RunRecord, RunStatus, SemgrepFindingRecord,
    SemgrepFindingSeverity, SemgrepPublication, SemgrepRunRecord, SemgrepRunStatus,
    SemgrepTargetScoreRecord, StorageError, Store,
};
pub use transcript::JsonlTranscriptStore;
pub use transcript_display::JsonlDisplayTranscriptStore;
