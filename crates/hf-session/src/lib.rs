//! hf-session: Session lifecycle manager — state machine, checkpoints, transcripts.
//!
//! This crate provides the high-level session management layer:
//!
//! - [`SessionManager`] — facade for session CRUD, state transitions, and transcripts
//! - [`CanonicalSessionManager`] — cross-channel session management
//! - [`ChatCheckpointManager`] — turn-level checkpoint and rollback
//! - [`StateMachine`] — validates session state transitions
//! - [`SessionConfig`] — tree depth limits and compaction thresholds

pub mod canonical;
pub mod checkpoint;
pub mod config;
pub mod error;
pub mod manager;
pub mod state_machine;

// Re-export primary types.
pub use canonical::{CanonicalConfig, CanonicalSessionManager, Channel};
pub use checkpoint::{ChatCheckpointManager, RollbackResult};
pub use config::SessionConfig;
pub use error::SessionManagerError;
pub use manager::{SessionManager, TranscriptSnapshot};
pub use state_machine::StateMachine;
