//! Optional compiler-resolved C/C++ harness evidence.
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | settings | Validated operation policy |
//! | inputs | Per-unit compiler invocation normalization |
//! | snapshot | Bounded immutable input capture and freshness |
pub(crate) mod inputs;
mod settings;
pub(crate) mod snapshot;
pub use crate::config::parse_clang_analysis_settings;
use hf_core::target::TargetLanguage;
use serde::{Deserialize, Serialize};
pub use settings::{ClangAnalysisSettings, ClangExplorationSettings};
use std::path::PathBuf;
use uuid::Uuid;

/// Explicit request for compiler analysis of persisted discovery targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartClangAnalysisRequest {
    /// Canonicalized existing project directory.
    pub project: PathBuf,
    /// Supported C/C++ language.
    pub language: TargetLanguage,
    /// Selected candidate IDs; empty selects the configured heuristic shortlist.
    pub target_ids: Vec<Uuid>,
}

pub use hf_storage::{ClangOperationRecord, ClangOperationState, ClangResultRecord};
