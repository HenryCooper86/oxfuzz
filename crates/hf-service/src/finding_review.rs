//! Durable, read-only finding review views.

use hf_core::crash::{Crash, CrashOrigin};
use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::finding_proof::{CasrExploitabilityDetermination, FindingProofCard};
use crate::triage_disposition::{Disposition, TriageDisposition};

/// Which dispositions a review queue includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "mode", content = "value")]
pub enum FindingDispositionFilter {
    /// Every unfinished finding. This is the safe operator default.
    #[default]
    Open,
    /// All retained findings, including resolved history.
    All,
    /// One exact disposition.
    Only(Disposition),
}

/// Typed filters owned and applied by the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingReviewFilter {
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    #[serde(default)]
    pub disposition: FindingDispositionFilter,
    pub origin: Option<CrashOrigin>,
    pub severity: Option<CasrExploitabilityDetermination>,
}

/// Exact retained evidence and service-derived review state for one finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingReviewItem {
    pub crash: Crash,
    pub project_root: String,
    pub target_id: Uuid,
    pub target_symbol: String,
    /// Workspace selector recovered from this finding's exact retained run.
    pub target_selector: String,
    pub target_language: TargetLanguage,
    pub engine: EngineKind,
    pub proof: FindingProofCard,
    pub disposition: TriageDisposition,
    /// Current report, reproduction, and `DefectDojo` operations all select the
    /// latest target run. Presentations must disable them for older evidence.
    pub latest_scoped_actions_allowed: bool,
    pub latest_scoped_action_reason: Option<String>,
}
