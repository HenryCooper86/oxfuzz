//! The result of a harness repair requested from a retained finding.
//!
//! See `docs/design/harness-generation-design.md`, section 5.2.

use hf_storage::FindingHarnessRepairOutcome;
use serde::Serialize;
use uuid::Uuid;

/// What one finding-driven repair produced. A proposal replaces nothing: it
/// must be adopted, reviewed, smoke-qualified, and promoted like any revision.
#[derive(Debug, Clone, Serialize)]
pub struct FindingHarnessRepair {
    /// The retained repair record.
    pub repair_id: Uuid,
    /// How the repair finished.
    pub outcome: FindingHarnessRepairOutcome,
    /// Why it finished that way.
    pub detail: String,
    /// The compiled proposal revision, for a `Proposed` outcome only.
    pub harness_id: Option<Uuid>,
    /// Target selector that adopting the proposal takes.
    pub target: String,
    /// Engine name that adopting the proposal takes.
    pub engine: String,
    /// Language name that adopting the proposal takes.
    pub lang: String,
    /// Compile repairs applied to the proposal.
    pub repairs_used: usize,
}
