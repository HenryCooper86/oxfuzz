//! Persisted native custom-mutator identity and bounded smoke observations.

use serde::{Deserialize, Serialize};

/// Existing upstream native callback API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutatorApi {
    AflPlusPlus,
    LibFuzzer,
}

/// Mutator artifact belonging to one reviewed harness revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedMutatorArtifact {
    pub version: u32,
    pub api: MutatorApi,
    pub source_sha256: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub sandbox_image_id: String,
    pub custom_trim: bool,
    pub self_test: Option<MutatorSelfTest>,
}

/// Observations from the real engine's bounded qualification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutatorSelfTest {
    /// Exit status of the bounded engine process after the observation.
    pub exit_code: i32,
    pub mutation_observed: bool,
    pub trim_observed: bool,
    pub log: String,
    pub log_truncated: bool,
    /// The report line of the crash in the target the run ended on, after
    /// the mutation callback ran, with no mutator callback on the crash
    /// stack. A target with known findings reaches its bug again through
    /// mutated inputs; that is a finding about the target, not a fault of
    /// the mutator. `None` when the run did not end that way, and on records
    /// written before this was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_finding: Option<String>,
}

impl MutatorSelfTest {
    /// Whether this self-test qualifies the mutator: its callback ran, and
    /// the run either ended cleanly or on a target finding.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.mutation_observed && (self.exit_code == 0 || self.target_finding.is_some())
    }
}
