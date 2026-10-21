//! Bounded, modeled Static Analyzer observations and evidence references for plans.
use super::{ClangFunctionId, ClangLocation};
use serde::{Deserialize, Serialize};

/// Explicitly resolved LLVM exploration and evidence collection limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangExplorationLimits {
    /// Analyzer nodes per top-level function.
    pub max_nodes: u32,
    /// Visits to one block on a path.
    pub max_block_visits: u32,
    /// Combined call and branch observation ceiling.
    pub max_records: usize,
    /// Total retained CFG block ceiling.
    pub max_cfg_blocks: usize,
    /// Maximum analyzer inline stack depth.
    pub max_inline_depth: u32,
}

impl ClangExplorationLimits {
    /// Validate limits received from configuration or foreign helper output.
    ///
    /// # Errors
    /// Returns the name of an out-of-range limit.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, maximum) in [
            ("max_nodes", u64::from(self.max_nodes), 1_000_000),
            ("max_block_visits", u64::from(self.max_block_visits), 64),
            ("max_records", self.max_records as u64, 10_000),
            ("max_cfg_blocks", self.max_cfg_blocks as u64, 100_000),
            ("max_inline_depth", u64::from(self.max_inline_depth), 16),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!(
                    "clang_analysis.exploration.{name} is outside its accepted range"
                ));
            }
        }
        Ok(())
    }
}

/// A source condition; parameter references are syntactic uses only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangCondition {
    /// Physical project source coordinate.
    pub location: ClangLocation,
    /// Bounded source text, absent when unavailable.
    pub text: Option<String>,
    /// Indices into the owning function's parameters.
    pub parameters: Vec<usize>,
}

/// One compiler CFG block, with explicitly pruned successors represented by null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangCfgBlock {
    /// Function-local block identity.
    pub id: u32,
    /// Reachable successor IDs; null denotes a pruned successor.
    pub successors: Vec<Option<u32>>,
    /// Terminator condition, when present.
    pub condition: Option<ClangCondition>,
}

/// Availability of a function's compiler CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClangCfgStatus {
    /// The complete block collection was retained.
    Complete,
    /// Clang could not build a CFG.
    Unavailable,
    /// The whole CFG was omitted for the block budget.
    Truncated,
}

/// Located CFG for one selected root definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangCfg {
    /// Owning root definition.
    pub function: ClangFunctionId,
    /// Collection availability.
    pub status: ClangCfgStatus,
    /// Complete blocks, or empty when unavailable/truncated.
    pub blocks: Vec<ClangCfgBlock>,
}

/// Projected range/nullness for an original root parameter in one analyzer state.
/// Holes, inter-parameter relations and other path predicates are not retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangInputConstraint {
    /// Root parameter index.
    pub parameter: usize,
    /// Inclusive decimal minimum; null means unknown.
    pub min: Option<String>,
    /// Inclusive decimal maximum; null means unknown.
    pub max: Option<String>,
    /// Modeled pointer nullness; null means unknown.
    pub nonnull: Option<bool>,
}

/// A previous call that produced the symbol subsequently passed as an argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangValueProducer {
    /// Producer declaration identity; implies no ownership semantics.
    pub function: ClangFunctionId,
    /// Producer call-site coordinate.
    pub location: ClangLocation,
}

/// One modeled argument's parameter origins, concrete scalar, or producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangArgumentFlow {
    /// Call argument index.
    pub argument: usize,
    /// Original root parameter indices; an empty list means unknown provenance.
    pub parameters: Vec<usize>,
    /// Concrete decimal scalar when known.
    pub constant: Option<String>,
    /// Symbol identity relation to an earlier return value when known.
    pub producer: Option<ClangValueProducer>,
}

/// A call visited by the symbolic engine, not proof of concrete execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangCallWitness {
    /// Selected top-level analysis root.
    pub root: ClangFunctionId,
    /// Current inline frame.
    pub caller: ClangFunctionId,
    /// Resolved declaration, if available.
    pub callee: Option<ClangFunctionId>,
    /// Physical call-site coordinate.
    pub location: ClangLocation,
    /// Modeled argument observations.
    pub arguments: Vec<ClangArgumentFlow>,
    /// Original root inputs under this state.
    pub constraints: Vec<ClangInputConstraint>,
    /// Root through current inline frame, followed by the callee when resolved.
    pub path: Vec<ClangFunctionId>,
}

/// Branch assumptions under a particular analyzer state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangBranchObservation {
    /// Selected analysis root.
    pub root: ClangFunctionId,
    /// Function containing the condition.
    pub caller: ClangFunctionId,
    /// Source condition, with syntactic parameter references.
    pub condition: ClangCondition,
    /// Incomplete input-range projection before the branch assumption.
    pub constraints: Vec<ClangInputConstraint>,
    /// Whether assuming true in the full analyzer state yielded a state.
    pub true_state: bool,
    /// Whether assuming false in the full analyzer state yielded a state.
    pub false_state: bool,
}

/// Versioned, bounded observations from the LLVM Static Analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangExploration {
    /// Checker and constraint interpretation identity.
    pub engine: String,
    /// Exact resolved invocation limits.
    pub limits: ClangExplorationLimits,
    /// Selected unit-qualified root definitions.
    pub roots: Vec<ClangFunctionId>,
    /// Selected root CFG records.
    pub cfgs: Vec<ClangCfg>,
    /// Modeled calls; absence never establishes unreachability.
    pub calls: Vec<ClangCallWitness>,
    /// State-specific branch observations.
    pub branches: Vec<ClangBranchObservation>,
    /// Analyzer or collection limits left work unreported.
    pub exhausted: bool,
    /// Observations omitted from helper output or context.
    pub omitted_records: usize,
}

/// Reference to an argument in a retained context call witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangPlanArgument {
    /// Index into context.exploration.calls.
    pub call: usize,
    /// Argument index in that witness.
    pub argument: usize,
}

/// Evidence references for harness authoring; alternatives must remain alternatives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangHarnessPlan {
    /// Arguments with observed root input provenance.
    pub inputs: Vec<ClangPlanArgument>,
    /// Indices into retained branch observations for guard-aware generation.
    pub guards: Vec<usize>,
    /// Observed producer/use relations; do not imply setup or cleanup duties.
    pub producer_uses: Vec<ClangPlanArgument>,
    /// Indices into context.paths for externally accessible caller candidates.
    pub caller_paths: Vec<usize>,
}
