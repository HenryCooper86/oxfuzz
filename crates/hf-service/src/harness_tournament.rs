//! Evaluate several harness candidates for one target and rank them on what
//! actually happened in the sandbox.
//!
//! One draft is a sample of one. This module generates a bounded set of
//! candidates, takes each through the existing compile-with-repair and smoke
//! paths, retains every candidate's evidence, and ranks them deterministically.
//! No model opinion enters the ranking, and the tournament never promotes: it
//! is an input to the existing human promotion decision, not a substitute.
//!
//! See `docs/design/harness-generation-design.md`, section 6.

use serde::Serialize;

use crate::verification::VerdictLevel;

/// Schema version of the tournament result.
pub const HARNESS_TOURNAMENT_SCHEMA_VERSION: u32 = 1;

/// Largest tournament accepted. Each candidate costs a model call, a sandbox
/// compile, and a sandbox smoke run, so an unbounded tournament is an unbounded
/// bill.
pub const MAX_CANDIDATES: usize = 5;

/// Where a candidate's source came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOrigin {
    /// The deterministic template draft. Always included, so a tournament whose
    /// model drafts all fail still leaves something that builds.
    Heuristic,
    /// An independent LLM draft.
    Llm,
}

/// What a candidate's smoke run showed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SmokeEvidence {
    pub verdict: VerdictLevel,
    pub execs_per_sec: f64,
    pub crashes: u32,
}

/// Everything retained about one candidate, win or lose. An operator cannot
/// judge a selection without seeing what it beat.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HarnessCandidateEvidence {
    pub index: usize,
    pub origin: CandidateOrigin,
    /// Digest of the exact source, so the candidate is reconstructable.
    pub source_sha256: String,
    pub compiled: bool,
    /// Repair passes applied before it built.
    pub repairs_used: usize,
    /// Bounded compile diagnostics when it did not build.
    pub compile_error: Option<String>,
    /// Present only for a candidate that compiled and was smoke-qualified.
    pub smoke: Option<SmokeEvidence>,
}

/// Request to evaluate several harness candidates for one target.
#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct HarnessTournamentRequest {
    pub project: String,
    pub target: String,
    pub engine: hf_core::engine::EngineKind,
    pub lang: hf_core::target::TargetLanguage,
    /// Number of candidates, including the deterministic baseline. Bounded by
    /// [`MAX_CANDIDATES`].
    pub candidates: usize,
    pub max_repairs: usize,
}

/// Service-owned result of one tournament. Retains every candidate, win or
/// lose, and promotes nothing.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessTournamentResult {
    pub schema_version: u32,
    pub candidates: Vec<HarnessCandidateEvidence>,
    /// Candidate indices, best first.
    pub ranking: Vec<usize>,
    /// Best candidate that actually compiled, if any.
    pub winner_index: Option<usize>,
    /// Always false. Promotion stays the existing explicit human step.
    pub promoted: bool,
}

/// Rank candidates best-first, returning their [`HarnessCandidateEvidence::index`]
/// values rather than positions in the slice, so a ranking identifies candidates
/// however the caller ordered them.
///
/// Deterministic and objective, in sequence: compiled before not compiled;
/// smoke verdict `Pass` before `Suspect` before `Fail` or absent; fewer repair
/// passes; higher executions per second; then lower candidate index so equal
/// evidence yields a stable order.
///
/// Throughput is a tie-break among candidates that already passed, never a
/// primary signal: a harness that does nothing quickly is not better than one
/// that does the right thing.
#[must_use]
pub fn rank_candidates(candidates: &[HarnessCandidateEvidence]) -> Vec<usize> {
    let mut order: Vec<&HarnessCandidateEvidence> = candidates.iter().collect();
    order.sort_by(|a, b| {
        b.compiled
            .cmp(&a.compiled)
            .then_with(|| verdict_rank(b).cmp(&verdict_rank(a)))
            .then_with(|| a.repairs_used.cmp(&b.repairs_used))
            .then_with(|| {
                throughput(b)
                    .partial_cmp(&throughput(a))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.index.cmp(&b.index))
    });
    order.into_iter().map(|candidate| candidate.index).collect()
}

/// Higher is better. An absent smoke result ranks below every real verdict:
/// a candidate that was never qualified has not shown anything.
fn verdict_rank(candidate: &HarnessCandidateEvidence) -> u8 {
    match candidate.smoke.map(|smoke| smoke.verdict) {
        Some(VerdictLevel::Pass) => 3,
        Some(VerdictLevel::Suspect) => 2,
        Some(VerdictLevel::Fail) => 1,
        None => 0,
    }
}

fn throughput(candidate: &HarnessCandidateEvidence) -> f64 {
    candidate.smoke.map_or(0.0, |smoke| smoke.execs_per_sec)
}
