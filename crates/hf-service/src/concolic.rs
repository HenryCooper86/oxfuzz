//! Service-owned concolic corpus enrichment.
//!
//! Mutation cannot guess a value it has to match. Concolic execution runs a
//! real input while recording the path constraints the program tests, negates
//! one, and asks a solver for an input taking the other branch.
//!
//! See `docs/design/concolic-enrichment-design.md`.
//!
//! This module is the pure part: which inputs a pass explores under its bounds,
//! and what the pass produced. Building and running the instrumented binary is
//! `container::concolic`, because it goes through `hf-runtime`.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ConcolicSettings;

/// Current serialized concolic enrichment schema.
pub const CONCOLIC_SCHEMA_VERSION: u32 = 1;

/// Whether the toolchain is present to run a pass at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConcolicAvailability {
    /// The sandbox image has no `SymCC` wrapper. Distinct from a pass that ran
    /// and solved nothing.
    Unavailable {
        /// Stable reason code.
        reason: String,
    },
    /// The toolchain answered a version probe.
    Available,
}

/// Why a pass stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConcolicStopReason {
    /// Every selected input was explored.
    CorpusExhausted,
    /// `max_inputs` was reached.
    InputCap,
    /// `max_solved_inputs` was reached.
    SolvedInputCap,
    /// `total_timeout_secs` elapsed.
    TotalTimeout,
}

/// What one pass produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConcolicOutcome {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// Inputs actually explored.
    pub inputs_explored: usize,
    /// Inputs a bound kept the pass from exploring.
    pub inputs_skipped: usize,
    /// Inputs the solver produced.
    pub inputs_solved: usize,
    /// Of those, how many the corpus did not already hold. This is the number
    /// that matters: a solver returning inputs already present has enriched
    /// nothing, and reporting only `inputs_solved` would present that as a
    /// success.
    pub inputs_novel: usize,
    /// Which bound stopped the pass.
    pub stop_reason: ConcolicStopReason,
    /// Corpus entry count before the fold.
    pub corpus_size_before: usize,
    /// Corpus entry count after it, counted from the corpus rather than added
    /// up from `inputs_novel`. A pass that enriched nothing leaves this equal
    /// to `corpus_size_before`, which is the honest reading of it.
    pub corpus_size_after: usize,
}

/// The corpus content digest, matching what the corpus uses for identity.
#[must_use]
pub fn content_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// The inputs a pass explores, and how many its bound left out.
///
/// Selection is a prefix of the corpus in its retained order rather than a
/// sample: a pass must be reproducible from the same corpus, and a random
/// sample would make two passes over identical state disagree.
#[must_use]
pub fn select_inputs(corpus: &[PathBuf], settings: &ConcolicSettings) -> (Vec<PathBuf>, usize) {
    let take = corpus.len().min(settings.max_inputs);
    (corpus[..take].to_vec(), corpus.len() - take)
}

/// Summarize a pass, capping retained solved inputs and counting the novel ones.
///
/// `stop` is reported verbatim. The caller runs the exploration loop and is the
/// only party that knows which bound it stopped on; deriving
/// [`ConcolicStopReason::SolvedInputCap`] here from `solved.len()` would
/// overwrite a real [`ConcolicStopReason::TotalTimeout`] with a cap that had
/// merely truncated a collection, and section 6 asks the reason to name the
/// bound that actually ended the pass.
#[must_use]
pub fn summarize<S: std::hash::BuildHasher>(
    explored: usize,
    skipped: usize,
    solved: &[Vec<u8>],
    existing_digests: &HashSet<String, S>,
    settings: &ConcolicSettings,
    stop: ConcolicStopReason,
) -> ConcolicOutcome {
    let novel = solved
        .iter()
        .filter(|bytes| !existing_digests.contains(&content_digest(bytes)))
        .take(settings.max_solved_inputs)
        .count();
    ConcolicOutcome {
        schema_version: CONCOLIC_SCHEMA_VERSION,
        inputs_explored: explored,
        inputs_skipped: skipped,
        inputs_solved: solved.len(),
        inputs_novel: novel,
        stop_reason: stop,
        corpus_size_before: 0,
        corpus_size_after: 0,
    }
}

impl ConcolicOutcome {
    /// Record the corpus sizes measured on both sides of the fold.
    ///
    /// Both sizes are counted from the corpus itself rather than derived from
    /// `corpus_size_before + inputs_novel`. The two diverge whenever solved
    /// inputs within one batch are byte-identical -- they each count as novel
    /// yet collapse onto one corpus path -- or when a write does not land.
    /// Reporting growth that did not happen is the single thing section 6
    /// exists to stop.
    #[must_use]
    pub fn with_corpus_sizes(mut self, before: usize, after: usize) -> Self {
        self.corpus_size_before = before;
        self.corpus_size_after = after;
        self
    }
}
