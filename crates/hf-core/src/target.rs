//! Fuzzing target taxonomy.
//!
//! See `docs/standards/TARGET_TAXONOMY.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// The language of a fuzzing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetLanguage {
    C,
    Cpp,
    Rust,
    Go,
    Python,
}

/// The kind of fuzzing target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    Function,
    Parser,
    ApiEntry,
    Ffi,
}

/// The input surface of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputSurface {
    Bytes,
    Structured,
    File,
    Stdin,
}

/// The sanitizer to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sanitizer {
    None,
    Address,
    Undefined,
    Memory,
    Thread,
}

/// A source location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
}

/// A candidate fuzzing target produced by `hf-discovery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCandidate {
    pub id: Uuid,
    pub project_root: PathBuf,
    pub language: TargetLanguage,
    pub symbol: String,
    pub kind: TargetKind,
    pub location: SourceLocation,
    pub signature: Option<String>,
    pub input_surface: InputSurface,
    pub complexity: u32,
    pub fit_score: f64,
    pub sanitizers: Vec<Sanitizer>,
    pub rationale: String,
}

/// A ranked inventory of fuzzing targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInventory {
    pub project_root: PathBuf,
    pub candidates: Vec<TargetCandidate>,
}

impl TargetInventory {
    /// Returns candidates sorted by fit score descending.
    #[must_use]
    pub fn ranked(&self) -> Vec<&TargetCandidate> {
        let mut sorted: Vec<&TargetCandidate> = self.candidates.iter().collect();
        sorted.sort_by(|a, b| {
            b.fit_score
                .partial_cmp(&a.fit_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }
}
