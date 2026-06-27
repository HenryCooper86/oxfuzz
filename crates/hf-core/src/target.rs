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

impl std::str::FromStr for TargetLanguage {
    type Err = String;

    /// Parse a language name (case-insensitive, with common aliases). Unknown
    /// names are rejected so entrypoints fail uniformly rather than silently
    /// defaulting to C.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "c" => Ok(Self::C),
            "cpp" | "c++" | "cxx" => Ok(Self::Cpp),
            "rust" | "rs" => Ok(Self::Rust),
            "go" | "golang" => Ok(Self::Go),
            "python" | "py" => Ok(Self::Python),
            other => Err(format!(
                "unknown target language '{other}' (expected one of: \
                 c, cpp, rust, go, python)"
            )),
        }
    }
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
    /// Project functions transitively reachable from this one (direct calls,
    /// capped). Empty until reachability analysis runs.
    #[serde(default)]
    pub reachable_functions: Vec<String>,
    /// Cyclomatic complexity of this function plus all reachable functions --
    /// how much code fuzzing this target exercises.
    #[serde(default)]
    pub accumulated_complexity: u32,
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
