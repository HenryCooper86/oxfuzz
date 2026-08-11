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

impl TargetLanguage {
    /// The canonical id used on the wire, in configs, and on the command line.
    /// Round-trips through [`std::str::FromStr`], so a value handed to a frontend
    /// comes back parseable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Python => "python",
        }
    }

    /// Source-file extensions (without the dot) that belong to this language.
    /// The single source of truth for the discovery scanners; the
    /// [`LanguageBackend`] trait delegates here.
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::C => &["c", "h"],
            Self::Cpp => &["cc", "cpp", "cxx", "hpp", "hh"],
            Self::Rust => &["rs"],
            Self::Go => &["go"],
            Self::Python => &["py"],
        }
    }

    /// The generated harness source filename (e.g. `harness.c`).
    #[must_use]
    pub const fn harness_filename(self) -> &'static str {
        match self {
            Self::C => "harness.c",
            Self::Cpp => "harness.cc",
            Self::Rust => "harness.rs",
            Self::Go => "harness.go",
            Self::Python => "harness.py",
        }
    }

    /// Whether a target in this language compiles to a libFuzzer binary, so the
    /// libFuzzer can drive it.
    #[must_use]
    pub const fn libfuzzer_compatible(self) -> bool {
        matches!(self, Self::C | Self::Cpp | Self::Rust)
    }
}

/// Per-language facts the fuzzing pipeline dispatches on: source extensions, the
/// harness filename, and whether the language compiles to a libFuzzer binary.
///
/// Centralizing these makes [`TargetLanguage`] the single source of truth,
/// replacing the `match TargetLanguage` arms that were scattered across the
/// discovery, harness, and engine crates. Adding a language means adding a
/// variant plus one arm to each method here -- not editing every dispatch site.
pub trait LanguageBackend {
    /// Source-file extensions (without the dot) that belong to this language.
    fn extensions(&self) -> &'static [&'static str];
    /// The generated harness source filename (e.g. `harness.c`).
    fn harness_filename(&self) -> &'static str;
    /// Whether a target in this language compiles to a libFuzzer binary, so the
    /// libFuzzer can drive it.
    fn libfuzzer_compatible(&self) -> bool;
}

impl LanguageBackend for TargetLanguage {
    fn extensions(&self) -> &'static [&'static str] {
        (*self).extensions()
    }

    fn harness_filename(&self) -> &'static str {
        (*self).harness_filename()
    }

    fn libfuzzer_compatible(&self) -> bool {
        (*self).libfuzzer_compatible()
    }
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
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub end_col: Option<u32>,
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

impl TargetCandidate {
    /// The defining file relative to the canonical project root, falling back
    /// to the stored path verbatim when it lies outside the root (or is
    /// already relative). This is the file component of the persistence
    /// identity `(project_root, file, symbol)` and of the `file::symbol`
    /// qualifier accepted by target resolution.
    #[must_use]
    pub fn relative_file(&self) -> String {
        self.location
            .file
            .strip_prefix(&self.project_root)
            .unwrap_or(&self.location.file)
            .to_string_lossy()
            .into_owned()
    }
}

/// A ranked inventory of fuzzing targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInventory {
    pub project_root: PathBuf,
    pub candidates: Vec<TargetCandidate>,
    /// Project-only call adjacency (`caller -> direct project callees`), for the
    /// call-tree view. Empty until reachability/scanning populates it.
    #[serde(default)]
    pub call_graph: std::collections::HashMap<String, Vec<String>>,
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

#[cfg(test)]
mod tests {
    use super::{
        InputSurface, LanguageBackend, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use std::path::PathBuf;

    fn candidate(project_root: &str, file: &str) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: PathBuf::from(project_root),
            language: TargetLanguage::C,
            symbol: "parse_opts".to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from(file),
                line: 1,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: 0.5,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        }
    }

    #[test]
    fn source_location_reads_legacy_json_without_end_coordinates() {
        let location: SourceLocation =
            serde_json::from_str(r#"{"file":"src/parser.c","line":4,"col":1}"#).unwrap();
        assert_eq!(location.end_line, None);
        assert_eq!(location.end_col, None);
    }

    #[test]
    fn language_backend_delegates_to_inherent_facts() {
        for lang in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            // The trait is a thin, dyn-capable view over the inherent const
            // methods -- both must agree so the single source of truth holds.
            assert_eq!(LanguageBackend::extensions(&lang), lang.extensions());
            assert_eq!(
                LanguageBackend::harness_filename(&lang),
                lang.harness_filename()
            );
            assert_eq!(
                LanguageBackend::libfuzzer_compatible(&lang),
                lang.libfuzzer_compatible()
            );
            // The harness filename carries a matching extension.
            let ext = lang.harness_filename().rsplit('.').next().unwrap();
            assert!(lang.extensions().contains(&ext), "{lang:?} harness ext");
        }
        assert!(TargetLanguage::C.libfuzzer_compatible());
        assert!(!TargetLanguage::Go.libfuzzer_compatible());
    }

    #[test]
    fn relative_file_strips_the_project_root_prefix() {
        let c = candidate("/proj", "/proj/src/a.c");
        assert_eq!(c.relative_file(), "src/a.c");
    }

    #[test]
    fn relative_file_falls_back_to_the_absolute_path_outside_the_root() {
        let c = candidate("/proj", "/elsewhere/a.c");
        assert_eq!(c.relative_file(), "/elsewhere/a.c");
    }

    #[test]
    fn relative_file_keeps_an_already_relative_path() {
        let c = candidate("/proj", "src/a.c");
        assert_eq!(c.relative_file(), "src/a.c");
    }

    #[test]
    fn test_target_language_serde_roundtrip() {
        for lang in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            let json = serde_json::to_string(&lang).unwrap();
            let parsed: TargetLanguage = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, lang);
        }
        // The wire representation is the variant name; adding Go/Python must
        // not change the encoding of the existing variants.
        assert_eq!(
            serde_json::to_string(&TargetLanguage::Go).unwrap(),
            "\"Go\""
        );
        assert_eq!(
            serde_json::to_string(&TargetLanguage::Python).unwrap(),
            "\"Python\""
        );
    }
}
