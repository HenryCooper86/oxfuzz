//! Fuzzing engine types.
//!
//! The engine adapter contract (`EngineAdapter`) and the runner live in
//! `hf-engine`; this module holds only the shared, serializable types.
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

use crate::target::Sanitizer;

/// The kind of fuzzing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineKind {
    AflPlusPlus,
    Honggfuzz,
    LibFuzzer,
    ClusterFuzzLite,
    /// Google's coverage-guided OS kernel fuzzer (syscall sequences).
    Syzkaller,
}

/// Static capability description for an engine/language combination. Keeping
/// this in `hf-core` lets CLI, REST, desktop, and service validation agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCapabilities {
    pub telemetry: EngineTelemetry,
    pub artifacts: EngineArtifacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineTelemetry {
    pub supports_live_stats: bool,
    pub supports_coverage: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineArtifacts {
    pub supports_crash_minimization: bool,
    pub requires_corpus_directory: bool,
}

impl EngineKind {
    /// Return the engine's operational capabilities.
    #[must_use]
    pub const fn capabilities(self) -> EngineCapabilities {
        match self {
            Self::AflPlusPlus => EngineCapabilities {
                telemetry: EngineTelemetry {
                    supports_live_stats: true,
                    supports_coverage: true,
                },
                artifacts: EngineArtifacts {
                    supports_crash_minimization: true,
                    requires_corpus_directory: true,
                },
            },
            Self::Honggfuzz => EngineCapabilities {
                telemetry: EngineTelemetry {
                    supports_live_stats: true,
                    supports_coverage: false,
                },
                artifacts: EngineArtifacts {
                    supports_crash_minimization: true,
                    requires_corpus_directory: true,
                },
            },
            Self::LibFuzzer | Self::ClusterFuzzLite => EngineCapabilities {
                telemetry: EngineTelemetry {
                    supports_live_stats: true,
                    supports_coverage: true,
                },
                artifacts: EngineArtifacts {
                    supports_crash_minimization: true,
                    requires_corpus_directory: false,
                },
            },
            Self::Syzkaller => EngineCapabilities {
                telemetry: EngineTelemetry {
                    supports_live_stats: true,
                    supports_coverage: true,
                },
                artifacts: EngineArtifacts {
                    supports_crash_minimization: false,
                    requires_corpus_directory: false,
                },
            },
        }
    }

    /// Whether this engine can build the requested harness language.
    #[must_use]
    pub const fn supports_language(self, language: crate::target::TargetLanguage) -> bool {
        match self {
            Self::AflPlusPlus | Self::Honggfuzz => matches!(
                language,
                crate::target::TargetLanguage::C | crate::target::TargetLanguage::Cpp
            ),
            Self::LibFuzzer | Self::ClusterFuzzLite => matches!(
                language,
                crate::target::TargetLanguage::C
                    | crate::target::TargetLanguage::Cpp
                    | crate::target::TargetLanguage::Rust
            ),
            Self::Syzkaller => false,
        }
    }
}

impl std::str::FromStr for EngineKind {
    type Err = String;

    /// Parse an engine name (case-insensitive, with common aliases). Unknown
    /// names are rejected so every entrypoint (CLI/web/GUI) fails the same way
    /// instead of silently defaulting to a different engine.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "afl++" | "aflplusplus" | "afl" => Ok(Self::AflPlusPlus),
            "honggfuzz" | "hfuzz" => Ok(Self::Honggfuzz),
            "libfuzzer" | "libfuzz" | "lf" => Ok(Self::LibFuzzer),
            "clusterfuzzlite" | "cfl" | "cflite" => Ok(Self::ClusterFuzzLite),
            "syzkaller" | "syz" => Ok(Self::Syzkaller),
            other => Err(format!(
                "unknown fuzzing engine '{other}' (expected one of: \
                 afl++, honggfuzz, libfuzzer, clusterfuzzlite, syzkaller)"
            )),
        }
    }
}

/// Configuration for a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRunConfig {
    pub harness_id: Uuid,
    pub engine: EngineKind,
    pub duration: Option<Duration>,
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub seed_corpus: Option<PathBuf>,
    pub sanitizer: Sanitizer,
    pub env: Vec<(String, String)>,
    pub extra_args: Vec<String>,
}

/// A progress event streamed from a running fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzProgress {
    ExecsPerSec(f64),
    EdgesCovered(u64),
    CrashesFound(u32),
    LogLine(String),
    Done,
}

#[cfg(test)]
mod tests {
    use super::EngineKind;
    use crate::target::TargetLanguage;

    #[test]
    fn capabilities_reject_unsupported_language_pairs() {
        assert!(EngineKind::LibFuzzer.supports_language(TargetLanguage::Rust));
        assert!(EngineKind::AflPlusPlus.supports_language(TargetLanguage::Cpp));
        assert!(!EngineKind::AflPlusPlus.supports_language(TargetLanguage::Rust));
        assert!(!EngineKind::LibFuzzer.supports_language(TargetLanguage::Python));
        assert!(!EngineKind::Syzkaller.supports_language(TargetLanguage::C));
    }

    #[test]
    fn capabilities_describe_corpus_and_coverage_behavior() {
        assert!(
            EngineKind::AflPlusPlus
                .capabilities()
                .artifacts
                .requires_corpus_directory
        );
        assert!(
            !EngineKind::Honggfuzz
                .capabilities()
                .telemetry
                .supports_coverage
        );
        assert!(
            EngineKind::LibFuzzer
                .capabilities()
                .artifacts
                .supports_crash_minimization
        );
        assert!(
            !EngineKind::Syzkaller
                .capabilities()
                .artifacts
                .supports_crash_minimization
        );
    }
}
