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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineKind {
    AflPlusPlus,
    Honggfuzz,
    LibFuzzer,
    /// Google's coverage-guided OS kernel fuzzer (syscall sequences).
    Syzkaller,
}

impl Serialize for EngineKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EngineKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
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
    /// Every active fuzzing engine in canonical presentation order.
    pub const ALL: [Self; 4] = [
        Self::LibFuzzer,
        Self::AflPlusPlus,
        Self::Honggfuzz,
        Self::Syzkaller,
    ];

    /// The canonical id used on the wire, in configs, and on the command line.
    /// Round-trips through [`std::str::FromStr`], so a value handed to a frontend
    /// comes back parseable.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AflPlusPlus => "afl++",
            Self::Honggfuzz => "honggfuzz",
            Self::LibFuzzer => "libfuzzer",
            Self::Syzkaller => "syzkaller",
        }
    }

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
                    // honggfuzz has no inline minimizer; `hf_crash::
                    // build_minimize_args` returns `None` for it.
                    supports_crash_minimization: false,
                    requires_corpus_directory: true,
                },
            },
            Self::LibFuzzer => EngineCapabilities {
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
                    // Syzkaller minimizes via `syz-repro`, driven separately.
                    // `hf_crash::build_minimize_args` returns `None` for it.
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
            // libFuzzer accepts anything that compiles to a libFuzzer binary --
            // the single source of truth on `TargetLanguage`.
            Self::LibFuzzer => language.libfuzzer_compatible(),
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
        let trimmed = s.trim();
        if crate::retired_engine::is_retired_engine_id(trimmed) {
            return Err(format!(
                "fuzzing engine '{trimmed}' has been retired; choose one of: \
                 afl++, honggfuzz, libfuzzer, syzkaller"
            ));
        }
        match trimmed.to_ascii_lowercase().as_str() {
            "afl++" | "aflplusplus" | "afl" => Ok(Self::AflPlusPlus),
            "honggfuzz" | "hfuzz" => Ok(Self::Honggfuzz),
            "libfuzzer" | "libfuzz" | "lf" => Ok(Self::LibFuzzer),
            "syzkaller" | "syz" => Ok(Self::Syzkaller),
            other => Err(format!(
                "unknown fuzzing engine '{other}' (expected one of: \
                 afl++, honggfuzz, libfuzzer, syzkaller)"
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
    /// Deterministic RNG seed recorded for reproducibility and run replay.
    /// Engines with a fixed-seed knob receive it (`afl-fuzz -s`, libFuzzer
    /// `-seed=`); engines without one (honggfuzz) ignore it. `None` on rows
    /// persisted before seeds were recorded.
    #[serde(default)]
    pub seed: Option<u64>,
    /// The run this run replays, when launched through `replay_run`.
    #[serde(default)]
    pub replay_of: Option<Uuid>,
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
    use serde_json::json;

    #[test]
    fn engine_serde_uses_canonical_ids_and_accepts_historical_active_names() {
        let cases = [
            (EngineKind::LibFuzzer, "libfuzzer", "LibFuzzer"),
            (EngineKind::AflPlusPlus, "afl++", "AflPlusPlus"),
            (EngineKind::Honggfuzz, "honggfuzz", "Honggfuzz"),
            (EngineKind::Syzkaller, "syzkaller", "Syzkaller"),
        ];

        for (engine, canonical, historical) in cases {
            assert_eq!(serde_json::to_value(engine).unwrap(), json!(canonical));
            assert_eq!(
                serde_json::from_value::<EngineKind>(json!(canonical)).unwrap(),
                engine
            );
            let restored = serde_json::from_value::<EngineKind>(json!(historical)).unwrap();
            assert_eq!(restored, engine);
            assert_eq!(serde_json::to_value(restored).unwrap(), json!(canonical));
        }
    }

    #[test]
    fn engine_serde_preserves_exact_retirement_errors() {
        let values = [
            crate::retired_engine::RETIRED_ENGINE_ID.to_owned(),
            crate::retired_engine::RETIRED_ENGINE_IDS[1].to_owned(),
            crate::retired_engine::RETIRED_ENGINE_IDS[2].to_owned(),
            format!(" {} ", crate::retired_engine::RETIRED_ENGINE_ID),
        ];

        for value in values {
            let error = serde_json::from_value::<EngineKind>(json!(value)).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "fuzzing engine '{}' has been retired; choose one of: \
                     afl++, honggfuzz, libfuzzer, syzkaller",
                    value.trim()
                )
            );
        }
    }

    #[test]
    fn engine_serde_preserves_the_generic_unknown_engine_error() {
        let error = serde_json::from_value::<EngineKind>(json!("not-an-engine")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown fuzzing engine 'not-an-engine' (expected one of: \
             afl++, honggfuzz, libfuzzer, syzkaller)"
        );
    }

    #[test]
    fn active_engine_ids_are_exact_and_round_trip() {
        assert_eq!(
            EngineKind::ALL.map(EngineKind::as_str),
            ["libfuzzer", "afl++", "honggfuzz", "syzkaller"],
        );
        for engine in EngineKind::ALL {
            assert_eq!(engine.as_str().parse::<EngineKind>(), Ok(engine));
        }
    }

    #[test]
    fn retired_engine_aliases_return_actionable_errors() {
        let values = [
            crate::retired_engine::RETIRED_ENGINE_ID.to_owned(),
            crate::retired_engine::RETIRED_ENGINE_IDS[1].to_owned(),
            crate::retired_engine::RETIRED_ENGINE_IDS[2].to_owned(),
            format!(" {} ", crate::retired_engine::RETIRED_ENGINE_ID),
        ];
        for value in values {
            let error = value.parse::<EngineKind>().unwrap_err();
            assert!(error.contains("has been retired"), "{error}");
            assert!(
                error.contains("afl++, honggfuzz, libfuzzer, syzkaller"),
                "{error}"
            );
        }
        assert!("not-an-engine"
            .parse::<EngineKind>()
            .unwrap_err()
            .contains("unknown fuzzing engine"));
    }

    #[test]
    fn engine_and_language_ids_round_trip_through_from_str() {
        // A frontend gets `as_str()` and hands it back; it must parse to the
        // same variant, or a scheduled campaign would silently change engine.
        for engine in EngineKind::ALL {
            assert_eq!(engine.as_str().parse::<EngineKind>(), Ok(engine));
        }
        for lang in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            assert_eq!(lang.as_str().parse::<TargetLanguage>(), Ok(lang));
        }
    }

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
        // Engines without a built-in minimizer must not advertise one; the
        // minimizer itself (`hf_crash::build_minimize_args`) rejects them.
        for engine in [EngineKind::Honggfuzz, EngineKind::Syzkaller] {
            assert!(
                !engine.capabilities().artifacts.supports_crash_minimization,
                "{engine:?} has no built-in crash minimizer"
            );
        }
    }
}
