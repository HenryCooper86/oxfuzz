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
    /// Go's native coverage-guided fuzzer, driven through the compiled
    /// `go test -c` binary. An admission-gated capability outside
    /// [`EngineKind::ALL`]: not enabled unless a deployment lists it.
    GoNative,
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
    /// Every active fuzzing engine in canonical presentation order. This is
    /// also the default `enabled_engines` set, so admission-gated capabilities
    /// (Go native fuzzing) deliberately stay out of it: a deployment lists
    /// them explicitly.
    pub const ALL: [Self; 4] = [
        Self::LibFuzzer,
        Self::AflPlusPlus,
        Self::Honggfuzz,
        Self::Syzkaller,
    ];

    /// The engine ids a default deployment can run, rendered for a
    /// user-facing message.
    ///
    /// Membership comes from [`Self::ALL`], so an admission-gated engine (Go
    /// native fuzzing) stays parseable for a deployment that opts in without
    /// being advertised to everyone else. The ids are listed in lexical order,
    /// which keeps the message stable when the canonical declaration order
    /// changes.
    #[must_use]
    pub fn advertised_ids() -> String {
        let mut ids = Self::ALL.map(Self::as_str);
        ids.sort_unstable();
        ids.join(", ")
    }

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
            Self::GoNative => "go-native",
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
            Self::GoNative => EngineCapabilities {
                telemetry: EngineTelemetry {
                    supports_live_stats: true,
                    // The `new interesting` cumulative total is a coverage
                    // proxy, persisted as edges like the other engines.
                    supports_coverage: true,
                },
                artifacts: EngineArtifacts {
                    // Go's fuzzer minimizes failing inputs itself during the
                    // run; there is no external raw-binary minimizer.
                    supports_crash_minimization: false,
                    requires_corpus_directory: true,
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
            Self::GoNative => matches!(language, crate::target::TargetLanguage::Go),
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
                "fuzzing engine '{trimmed}' has been retired; choose one of: {}",
                Self::advertised_ids()
            ));
        }
        match trimmed.to_ascii_lowercase().as_str() {
            "afl++" | "aflplusplus" | "afl" => Ok(Self::AflPlusPlus),
            "honggfuzz" | "hfuzz" => Ok(Self::Honggfuzz),
            "libfuzzer" | "libfuzz" | "lf" => Ok(Self::LibFuzzer),
            "syzkaller" | "syz" => Ok(Self::Syzkaller),
            "go-native" | "gonative" | "go" => Ok(Self::GoNative),
            other => Err(format!(
                "unknown fuzzing engine '{other}' (expected one of: {})",
                Self::advertised_ids()
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
    /// Digest of the retained execution-input manifest; absent on older runs.
    #[serde(default)]
    pub input_manifest_sha256: Option<String>,
    /// Per-input timeout: one input that runs longer than this is a hang
    /// finding. Resolved explicitly by `hf-service` policy
    /// (`fuzzing.default_timeout_ms`, overridable per run) before a campaign
    /// launches; `None` on rows persisted before timeouts were recorded and on
    /// internal probes that keep the engine's built-in default. Adapters emit
    /// the engine flag only for `Some`: libFuzzer `-timeout=<s>` and honggfuzz
    /// `--timeout=<s>` take whole seconds (rounded up, never 0, which libFuzzer
    /// reads as "no timeout"), AFL++ `-t` takes the exact milliseconds.
    /// Syzkaller has no per-input knob in its manager config and ignores this.
    #[serde(default)]
    pub input_timeout: Option<Duration>,
    /// Continue the most recent compatible AFL++ output tree instead of
    /// cold-starting (queue cycle position, favored bookkeeping, and cycle
    /// counts survive an interrupted run or a chained campaign iteration).
    /// Resolved explicitly by `hf-service` policy (`--resume` over
    /// `fuzzing.default_resume`) before a campaign launches; only the AFL++
    /// adapter consumes it (via `AFL_AUTORESUME`, injected by the runner --
    /// never through argv or a hand-set env). `false` on rows persisted before
    /// resume was recorded and on exact-input replays, which never resume.
    /// `false` is omitted from the wire so run manifests sealed before this
    /// field existed keep verifying.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resume: bool,
}

/// A point-in-time statistics snapshot from a running (or just-finished)
/// fuzzer, projected onto engine-neutral fields.
///
/// Every field is optional: availability differs per engine and per moment
/// (AFL++ flushes `fuzzer_stats` about once a second; libFuzzer reports
/// coverage only on pulse lines; honggfuzz never reports edges). `Some(0)` is
/// a measured zero, distinct from "not reported". Absent fields stay off the
/// wire so older readers ignore them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineStats {
    /// Inputs executed since the run started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execs_total: Option<u64>,
    /// Current execution throughput.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execs_per_sec: Option<f64>,
    /// Coverage edges (or the engine's coverage proxy) discovered so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edges_covered: Option<u64>,
    /// AFL++ queue cycles completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles_done: Option<u64>,
    /// Inputs retained in the engine's active corpus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_count: Option<u64>,
    /// AFL++ stability percentage (bitmap variability across calibration runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stability_pct: Option<f64>,
    /// Hangs/timeout findings retained by the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hangs: Option<u64>,
    /// Seconds since the engine last found new coverage or a retained input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_find_age_secs: Option<u64>,
    /// Seconds the engine has been running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
}

impl EngineStats {
    /// Overlay `other` onto `self`: every field present in `other` replaces the
    /// current value; absent fields keep it. Snapshots from one engine stream
    /// are cumulative, so a newer partial snapshot refines rather than erases.
    pub fn merge_from(&mut self, other: &Self) {
        let Self {
            execs_total,
            execs_per_sec,
            edges_covered,
            cycles_done,
            corpus_count,
            stability_pct,
            hangs,
            last_find_age_secs,
            uptime_secs,
        } = other;
        if let Some(value) = execs_total {
            self.execs_total = Some(*value);
        }
        if let Some(value) = execs_per_sec {
            self.execs_per_sec = Some(*value);
        }
        if let Some(value) = edges_covered {
            self.edges_covered = Some(*value);
        }
        if let Some(value) = cycles_done {
            self.cycles_done = Some(*value);
        }
        if let Some(value) = corpus_count {
            self.corpus_count = Some(*value);
        }
        if let Some(value) = stability_pct {
            self.stability_pct = Some(*value);
        }
        if let Some(value) = hangs {
            self.hangs = Some(*value);
        }
        if let Some(value) = last_find_age_secs {
            self.last_find_age_secs = Some(*value);
        }
        if let Some(value) = uptime_secs {
            self.uptime_secs = Some(*value);
        }
    }
}

/// A progress event streamed from a running fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzProgress {
    ExecsPerSec(f64),
    EdgesCovered(u64),
    CrashesFound(u32),
    LogLine(String),
    /// An engine-neutral statistics snapshot; see [`EngineStats`]. Additive
    /// with the scalar variants above, which keep flowing unchanged for
    /// aggregation and health telemetry.
    Stats(EngineStats),
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
    fn advertised_engine_ids_name_every_default_engine_and_no_gated_one() {
        let advertised = EngineKind::advertised_ids();

        for engine in EngineKind::ALL {
            assert!(advertised.contains(engine.as_str()), "{advertised}");
        }
        // Go native fuzzing parses for a deployment that opts in, but a
        // user-facing message must not offer an engine the default set cannot
        // run.
        assert!(
            !advertised.contains(EngineKind::GoNative.as_str()),
            "{advertised}"
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
            assert!(error.contains(&EngineKind::advertised_ids()), "{error}");
        }
        // Both engine errors render one advertised list, so a new engine cannot
        // reach only one of them.
        let unknown = "not-an-engine".parse::<EngineKind>().unwrap_err();
        assert!(unknown.contains("unknown fuzzing engine"), "{unknown}");
        assert!(unknown.contains(&EngineKind::advertised_ids()), "{unknown}");
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

    #[test]
    fn go_native_parses_but_is_not_a_default_engine() {
        let parsed: EngineKind = "go-native".parse().unwrap();
        assert_eq!(parsed, EngineKind::GoNative);
        assert_eq!(parsed.as_str(), "go-native");
        // The capability is opt-in: default enabled-engine lists exclude it.
        assert!(
            !EngineKind::ALL.contains(&EngineKind::GoNative),
            "go-native must not be enabled by default"
        );
    }

    #[test]
    fn go_native_supports_go_and_only_go() {
        assert!(EngineKind::GoNative.supports_language(crate::target::TargetLanguage::Go));
        assert!(!EngineKind::GoNative.supports_language(crate::target::TargetLanguage::C));
        assert!(!EngineKind::GoNative.supports_language(crate::target::TargetLanguage::Rust));
    }

    #[test]
    fn existing_progress_variants_keep_their_exact_wire_shape() {
        use super::FuzzProgress;
        // The CLI, web SSE, and desktop GUI consume these events; their
        // encoding must not move when new variants are added.
        assert_eq!(
            serde_json::to_value(FuzzProgress::ExecsPerSec(842.5)).unwrap(),
            json!({"ExecsPerSec": 842.5})
        );
        assert_eq!(
            serde_json::to_value(FuzzProgress::EdgesCovered(1523)).unwrap(),
            json!({"EdgesCovered": 1523})
        );
        assert_eq!(
            serde_json::to_value(FuzzProgress::CrashesFound(2)).unwrap(),
            json!({"CrashesFound": 2})
        );
        assert_eq!(
            serde_json::to_value(FuzzProgress::LogLine("line".to_owned())).unwrap(),
            json!({"LogLine": "line"})
        );
        assert_eq!(
            serde_json::to_value(FuzzProgress::Done).unwrap(),
            json!("Done")
        );
    }

    #[test]
    fn stats_progress_round_trips_with_all_fields() {
        use super::{EngineStats, FuzzProgress};
        let stats = EngineStats {
            execs_total: Some(128_934),
            execs_per_sec: Some(842.0),
            edges_covered: Some(1523),
            cycles_done: Some(2),
            corpus_count: Some(91),
            stability_pct: Some(100.0),
            hangs: Some(0),
            last_find_age_secs: Some(14),
            uptime_secs: Some(153),
        };
        let event = FuzzProgress::Stats(stats.clone());
        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(
            encoded,
            json!({"Stats": {
                "execs_total": 128934,
                "execs_per_sec": 842.0,
                "edges_covered": 1523,
                "cycles_done": 2,
                "corpus_count": 91,
                "stability_pct": 100.0,
                "hangs": 0,
                "last_find_age_secs": 14,
                "uptime_secs": 153,
            }})
        );
        let restored: FuzzProgress = serde_json::from_value(encoded).unwrap();
        assert!(
            matches!(restored, FuzzProgress::Stats(ref parsed) if *parsed == stats),
            "{restored:?}"
        );
    }

    #[test]
    fn stats_progress_omits_absent_fields_and_accepts_partial_payloads() {
        use super::{EngineStats, FuzzProgress};
        // Per-engine availability differs: an AFL++ snapshot may lack a find
        // age, a libFuzzer pulse lacks cycles. Absent fields stay off the wire
        // and partial payloads decode with None.
        let sparse = FuzzProgress::Stats(EngineStats {
            execs_per_sec: Some(43_690.0),
            ..EngineStats::default()
        });
        assert_eq!(
            serde_json::to_value(&sparse).unwrap(),
            json!({"Stats": {"execs_per_sec": 43690.0}})
        );
        let decoded: FuzzProgress =
            serde_json::from_value(json!({"Stats": {"execs_total": 128934}})).unwrap();
        match decoded {
            FuzzProgress::Stats(stats) => {
                assert_eq!(stats.execs_total, Some(128_934));
                assert_eq!(stats.execs_per_sec, None);
                assert_eq!(stats.stability_pct, None);
            }
            other => panic!("expected Stats, got {other:?}"),
        }
    }

    #[test]
    fn engine_stats_merge_overlays_present_fields_only() {
        use super::EngineStats;
        let mut base = EngineStats {
            execs_total: Some(100),
            edges_covered: Some(50),
            ..EngineStats::default()
        };
        base.merge_from(&EngineStats {
            execs_total: Some(200),
            hangs: Some(1),
            ..EngineStats::default()
        });
        assert_eq!(base.execs_total, Some(200));
        assert_eq!(
            base.edges_covered,
            Some(50),
            "absent fields keep the old value"
        );
        assert_eq!(base.hangs, Some(1));
    }

    #[test]
    fn run_config_resume_is_explicit_and_omitted_when_off() {
        use super::FuzzRunConfig;
        use crate::target::Sanitizer;
        use std::time::Duration;

        let config = FuzzRunConfig {
            harness_id: uuid::Uuid::nil(),
            engine: EngineKind::LibFuzzer,
            duration: Some(Duration::from_secs(60)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
        };
        // `false` stays off the wire: run manifests persisted before the field
        // existed carry no `resume` key and must keep verifying against it.
        let encoded = serde_json::to_value(&config).unwrap();
        assert!(encoded.get("resume").is_none(), "{encoded}");
        let restored: FuzzRunConfig = serde_json::from_value(encoded).unwrap();
        assert!(!restored.resume);

        let mut resumed = config.clone();
        resumed.resume = true;
        let encoded = serde_json::to_value(&resumed).unwrap();
        assert_eq!(encoded["resume"], serde_json::json!(true));
        let restored: FuzzRunConfig = serde_json::from_value(encoded).unwrap();
        assert!(restored.resume);
    }

    #[test]
    fn run_config_round_trips_input_timeout_and_defaults_absent_to_none() {
        use super::FuzzRunConfig;
        use crate::target::Sanitizer;
        use std::time::Duration;

        let mut config = FuzzRunConfig {
            harness_id: uuid::Uuid::nil(),
            engine: EngineKind::LibFuzzer,
            duration: Some(Duration::from_secs(60)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: Some(Duration::from_millis(1500)),
            resume: false,
        };
        let encoded = serde_json::to_value(&config).unwrap();
        assert_eq!(
            encoded["input_timeout"],
            serde_json::json!({"secs": 1, "nanos": 500_000_000}),
            "the persisted record carries the exact per-input timeout"
        );
        let restored: FuzzRunConfig = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored.input_timeout, Some(Duration::from_millis(1500)));

        // Rows persisted before per-input timeouts were recorded carry no
        // field; they decode to None, and adapters then leave the engine's
        // built-in default alone.
        config.input_timeout = None;
        let encoded = serde_json::to_value(&config).unwrap();
        let mut historical = encoded.clone();
        historical.as_object_mut().unwrap().remove("input_timeout");
        let restored: FuzzRunConfig = serde_json::from_value(historical).unwrap();
        assert_eq!(restored.input_timeout, None);
    }
}
