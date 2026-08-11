//! File-backed configuration access shared by every presentation layer.
//!
//! Config lives in `<repo>/config/<section>.toml` (falling back to the bundled
//! `<section>.example.toml` template). The CLI, web API, and GUI all read and
//! write it through these functions so the logic lives in the service layer and
//! never diverges between presentations (AGENTS.md 2.9).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use serde::{Deserialize, Serialize};

use crate::init::config_dir;

use hf_core::engine::EngineKind;

/// The editable config sections consumed by the production service.
///
/// A section must not be added here until service bootstrap or a service-owned
/// integration loads and applies its typed configuration. This prevents the
/// settings APIs from accepting files that have no runtime effect.
pub const CONFIG_SECTIONS: &[&str] = &["oxfuzz", "providers", "defectdojo", "issue_tracker"];

/// Knowledge settings that the production project index currently consumes.
///
/// Keeping this narrower than `hf_knowledge::KnowledgeConfig` prevents the
/// global config from advertising embedding and multi-resolution controls that
/// this service index does not execute.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KnowledgeRuntimeConfig {
    l2_max_tokens: u32,
    min_similarity_threshold: f64,
    retrieval_strategy: String,
    bm25_weight: f64,
    vector_weight: f64,
    // Embedding pipeline. Off by default: BM25-only retrieval is the guaranteed
    // offline behaviour. When enabled, chunks and queries are embedded via an
    // OpenAI-compatible endpoint (configurable base URL covers OpenAI/Azure/
    // Ollama) so "hybrid"/"semantic" strategies run real cosine.
    embedding_enabled: bool,
    embedding_model: String,
    embedding_dimensions: usize,
    embedding_base_url: String,
    embedding_api_key_env: String,
    embedding_max_tokens: u32,
}

impl Default for KnowledgeRuntimeConfig {
    fn default() -> Self {
        let defaults = hf_knowledge::config::KnowledgeConfig::default();
        Self {
            l2_max_tokens: defaults.l2_max_tokens,
            min_similarity_threshold: defaults.min_similarity_threshold,
            retrieval_strategy: defaults.retrieval_strategy,
            bm25_weight: defaults.bm25_weight,
            vector_weight: defaults.vector_weight,
            embedding_enabled: defaults.embedding_enabled,
            embedding_model: defaults.embedding_model,
            embedding_dimensions: defaults.embedding_dimensions,
            embedding_base_url: defaults.embedding_base_url,
            embedding_api_key_env: defaults.embedding_api_key_env,
            embedding_max_tokens: defaults.embedding_max_tokens,
        }
    }
}

impl KnowledgeRuntimeConfig {
    fn effective(&self) -> hf_knowledge::config::KnowledgeConfig {
        hf_knowledge::config::KnowledgeConfig {
            l2_max_tokens: self.l2_max_tokens,
            min_similarity_threshold: self.min_similarity_threshold,
            retrieval_strategy: self.retrieval_strategy.clone(),
            bm25_weight: self.bm25_weight,
            vector_weight: self.vector_weight,
            embedding_enabled: self.embedding_enabled,
            embedding_model: self.embedding_model.clone(),
            embedding_dimensions: self.embedding_dimensions,
            embedding_base_url: self.embedding_base_url.clone(),
            embedding_api_key_env: self.embedding_api_key_env.clone(),
            embedding_max_tokens: self.embedding_max_tokens,
            ..Default::default()
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.l2_max_tokens == 0 {
            return Err("knowledge.l2_max_tokens must be greater than zero".to_owned());
        }
        if !self.min_similarity_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.min_similarity_threshold)
        {
            return Err(
                "knowledge.min_similarity_threshold must be finite and within 0..=1".to_owned(),
            );
        }
        let strategy = self.retrieval_strategy.trim().to_ascii_lowercase();
        match strategy.as_str() {
            "hybrid" | "keyword" => {}
            "semantic" if self.embedding_enabled => {}
            "semantic" => {
                return Err(
                    "knowledge.retrieval_strategy = semantic requires knowledge.embedding_enabled = true"
                        .to_owned(),
                );
            }
            _ => {
                return Err(
                    "knowledge.retrieval_strategy must be hybrid, keyword, or semantic".to_owned(),
                );
            }
        }
        if self.embedding_enabled {
            if self.embedding_dimensions == 0 {
                return Err("knowledge.embedding_dimensions must be greater than zero".to_owned());
            }
            if self.embedding_model.trim().is_empty() {
                return Err("knowledge.embedding_model must not be empty".to_owned());
            }
            validate_http_url(&self.embedding_base_url, "knowledge.embedding_base_url")?;
        }
        for (name, value) in [
            ("bm25_weight", self.bm25_weight),
            ("vector_weight", self.vector_weight),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!(
                    "knowledge.{name} must be a finite, non-negative value"
                ));
            }
        }
        if self.bm25_weight == 0.0 && self.vector_weight == 0.0 {
            return Err("knowledge retrieval weights cannot both be zero".to_owned());
        }
        Ok(())
    }
}

/// Resource limits applied to harness-based fuzzing campaigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuzzingSandboxSettings {
    /// Memory available to the fuzzer container, in MiB.
    pub max_mem_mb: u64,
    /// CPU cores available to the fuzzer container.
    pub max_cpus: u32,
    /// Largest campaign duration an operator may request.
    pub max_duration_secs: u64,
}

impl Default for FuzzingSandboxSettings {
    fn default() -> Self {
        Self {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 7200,
        }
    }
}

/// Global operator policy for fuzzing engines and campaign defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuzzingSettings {
    /// Canonical engine ids permitted for new harness work and campaigns.
    pub enabled_engines: Vec<String>,
    /// Canonical engine id selected when a client does not provide one.
    pub default_engine: String,
    /// Campaign duration selected when a client does not provide one.
    pub default_duration_secs: u64,
    /// Sandboxed resource limits for harness-based campaigns.
    pub sandbox: FuzzingSandboxSettings,
}

impl Default for FuzzingSettings {
    fn default() -> Self {
        Self {
            enabled_engines: all_engine_ids(),
            default_engine: EngineKind::LibFuzzer.as_str().to_owned(),
            default_duration_secs: 60,
            sandbox: FuzzingSandboxSettings::default(),
        }
    }
}

/// One immutable policy snapshot resolved before a fuzz run starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedFuzzingRun {
    /// Engine approved by the current operator policy.
    pub engine: EngineKind,
    /// Validated requested or default duration.
    pub duration_secs: u64,
    /// Memory copied into the persisted run configuration.
    pub max_mem_mb: u64,
    /// CPU limit copied into the persisted run configuration.
    pub max_cpus: u32,
}

/// Resource and evidence ceilings for one automotive sidecar operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutomotiveLimitSettings {
    /// Maximum decoded, generated, or replayed packet events.
    pub max_packets: u32,
    /// Maximum immutable capture or seed artifact bytes accepted for staging.
    pub max_input_bytes: u64,
    /// Maximum aggregate payload bytes accepted from the sidecar.
    pub max_payload_bytes: u64,
    /// Maximum wall-clock duration.
    pub max_duration_secs: u64,
    /// Maximum transmitted events per second for virtual or physical modes.
    pub max_rate_per_second: u32,
    /// Maximum aggregate evidence bytes written by the operation.
    pub max_output_bytes: u64,
    /// Container memory ceiling in MiB.
    pub max_mem_mb: u64,
    /// Container CPU ceiling.
    pub max_cpus: u32,
}

impl Default for AutomotiveLimitSettings {
    fn default() -> Self {
        Self {
            max_packets: 10_000,
            max_input_bytes: 64 * 1024 * 1024,
            max_payload_bytes: 1024 * 1024,
            max_duration_secs: 300,
            max_rate_per_second: 100,
            max_output_bytes: 64 * 1024 * 1024,
            max_mem_mb: 1024,
            max_cpus: 1,
        }
    }
}

/// Exceptional physical-bench policy. It is disabled and empty by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutomotivePhysicalBenchSettings {
    /// Whether any physical interface may be exposed to the sandbox.
    pub enabled: bool,
    /// Mandatory human approval for every operation; must remain true.
    pub require_approval: bool,
    /// Exact host interface names eligible for approval.
    pub interfaces: Vec<String>,
    /// Exact standard or extended CAN arbitration ids eligible for use.
    pub arbitration_ids: Vec<u32>,
    /// UDS service ids eligible for use after the fixed dangerous denylist.
    pub uds_services: Vec<u8>,
    /// Permit a separately approved request to use a dangerous UDS service.
    pub allow_dangerous_services: bool,
}

impl Default for AutomotivePhysicalBenchSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            require_approval: true,
            interfaces: Vec::new(),
            arbitration_ids: Vec::new(),
            uds_services: Vec::new(),
            allow_dangerous_services: false,
        }
    }
}

/// Global operator policy for the optional Scapy automotive subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutomotiveSettings {
    /// Runtime switch independent of the compile-time feature. Enabled by
    /// default so the offline/virtual automotive workspace is usable out of the
    /// box; physical-bench access stays separately gated below.
    pub enabled: bool,
    /// Pinned sandbox image containing the sidecar and Scapy.
    pub sidecar_image: String,
    /// Canonical protocol ids the service may admit.
    pub allowed_protocols: Vec<String>,
    /// Canonical execution mode ids the service may admit.
    pub allowed_modes: Vec<String>,
    /// Exact isolated vcan interfaces eligible for virtual sessions.
    pub virtual_interfaces: Vec<String>,
    /// Resource and evidence ceilings.
    pub limits: AutomotiveLimitSettings,
    /// Additional policy for physical interfaces.
    pub physical_bench: AutomotivePhysicalBenchSettings,
}

impl Default for AutomotiveSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            sidecar_image: "oxfuzz/scapy-automotive:2.7.0".to_owned(),
            allowed_protocols: AUTOMOTIVE_PROTOCOL_IDS
                .iter()
                .map(ToString::to_string)
                .collect(),
            allowed_modes: vec!["offline_pcap".to_owned(), "virtual_can".to_owned()],
            virtual_interfaces: vec!["vcan0".to_owned()],
            limits: AutomotiveLimitSettings::default(),
            physical_bench: AutomotivePhysicalBenchSettings::default(),
        }
    }
}

const AUTOMOTIVE_PROTOCOL_IDS: &[&str] = &[
    "can",
    "can_fd",
    "iso_tp",
    "uds",
    "gmlan",
    "some_ip",
    "some_ip_sd",
    "do_ip",
    "obd",
    "ccp",
    "xcp",
    "bmw_hsfz",
    "sec_oc",
];
const AUTOMOTIVE_MODE_IDS: &[&str] = &["offline_pcap", "virtual_can", "physical_bench"];

impl AutomotiveSettings {
    fn validate_unique_ids(values: &[String], allowed: &[&str], field: &str) -> Result<(), String> {
        if values.is_empty() {
            return Err(format!("automotive.{field} must not be empty"));
        }
        let mut seen = std::collections::HashSet::new();
        for value in values {
            if !allowed.contains(&value.as_str()) {
                return Err(format!("automotive.{field} contains unknown id '{value}'"));
            }
            if !seen.insert(value) {
                return Err(format!(
                    "automotive.{field} contains duplicate id '{value}'"
                ));
            }
        }
        Ok(())
    }

    fn validate_interface(interface: &str) -> bool {
        !interface.is_empty()
            && interface.len() <= 15
            && interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    }

    fn validate_virtual_interface(interface: &str) -> bool {
        interface.strip_prefix("vcan").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 3
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    }

    fn validate_pinned_image(image: &str) -> bool {
        if image.is_empty()
            || image.len() > 256
            // The image is later emitted verbatim into the `docker run` argv;
            // a leading `-` would be parsed as a docker CLI flag instead of
            // an image, voiding the pinned-image guarantee.
            || image.starts_with('-')
            || image.chars().any(char::is_whitespace)
            || image
                .chars()
                .any(|character| matches!(character, '\0' | '\n' | '\r'))
        {
            return false;
        }
        if let Some((name, digest)) = image.rsplit_once("@sha256:") {
            return !name.is_empty()
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
        }
        image.rsplit_once(':').is_some_and(|(name, tag)| {
            !name.is_empty() && !tag.is_empty() && tag != "latest" && !tag.contains('/')
        })
    }

    /// Validate the persisted operator policy without widening unsafe values.
    ///
    /// # Errors
    /// Returns a field-specific error for an invalid image, protocol, mode,
    /// interface, physical policy, or resource ceiling.
    pub fn validate(&self) -> Result<(), String> {
        if !Self::validate_pinned_image(&self.sidecar_image) {
            return Err(
                "automotive.sidecar_image must be a pinned tag or sha256 digest".to_owned(),
            );
        }
        Self::validate_unique_ids(
            &self.allowed_protocols,
            AUTOMOTIVE_PROTOCOL_IDS,
            "allowed_protocols",
        )?;
        Self::validate_unique_ids(&self.allowed_modes, AUTOMOTIVE_MODE_IDS, "allowed_modes")?;
        if self.virtual_interfaces.is_empty()
            || self
                .virtual_interfaces
                .iter()
                .any(|interface| !Self::validate_virtual_interface(interface))
        {
            return Err(
                "automotive.virtual_interfaces must contain only vcanN interfaces".to_owned(),
            );
        }
        let unique_virtual_interfaces = self
            .virtual_interfaces
            .iter()
            .collect::<std::collections::HashSet<_>>();
        if unique_virtual_interfaces.len() != self.virtual_interfaces.len() {
            return Err("automotive.virtual_interfaces contains a duplicate interface".to_owned());
        }
        let limits = &self.limits;
        if limits.max_packets == 0 || limits.max_packets > 1_000_000 {
            return Err("automotive.limits.max_packets must be within 1..=1000000".to_owned());
        }
        if limits.max_input_bytes == 0 || limits.max_input_bytes > 1024 * 1024 * 1024 {
            return Err(
                "automotive.limits.max_input_bytes must be within 1..=1073741824".to_owned(),
            );
        }
        if limits.max_payload_bytes == 0 || limits.max_payload_bytes > 1024 * 1024 {
            return Err(
                "automotive.limits.max_payload_bytes must be within 1..=1048576".to_owned(),
            );
        }
        if limits.max_duration_secs == 0 || limits.max_duration_secs > 3600 {
            return Err("automotive.limits.max_duration_secs must be within 1..=3600".to_owned());
        }
        if limits.max_rate_per_second == 0 || limits.max_rate_per_second > 10_000 {
            return Err(
                "automotive.limits.max_rate_per_second must be within 1..=10000".to_owned(),
            );
        }
        if limits.max_output_bytes == 0 || limits.max_output_bytes > 512 * 1024 * 1024 {
            return Err(
                "automotive.limits.max_output_bytes must be within 1..=536870912".to_owned(),
            );
        }
        if limits.max_mem_mb == 0 || limits.max_mem_mb > 8192 {
            return Err("automotive.limits.max_mem_mb must be within 1..=8192".to_owned());
        }
        if limits.max_cpus == 0 || limits.max_cpus > 8 {
            return Err("automotive.limits.max_cpus must be within 1..=8".to_owned());
        }
        let mode_caps = [
            ("offline_pcap", 100_000_u32, 3_600_u64, 100_000_u32),
            ("virtual_can", 10_000, 3_600, 1_000),
            ("physical_bench", 1_000, 300, 100),
        ];
        for (mode, max_packets, max_duration_secs, max_rate_per_second) in mode_caps {
            if !self.allowed_modes.iter().any(|allowed| allowed == mode) {
                continue;
            }
            if limits.max_packets > max_packets
                || limits.max_duration_secs > max_duration_secs
                || limits.max_rate_per_second > max_rate_per_second
            {
                return Err(format!(
                    "automotive limits exceed the pinned {mode} adapter profile"
                ));
            }
        }
        let physical = &self.physical_bench;
        let physical_mode_allowed = self
            .allowed_modes
            .iter()
            .any(|mode_| mode_ == "physical_bench");
        if physical.enabled {
            if !physical_mode_allowed {
                return Err(
                    "automotive physical bench requires physical_bench in allowed_modes".to_owned(),
                );
            }
            if !physical.require_approval {
                return Err("automotive physical bench approval is mandatory".to_owned());
            }
            if physical.interfaces.is_empty()
                || physical
                    .interfaces
                    .iter()
                    .any(|interface| !Self::validate_interface(interface))
            {
                return Err(
                    "automotive.physical_bench.interfaces must contain valid interfaces".to_owned(),
                );
            }
            let unique_interfaces = physical
                .interfaces
                .iter()
                .collect::<std::collections::HashSet<_>>();
            if unique_interfaces.len() != physical.interfaces.len() {
                return Err("automotive.physical_bench.interfaces contains a duplicate".to_owned());
            }
        } else if physical_mode_allowed {
            return Err(
                "automotive.allowed_modes cannot enable physical_bench while its policy is disabled"
                    .to_owned(),
            );
        }
        if physical.arbitration_ids.iter().any(|id| *id > 0x1fff_ffff) {
            return Err(
                "automotive.physical_bench.arbitration_ids contains an out-of-range id".to_owned(),
            );
        }
        if physical
            .arbitration_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != physical.arbitration_ids.len()
            || physical
                .uds_services
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != physical.uds_services.len()
        {
            return Err("automotive physical allowlists contain a duplicate".to_owned());
        }
        Ok(())
    }
}

const HARD_MAX_FUZZ_DURATION_SECS: u64 = 7 * 24 * 60 * 60;
const HARD_MAX_FUZZ_MEMORY_MB: u64 = 64 * 1024;
const HARD_MAX_FUZZ_CPUS: u32 = 64;

fn all_engine_ids() -> Vec<String> {
    EngineKind::ALL
        .into_iter()
        .map(|engine| engine.as_str().to_owned())
        .collect()
}

fn canonical_engine(value: &str) -> Result<EngineKind, String> {
    let trimmed = value.trim();
    let engine = trimmed.parse::<EngineKind>()?;
    if trimmed != engine.as_str() {
        return Err(format!(
            "fuzzing engine id '{value}' is not canonical; use '{}'",
            engine.as_str()
        ));
    }
    Ok(engine)
}

impl FuzzingSettings {
    fn enabled_engine_set(&self) -> Result<std::collections::HashSet<EngineKind>, String> {
        let mut enabled = std::collections::HashSet::new();
        for value in &self.enabled_engines {
            let engine = canonical_engine(value)?;
            if !enabled.insert(engine) {
                return Err(format!(
                    "fuzzing.enabled_engines contains duplicate engine '{}'",
                    engine.as_str()
                ));
            }
        }
        if enabled.is_empty() {
            return Err("fuzzing.enabled_engines must contain at least one engine".to_owned());
        }
        Ok(enabled)
    }

    fn validate(&self) -> Result<(), String> {
        let enabled = self.enabled_engine_set()?;
        let default_engine = canonical_engine(&self.default_engine)?;
        if !enabled.contains(&default_engine) {
            return Err("fuzzing.default_engine must be enabled".to_owned());
        }
        if self.default_duration_secs == 0 {
            return Err("fuzzing.default_duration_secs must be greater than zero".to_owned());
        }
        if self.sandbox.max_duration_secs == 0
            || self.sandbox.max_duration_secs > HARD_MAX_FUZZ_DURATION_SECS
        {
            return Err(format!(
                "fuzzing.sandbox.max_duration_secs must be within 1..={HARD_MAX_FUZZ_DURATION_SECS}"
            ));
        }
        if self.default_duration_secs > self.sandbox.max_duration_secs {
            return Err(
                "fuzzing.default_duration_secs cannot exceed sandbox.max_duration_secs".to_owned(),
            );
        }
        if self.sandbox.max_mem_mb == 0 || self.sandbox.max_mem_mb > HARD_MAX_FUZZ_MEMORY_MB {
            return Err(format!(
                "fuzzing.sandbox.max_mem_mb must be within 1..={HARD_MAX_FUZZ_MEMORY_MB}"
            ));
        }
        if self.sandbox.max_cpus == 0 || self.sandbox.max_cpus > HARD_MAX_FUZZ_CPUS {
            return Err(format!(
                "fuzzing.sandbox.max_cpus must be within 1..={HARD_MAX_FUZZ_CPUS}"
            ));
        }
        Ok(())
    }

    /// Resolve a requested engine and duration against this policy.
    ///
    /// # Errors
    /// Returns an error when the policy is invalid, the engine is disabled, or
    /// the duration is zero or above the configured ceiling.
    pub fn resolve(
        &self,
        engine: Option<EngineKind>,
        duration_secs: Option<u64>,
    ) -> Result<ResolvedFuzzingRun, String> {
        self.validate()?;
        let enabled = self.enabled_engine_set()?;
        let engine = match engine {
            Some(engine) => engine,
            None => canonical_engine(&self.default_engine)?,
        };
        if !enabled.contains(&engine) {
            return Err(format!(
                "fuzzing engine '{}' is disabled in Settings",
                engine.as_str()
            ));
        }
        let duration_secs = duration_secs.unwrap_or(self.default_duration_secs);
        if duration_secs == 0 {
            return Err("fuzzing duration must be greater than zero".to_owned());
        }
        if duration_secs > self.sandbox.max_duration_secs {
            return Err(format!(
                "fuzzing duration {duration_secs}s exceeds the configured maximum of {}s",
                self.sandbox.max_duration_secs
            ));
        }
        Ok(ResolvedFuzzingRun {
            engine,
            duration_secs,
            max_mem_mb: self.sandbox.max_mem_mb,
            max_cpus: self.sandbox.max_cpus,
        })
    }

    /// Resolve a fixed internal maintenance budget against this policy.
    ///
    /// Internal pipeline steps (smoke qualification, coverage-guided pruning,
    /// corpus minimization) run implementation-defined budgets, not
    /// operator-requested campaigns, so an over-ceiling budget clamps to the
    /// ceiling instead of failing: a low `sandbox.max_duration_secs` must not
    /// block mandatory operations like harness smoke qualification.
    ///
    /// # Errors
    /// Returns an error when the policy is invalid or the engine is disabled.
    pub fn resolve_internal(
        &self,
        engine: EngineKind,
        internal_budget_secs: u64,
    ) -> Result<ResolvedFuzzingRun, String> {
        let clamped = internal_budget_secs.min(self.sandbox.max_duration_secs);
        self.resolve(Some(engine), Some(clamped))
    }

    /// Check that an engine is enabled without resolving run-specific values.
    ///
    /// # Errors
    /// Returns an error for an invalid policy or a disabled engine.
    pub fn require_engine(&self, engine: EngineKind) -> Result<(), String> {
        self.resolve(Some(engine), None).map(|_| ())
    }

    /// Resolve an enabled engine that can build a harness for `language`.
    ///
    /// An explicit request is never substituted. When the global default is a
    /// kernel-only engine, an omitted request falls through to the first
    /// enabled engine that supports the target language.
    ///
    /// # Errors
    /// Returns an error for invalid policy, a disabled or incompatible explicit
    /// engine, or when no enabled engine supports the requested language.
    pub fn resolve_harness_engine(
        &self,
        engine: Option<EngineKind>,
        language: hf_core::target::TargetLanguage,
    ) -> Result<EngineKind, String> {
        self.validate()?;
        if let Some(engine) = engine {
            self.require_engine(engine)?;
            if engine.supports_language(language) {
                return Ok(engine);
            }
            return Err(format!(
                "{language:?} harnesses are not supported by fuzzing engine '{}'",
                engine.as_str()
            ));
        }

        let default_engine = canonical_engine(&self.default_engine)?;
        if default_engine.supports_language(language) {
            return Ok(default_engine);
        }
        for value in &self.enabled_engines {
            let candidate = canonical_engine(value)?;
            if candidate.supports_language(language) {
                return Ok(candidate);
            }
        }
        Err(format!(
            "no enabled fuzzing engine supports {language:?} harnesses"
        ))
    }
}

/// Typed global settings whose values are consumed during service bootstrap.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OxfuzzRuntimeConfig {
    coverage_stagnation_secs: u64,
    coverage_stagnation_new_harness_windows: u64,
    coverage_stagnation_stop_windows: u64,
    auto_revert_enabled: bool,
    auto_revert_threshold_pct: f64,
    auto_revert_notify_only: bool,
    fuzzing: FuzzingSettings,
    automotive: AutomotiveSettings,
    knowledge: KnowledgeRuntimeConfig,
    session: hf_session::SessionConfig,
    scheduler: hf_scheduler::SchedulerConfig,
}

impl Default for OxfuzzRuntimeConfig {
    fn default() -> Self {
        Self {
            coverage_stagnation_secs: DEFAULT_STAGNATION_THRESHOLD_SECS,
            coverage_stagnation_new_harness_windows: DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS,
            coverage_stagnation_stop_windows: DEFAULT_STAGNATION_STOP_WINDOWS,
            auto_revert_enabled: false,
            auto_revert_threshold_pct: DEFAULT_AUTO_REVERT_THRESHOLD_PCT,
            auto_revert_notify_only: false,
            fuzzing: FuzzingSettings::default(),
            automotive: AutomotiveSettings::default(),
            knowledge: KnowledgeRuntimeConfig::default(),
            session: hf_session::SessionConfig::default(),
            scheduler: hf_scheduler::SchedulerConfig::default(),
        }
    }
}

impl OxfuzzRuntimeConfig {
    fn validate(&self) -> Result<(), String> {
        if !valid_auto_revert_threshold(self.auto_revert_threshold_pct) {
            return Err("auto_revert_threshold_pct must be within (0, 100]".to_owned());
        }
        if !valid_stagnation_windows(
            self.coverage_stagnation_new_harness_windows,
            self.coverage_stagnation_stop_windows,
        ) {
            return Err(
                "coverage_stagnation windows must satisfy 1 <= new_harness_windows < stop_windows"
                    .to_owned(),
            );
        }
        self.fuzzing.validate()?;
        self.automotive.validate()?;
        self.knowledge.validate()?;
        if self.session.max_depth == 0 {
            return Err("session.max_depth must be greater than zero".to_owned());
        }
        if self.scheduler.max_concurrent_executions == 0 {
            return Err("scheduler.max_concurrent_executions must be greater than zero".to_owned());
        }
        Ok(())
    }
}

fn parse_oxfuzz_runtime_config(raw: &str) -> Result<OxfuzzRuntimeConfig, String> {
    let config: OxfuzzRuntimeConfig =
        toml::from_str(raw).map_err(|error| format!("invalid oxfuzz config: {error}"))?;
    config.validate()?;
    Ok(config)
}

fn effective_runtime_config() -> OxfuzzRuntimeConfig {
    let raw = read_config("oxfuzz").unwrap_or_default();
    match parse_oxfuzz_runtime_config(&raw) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(%error, "invalid oxfuzz runtime config; using safe defaults");
            OxfuzzRuntimeConfig::default()
        }
    }
}

/// Resolve the knowledge configuration applied to project indexing/retrieval.
#[must_use]
pub fn effective_knowledge_config() -> hf_knowledge::config::KnowledgeConfig {
    effective_runtime_config().knowledge.effective()
}

/// Resolve the session configuration applied when building `SessionManager`.
#[must_use]
pub fn effective_session_config() -> hf_session::SessionConfig {
    effective_runtime_config().session
}

/// Resolve the scheduler configuration applied at campaign scheduler startup.
#[must_use]
pub fn effective_scheduler_config() -> hf_scheduler::SchedulerConfig {
    effective_runtime_config().scheduler
}

/// Read and validate the operator fuzzing policy for the next operation.
///
/// This intentionally reads the atomic config file for every preflight, so a
/// Settings save affects the next harness or run without restarting the app.
/// An invalid manually-edited policy fails closed instead of widening back to
/// permissive defaults.
///
/// # Errors
/// Returns an error when the global config cannot be read or validated.
pub fn effective_fuzzing_settings() -> Result<FuzzingSettings, String> {
    let raw = read_config("oxfuzz")?;
    Ok(parse_oxfuzz_runtime_config(&raw)?.fuzzing)
}

/// Read and validate the automotive sidecar policy for the next operation.
///
/// # Errors
/// Returns an error when the global config cannot be read or validated.
pub fn effective_automotive_settings() -> Result<AutomotiveSettings, String> {
    let raw = read_config("oxfuzz")?;
    Ok(parse_oxfuzz_runtime_config(&raw)?.automotive)
}

/// Resolve the next fuzz run from the current persisted operator policy.
///
/// # Errors
/// Returns an error for an invalid policy, disabled engine, or invalid duration.
pub fn resolve_fuzzing_run(
    engine: Option<EngineKind>,
    duration_secs: Option<u64>,
) -> Result<ResolvedFuzzingRun, String> {
    effective_fuzzing_settings()?.resolve(engine, duration_secs)
}

/// Resolve a fixed internal maintenance budget from the current persisted
/// operator policy, clamping it to the configured campaign ceiling.
///
/// # Errors
/// Returns an error for an invalid policy or a disabled engine.
pub fn resolve_internal_fuzzing_run(
    engine: EngineKind,
    internal_budget_secs: u64,
) -> Result<ResolvedFuzzingRun, String> {
    effective_fuzzing_settings()?.resolve_internal(engine, internal_budget_secs)
}

/// Resolve an enabled user-space harness engine for the target language.
///
/// # Errors
/// Returns an error for invalid policy or when the requested language has no
/// compatible enabled engine.
pub fn resolve_harness_engine(
    engine: Option<EngineKind>,
    language: hf_core::target::TargetLanguage,
) -> Result<EngineKind, String> {
    effective_fuzzing_settings()?.resolve_harness_engine(engine, language)
}

/// One editable config section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSection {
    /// Section name (the TOML file stem).
    pub name: String,
    /// Whether a live (non-example) file exists for it.
    pub exists: bool,
}

/// Resolved on-disk locations surfaced in the General settings page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPaths {
    /// The config directory.
    pub config_dir: String,
    /// The runtime data directory.
    pub data_dir: String,
    /// The fuzz workspace root (compiled harnesses, corpora, crash reproducers).
    pub workspace_dir: String,
}

/// A model offered by a configured provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// The provider id that offers the model.
    pub id: String,
    /// The provider type (e.g. `openai-compat`).
    pub provider_type: String,
    /// The model identifier.
    pub model: String,
}

/// The provider form struct surfaced to / received from the GUI is the full
/// pool [`hf_provider::ProviderConfig`] (every field round-trips 1:1).
pub use hf_provider::ProviderConfig;

/// An explicit update for a value omitted from public browser config DTOs.
///
/// Omitting the containing patch field preserves the stored value. `Clear` and
/// `Replace` make destructive or secret-bearing changes explicit instead of
/// overloading an empty/redacted browser value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfigValuePatch<T> {
    /// Replace the stored value with the supplied value.
    Replace {
        /// The new value.
        value: T,
    },
    /// Remove the stored value.
    Clear,
}

/// Public state for a string that may contain a protected host path.
///
/// Safe values remain visible for operator context. Absolute paths and
/// redaction markers are represented by `configured = true` with no value, so
/// presentations can preserve, explicitly replace, or explicitly clear them
/// without round-tripping a placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicConfigString {
    /// Whether the underlying value is non-empty, including when it is hidden.
    pub configured: bool,
    /// The value when it is safe to expose.
    pub value: Option<String>,
}

/// Browser-safe view of `DefectDojo` lifecycle settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefectDojoPublicLifecycle {
    /// Start a managed local `DefectDojo` installation on app launch.
    pub autostart: bool,
    /// Docker Compose project override, with host paths kept opaque.
    pub compose_project: PublicConfigString,
    /// Whether one or more hidden compose file paths are configured.
    pub compose_files_configured: bool,
    /// Readiness wait timeout, when overridden.
    pub startup_timeout_secs: Option<u64>,
}

/// Configured-state flags for protected `DefectDojo` credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefectDojoPublicCredentialState {
    /// Whether a direct token is stored.
    pub api_token_configured: bool,
    /// Whether a secret environment-variable name is stored.
    pub api_token_env_configured: bool,
}

/// Browser-safe `DefectDojo` transport and import policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefectDojoPublicPolicy {
    /// Whether the server certificate is verified.
    pub verify_tls: bool,
    /// Whether missing `DefectDojo` objects may be created.
    pub auto_create: bool,
    /// Whether repeat uploads use reimport semantics.
    pub reimport: bool,
}

/// Browser-safe `DefectDojo` settings.
///
/// Secret values, secret environment-variable names, and compose paths are
/// represented only by configured-state booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefectDojoPublicConfig {
    /// Base URL of the `DefectDojo` instance.
    pub url: String,
    /// Protected credential state, flattened to preserve the public JSON schema.
    #[serde(flatten)]
    pub credentials: DefectDojoPublicCredentialState,
    /// Product override.
    pub product_name: Option<String>,
    /// Product-type override.
    pub product_type_name: Option<String>,
    /// Engagement override.
    pub engagement_name: Option<String>,
    /// Transport and import behavior, flattened to preserve the public JSON schema.
    #[serde(flatten)]
    pub policy: DefectDojoPublicPolicy,
    /// Browser-safe lifecycle settings.
    pub lifecycle: DefectDojoPublicLifecycle,
}

impl From<&crate::defectdojo::DefectDojoConfig> for DefectDojoPublicConfig {
    fn from(config: &crate::defectdojo::DefectDojoConfig) -> Self {
        Self {
            url: browser_safe_url(&config.url),
            credentials: DefectDojoPublicCredentialState {
                api_token_configured: config
                    .api_token
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()),
                api_token_env_configured: !config.api_token_env.trim().is_empty(),
            },
            product_name: config.product_name.clone(),
            product_type_name: config.product_type_name.clone(),
            engagement_name: config.engagement_name.clone(),
            policy: DefectDojoPublicPolicy {
                verify_tls: config.verify_tls,
                auto_create: config.auto_create,
                reimport: config.reimport,
            },
            lifecycle: DefectDojoPublicLifecycle {
                autostart: config.lifecycle.autostart,
                compose_project: public_config_string(config.lifecycle.compose_project.as_deref()),
                compose_files_configured: !config.lifecycle.compose_files.is_empty(),
                startup_timeout_secs: config.lifecycle.startup_timeout_secs,
            },
        }
    }
}

/// Typed `DefectDojo` lifecycle patch accepted at the browser boundary.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefectDojoLifecyclePatch {
    /// Change autostart; omission preserves it.
    pub autostart: Option<bool>,
    /// Replace or clear the optional Compose project name.
    pub compose_project: Option<ConfigValuePatch<String>>,
    /// Explicitly replace or clear the protected compose file paths.
    pub compose_files: Option<ConfigValuePatch<Vec<String>>>,
    /// Replace or clear the optional readiness timeout.
    pub startup_timeout_secs: Option<ConfigValuePatch<u64>>,
}

/// Typed `DefectDojo` patch accepted at the browser boundary.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DefectDojoConfigPatch {
    /// Replace the `DefectDojo` base URL.
    pub url: Option<String>,
    /// Explicitly replace or clear the direct token.
    pub api_token: Option<ConfigValuePatch<String>>,
    /// Explicitly replace or clear the protected secret environment name.
    pub api_token_env: Option<ConfigValuePatch<String>>,
    /// Change TLS verification.
    pub verify_tls: Option<bool>,
    /// Replace or clear the optional product name.
    pub product_name: Option<ConfigValuePatch<String>>,
    /// Replace or clear the optional product-type name.
    pub product_type_name: Option<ConfigValuePatch<String>>,
    /// Replace or clear the optional engagement name.
    pub engagement_name: Option<ConfigValuePatch<String>>,
    /// Change automatic object creation.
    pub auto_create: Option<bool>,
    /// Change import versus reimport behavior.
    pub reimport: Option<bool>,
    /// Patch lifecycle settings.
    pub lifecycle: Option<DefectDojoLifecyclePatch>,
}

/// Browser-safe issue-tracker settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssueTrackerPublicConfig {
    /// `github`, `gitlab`, or `none`.
    pub provider: String,
    /// Public forge base URL override.
    pub host: Option<String>,
    /// Target repository identifier, with legacy host paths kept opaque.
    pub repo: PublicConfigString,
    /// Whether a direct Personal Access Token is stored.
    pub api_token_configured: bool,
    /// Whether a protected secret environment-variable name is stored.
    pub api_token_env_configured: bool,
    /// Optional attribution username.
    pub username: Option<String>,
    /// Labels added to filed issues.
    pub labels: Vec<String>,
    /// Whether the forge certificate is verified.
    pub verify_tls: bool,
}

impl From<&crate::issue_tracker::IssueTrackerConfig> for IssueTrackerPublicConfig {
    fn from(config: &crate::issue_tracker::IssueTrackerConfig) -> Self {
        Self {
            provider: config.provider.clone(),
            host: config.host.as_deref().map(browser_safe_url),
            repo: public_config_string(Some(&config.repo)),
            api_token_configured: config
                .api_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            api_token_env_configured: !config.api_token_env.trim().is_empty(),
            username: config.username.clone(),
            labels: config.labels.clone(),
            verify_tls: config.verify_tls,
        }
    }
}

fn browser_safe_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return String::new();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn public_config_string(value: Option<&str>) -> PublicConfigString {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    let configured = value.is_some();
    let value = value
        .filter(|value| !looks_like_absolute_host_path(value))
        .filter(|value| !contains_redaction_marker(value))
        .map(str::to_owned);
    PublicConfigString { configured, value }
}

fn looks_like_absolute_host_path(value: &str) -> bool {
    // A POSIX-rooted value must be withheld on every host: `std::path` does
    // not consider /var/lib absolute on Windows, so relying on it alone would
    // serve such paths through the public API there. Values that name paths
    // inside the Linux sandbox are POSIX regardless of the host.
    value.starts_with('/')
        || Path::new(value).is_absolute()
        || value.starts_with("\\\\")
        || value
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

/// Typed issue-tracker patch accepted at the browser boundary.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssueTrackerConfigPatch {
    /// Replace the provider id.
    pub provider: Option<String>,
    /// Replace or clear the optional forge host override.
    pub host: Option<ConfigValuePatch<String>>,
    /// Explicitly replace or clear the target repository identifier.
    pub repo: Option<ConfigValuePatch<String>>,
    /// Explicitly replace or clear the direct Personal Access Token.
    pub api_token: Option<ConfigValuePatch<String>>,
    /// Explicitly replace or clear the protected secret environment name.
    pub api_token_env: Option<ConfigValuePatch<String>>,
    /// Replace or clear the optional attribution username.
    pub username: Option<ConfigValuePatch<String>>,
    /// Replace the issue labels.
    pub labels: Option<Vec<String>>,
    /// Change TLS verification.
    pub verify_tls: Option<bool>,
}

/// File-backed integration settings store.
///
/// Production uses [`Default`], while tests and embedders can provide an
/// isolated directory without mutating process-global environment variables.
/// Patch transactions targeting the same resolved directory are serialized
/// across store instances within this process. Atomic replacement prevents
/// partial files across processes, but there is no cross-process advisory lock;
/// concurrent writers in separate processes remain last-writer-wins.
#[derive(Debug, Clone)]
pub struct IntegrationConfigStore {
    directory: PathBuf,
    transaction_lock: Arc<Mutex<()>>,
    #[cfg(test)]
    patch_gate: Option<Arc<IntegrationConfigPatchGate>>,
}

/// Typed automotive settings store over the shared global config file.
///
/// The read-modify-write transaction preserves every unrelated global setting,
/// validates the complete resulting document, and uses the same per-directory
/// lock and atomic private-file replacement as protected integration settings.
#[derive(Debug, Clone)]
pub struct AutomotiveConfigStore {
    directory: PathBuf,
    transaction_lock: Arc<Mutex<()>>,
}

impl Default for AutomotiveConfigStore {
    fn default() -> Self {
        Self::new(config_dir())
    }
}

impl AutomotiveConfigStore {
    /// Create a store rooted at `directory`.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            transaction_lock: integration_config_lock(&directory),
            directory,
        }
    }

    /// Load the validated automotive policy, applying documented defaults when
    /// the table is absent.
    ///
    /// # Errors
    /// Returns an error when the global config cannot be read or validated.
    pub fn get(&self) -> Result<AutomotiveSettings, String> {
        let raw = read_config_from(&self.directory, "oxfuzz")?;
        Ok(parse_oxfuzz_runtime_config(&raw)?.automotive)
    }

    /// Replace only the automotive table after validating the full global file.
    ///
    /// # Errors
    /// Returns without writing when the current config or replacement policy is
    /// invalid, or when the atomic private-file replacement fails.
    pub fn set(&self, settings: AutomotiveSettings) -> Result<AutomotiveSettings, String> {
        settings.validate()?;
        let _transaction = lock_recover(&self.transaction_lock);
        let raw = read_config_from(&self.directory, "oxfuzz")?;
        parse_oxfuzz_runtime_config(&raw)?;
        let mut document: toml::Table =
            toml::from_str(&raw).map_err(|error| format!("invalid oxfuzz config: {error}"))?;
        let automotive = toml::Value::try_from(&settings)
            .map_err(|error| format!("automotive settings could not be serialized: {error}"))?;
        document.insert("automotive".to_owned(), automotive);
        let content = toml::to_string_pretty(&document)
            .map_err(|error| format!("oxfuzz settings could not be serialized: {error}"))?;
        parse_oxfuzz_runtime_config(&content)?;
        std::fs::create_dir_all(&self.directory).map_err(|error| error.to_string())?;
        write_private_config_file(&self.directory.join("oxfuzz.toml"), &content)?;
        Ok(settings)
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct IntegrationConfigPatchGate {
    state: Mutex<IntegrationConfigPatchGateState>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct IntegrationConfigPatchGateState {
    paused: bool,
    released: bool,
}

#[cfg(test)]
impl IntegrationConfigPatchGate {
    fn pause(&self) {
        let mut state = lock_recover(&self.state);
        state.paused = true;
        self.changed.notify_all();
        while !state.released {
            state = match self.changed.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn wait_until_paused(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = lock_recover(&self.state);
        while !state.paused {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return false;
            };
            let (next, result) = match self.changed.wait_timeout(state, remaining) {
                Ok(waited) => waited,
                Err(poisoned) => poisoned.into_inner(),
            };
            state = next;
            if result.timed_out() && !state.paused {
                return false;
            }
        }
        true
    }

    fn release(&self) {
        let mut state = lock_recover(&self.state);
        state.released = true;
        self.changed.notify_all();
    }
}

impl Default for IntegrationConfigStore {
    fn default() -> Self {
        Self::new(config_dir())
    }
}

impl IntegrationConfigStore {
    /// Create a store rooted at `directory`.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            transaction_lock: integration_config_lock(&directory),
            directory,
            #[cfg(test)]
            patch_gate: None,
        }
    }

    #[cfg(test)]
    fn with_patch_gate(mut self, gate: Arc<IntegrationConfigPatchGate>) -> Self {
        self.patch_gate = Some(gate);
        self
    }

    /// Load a browser-safe `DefectDojo` DTO.
    ///
    /// # Errors
    /// Returns an error when the stored config cannot be read or validated.
    pub fn defectdojo(&self) -> Result<DefectDojoPublicConfig, String> {
        let config = self.load_defectdojo()?;
        Ok(DefectDojoPublicConfig::from(&config))
    }

    /// Merge, validate, and atomically persist a `DefectDojo` patch.
    ///
    /// Omitted protected fields are preserved. Secret/path values change only
    /// through an explicit [`ConfigValuePatch`].
    ///
    /// # Errors
    /// Returns an error without writing when the stored config or patch is invalid.
    pub fn patch_defectdojo(
        &self,
        patch: DefectDojoConfigPatch,
    ) -> Result<DefectDojoPublicConfig, String> {
        let _transaction = lock_recover(&self.transaction_lock);
        let mut config = self.load_defectdojo()?;
        #[cfg(test)]
        if let Some(gate) = &self.patch_gate {
            gate.pause();
        }
        apply_defectdojo_patch(&mut config, patch)?;
        validate_defectdojo_for_write(&config)?;
        let content = toml::to_string_pretty(&config)
            .map_err(|_| "DefectDojo settings could not be serialized".to_owned())?;
        crate::defectdojo::resolve_config(&content).map_err(|error| error.to_string())?;
        self.write_section("defectdojo", &content)?;
        Ok(DefectDojoPublicConfig::from(&config))
    }

    /// Load a browser-safe issue-tracker DTO.
    ///
    /// # Errors
    /// Returns an error when the stored config cannot be read or decoded.
    pub fn issue_tracker(&self) -> Result<IssueTrackerPublicConfig, String> {
        let config = self.load_issue_tracker()?;
        Ok(IssueTrackerPublicConfig::from(&config))
    }

    /// Merge, validate, and atomically persist an issue-tracker patch.
    ///
    /// Omitted protected fields are preserved. Secret values change only
    /// through an explicit [`ConfigValuePatch`].
    ///
    /// # Errors
    /// Returns an error without writing when the stored config or patch is invalid.
    pub fn patch_issue_tracker(
        &self,
        patch: IssueTrackerConfigPatch,
    ) -> Result<IssueTrackerPublicConfig, String> {
        let _transaction = lock_recover(&self.transaction_lock);
        let mut config = self.load_issue_tracker()?;
        #[cfg(test)]
        if let Some(gate) = &self.patch_gate {
            gate.pause();
        }
        apply_issue_tracker_patch(&mut config, patch)?;
        validate_issue_tracker_for_write(&config)?;
        let content = toml::to_string_pretty(&config)
            .map_err(|_| "issue-tracker settings could not be serialized".to_owned())?;
        crate::issue_tracker::resolve_config(&content)
            .map_err(|_| "issue-tracker settings failed validation".to_owned())?;
        self.write_section("issue_tracker", &content)?;
        Ok(IssueTrackerPublicConfig::from(&config))
    }

    fn load_defectdojo(&self) -> Result<crate::defectdojo::DefectDojoConfig, String> {
        let raw = read_config_from(&self.directory, "defectdojo")?;
        crate::defectdojo::resolve_config(&raw)
            .map_err(|_| "stored DefectDojo settings are invalid".to_owned())
    }

    fn load_issue_tracker(&self) -> Result<crate::issue_tracker::IssueTrackerConfig, String> {
        let raw = read_config_from(&self.directory, "issue_tracker")?;
        crate::issue_tracker::resolve_config(&raw)
            .map_err(|_| "stored issue-tracker settings are invalid".to_owned())
    }

    fn write_section(&self, section: &str, content: &str) -> Result<(), String> {
        let section = validated_section(section)?;
        std::fs::create_dir_all(&self.directory).map_err(|error| error.to_string())?;
        write_private_config_file(&self.directory.join(format!("{section}.toml")), content)
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn integration_config_lock(directory: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<std::collections::HashMap<PathBuf, Weak<Mutex<()>>>>> =
        OnceLock::new();

    let key = std::fs::canonicalize(directory)
        .or_else(|_| std::path::absolute(directory))
        .unwrap_or_else(|_| directory.to_path_buf());
    let mut locks =
        lock_recover(LOCKS.get_or_init(|| Mutex::new(std::collections::HashMap::new())));
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn apply_optional_string_patch(
    target: &mut Option<String>,
    patch: ConfigValuePatch<String>,
    field: &str,
) -> Result<(), String> {
    match patch {
        ConfigValuePatch::Replace { value } => {
            if value.trim().is_empty() {
                return Err(format!("{field} replacement cannot be empty; use clear"));
            }
            reject_redaction_marker(&value, field)?;
            *target = Some(value);
        }
        ConfigValuePatch::Clear => *target = None,
    }
    Ok(())
}

fn apply_environment_patch(
    target: &mut String,
    patch: ConfigValuePatch<String>,
    field: &str,
) -> Result<(), String> {
    match patch {
        ConfigValuePatch::Replace { value } => {
            validate_environment_name(&value, field)?;
            *target = value;
        }
        ConfigValuePatch::Clear => target.clear(),
    }
    Ok(())
}

fn reject_redaction_marker(value: &str, field: &str) -> Result<(), String> {
    if contains_redaction_marker(value) {
        return Err(format!("{field} cannot contain a redaction marker"));
    }
    Ok(())
}

fn contains_redaction_marker(value: &str) -> bool {
    value.contains("<redacted>") || value.contains("<redacted-path>")
}

fn apply_optional_non_path_string_patch(
    target: &mut Option<String>,
    patch: ConfigValuePatch<String>,
    field: &str,
) -> Result<(), String> {
    match patch {
        ConfigValuePatch::Replace { value } => {
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("{field} replacement cannot be empty; use clear"));
            }
            reject_redaction_marker(value, field)?;
            if looks_like_absolute_host_path(value) {
                return Err(format!("{field} must not be an absolute path"));
            }
            *target = Some(value.to_owned());
        }
        ConfigValuePatch::Clear => *target = None,
    }
    Ok(())
}

fn apply_repository_patch(
    target: &mut String,
    patch: ConfigValuePatch<String>,
) -> Result<(), String> {
    match patch {
        ConfigValuePatch::Replace { value } => {
            let value = value.trim();
            if value.is_empty() {
                return Err("repo replacement cannot be empty; use clear".to_owned());
            }
            reject_redaction_marker(value, "repo")?;
            if looks_like_absolute_host_path(value) || value.contains("://") {
                return Err("repo must be a repository identifier, not a URL or path".to_owned());
            }
            value.clone_into(target);
        }
        ConfigValuePatch::Clear => target.clear(),
    }
    Ok(())
}

fn validate_environment_name(value: &str, field: &str) -> Result<(), String> {
    reject_redaction_marker(value, field)?;
    let mut chars = value.chars();
    let valid_first = chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic());
    if !valid_first || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(format!("{field} must be an environment-variable name"));
    }
    Ok(())
}

fn validate_http_url(value: &str, field: &str) -> Result<(), String> {
    reject_redaction_marker(value, field)?;
    let url = reqwest::Url::parse(value).map_err(|_| format!("{field} must be a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{field} must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{field} must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{field} must not contain a query or fragment"));
    }
    if url.host_str().is_none() {
        return Err(format!("{field} must include a host"));
    }
    Ok(())
}

fn apply_defectdojo_patch(
    config: &mut crate::defectdojo::DefectDojoConfig,
    patch: DefectDojoConfigPatch,
) -> Result<(), String> {
    if let Some(url) = patch.url {
        config.url = url;
    }
    if let Some(api_token) = patch.api_token {
        apply_optional_string_patch(&mut config.api_token, api_token, "api_token")?;
    }
    if let Some(api_token_env) = patch.api_token_env {
        apply_environment_patch(&mut config.api_token_env, api_token_env, "api_token_env")?;
    }
    if let Some(verify_tls) = patch.verify_tls {
        config.verify_tls = verify_tls;
    }
    if let Some(product_name) = patch.product_name {
        apply_optional_string_patch(&mut config.product_name, product_name, "product_name")?;
    }
    if let Some(product_type_name) = patch.product_type_name {
        apply_optional_string_patch(
            &mut config.product_type_name,
            product_type_name,
            "product_type_name",
        )?;
    }
    if let Some(engagement_name) = patch.engagement_name {
        apply_optional_string_patch(
            &mut config.engagement_name,
            engagement_name,
            "engagement_name",
        )?;
    }
    if let Some(auto_create) = patch.auto_create {
        config.auto_create = auto_create;
    }
    if let Some(reimport) = patch.reimport {
        config.reimport = reimport;
    }
    if let Some(lifecycle) = patch.lifecycle {
        if let Some(autostart) = lifecycle.autostart {
            config.lifecycle.autostart = autostart;
        }
        if let Some(compose_project) = lifecycle.compose_project {
            apply_optional_non_path_string_patch(
                &mut config.lifecycle.compose_project,
                compose_project,
                "lifecycle.compose_project",
            )?;
        }
        if let Some(compose_files) = lifecycle.compose_files {
            match compose_files {
                ConfigValuePatch::Replace { value } => {
                    for path in &value {
                        if path.trim().is_empty() {
                            return Err(
                                "lifecycle.compose_files cannot contain an empty path".to_owned()
                            );
                        }
                        reject_redaction_marker(path, "lifecycle.compose_files")?;
                    }
                    config.lifecycle.compose_files = value;
                }
                ConfigValuePatch::Clear => config.lifecycle.compose_files.clear(),
            }
        }
        if let Some(timeout) = lifecycle.startup_timeout_secs {
            match timeout {
                ConfigValuePatch::Replace { value } if value > 0 => {
                    config.lifecycle.startup_timeout_secs = Some(value);
                }
                ConfigValuePatch::Replace { .. } => {
                    return Err(
                        "lifecycle.startup_timeout_secs must be greater than zero".to_owned()
                    );
                }
                ConfigValuePatch::Clear => config.lifecycle.startup_timeout_secs = None,
            }
        }
    }
    Ok(())
}

fn validate_defectdojo_for_write(
    config: &crate::defectdojo::DefectDojoConfig,
) -> Result<(), String> {
    validate_http_url(config.url.trim(), "url")?;
    if let Some(token) = config.api_token.as_deref() {
        if token.trim().is_empty() {
            return Err("api_token cannot be empty; use clear".to_owned());
        }
        reject_redaction_marker(token, "api_token")?;
    }
    if !config.api_token_env.is_empty() {
        validate_environment_name(&config.api_token_env, "api_token_env")?;
    }
    if config
        .api_token
        .as_deref()
        .is_none_or(|token| token.trim().is_empty())
        && config.api_token_env.trim().is_empty()
    {
        return Err("DefectDojo requires a direct token or token environment name".to_owned());
    }
    if config.lifecycle.startup_timeout_secs == Some(0) {
        return Err("lifecycle.startup_timeout_secs must be greater than zero".to_owned());
    }
    if let Some(compose_project) = config.lifecycle.compose_project.as_deref() {
        reject_redaction_marker(compose_project, "lifecycle.compose_project")?;
    }
    for path in &config.lifecycle.compose_files {
        if path.trim().is_empty() {
            return Err("lifecycle.compose_files cannot contain an empty path".to_owned());
        }
        reject_redaction_marker(path, "lifecycle.compose_files")?;
    }
    Ok(())
}

fn apply_issue_tracker_patch(
    config: &mut crate::issue_tracker::IssueTrackerConfig,
    patch: IssueTrackerConfigPatch,
) -> Result<(), String> {
    if let Some(provider) = patch.provider {
        config.provider = provider.trim().to_ascii_lowercase();
    }
    if let Some(host) = patch.host {
        apply_optional_string_patch(&mut config.host, host, "host")?;
    }
    if let Some(repo) = patch.repo {
        apply_repository_patch(&mut config.repo, repo)?;
    }
    if let Some(api_token) = patch.api_token {
        apply_optional_string_patch(&mut config.api_token, api_token, "api_token")?;
    }
    if let Some(api_token_env) = patch.api_token_env {
        apply_environment_patch(&mut config.api_token_env, api_token_env, "api_token_env")?;
    }
    if let Some(username) = patch.username {
        apply_optional_string_patch(&mut config.username, username, "username")?;
    }
    if let Some(labels) = patch.labels {
        if labels.iter().any(|label| label.trim().is_empty()) {
            return Err("labels cannot contain an empty value".to_owned());
        }
        config.labels = labels;
    }
    if let Some(verify_tls) = patch.verify_tls {
        config.verify_tls = verify_tls;
    }
    Ok(())
}

fn validate_issue_tracker_for_write(
    config: &crate::issue_tracker::IssueTrackerConfig,
) -> Result<(), String> {
    let provider = config.provider.trim().to_ascii_lowercase();
    reject_redaction_marker(&config.repo, "repo")?;
    match provider.as_str() {
        "" | "none" => {}
        "github" | "gitlab" => {
            let repo = config.repo.trim();
            if repo.is_empty() {
                return Err("repo is required when the issue tracker is enabled".to_owned());
            }
            if !looks_like_absolute_host_path(repo) && repo.contains("://") {
                return Err("repo must be a repository identifier, not a URL or path".to_owned());
            }
        }
        _ => return Err("provider must be github, gitlab, or none".to_owned()),
    }
    if let Some(host) = config
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        validate_http_url(host, "host")?;
    }
    if let Some(token) = config.api_token.as_deref() {
        if token.trim().is_empty() {
            return Err("api_token cannot be empty; use clear".to_owned());
        }
        reject_redaction_marker(token, "api_token")?;
    }
    if !config.api_token_env.is_empty() {
        validate_environment_name(&config.api_token_env, "api_token_env")?;
    }
    if config.labels.iter().any(|label| label.trim().is_empty()) {
        return Err("labels cannot contain an empty value".to_owned());
    }
    Ok(())
}

/// Validate that `name` is a known section before touching the filesystem.
///
/// # Errors
/// Returns an error string if `name` is not a recognized section.
pub fn validated_section(name: &str) -> Result<&'static str, String> {
    CONFIG_SECTIONS
        .iter()
        .copied()
        .find(|s| *s == name)
        .ok_or_else(|| format!("unknown config section: {name}"))
}

/// Resolve the runtime data directory (`<repo>/data`, else `./data`).
#[must_use]
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("HF_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    // Source checkout keeps data next to the tree; an installed app uses a
    // writable per-user directory instead of the read-only `/data` that a
    // Finder-launched .app would otherwise target (see `init::config_dir`).
    crate::repo_root().map_or_else(
        || crate::init::user_app_dir().join("data"),
        |r| r.join("data"),
    )
}

/// Default seconds of flat coverage before a run surfaces a stagnation proposal.
pub const DEFAULT_STAGNATION_THRESHOLD_SECS: u64 = 120;

/// Default stagnation windows (each `coverage_stagnation_secs` long) before a
/// run's proposal escalates from improving the mutation inputs to
/// regenerating the harness.
pub const DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS: u64 = 2;

/// Default stagnation windows before a run's proposal escalates to
/// recommending a stop.
pub const DEFAULT_STAGNATION_STOP_WINDOWS: u64 = 4;

/// Default coverage-drop threshold (percent) at which the auto-revert policy
/// restores the previous harness revision.
pub const DEFAULT_AUTO_REVERT_THRESHOLD_PCT: f64 = 20.0;

/// Whether a coverage-drop threshold is a meaningful percentage.
///
/// Rejecting non-finite and out-of-range values prevents a malformed config
/// from silently making an armed rollback policy impossible to trigger.
#[must_use]
pub(crate) fn valid_auto_revert_threshold(value: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= 100.0
}

/// The auto-revert policy: whether a harness change that regresses coverage
/// past [`Self::threshold_pct`] should automatically restore the previous
/// (last-good) harness revision, and by how much coverage must drop to trigger.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AutoRevertPolicy {
    /// Whether the policy is armed. Off by default -- restoring a harness is a
    /// mutation, so a user must opt in.
    pub enabled: bool,
    /// The edge-coverage drop (percent, vs a comparable run's harness) at or
    /// above which the revert fires.
    pub threshold_pct: f64,
    /// When set, a detected regression is only reported (journaled + surfaced),
    /// never applied. Intended for headless/scheduled campaigns, which run with
    /// permissive guardrails and would otherwise mutate the harness with no
    /// human in the loop.
    pub notify_only: bool,
}

/// The resolved auto-revert policy.
///
/// Resolution order: the `HF_AUTO_REVERT` / `HF_AUTO_REVERT_THRESHOLD_PCT` /
/// `HF_AUTO_REVERT_NOTIFY_ONLY` env overrides, then `auto_revert_enabled` /
/// `auto_revert_threshold_pct` / `auto_revert_notify_only` in `oxfuzz.toml`,
/// then off with a [`DEFAULT_AUTO_REVERT_THRESHOLD_PCT`] threshold.
#[must_use]
pub fn auto_revert_policy() -> AutoRevertPolicy {
    resolve_auto_revert_policy(
        std::env::var("HF_AUTO_REVERT").ok().as_deref(),
        std::env::var("HF_AUTO_REVERT_THRESHOLD_PCT")
            .ok()
            .as_deref(),
        std::env::var("HF_AUTO_REVERT_NOTIFY_ONLY").ok().as_deref(),
        read_config("oxfuzz").ok().as_deref(),
    )
}

/// Parse a permissive boolean env value (`1/true/yes/on` vs `0/false/no/off`);
/// `None` when unset or unrecognized so the next precedence tier applies.
fn parse_flag(s: Option<&str>) -> Option<bool> {
    match s.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "true" | "yes" | "on") => Some(true),
        Some("0" | "false" | "no" | "off") => Some(false),
        _ => None,
    }
}

/// Pure resolver for [`auto_revert_policy`], split out so the precedence (env
/// over TOML over default) is unit-testable without touching the environment or
/// filesystem.
fn resolve_auto_revert_policy(
    env_enabled: Option<&str>,
    env_threshold: Option<&str>,
    env_notify_only: Option<&str>,
    oxfuzz_toml: Option<&str>,
) -> AutoRevertPolicy {
    #[derive(Deserialize)]
    struct OxfuzzConfig {
        auto_revert_enabled: Option<bool>,
        auto_revert_threshold_pct: Option<f64>,
        auto_revert_notify_only: Option<bool>,
    }
    let parsed = oxfuzz_toml.and_then(|raw| toml::from_str::<OxfuzzConfig>(raw).ok());
    let enabled = parse_flag(env_enabled)
        .or_else(|| parsed.as_ref().and_then(|c| c.auto_revert_enabled))
        .unwrap_or(false);
    // Validate each source independently so an out-of-range env value falls
    // through to a valid TOML threshold instead of skipping it and landing on the
    // hard-coded default (the env value would otherwise win the `or_else`, then be
    // filtered out after TOML was already bypassed).
    let threshold_pct = env_threshold
        .map(str::trim)
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| valid_auto_revert_threshold(*v))
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|c| c.auto_revert_threshold_pct)
                .filter(|v| valid_auto_revert_threshold(*v))
        })
        .unwrap_or(DEFAULT_AUTO_REVERT_THRESHOLD_PCT);
    let notify_only = parse_flag(env_notify_only)
        .or_else(|| parsed.as_ref().and_then(|c| c.auto_revert_notify_only))
        .unwrap_or(false);
    AutoRevertPolicy {
        enabled,
        threshold_pct,
        notify_only,
    }
}

/// Seconds without a coverage increase before `run_fuzzer` surfaces a
/// stagnation proposal (regenerate the harness / add seeds).
///
/// Resolution order: the `HF_COVERAGE_STAGNATION_SECS` env override, then
/// `coverage_stagnation_secs` in `oxfuzz.toml`, then
/// [`DEFAULT_STAGNATION_THRESHOLD_SECS`]. Lower proposes sooner; set it very
/// high to effectively silence the proposal.
#[must_use]
pub fn coverage_stagnation_secs() -> u64 {
    resolve_stagnation_secs(
        std::env::var("HF_COVERAGE_STAGNATION_SECS").ok().as_deref(),
        read_config("oxfuzz").ok().as_deref(),
    )
}

/// Pure resolver for [`coverage_stagnation_secs`], split out so the precedence
/// (env over TOML over default) is unit-testable without touching the
/// environment or filesystem.
fn resolve_stagnation_secs(env: Option<&str>, oxfuzz_toml: Option<&str>) -> u64 {
    #[derive(Deserialize)]
    struct OxfuzzConfig {
        coverage_stagnation_secs: Option<u64>,
    }
    if let Some(v) = env.map(str::trim).and_then(|s| s.parse::<u64>().ok()) {
        return v;
    }
    oxfuzz_toml
        .and_then(|raw| toml::from_str::<OxfuzzConfig>(raw).ok())
        .and_then(|c| c.coverage_stagnation_secs)
        .unwrap_or(DEFAULT_STAGNATION_THRESHOLD_SECS)
}

/// The resolved stagnation-escalation policy for `run_fuzzer`.
///
/// Resolution order per knob: the `HF_COVERAGE_STAGNATION_SECS` /
/// `HF_COVERAGE_STAGNATION_NEW_HARNESS_WINDOWS` /
/// `HF_COVERAGE_STAGNATION_STOP_WINDOWS` env overrides, then
/// `coverage_stagnation_secs` / `coverage_stagnation_new_harness_windows` /
/// `coverage_stagnation_stop_windows` in `oxfuzz.toml`, then the defaults.
/// Window counts that violate `1 <= new_harness_windows < stop_windows` (they
/// would make the harness tier unreachable) fall back to the default windows.
#[must_use]
pub fn coverage_stagnation_policy() -> hf_coverage::StagnationPolicy {
    resolve_stagnation_policy(
        std::env::var("HF_COVERAGE_STAGNATION_SECS").ok().as_deref(),
        std::env::var("HF_COVERAGE_STAGNATION_NEW_HARNESS_WINDOWS")
            .ok()
            .as_deref(),
        std::env::var("HF_COVERAGE_STAGNATION_STOP_WINDOWS")
            .ok()
            .as_deref(),
        read_config("oxfuzz").ok().as_deref(),
    )
}

/// Pure resolver for [`coverage_stagnation_policy`], split out so the
/// precedence (env over TOML over default) and the window validation are
/// unit-testable without touching the environment or filesystem.
fn resolve_stagnation_policy(
    env_secs: Option<&str>,
    env_new_harness: Option<&str>,
    env_stop: Option<&str>,
    oxfuzz_toml: Option<&str>,
) -> hf_coverage::StagnationPolicy {
    #[derive(Deserialize)]
    struct OxfuzzConfig {
        coverage_stagnation_new_harness_windows: Option<u64>,
        coverage_stagnation_stop_windows: Option<u64>,
    }
    let parsed = oxfuzz_toml.and_then(|raw| toml::from_str::<OxfuzzConfig>(raw).ok());
    let parse_windows = |env: Option<&str>, toml: Option<u64>, default: u64| {
        env.map(str::trim)
            .and_then(|s| s.parse::<u64>().ok())
            .or(toml)
            .unwrap_or(default)
    };
    let new_harness_windows = parse_windows(
        env_new_harness,
        parsed
            .as_ref()
            .and_then(|c| c.coverage_stagnation_new_harness_windows),
        DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS,
    );
    let stop_windows = parse_windows(
        env_stop,
        parsed
            .as_ref()
            .and_then(|c| c.coverage_stagnation_stop_windows),
        DEFAULT_STAGNATION_STOP_WINDOWS,
    );
    let (new_harness_windows, stop_windows) =
        if valid_stagnation_windows(new_harness_windows, stop_windows) {
            (new_harness_windows, stop_windows)
        } else {
            (
                DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS,
                DEFAULT_STAGNATION_STOP_WINDOWS,
            )
        };
    hf_coverage::StagnationPolicy {
        threshold_secs: resolve_stagnation_secs(env_secs, oxfuzz_toml),
        new_harness_windows,
        stop_windows,
    }
}

/// The escalation windows keep every tier reachable: at least one window
/// before the harness proposal, and the stop proposal strictly after it.
fn valid_stagnation_windows(new_harness_windows: u64, stop_windows: u64) -> bool {
    new_harness_windows >= 1 && stop_windows > new_harness_windows
}

/// Resolved config/data locations.
#[must_use]
pub fn app_paths() -> AppPaths {
    AppPaths {
        config_dir: config_dir().display().to_string(),
        data_dir: data_dir().display().to_string(),
        workspace_dir: crate::workspace_root().display().to_string(),
    }
}

/// List the editable config sections and whether each has a live file.
#[must_use]
pub fn list_configs() -> Vec<ConfigSection> {
    let dir = config_dir();
    CONFIG_SECTIONS
        .iter()
        .map(|name| ConfigSection {
            name: (*name).to_string(),
            exists: dir.join(format!("{name}.toml")).is_file(),
        })
        .collect()
}

/// Read a config section's raw TOML.
///
/// Resolution order: the live `<section>.toml`, then an on-disk
/// `<section>.example.toml`, then the example **embedded at compile time**. The
/// embedded fallback matters for an installed app: its per-user `config_dir()`
/// is unseeded (no live or example files on disk), so without it every settings
/// form would render empty. The embedded defaults give the same content a source
/// checkout sees, and saving writes a live file into the writable config dir.
///
/// # Errors
/// Returns an error string if `name` is unknown or the file cannot be read.
pub fn read_config(name: &str) -> Result<String, String> {
    read_config_from(&config_dir(), name)
}

fn read_config_from(directory: &Path, name: &str) -> Result<String, String> {
    let section = validated_section(name)?;
    let live = directory.join(format!("{section}.toml"));
    let example = directory.join(format!("{section}.example.toml"));
    if live.is_file() {
        std::fs::read_to_string(&live).map_err(|e| e.to_string())
    } else if example.is_file() {
        std::fs::read_to_string(&example).map_err(|e| e.to_string())
    } else {
        Ok(bundled_example(section).to_owned())
    }
}

/// The example TOML for a section, embedded at compile time so an installed app
/// (whose per-user config dir is unseeded) still shows sensible defaults rather
/// than an empty form. Returns `""` for an unrecognized section (already
/// rejected by [`validated_section`]).
fn bundled_example(section: &str) -> &'static str {
    match section {
        "oxfuzz" => include_str!("../../../config/oxfuzz.example.toml"),
        "providers" => include_str!("../../../config/providers.example.toml"),
        "defectdojo" => include_str!("../../../config/defectdojo.example.toml"),
        "issue_tracker" => include_str!("../../../config/issue_tracker.example.toml"),
        _ => "",
    }
}

/// Parse raw TOML into a JSON value, for driving structured settings forms.
/// Empty content yields an empty object.
///
/// # Errors
/// Returns an error string if the content is not valid TOML.
pub fn toml_to_json(content: &str) -> Result<serde_json::Value, String> {
    if content.trim().is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let value: toml::Value = toml::from_str(content).map_err(|e| format!("invalid TOML: {e}"))?;
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// Serialize a JSON value (from a settings form) back into TOML text.
///
/// # Errors
/// Returns an error string if the value cannot be represented as TOML.
pub fn json_to_toml(value: &serde_json::Value) -> Result<String, String> {
    // TOML has no null type, so a form field left unset (serialized as JSON
    // `null` by the GUI) cannot be represented. Drop null entries -- the correct
    // TOML representation of an absent optional value -- before converting.
    let mut value = value.clone();
    strip_nulls(&mut value);
    let toml_value: toml::Value =
        serde_json::from_value(value).map_err(|e| format!("not representable: {e}"))?;
    toml::to_string_pretty(&toml_value).map_err(|e| e.to_string())
}

/// Recursively remove `null` values from a JSON value (objects drop the key,
/// arrays recurse into elements) so it can be represented as TOML.
fn strip_nulls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

/// Write a config section's raw TOML to its live file (validated first).
///
/// # Errors
/// Returns an error string if `name` is unknown, the content is invalid TOML,
/// or the file cannot be written.
pub fn write_config(name: &str, content: &str) -> Result<(), String> {
    let section = validated_section(name)?;
    toml::from_str::<toml::Value>(content).map_err(|e| format!("invalid TOML: {e}"))?;
    if section == "oxfuzz" {
        parse_oxfuzz_runtime_config(content)?;
    }
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_private_config_file(&dir.join(format!("{section}.toml")), content)
}

/// Create and fully sync an owner-only temporary config file.
fn private_temporary_file(parent: &Path, content: &str) -> Result<tempfile::NamedTempFile, String> {
    use std::io::Write as _;

    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".oxfuzz-config-")
        .tempfile_in(parent)
        .map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    temporary
        .write_all(content.as_bytes())
        .map_err(|error| error.to_string())?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    Ok(temporary)
}

/// Atomically replace a config file with owner-only permissions.
///
/// Creating a fresh inode repairs a pre-existing `0644` file instead of
/// preserving its public mode during an in-place truncate/write. `persist`
/// uses the platform's replace operation, including replacement on Windows.
pub(crate) fn write_private_config_file(path: &Path, content: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    private_temporary_file(parent, content)?
        .persist(path)
        .map_err(|error| error.error.to_string())?;
    Ok(())
}

/// Copy a config into place exactly once with private permissions.
///
/// A fully written temporary inode is persisted without replacement, making
/// creation atomic and non-clobbering: a concurrent creator or pre-existing
/// symlink yields `Ok(false)` instead of being overwritten or followed.
pub fn copy_private_config_if_missing(source: &Path, destination: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    if !std::fs::symlink_metadata(source).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(format!(
            "config source is not a regular file: {}",
            source.display()
        ));
    }
    let content = std::fs::read_to_string(source).map_err(|error| error.to_string())?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match private_temporary_file(parent, &content)?.persist_noclobber(destination) {
        Ok(_) => Ok(true),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.error.to_string()),
    }
}

/// Validate real TOML config files and tighten them to owner-only on Unix.
/// Example templates contain no live credentials and retain repository modes.
pub fn secure_config_directory(config_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(config_dir).map_err(|error| error.to_string())?;
    let entries = std::fs::read_dir(config_dir).map_err(|error| error.to_string())?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension() != Some(std::ffi::OsStr::new("toml"))
            || path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.ends_with(".example"))
        {
            continue;
        }
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            return Err(format!("config must be a regular file: {}", path.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = entry
                .metadata()
                .map_err(|error| format!("inspect {}: {error}", path.display()))?
                .permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions)
                .map_err(|error| format!("secure {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

/// List the models from the configured provider pool. Drives model selectors.
#[must_use]
pub fn list_models() -> Vec<ModelInfo> {
    get_providers()
        .into_iter()
        .filter(|p| !p.model.is_empty())
        .map(|p| ModelInfo {
            id: p.id,
            provider_type: p.provider_type,
            model: p.model,
        })
        .collect()
}

/// Load the provider pool as structured data for the settings form.
#[must_use]
pub fn get_providers() -> Vec<ProviderConfig> {
    match try_get_providers() {
        Ok(providers) => providers,
        Err(error) => {
            tracing::warn!(%error, "provider config could not be loaded");
            Vec::new()
        }
    }
}

fn parse_provider_config(raw: &str) -> Result<Vec<ProviderConfig>, String> {
    let config: hf_provider::ProviderPoolConfig =
        toml::from_str(raw).map_err(|error| format!("invalid provider config: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("invalid provider config: {error}"))?;
    Ok(config.providers)
}

fn try_get_providers() -> Result<Vec<ProviderConfig>, String> {
    parse_provider_config(&read_config("providers")?)
}

fn merge_provider_secrets(incoming: &mut [ProviderConfig], existing: &[ProviderConfig]) {
    let existing: std::collections::HashMap<_, _> = existing
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    for provider in incoming {
        let Some(prior) = existing.get(provider.id.as_str()) else {
            continue;
        };
        if provider.api_key.as_deref().is_none_or(str::is_empty) {
            provider.api_key.clone_from(&prior.api_key);
        }
        if provider.api_key_env.as_deref().is_none_or(str::is_empty) {
            provider.api_key_env.clone_from(&prior.api_key_env);
        }
        for (name, value) in &prior.headers {
            provider
                .headers
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }
}

/// Persist provider edits from a redacted presentation DTO without erasing
/// existing credentials or secret headers omitted by that DTO.
///
/// Trusted local presentations that need to clear a credential explicitly use
/// [`set_providers`] instead. An explicit non-empty incoming secret replaces the
/// existing value.
///
/// # Errors
/// Returns an error when the provider config cannot be written.
pub fn set_providers_preserving_secrets(providers: &[ProviderConfig]) -> Result<(), String> {
    let mut merged = providers.to_vec();
    merge_provider_secrets(&mut merged, &try_get_providers()?);
    set_providers(&merged)
}

/// Quote/escape a value as a TOML basic string.
fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Serialize a serde enum (e.g. `ToolCallingMode`) to its wire string.
fn enum_str<T: Serialize>(v: &T) -> Option<String> {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
}

fn render_provider(body: &mut String, provider: &ProviderConfig) {
    body.push_str("[[providers]]\n");
    let _ = writeln!(body, "id = {}", toml_string(&provider.id));
    let _ = writeln!(
        body,
        "provider_type = {}",
        toml_string(&provider.provider_type)
    );
    let _ = writeln!(body, "model = {}", toml_string(&provider.model));
    if !provider.enabled {
        let _ = writeln!(body, "enabled = false");
    }
    if !provider.tags.is_empty() {
        let values = provider
            .tags
            .iter()
            .map(|tag| toml_string(tag))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(body, "tags = [{values}]");
    }
    if !provider.capabilities.is_empty() {
        let values = provider
            .capabilities
            .iter()
            .filter_map(enum_str)
            .map(|capability| toml_string(&capability))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(body, "capabilities = [{values}]");
    }
    let _ = writeln!(body, "max_concurrency = {}", provider.max_concurrency);
    let _ = writeln!(body, "context_window = {}", provider.context_window);
    if provider.cost_per_1k_input > 0.0 {
        let _ = writeln!(body, "cost_per_1k_input = {}", provider.cost_per_1k_input);
    }
    if provider.cost_per_1k_output > 0.0 {
        let _ = writeln!(body, "cost_per_1k_output = {}", provider.cost_per_1k_output);
    }
    render_provider_optional_fields(body, provider);
    body.push('\n');
}

fn render_provider_optional_fields(body: &mut String, provider: &ProviderConfig) {
    if let Some(value) = provider.api_key.as_ref().filter(|value| !value.is_empty()) {
        let _ = writeln!(body, "api_key = {}", toml_string(value));
    }
    if let Some(value) = provider
        .api_key_env
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        let _ = writeln!(body, "api_key_env = {}", toml_string(value));
    }
    if let Some(value) = provider.base_url.as_ref().filter(|value| !value.is_empty()) {
        let _ = writeln!(body, "base_url = {}", toml_string(value));
    }
    if enum_str(&provider.http_protocol).as_deref() == Some("http2") {
        let _ = writeln!(body, "http_protocol = \"http2\"");
    }
    if let Some(value) = provider.include_usage {
        let _ = writeln!(body, "include_usage = {value}");
    }
    if let Some(value) = provider.use_max_completion_tokens {
        let _ = writeln!(body, "use_max_completion_tokens = {value}");
    }
    if let Some(value) = provider.temperature {
        let _ = writeln!(body, "temperature = {value}");
    }
    if let Some(value) = provider.top_p {
        let _ = writeln!(body, "top_p = {value}");
    }
    if let Some(value) = provider.tool_calling_mode.as_ref().and_then(enum_str) {
        let _ = writeln!(body, "tool_calling_mode = {}", toml_string(&value));
    }
    if let Some(value) = provider.icon.as_ref().filter(|value| !value.is_empty()) {
        let _ = writeln!(body, "icon = {}", toml_string(value));
    }
    render_azure_provider_fields(body, provider);
    render_provider_headers(body, provider);
}

fn render_azure_provider_fields(body: &mut String, provider: &ProviderConfig) {
    if let Some(value) = provider
        .azure_resource_name
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        let _ = writeln!(body, "azure_resource_name = {}", toml_string(value));
    }
    if let Some(value) = provider
        .azure_api_version
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        let _ = writeln!(body, "azure_api_version = {}", toml_string(value));
    }
    if let Some(value) = provider.azure_use_deployment_urls {
        let _ = writeln!(body, "azure_use_deployment_urls = {value}");
    }
    if let Some(value) = provider.azure_auth_mode.as_ref().and_then(enum_str) {
        let _ = writeln!(body, "azure_auth_mode = {}", toml_string(&value));
    }
}

fn render_provider_headers(body: &mut String, provider: &ProviderConfig) {
    let headers: Vec<_> = provider
        .headers
        .iter()
        .filter(|(key, _)| !key.trim().is_empty())
        .collect();
    if headers.is_empty() {
        return;
    }
    let _ = writeln!(body, "[providers.headers]");
    for (key, value) in headers {
        let _ = writeln!(body, "{} = {}", toml_string(key), toml_string(value));
    }
}

/// Persist the provider pool back to `providers.toml`, preserving the
/// pool-level preamble (freeze/health/proxy settings) ahead of the provider
/// entries. Emits every field of the full schema, with the optional
/// `[providers.headers]` table last (TOML requires sub-tables after scalars).
///
/// # Errors
/// Returns an error string if the rendered TOML is invalid or cannot be written.
pub fn set_providers(providers: &[ProviderConfig]) -> Result<(), String> {
    let existing = read_config("providers")?;
    let preamble = existing.find("[[providers]]").map_or_else(
        || {
            "# oxfuzz -- LLM Provider Pool Configuration\n\
             default_freeze_duration_secs = 60\n\
             max_freeze_duration_secs = 3600\n\
             health_check_interval_secs = 30\n\n"
                .to_string()
        },
        |idx| existing[..idx].to_string(),
    );

    let mut body = String::new();
    for provider in providers {
        render_provider(&mut body, provider);
    }

    let content = format!("{preamble}{body}");
    parse_provider_config(&content)?;
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_private_config_file(&dir.join("providers.toml"), &content)
}

/// Probe a provider configuration by building it and sending a tiny chat
/// request. Powers the Settings -> Providers "Test Connection" button.
///
/// # Errors
/// Returns the provider error string if the request fails.
pub async fn test_provider(mut cfg: ProviderConfig) -> Result<String, String> {
    cfg.enabled = true;
    let pool_cfg = hf_provider::ProviderPoolConfig {
        providers: vec![cfg],
        ..Default::default()
    };
    let provider = hf_provider::build_providers(&pool_cfg)
        .into_iter()
        .next()
        .ok_or_else(|| "could not construct provider from config".to_owned())?;
    let mut req =
        hf_core::provider::ChatRequest::from_messages(vec![hf_core::types::Message::user(
            "Reply with the single word: OK",
        )]);
    req.max_tokens = Some(16);
    match provider.chat_completion(&req).await {
        Ok(resp) => {
            let reply: String = resp.text().chars().take(120).collect();
            Ok(format!(
                "Connected to model {}. Reply: {}",
                provider.metadata().model,
                reply.trim()
            ))
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stagnation_secs_precedence_env_then_toml_then_default() {
        // Env wins over everything.
        assert_eq!(
            resolve_stagnation_secs(Some("45"), Some("coverage_stagnation_secs = 200")),
            45
        );
        // No env -> the TOML value.
        assert_eq!(
            resolve_stagnation_secs(None, Some("coverage_stagnation_secs = 200")),
            200
        );
        // TOML without the key -> the default.
        assert_eq!(
            resolve_stagnation_secs(None, Some("log_level = \"info\"")),
            DEFAULT_STAGNATION_THRESHOLD_SECS
        );
        // Nothing configured -> the default.
        assert_eq!(
            resolve_stagnation_secs(None, None),
            DEFAULT_STAGNATION_THRESHOLD_SECS
        );
        // A non-numeric env value falls through rather than panicking.
        assert_eq!(
            resolve_stagnation_secs(Some("not-a-number"), None),
            DEFAULT_STAGNATION_THRESHOLD_SECS
        );
    }

    #[test]
    fn stagnation_policy_precedence_env_then_toml_then_default() {
        // Env wins over everything, per knob.
        let policy = resolve_stagnation_policy(
            Some("45"),
            Some("3"),
            Some("9"),
            Some(
                "coverage_stagnation_secs = 200\n\
                 coverage_stagnation_new_harness_windows = 5\n\
                 coverage_stagnation_stop_windows = 12\n",
            ),
        );
        assert_eq!(policy.threshold_secs, 45);
        assert_eq!(policy.new_harness_windows, 3);
        assert_eq!(policy.stop_windows, 9);

        // No env -> the TOML values.
        let policy = resolve_stagnation_policy(
            None,
            None,
            None,
            Some(
                "coverage_stagnation_secs = 200\n\
                 coverage_stagnation_new_harness_windows = 5\n\
                 coverage_stagnation_stop_windows = 12\n",
            ),
        );
        assert_eq!(policy.threshold_secs, 200);
        assert_eq!(policy.new_harness_windows, 5);
        assert_eq!(policy.stop_windows, 12);

        // Nothing configured -> the defaults (which keep the historical 120s
        // threshold and surface the gentlest tier first).
        let policy = resolve_stagnation_policy(None, None, None, None);
        assert_eq!(policy.threshold_secs, DEFAULT_STAGNATION_THRESHOLD_SECS);
        assert_eq!(
            policy.new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(policy.stop_windows, DEFAULT_STAGNATION_STOP_WINDOWS);
    }

    #[test]
    fn stagnation_policy_rejects_inverted_or_zero_windows() {
        // stop <= new_harness makes the harness tier unreachable: both window
        // knobs fall back to the defaults.
        let policy = resolve_stagnation_policy(None, Some("4"), Some("4"), None);
        assert_eq!(
            policy.new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(policy.stop_windows, DEFAULT_STAGNATION_STOP_WINDOWS);

        let policy = resolve_stagnation_policy(None, Some("5"), Some("4"), None);
        assert_eq!(
            policy.new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(policy.stop_windows, DEFAULT_STAGNATION_STOP_WINDOWS);

        // A zero window count is rejected the same way.
        let policy = resolve_stagnation_policy(None, Some("0"), Some("9"), None);
        assert_eq!(
            policy.new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(policy.stop_windows, DEFAULT_STAGNATION_STOP_WINDOWS);

        // An invalid TOML pair falls back the same way, while the threshold
        // knob still resolves independently.
        let policy = resolve_stagnation_policy(
            None,
            None,
            None,
            Some(
                "coverage_stagnation_secs = 90\n\
                 coverage_stagnation_new_harness_windows = 6\n\
                 coverage_stagnation_stop_windows = 6\n",
            ),
        );
        assert_eq!(policy.threshold_secs, 90);
        assert_eq!(
            policy.new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(policy.stop_windows, DEFAULT_STAGNATION_STOP_WINDOWS);

        // A non-numeric env value falls through to the TOML value.
        let policy = resolve_stagnation_policy(
            None,
            Some("not-a-number"),
            None,
            Some("coverage_stagnation_new_harness_windows = 3\n"),
        );
        assert_eq!(policy.new_harness_windows, 3);
    }

    #[test]
    fn auto_revert_policy_precedence_env_then_toml_then_default() {
        // Default: off, with the default threshold, applying (not notify-only).
        let p = resolve_auto_revert_policy(None, None, None, None);
        assert!(!p.enabled);
        assert!(!p.notify_only);
        assert!((p.threshold_pct - DEFAULT_AUTO_REVERT_THRESHOLD_PCT).abs() < f64::EPSILON);

        // TOML supplies all values when no env is set.
        let toml =
            "auto_revert_enabled = true\nauto_revert_threshold_pct = 35.0\nauto_revert_notify_only = true\n";
        let p = resolve_auto_revert_policy(None, None, None, Some(toml));
        assert!(p.enabled);
        assert!(p.notify_only);
        assert!((p.threshold_pct - 35.0).abs() < f64::EPSILON);

        // Env overrides the TOML for every field.
        let toml =
            "auto_revert_enabled = false\nauto_revert_threshold_pct = 35.0\nauto_revert_notify_only = true\n";
        let p = resolve_auto_revert_policy(Some("1"), Some("50"), Some("false"), Some(toml));
        assert!(p.enabled);
        assert!(!p.notify_only);
        assert!((p.threshold_pct - 50.0).abs() < f64::EPSILON);

        // A non-positive or non-numeric threshold falls through to the default.
        let p = resolve_auto_revert_policy(Some("yes"), Some("-5"), None, None);
        assert!(p.enabled);
        assert!((p.threshold_pct - DEFAULT_AUTO_REVERT_THRESHOLD_PCT).abs() < f64::EPSILON);

        // Percent thresholds outside (0, 100] or non-finite values are not
        // meaningful coverage gates and must not silently disable rollback.
        for invalid in ["0", "100.1", "inf", "NaN"] {
            let p = resolve_auto_revert_policy(Some("yes"), Some(invalid), None, None);
            assert!(
                (p.threshold_pct - DEFAULT_AUTO_REVERT_THRESHOLD_PCT).abs() < f64::EPSILON,
                "invalid threshold {invalid} was accepted"
            );
        }

        // An unrecognized flag value leaves the policy off.
        assert!(!resolve_auto_revert_policy(Some("maybe"), None, None, None).enabled);
    }

    #[test]
    fn toml_json_round_trip_preserves_values() {
        let src = "\
name = \"runtime\"\n\
max_mem_mb = 2048\n\
network = false\n\
tags = [\"a\", \"b\"]\n\n\
[sandbox]\n\
image = \"oxfuzz\"\n\
cpus = 2\n";
        let value = toml_to_json(src).expect("parse");
        assert_eq!(value["max_mem_mb"], 2048);
        assert_eq!(value["network"], false);
        assert_eq!(value["sandbox"]["image"], "oxfuzz");

        // Re-serialize and re-parse: the structured values survive the trip.
        let back = json_to_toml(&value).expect("serialize");
        let reparsed = toml_to_json(&back).expect("reparse");
        assert_eq!(reparsed, value);
    }

    #[test]
    fn json_to_toml_strips_nulls_in_provider_arrays() {
        let v = serde_json::json!({
            "providers": [{
                "id": "p", "model": "m", "api_key": "k",
                "api_key_env": null, "temperature": null, "tool_calling_mode": null
            }]
        });
        let toml = json_to_toml(&v).expect("null fields should be stripped, not error");
        assert!(toml.contains("id = \"p\""));
        assert!(!toml.contains("api_key_env"), "null keys must be dropped");
    }

    #[test]
    fn browser_provider_updates_preserve_opaque_secrets() {
        let parse = |raw: &str| {
            toml::from_str::<hf_provider::ProviderPoolConfig>(raw)
                .unwrap()
                .providers
                .into_iter()
                .next()
                .unwrap()
        };
        let existing = vec![parse(
            "[[providers]]\nid = \"primary\"\nprovider_type = \"openai\"\nmodel = \"old\"\napi_key = \"secret\"\napi_key_env = \"HF_PROVIDER_KEY\"\n[providers.headers]\nX-Secret = \"hidden\"\n",
        )];
        let mut incoming = vec![parse(
            "[[providers]]\nid = \"primary\"\nprovider_type = \"openai\"\nmodel = \"new\"\napi_key = \"\"\napi_key_env = \"\"\n[providers.headers]\nX-Public = \"new\"\n",
        )];

        merge_provider_secrets(&mut incoming, &existing);

        assert_eq!(incoming[0].model, "new");
        assert_eq!(incoming[0].api_key.as_deref(), Some("secret"));
        assert_eq!(incoming[0].api_key_env.as_deref(), Some("HF_PROVIDER_KEY"));
        assert_eq!(
            incoming[0].headers.get("X-Secret").map(String::as_str),
            Some("hidden")
        );
        assert_eq!(
            incoming[0].headers.get("X-Public").map(String::as_str),
            Some("new")
        );
    }

    #[test]
    fn browser_integration_updates_preserve_protected_values_by_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("defectdojo.toml"),
            r#"
url = "https://dojo.example.test"
api_token = "synthetic-dojo-token"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"
verify_tls = true
product_name = "old-product"
auto_create = true
reimport = true

[lifecycle]
autostart = true
compose_files = ["/synthetic/private/compose.yml"]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("issue_tracker.toml"),
            r#"
provider = "github"
host = "https://github.example.test"
repo = "example/project"
api_token = "synthetic-issue-token"
api_token_env = "SYNTHETIC_ISSUE_TOKEN_ENV"
labels = ["fuzzing"]
verify_tls = true
"#,
        )
        .unwrap();
        let store = IntegrationConfigStore::new(dir.path());

        let dojo = store
            .patch_defectdojo(DefectDojoConfigPatch {
                product_name: Some(ConfigValuePatch::Replace {
                    value: "new-product".to_owned(),
                }),
                ..DefectDojoConfigPatch::default()
            })
            .expect("safe DefectDojo patch");
        let tracker = store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                labels: Some(vec!["security".to_owned(), "fuzzing".to_owned()]),
                ..IssueTrackerConfigPatch::default()
            })
            .expect("safe issue-tracker patch");

        assert_eq!(dojo.product_name.as_deref(), Some("new-product"));
        assert!(dojo.credentials.api_token_configured);
        assert!(dojo.credentials.api_token_env_configured);
        assert!(dojo.lifecycle.compose_files_configured);
        assert_eq!(tracker.labels, ["security", "fuzzing"]);
        assert!(tracker.api_token_configured);
        assert!(tracker.api_token_env_configured);

        let dojo_raw = std::fs::read_to_string(dir.path().join("defectdojo.toml")).unwrap();
        let tracker_raw = std::fs::read_to_string(dir.path().join("issue_tracker.toml")).unwrap();
        assert!(dojo_raw.contains("synthetic-dojo-token"));
        assert!(dojo_raw.contains("SYNTHETIC_DOJO_TOKEN_ENV"));
        assert!(dojo_raw.contains("/synthetic/private/compose.yml"));
        assert!(tracker_raw.contains("synthetic-issue-token"));
        assert!(tracker_raw.contains("SYNTHETIC_ISSUE_TOKEN_ENV"));
    }

    #[test]
    fn browser_integration_updates_require_explicit_replace_or_clear() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("defectdojo.toml"),
            r#"
url = "https://dojo.example.test"
api_token = "synthetic-old-token"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"

[lifecycle]
compose_files = ["/synthetic/old/compose.yml"]
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("issue_tracker.toml"),
            r#"
provider = "gitlab"
host = "https://gitlab.example.test"
repo = "example/project"
api_token = "synthetic-old-issue-token"
api_token_env = "SYNTHETIC_ISSUE_TOKEN_ENV"
"#,
        )
        .unwrap();
        let store = IntegrationConfigStore::new(dir.path());

        let dojo = store
            .patch_defectdojo(DefectDojoConfigPatch {
                api_token: Some(ConfigValuePatch::Clear),
                api_token_env: Some(ConfigValuePatch::Replace {
                    value: "SYNTHETIC_NEW_DOJO_ENV".to_owned(),
                }),
                lifecycle: Some(DefectDojoLifecyclePatch {
                    compose_files: Some(ConfigValuePatch::Replace {
                        value: vec!["/synthetic/new/compose.yml".to_owned()],
                    }),
                    ..DefectDojoLifecyclePatch::default()
                }),
                ..DefectDojoConfigPatch::default()
            })
            .expect("explicit DefectDojo protected-value patch");
        let tracker = store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                api_token: Some(ConfigValuePatch::Replace {
                    value: "synthetic-new-issue-token".to_owned(),
                }),
                api_token_env: Some(ConfigValuePatch::Clear),
                ..IssueTrackerConfigPatch::default()
            })
            .expect("explicit issue-tracker protected-value patch");

        assert!(!dojo.credentials.api_token_configured);
        assert!(dojo.credentials.api_token_env_configured);
        assert!(dojo.lifecycle.compose_files_configured);
        assert!(tracker.api_token_configured);
        assert!(!tracker.api_token_env_configured);

        let dojo_raw = std::fs::read_to_string(dir.path().join("defectdojo.toml")).unwrap();
        let tracker_raw = std::fs::read_to_string(dir.path().join("issue_tracker.toml")).unwrap();
        assert!(!dojo_raw.contains("synthetic-old-token"));
        assert!(!dojo_raw.contains("SYNTHETIC_DOJO_TOKEN_ENV"));
        assert!(!dojo_raw.contains("/synthetic/old/compose.yml"));
        assert!(dojo_raw.contains("SYNTHETIC_NEW_DOJO_ENV"));
        assert!(dojo_raw.contains("/synthetic/new/compose.yml"));
        assert!(!tracker_raw.contains("synthetic-old-issue-token"));
        assert!(!tracker_raw.contains("SYNTHETIC_ISSUE_TOKEN_ENV"));
        assert!(tracker_raw.contains("synthetic-new-issue-token"));
    }

    #[test]
    fn invalid_browser_integration_patch_is_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issue_tracker.toml");
        let original = r#"
provider = "github"
repo = "example/project"
api_token_env = "SYNTHETIC_ISSUE_TOKEN_ENV"
"#;
        std::fs::write(&path, original).unwrap();
        let store = IntegrationConfigStore::new(dir.path());

        let error = store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                provider: Some("github".to_owned()),
                repo: Some(ConfigValuePatch::Replace {
                    value: String::new(),
                }),
                ..IssueTrackerConfigPatch::default()
            })
            .expect_err("an enabled tracker requires a repository");

        assert!(error.contains("repo"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), original);
    }

    #[test]
    fn public_integration_dtos_serialize_without_protected_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("defectdojo.toml"),
            r#"
url = "https://synthetic-user:synthetic-password@dojo.example.test/base?token=synthetic-query-secret"
api_token = "synthetic-dojo-token"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"

[lifecycle]
compose_project = "/synthetic/private/compose-project"
compose_files = ["/synthetic/private/compose.yml"]
"#,
        )
        .unwrap();
        let store = IntegrationConfigStore::new(dir.path());

        let json = serde_json::to_string(&store.defectdojo().unwrap()).unwrap();

        assert!(!json.contains("synthetic-dojo-token"));
        assert!(!json.contains("SYNTHETIC_DOJO_TOKEN_ENV"));
        assert!(!json.contains("synthetic-user"));
        assert!(!json.contains("synthetic-password"));
        assert!(!json.contains("synthetic-query-secret"));
        assert!(!json.contains("/synthetic/private"));
        assert!(!json.contains("compose-project"));
        assert!(!json.contains("compose.yml"));
        assert!(json.contains("api_token_configured"));
        assert!(json.contains("compose_files_configured"));
    }

    #[test]
    fn path_shaped_integration_values_are_opaque_until_explicitly_changed() {
        let dir = tempfile::tempdir().unwrap();
        let dojo_path = dir.path().join("defectdojo.toml");
        let tracker_path = dir.path().join("issue_tracker.toml");
        std::fs::write(
            &dojo_path,
            r#"
url = "https://dojo.example.test"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"
product_name = "old-product"

[lifecycle]
compose_project = "/synthetic/private/dojo-project"
"#,
        )
        .unwrap();
        std::fs::write(
            &tracker_path,
            r#"
provider = "github"
repo = "/synthetic/private/repository"
api_token_env = "SYNTHETIC_ISSUE_TOKEN_ENV"
labels = ["fuzzing"]
"#,
        )
        .unwrap();
        let store = IntegrationConfigStore::new(dir.path());

        let dojo = store.defectdojo().unwrap();
        let tracker = store.issue_tracker().unwrap();
        assert!(dojo.lifecycle.compose_project.configured);
        assert_eq!(dojo.lifecycle.compose_project.value, None);
        assert!(tracker.repo.configured);
        assert_eq!(tracker.repo.value, None);
        let public_json = serde_json::json!({ "dojo": dojo, "tracker": tracker }).to_string();
        assert!(!public_json.contains("/synthetic/private"));
        assert!(!public_json.contains("<redacted-path>"));

        store
            .patch_defectdojo(DefectDojoConfigPatch {
                product_name: Some(ConfigValuePatch::Replace {
                    value: "new-product".to_owned(),
                }),
                ..DefectDojoConfigPatch::default()
            })
            .unwrap();
        store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                labels: Some(vec!["security".to_owned()]),
                ..IssueTrackerConfigPatch::default()
            })
            .unwrap();
        assert!(std::fs::read_to_string(&dojo_path)
            .unwrap()
            .contains("/synthetic/private/dojo-project"));
        assert!(std::fs::read_to_string(&tracker_path)
            .unwrap()
            .contains("/synthetic/private/repository"));

        let dojo = store
            .patch_defectdojo(DefectDojoConfigPatch {
                lifecycle: Some(DefectDojoLifecyclePatch {
                    compose_project: Some(ConfigValuePatch::Replace {
                        value: "dojo-main".to_owned(),
                    }),
                    ..DefectDojoLifecyclePatch::default()
                }),
                ..DefectDojoConfigPatch::default()
            })
            .unwrap();
        let tracker = store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                repo: Some(ConfigValuePatch::Replace {
                    value: "security/project".to_owned(),
                }),
                ..IssueTrackerConfigPatch::default()
            })
            .unwrap();
        assert_eq!(
            dojo.lifecycle.compose_project.value.as_deref(),
            Some("dojo-main")
        );
        assert_eq!(tracker.repo.value.as_deref(), Some("security/project"));

        let dojo_before_marker = std::fs::read_to_string(&dojo_path).unwrap();
        let tracker_before_marker = std::fs::read_to_string(&tracker_path).unwrap();
        assert!(store
            .patch_defectdojo(DefectDojoConfigPatch {
                lifecycle: Some(DefectDojoLifecyclePatch {
                    compose_project: Some(ConfigValuePatch::Replace {
                        value: "<redacted-path>".to_owned(),
                    }),
                    ..DefectDojoLifecyclePatch::default()
                }),
                ..DefectDojoConfigPatch::default()
            })
            .is_err());
        assert!(store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                repo: Some(ConfigValuePatch::Replace {
                    value: "<redacted-path>".to_owned(),
                }),
                ..IssueTrackerConfigPatch::default()
            })
            .is_err());
        assert_eq!(
            std::fs::read_to_string(&dojo_path).unwrap(),
            dojo_before_marker
        );
        assert_eq!(
            std::fs::read_to_string(&tracker_path).unwrap(),
            tracker_before_marker
        );
        assert!(!dojo_before_marker.contains("<redacted-path>"));
        assert!(!tracker_before_marker.contains("<redacted-path>"));

        store
            .patch_defectdojo(DefectDojoConfigPatch {
                lifecycle: Some(DefectDojoLifecyclePatch {
                    compose_project: Some(ConfigValuePatch::Clear),
                    ..DefectDojoLifecyclePatch::default()
                }),
                ..DefectDojoConfigPatch::default()
            })
            .unwrap();
        store
            .patch_issue_tracker(IssueTrackerConfigPatch {
                provider: Some("none".to_owned()),
                repo: Some(ConfigValuePatch::Clear),
                ..IssueTrackerConfigPatch::default()
            })
            .unwrap();
        assert!(
            !store
                .defectdojo()
                .unwrap()
                .lifecycle
                .compose_project
                .configured
        );
        assert!(!store.issue_tracker().unwrap().repo.configured);
    }

    #[test]
    fn integration_patch_transactions_are_serialized_across_store_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("defectdojo.toml");
        std::fs::write(
            &path,
            r#"
url = "https://dojo.example.test"
api_token = "synthetic-old-token"
product_name = "old-product"
"#,
        )
        .unwrap();
        let gate = std::sync::Arc::new(IntegrationConfigPatchGate::default());
        let first_store = IntegrationConfigStore::new(dir.path()).with_patch_gate(gate.clone());
        let second_store = IntegrationConfigStore::new(dir.path());

        let first = std::thread::spawn(move || {
            first_store.patch_defectdojo(DefectDojoConfigPatch {
                product_name: Some(ConfigValuePatch::Replace {
                    value: "new-product".to_owned(),
                }),
                ..DefectDojoConfigPatch::default()
            })
        });
        assert!(gate.wait_until_paused(std::time::Duration::from_secs(5)));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            let result = second_store.patch_defectdojo(DefectDojoConfigPatch {
                api_token: Some(ConfigValuePatch::Replace {
                    value: "synthetic-new-token".to_owned(),
                }),
                ..DefectDojoConfigPatch::default()
            });
            done_tx.send(()).unwrap();
            result
        });
        assert_eq!(
            done_rx.recv_timeout(std::time::Duration::from_millis(150)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "the second store entered the read-modify-write transaction concurrently"
        );

        gate.release();
        first.join().unwrap().unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        second.join().unwrap().unwrap();

        let raw = std::fs::read_to_string(path).unwrap();
        assert!(raw.contains("new-product"));
        assert!(raw.contains("synthetic-new-token"));
        assert!(!raw.contains("synthetic-old-token"));
    }

    #[test]
    fn malformed_provider_config_is_not_treated_as_an_empty_secret_set() {
        let error = parse_provider_config("[[providers]]\nid = [not valid toml")
            .expect_err("malformed provider state must fail closed");

        assert!(error.contains("invalid provider config"));
    }

    #[test]
    fn toml_to_json_empty_is_object() {
        assert_eq!(
            toml_to_json("   ").expect("empty"),
            serde_json::Value::Object(serde_json::Map::new())
        );
    }

    #[test]
    fn runtime_subsystem_config_is_deserialized_and_validated() {
        let config = parse_oxfuzz_runtime_config(
            r#"
            coverage_stagnation_secs = 90

            [fuzzing]
            enabled_engines = ["libfuzzer", "afl++"]
            default_engine = "afl++"
            default_duration_secs = 45

            [fuzzing.sandbox]
            max_mem_mb = 3072
            max_cpus = 2
            max_duration_secs = 600

            [automotive]
            enabled = true
            sidecar_image = "oxfuzz/scapy-automotive:2.7.0"
            allowed_protocols = ["can", "iso_tp", "uds", "do_ip"]
            allowed_modes = ["offline_pcap", "virtual_can"]
            virtual_interfaces = ["vcan0"]

            [automotive.limits]
            max_packets = 500
            max_input_bytes = 16777216
            max_payload_bytes = 1048576
            max_duration_secs = 30
            max_rate_per_second = 50
            max_output_bytes = 16777216
            max_mem_mb = 768
            max_cpus = 1

            [automotive.physical_bench]
            enabled = false
            require_approval = true
            interfaces = []
            arbitration_ids = []
            uds_services = []
            allow_dangerous_services = false

            [knowledge]
            l2_max_tokens = 123
            retrieval_strategy = "keyword"
            bm25_weight = 2.5
            vector_weight = 0.25

            [session]
            max_depth = 4

            [scheduler]
            max_concurrent_executions = 3
            default_missed_policy = "catch_up"
            default_concurrency_policy = "allow"
            history_retention_limit = 17
            "#,
        )
        .expect("runtime config should parse");

        assert_eq!(config.knowledge.l2_max_tokens, 123);
        let run = config
            .fuzzing
            .resolve(Some(hf_core::engine::EngineKind::AflPlusPlus), Some(90))
            .expect("enabled engine and bounded duration should resolve");
        assert_eq!(run.engine, hf_core::engine::EngineKind::AflPlusPlus);
        assert_eq!(run.duration_secs, 90);
        assert_eq!(run.max_mem_mb, 3072);
        assert_eq!(run.max_cpus, 2);
        assert_eq!(config.knowledge.retrieval_strategy, "keyword");
        assert!((config.knowledge.bm25_weight - 2.5).abs() < f64::EPSILON);
        assert_eq!(config.session.max_depth, 4);
        assert_eq!(config.scheduler.max_concurrent_executions, 3);
        assert_eq!(
            config.scheduler.default_missed_policy,
            hf_scheduler::MissedPolicy::CatchUp
        );
        assert_eq!(
            config.scheduler.default_concurrency_policy,
            hf_scheduler::ConcurrencyPolicy::Allow
        );
        assert_eq!(config.scheduler.history_retention_limit, 17);
        assert!(config.automotive.enabled);
        assert_eq!(config.automotive.limits.max_packets, 500);
        assert_eq!(config.automotive.limits.max_input_bytes, 16_777_216);
        assert_eq!(config.automotive.allowed_protocols[2], "uds");
    }

    #[test]
    fn stagnation_windows_parse_and_default_in_the_typed_config() {
        // Absent knobs keep the documented defaults.
        let config = parse_oxfuzz_runtime_config("coverage_stagnation_secs = 90\n")
            .expect("runtime config should parse");
        assert_eq!(config.coverage_stagnation_secs, 90);
        assert_eq!(
            config.coverage_stagnation_new_harness_windows,
            DEFAULT_STAGNATION_NEW_HARNESS_WINDOWS
        );
        assert_eq!(
            config.coverage_stagnation_stop_windows,
            DEFAULT_STAGNATION_STOP_WINDOWS
        );

        // Present knobs are honored.
        let config = parse_oxfuzz_runtime_config(
            "coverage_stagnation_new_harness_windows = 3\ncoverage_stagnation_stop_windows = 8\n",
        )
        .expect("runtime config should parse");
        assert_eq!(config.coverage_stagnation_new_harness_windows, 3);
        assert_eq!(config.coverage_stagnation_stop_windows, 8);
    }

    #[test]
    fn automotive_defaults_are_enabled_but_exclude_physical_access() {
        let settings = AutomotiveSettings::default();

        // The subsystem is on by default (offline + virtual modes) so the
        // workspace is present out of the box, but physical-bench access stays
        // off and approval-gated regardless of this master switch.
        assert!(settings.enabled);
        assert_eq!(settings.sidecar_image, "oxfuzz/scapy-automotive:2.7.0");
        assert!(settings
            .allowed_modes
            .iter()
            .any(|mode_| mode_ == "offline_pcap"));
        assert!(settings
            .allowed_modes
            .iter()
            .any(|mode_| mode_ == "virtual_can"));
        assert!(!settings
            .allowed_modes
            .iter()
            .any(|mode_| mode_ == "physical_bench"));
        assert!(!settings.physical_bench.enabled);
        assert!(settings.physical_bench.require_approval);
        assert!(settings.physical_bench.interfaces.is_empty());
        assert!(!settings.physical_bench.allow_dangerous_services);
        settings.validate().expect("safe defaults");
    }

    #[test]
    fn automotive_policy_rejects_unpinned_images_unsafe_interfaces_and_excessive_limits() {
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };

        settings.sidecar_image = "oxfuzz/scapy-automotive:latest".to_owned();
        assert!(settings.validate().unwrap_err().contains("pinned"));

        settings.sidecar_image = "oxfuzz/scapy-automotive:2.7.0".to_owned();
        settings.virtual_interfaces = vec!["../can0".to_owned()];
        assert!(settings.validate().unwrap_err().contains("interface"));

        settings.virtual_interfaces = vec!["can0".to_owned()];
        assert!(settings.validate().unwrap_err().contains("vcan"));

        settings.virtual_interfaces = vec!["vcan0".to_owned(), "vcan0".to_owned()];
        assert!(settings.validate().unwrap_err().contains("duplicate"));

        settings.virtual_interfaces = vec!["vcan0".to_owned()];
        settings.limits.max_packets = 10_001;
        assert!(settings.validate().unwrap_err().contains("virtual_can"));

        settings.limits.max_packets = 10_000;
        settings.limits.max_rate_per_second = 0;
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("max_rate_per_second"));

        settings.limits.max_rate_per_second = 100;
        settings.limits.max_packets = 1_000;
        settings.physical_bench.enabled = true;
        settings.physical_bench.require_approval = false;
        settings.physical_bench.interfaces = vec!["can0".to_owned()];
        settings.allowed_modes.push("physical_bench".to_owned());
        assert!(settings.validate().unwrap_err().contains("approval"));

        settings.physical_bench.require_approval = true;
        settings.limits.max_packets = 1_001;
        assert!(settings.validate().unwrap_err().contains("physical_bench"));

        settings.limits.max_packets = 1_000;
        settings.physical_bench.arbitration_ids = vec![0x7e0, 0x7e0];
        assert!(settings.validate().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn automotive_policy_rejects_flag_like_and_nameless_sidecar_images() {
        // The image is later emitted verbatim into the `docker run` argv, so
        // a leading `-` would be parsed as a docker CLI flag, voiding the
        // pinned-image guarantee.
        let mut settings = AutomotiveSettings {
            sidecar_image: "-w/tmp:x".to_owned(),
            ..AutomotiveSettings::default()
        };
        assert!(settings.validate().unwrap_err().contains("pinned"));

        settings.sidecar_image = "-evil".to_owned();
        assert!(settings.validate().unwrap_err().contains("pinned"));

        // A tag or digest without a name component is not a usable reference.
        settings.sidecar_image = ":2.7.0".to_owned();
        assert!(settings.validate().unwrap_err().contains("pinned"));

        settings.sidecar_image = format!("@sha256:{}", "a".repeat(64));
        assert!(settings.validate().unwrap_err().contains("pinned"));

        settings.sidecar_image = "oxfuzz/scapy-automotive:2.7.0".to_owned();
        settings.validate().expect("pinned tag");

        settings.sidecar_image = format!("oxfuzz/scapy-automotive@sha256:{}", "a".repeat(64));
        settings.validate().expect("pinned digest");
    }

    #[test]
    fn automotive_config_store_updates_only_the_typed_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oxfuzz.toml");
        std::fs::write(
            &path,
            r#"
coverage_stagnation_secs = 77

[fuzzing]
enabled_engines = ["libfuzzer"]
default_engine = "libfuzzer"
default_duration_secs = 22
"#,
        )
        .unwrap();
        let store = AutomotiveConfigStore::new(dir.path());
        let mut settings = AutomotiveSettings {
            enabled: true,
            ..AutomotiveSettings::default()
        };
        settings.allowed_protocols = vec!["can".to_owned(), "uds".to_owned()];

        assert_eq!(store.set(settings.clone()).unwrap(), settings);
        assert_eq!(store.get().unwrap(), settings);
        let raw = std::fs::read_to_string(path).unwrap();
        assert!(raw.contains("coverage_stagnation_secs = 77"));
        assert!(raw.contains("default_duration_secs = 22"));
        assert!(raw.contains("[automotive]"));
    }

    #[test]
    fn automotive_config_store_fails_closed_without_replacing_valid_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = AutomotiveConfigStore::new(dir.path());
        let valid = AutomotiveSettings::default();
        store.set(valid.clone()).unwrap();
        let path = dir.path().join("oxfuzz.toml");
        let before = std::fs::read_to_string(&path).unwrap();

        let mut invalid = valid;
        invalid.sidecar_image = "oxfuzz/scapy-automotive:latest".to_owned();
        assert!(store.set(invalid).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), before);
    }

    #[test]
    fn oxfuzz_config_rejects_removed_session_knobs() {
        let error =
            parse_oxfuzz_runtime_config("[session]\nmax_depth = 4\ntitle_summarize_interval = 3\n")
                .expect_err("removed no-op session option should be rejected");

        assert!(error.contains("title_summarize_interval"));
    }

    #[test]
    fn oxfuzz_config_rejects_invalid_runtime_values() {
        for raw in [
            "[fuzzing]\nenabled_engines = []\n",
            "[fuzzing]\nenabled_engines = [\"libfuzzer\", \"libfuzzer\"]\n",
            "[fuzzing]\nenabled_engines = [\"unknown\"]\ndefault_engine = \"unknown\"\n",
            "[fuzzing]\nenabled_engines = [\"afl++\"]\ndefault_engine = \"libfuzzer\"\n",
            "[fuzzing]\ndefault_duration_secs = 0\n",
            "[fuzzing]\ndefault_duration_secs = 120\n[fuzzing.sandbox]\nmax_duration_secs = 60\n",
            "[fuzzing.sandbox]\nmax_mem_mb = 0\n",
            "[fuzzing.sandbox]\nmax_cpus = 0\n",
            "[fuzzing.sandbox]\nmax_duration_secs = 0\n",
            "[knowledge]\nretrieval_strategy = \"unknown\"\n",
            "[knowledge]\nretrieval_strategy = \"semantic\"\n",
            "[knowledge]\nbm25_weight = -1.0\n",
            "[knowledge]\nvector_weight = nan\n",
            "[scheduler]\nmax_concurrent_executions = 0\n",
            "[session]\nmax_depth = 0\n",
            "coverage_stagnation_new_harness_windows = 0\n",
            "coverage_stagnation_new_harness_windows = 4\ncoverage_stagnation_stop_windows = 4\n",
            "coverage_stagnation_new_harness_windows = 5\ncoverage_stagnation_stop_windows = 4\n",
        ] {
            assert!(
                parse_oxfuzz_runtime_config(raw).is_err(),
                "invalid runtime config was accepted: {raw}"
            );
        }
    }

    #[test]
    fn semantic_strategy_is_accepted_once_embedding_is_enabled() {
        // The gate lifts only when the embedding pipeline is turned on.
        let raw = "[knowledge]\nretrieval_strategy = \"semantic\"\nembedding_enabled = true\n";
        let parsed =
            parse_oxfuzz_runtime_config(raw).expect("semantic + embedding_enabled must parse");
        assert_eq!(parsed.knowledge.retrieval_strategy, "semantic");
        assert!(parsed.knowledge.embedding_enabled);
    }

    #[test]
    fn fuzzing_policy_uses_defaults_and_rejects_disabled_or_excessive_runs() {
        assert_eq!(
            FuzzingSettings::default().enabled_engines,
            vec!["libfuzzer", "afl++", "honggfuzz", "syzkaller"],
        );

        let settings = FuzzingSettings {
            enabled_engines: vec!["honggfuzz".to_owned()],
            default_engine: "honggfuzz".to_owned(),
            default_duration_secs: 30,
            sandbox: FuzzingSandboxSettings {
                max_mem_mb: 1024,
                max_cpus: 1,
                max_duration_secs: 60,
            },
        };

        let resolved = settings
            .resolve(None, None)
            .expect("defaults should resolve");
        assert_eq!(resolved.engine, hf_core::engine::EngineKind::Honggfuzz);
        assert_eq!(resolved.duration_secs, 30);
        assert_eq!(resolved.max_mem_mb, 1024);
        assert_eq!(resolved.max_cpus, 1);

        assert!(settings
            .resolve(Some(hf_core::engine::EngineKind::LibFuzzer), Some(30))
            .unwrap_err()
            .contains("disabled"));
        assert!(settings
            .resolve(Some(hf_core::engine::EngineKind::Honggfuzz), Some(61))
            .unwrap_err()
            .contains("maximum"));
    }

    #[test]
    fn internal_budgets_clamp_to_the_operator_ceiling() {
        // An operator who lowers the campaign ceiling must still be able to
        // smoke-qualify and promote harnesses: internal pipeline budgets clamp
        // to the ceiling instead of failing the resolution.
        let settings = FuzzingSettings {
            default_duration_secs: 30,
            sandbox: FuzzingSandboxSettings {
                max_duration_secs: 30,
                ..FuzzingSandboxSettings::default()
            },
            ..FuzzingSettings::default()
        };

        // The operator-requested path still rejects over-ceiling durations.
        assert!(settings
            .resolve(Some(hf_core::engine::EngineKind::LibFuzzer), Some(60))
            .unwrap_err()
            .contains("maximum"));

        // The internal path clamps the same budget to the ceiling.
        let resolved = settings
            .resolve_internal(hf_core::engine::EngineKind::LibFuzzer, 60)
            .expect("internal budget should clamp to the operator ceiling");
        assert_eq!(resolved.duration_secs, 30);

        // A budget already under the ceiling resolves unchanged.
        let under = settings
            .resolve_internal(hf_core::engine::EngineKind::LibFuzzer, 10)
            .expect("under-ceiling internal budget should resolve unchanged");
        assert_eq!(under.duration_secs, 10);
    }

    #[test]
    fn harness_default_skips_enabled_engines_that_do_not_support_the_language() {
        let settings = FuzzingSettings {
            enabled_engines: vec![
                "syzkaller".to_owned(),
                "afl++".to_owned(),
                "libfuzzer".to_owned(),
            ],
            default_engine: "syzkaller".to_owned(),
            ..FuzzingSettings::default()
        };

        assert_eq!(
            settings
                .resolve_harness_engine(None, hf_core::target::TargetLanguage::C)
                .expect("C should use the first enabled user-space engine"),
            hf_core::engine::EngineKind::AflPlusPlus
        );
        assert_eq!(
            settings
                .resolve_harness_engine(None, hf_core::target::TargetLanguage::Rust)
                .expect("Rust should skip engines without Rust harness support"),
            hf_core::engine::EngineKind::LibFuzzer
        );
        assert!(settings
            .resolve_harness_engine(
                Some(hf_core::engine::EngineKind::Syzkaller),
                hf_core::target::TargetLanguage::C,
            )
            .unwrap_err()
            .contains("not supported"));
    }

    #[test]
    fn every_section_has_a_valid_embedded_example() {
        // The embedded fallback is what an installed app (unseeded config dir)
        // renders, so each section must yield non-empty, valid TOML.
        for &section in CONFIG_SECTIONS {
            let example = bundled_example(section);
            assert!(
                !example.trim().is_empty(),
                "section '{section}' has no embedded example"
            );
            toml_to_json(example).unwrap_or_else(|e| {
                panic!("embedded example for '{section}' is invalid TOML: {e}")
            });
        }
    }

    #[test]
    fn editable_sections_only_include_runtime_consumed_configuration() {
        assert_eq!(
            CONFIG_SECTIONS,
            ["oxfuzz", "providers", "defectdojo", "issue_tracker"]
        );

        for retired in [
            "engines",
            "runtime",
            "guardrails",
            "storage",
            "session",
            "tools",
        ] {
            assert!(
                validated_section(retired).is_err(),
                "no-op section '{retired}' must not be editable"
            );
        }
    }

    #[test]
    fn global_templates_only_document_consumed_settings() {
        let expected = [
            "auto_revert_enabled",
            "auto_revert_notify_only",
            "auto_revert_threshold_pct",
            "automotive",
            "coverage_stagnation_new_harness_windows",
            "coverage_stagnation_secs",
            "coverage_stagnation_stop_windows",
            "fuzzing",
            "knowledge",
            "scheduler",
            "session",
        ];

        for (label, raw) in [
            ("example", bundled_example("oxfuzz")),
            ("live", include_str!("../../../config/oxfuzz.toml")),
        ] {
            let value = toml_to_json(raw).expect("global template must be valid TOML");
            let mut keys = value
                .as_object()
                .expect("global template must be a TOML table")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(
                keys, expected,
                "{label} global config advertises no-op keys"
            );
        }
    }

    #[test]
    fn environment_template_uses_the_production_workspace_override() {
        let template = include_str!("../../../.env.example");
        assert!(template.contains("HF_WORKSPACE_DIR="));
        assert!(!template.contains("HF_FUZZ_WORKSPACE"));
        for unsupported in [
            "HF_WEB_PORT",
            "AFL_FUZZ_BIN",
            "HONGGFUZZ_BIN",
            "LIBFUZZER_LINK_FLAGS",
        ] {
            assert!(
                !template.contains(unsupported),
                "environment template advertises unsupported override {unsupported}"
            );
        }
    }

    #[test]
    fn private_config_write_replaces_existing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("providers.toml");
        std::fs::write(&path, "api_key = \"old\"\n").unwrap();

        write_private_config_file(&path, "api_key = \"new\"\n").unwrap();

        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "api_key = \"new\"\n"
        );
    }

    #[test]
    fn private_config_copy_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.toml");
        let destination = dir.path().join("user").join("providers.toml");
        std::fs::write(&source, "api_key = \"first\"\n").unwrap();

        assert!(copy_private_config_if_missing(&source, &destination).unwrap());
        std::fs::write(&source, "api_key = \"replacement\"\n").unwrap();
        assert!(!copy_private_config_if_missing(&source, &destination).unwrap());
        assert_eq!(
            std::fs::read_to_string(destination).unwrap(),
            "api_key = \"first\"\n"
        );
    }

    #[test]
    fn private_config_copy_does_not_require_source_when_destination_exists() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("missing-source.toml");
        let destination = dir.path().join("providers.toml");
        std::fs::write(&destination, "api_key = \"existing\"\n").unwrap();

        assert!(!copy_private_config_if_missing(&source, &destination).unwrap());
        assert_eq!(
            std::fs::read_to_string(destination).unwrap(),
            "api_key = \"existing\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_config_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.toml");
        let copied = dir.path().join("copied.toml");
        let replaced = dir.path().join("replaced.toml");
        std::fs::write(&source, "api_key = \"source\"\n").unwrap();
        std::fs::write(&replaced, "api_key = \"old\"\n").unwrap();
        std::fs::set_permissions(&replaced, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(copy_private_config_if_missing(&source, &copied).unwrap());
        write_private_config_file(&replaced, "api_key = \"new\"\n").unwrap();

        for path in [copied, replaced] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
