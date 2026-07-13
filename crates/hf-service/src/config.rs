//! File-backed configuration access shared by every presentation layer.
//!
//! Config lives in `<repo>/config/<section>.toml` (falling back to the bundled
//! `<section>.example.toml` template). The CLI, web API, and GUI all read and
//! write it through these functions so the logic lives in the service layer and
//! never diverges between presentations (AGENTS.md 2.9).

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::init::config_dir;

/// The editable config sections. Each maps to a `config/<name>.toml` file.
pub const CONFIG_SECTIONS: &[&str] = &[
    "hobot-fuzz",
    "providers",
    "engines",
    "runtime",
    "guardrails",
    "storage",
    "session",
    "tools",
    "defectdojo",
    "issue_tracker",
];

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
/// `auto_revert_threshold_pct` / `auto_revert_notify_only` in `hobot-fuzz.toml`,
/// then off with a [`DEFAULT_AUTO_REVERT_THRESHOLD_PCT`] threshold.
#[must_use]
pub fn auto_revert_policy() -> AutoRevertPolicy {
    resolve_auto_revert_policy(
        std::env::var("HF_AUTO_REVERT").ok().as_deref(),
        std::env::var("HF_AUTO_REVERT_THRESHOLD_PCT")
            .ok()
            .as_deref(),
        std::env::var("HF_AUTO_REVERT_NOTIFY_ONLY").ok().as_deref(),
        read_config("hobot-fuzz").ok().as_deref(),
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
    hobot_toml: Option<&str>,
) -> AutoRevertPolicy {
    #[derive(Deserialize)]
    struct HobotConfig {
        auto_revert_enabled: Option<bool>,
        auto_revert_threshold_pct: Option<f64>,
        auto_revert_notify_only: Option<bool>,
    }
    let parsed = hobot_toml.and_then(|raw| toml::from_str::<HobotConfig>(raw).ok());
    let enabled = parse_flag(env_enabled)
        .or_else(|| parsed.as_ref().and_then(|c| c.auto_revert_enabled))
        .unwrap_or(false);
    let threshold_pct = env_threshold
        .map(str::trim)
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| parsed.as_ref().and_then(|c| c.auto_revert_threshold_pct))
        .filter(|v| valid_auto_revert_threshold(*v))
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
/// `coverage_stagnation_secs` in `hobot-fuzz.toml`, then
/// [`DEFAULT_STAGNATION_THRESHOLD_SECS`]. Lower proposes sooner; set it very
/// high to effectively silence the proposal.
#[must_use]
pub fn coverage_stagnation_secs() -> u64 {
    resolve_stagnation_secs(
        std::env::var("HF_COVERAGE_STAGNATION_SECS").ok().as_deref(),
        read_config("hobot-fuzz").ok().as_deref(),
    )
}

/// Pure resolver for [`coverage_stagnation_secs`], split out so the precedence
/// (env over TOML over default) is unit-testable without touching the
/// environment or filesystem.
fn resolve_stagnation_secs(env: Option<&str>, hobot_toml: Option<&str>) -> u64 {
    #[derive(Deserialize)]
    struct HobotConfig {
        coverage_stagnation_secs: Option<u64>,
    }
    if let Some(v) = env.map(str::trim).and_then(|s| s.parse::<u64>().ok()) {
        return v;
    }
    hobot_toml
        .and_then(|raw| toml::from_str::<HobotConfig>(raw).ok())
        .and_then(|c| c.coverage_stagnation_secs)
        .unwrap_or(DEFAULT_STAGNATION_THRESHOLD_SECS)
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
    let section = validated_section(name)?;
    let dir = config_dir();
    let live = dir.join(format!("{section}.toml"));
    let example = dir.join(format!("{section}.example.toml"));
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
        "hobot-fuzz" => include_str!("../../../config/hobot-fuzz.example.toml"),
        "providers" => include_str!("../../../config/providers.example.toml"),
        "engines" => include_str!("../../../config/engines.example.toml"),
        "runtime" => include_str!("../../../config/runtime.example.toml"),
        "guardrails" => include_str!("../../../config/guardrails.example.toml"),
        "storage" => include_str!("../../../config/storage.example.toml"),
        "session" => include_str!("../../../config/session.example.toml"),
        "tools" => include_str!("../../../config/tools.example.toml"),
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
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(format!("{section}.toml")), content).map_err(|e| e.to_string())
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
    let raw = read_config("providers").unwrap_or_default();
    toml::from_str::<hf_provider::ProviderPoolConfig>(&raw)
        .map(|c| c.providers)
        .unwrap_or_default()
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

/// Persist the provider pool back to `providers.toml`, preserving the
/// pool-level preamble (freeze/health/proxy settings) ahead of the provider
/// entries. Emits every field of the full schema, with the optional
/// `[providers.headers]` table last (TOML requires sub-tables after scalars).
///
/// # Errors
/// Returns an error string if the rendered TOML is invalid or cannot be written.
#[allow(clippy::too_many_lines)]
pub fn set_providers(providers: &[ProviderConfig]) -> Result<(), String> {
    let existing = read_config("providers").unwrap_or_default();
    let preamble = existing.find("[[providers]]").map_or_else(
        || {
            "# hobot_fuzz -- LLM Provider Pool Configuration\n\
             default_freeze_duration_secs = 60\n\
             max_freeze_duration_secs = 3600\n\
             health_check_interval_secs = 30\n\n"
                .to_string()
        },
        |idx| existing[..idx].to_string(),
    );

    let mut body = String::new();
    for p in providers {
        body.push_str("[[providers]]\n");
        let _ = writeln!(body, "id = {}", toml_string(&p.id));
        let _ = writeln!(body, "provider_type = {}", toml_string(&p.provider_type));
        let _ = writeln!(body, "model = {}", toml_string(&p.model));
        if !p.enabled {
            let _ = writeln!(body, "enabled = false");
        }
        if !p.tags.is_empty() {
            let tags = p
                .tags
                .iter()
                .map(|t| toml_string(t))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(body, "tags = [{tags}]");
        }
        if !p.capabilities.is_empty() {
            let caps = p
                .capabilities
                .iter()
                .filter_map(enum_str)
                .map(|c| toml_string(&c))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(body, "capabilities = [{caps}]");
        }
        let _ = writeln!(body, "max_concurrency = {}", p.max_concurrency);
        let _ = writeln!(body, "context_window = {}", p.context_window);
        if p.cost_per_1k_input > 0.0 {
            let _ = writeln!(body, "cost_per_1k_input = {}", p.cost_per_1k_input);
        }
        if p.cost_per_1k_output > 0.0 {
            let _ = writeln!(body, "cost_per_1k_output = {}", p.cost_per_1k_output);
        }
        if let Some(k) = p.api_key.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "api_key = {}", toml_string(k));
        }
        if let Some(k) = p.api_key_env.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "api_key_env = {}", toml_string(k));
        }
        if let Some(u) = p.base_url.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "base_url = {}", toml_string(u));
        }
        if enum_str(&p.http_protocol).as_deref() == Some("http2") {
            let _ = writeln!(body, "http_protocol = \"http2\"");
        }
        if let Some(b) = p.include_usage {
            let _ = writeln!(body, "include_usage = {b}");
        }
        if let Some(b) = p.use_max_completion_tokens {
            let _ = writeln!(body, "use_max_completion_tokens = {b}");
        }
        if let Some(t) = p.temperature {
            let _ = writeln!(body, "temperature = {t}");
        }
        if let Some(t) = p.top_p {
            let _ = writeln!(body, "top_p = {t}");
        }
        if let Some(m) = p.tool_calling_mode.as_ref().and_then(enum_str) {
            let _ = writeln!(body, "tool_calling_mode = {}", toml_string(&m));
        }
        if let Some(i) = p.icon.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "icon = {}", toml_string(i));
        }
        if let Some(r) = p.azure_resource_name.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "azure_resource_name = {}", toml_string(r));
        }
        if let Some(v) = p.azure_api_version.as_ref().filter(|s| !s.is_empty()) {
            let _ = writeln!(body, "azure_api_version = {}", toml_string(v));
        }
        if let Some(b) = p.azure_use_deployment_urls {
            let _ = writeln!(body, "azure_use_deployment_urls = {b}");
        }
        if let Some(m) = p.azure_auth_mode.as_ref().and_then(enum_str) {
            let _ = writeln!(body, "azure_auth_mode = {}", toml_string(&m));
        }
        let headers: Vec<_> = p
            .headers
            .iter()
            .filter(|(k, _)| !k.trim().is_empty())
            .collect();
        if !headers.is_empty() {
            let _ = writeln!(body, "[providers.headers]");
            for (k, v) in headers {
                let _ = writeln!(body, "{} = {}", toml_string(k), toml_string(v));
            }
        }
        body.push('\n');
    }

    let content = format!("{preamble}{body}");
    toml::from_str::<toml::Value>(&content).map_err(|e| format!("invalid TOML: {e}"))?;
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("providers.toml"), content).map_err(|e| e.to_string())
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
            assert_eq!(
                p.threshold_pct, DEFAULT_AUTO_REVERT_THRESHOLD_PCT,
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
image = \"hobot\"\n\
cpus = 2\n";
        let value = toml_to_json(src).expect("parse");
        assert_eq!(value["max_mem_mb"], 2048);
        assert_eq!(value["network"], false);
        assert_eq!(value["sandbox"]["image"], "hobot");

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
    fn toml_to_json_empty_is_object() {
        assert_eq!(
            toml_to_json("   ").expect("empty"),
            serde_json::Value::Object(serde_json::Map::new())
        );
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
    fn embedded_engines_example_exposes_the_engines_array() {
        // The settings form reads `value.engines`; the fallback must populate it
        // (this is exactly what the empty-form bug needed).
        let value = toml_to_json(bundled_example("engines")).expect("valid toml");
        let engines = value["engines"].as_array().expect("engines array");
        assert!(!engines.is_empty(), "embedded engines example is empty");
    }
}
