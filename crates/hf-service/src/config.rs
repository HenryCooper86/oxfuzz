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

/// One provider as surfaced to / received from the Providers settings form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// Stable provider id.
    pub id: String,
    /// Provider type (defaults to `openai-compat`).
    #[serde(default)]
    pub provider_type: String,
    /// Default model.
    #[serde(default)]
    pub model: String,
    /// Base URL for OpenAI-compatible endpoints.
    #[serde(default)]
    pub base_url: String,
    /// Inline API key (kept only in the gitignored live file).
    #[serde(default)]
    pub api_key: String,
    /// Name of an env var holding the API key.
    #[serde(default)]
    pub api_key_env: String,
    /// Whether the provider is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// HTTP protocol hint (`http1`/`http2`).
    #[serde(default)]
    pub http_protocol: String,
    /// Tool-calling mode hint.
    #[serde(default)]
    pub tool_calling_mode: String,
    /// Routing tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Max in-flight requests.
    #[serde(default = "default_concurrency")]
    pub max_concurrency: u32,
    /// Context window in tokens.
    #[serde(default = "default_context_window")]
    pub context_window: u64,
}

const fn default_true() -> bool {
    true
}
const fn default_concurrency() -> u32 {
    3
}
const fn default_context_window() -> u64 {
    128_000
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
    crate::repo_root().map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("data")
        },
        |r| r.join("data"),
    )
}

/// Resolved config/data locations.
#[must_use]
pub fn app_paths() -> AppPaths {
    AppPaths {
        config_dir: config_dir().display().to_string(),
        data_dir: data_dir().display().to_string(),
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

/// Read a config section's raw TOML, falling back to the bundled example.
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
        Ok(String::new())
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
    let parsed: toml::Value =
        toml::from_str(&raw).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
    let Some(arr) = parsed.get("providers").and_then(toml::Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .map(|p| {
            let get = |k: &str| {
                p.get(k)
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let provider_type = {
                let t = get("provider_type");
                if t.is_empty() {
                    "openai-compat".to_string()
                } else {
                    t
                }
            };
            let http_protocol = {
                let h = get("http_protocol");
                if h.is_empty() {
                    "http1".to_string()
                } else {
                    h
                }
            };
            let tags = p
                .get("tags")
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            ProviderConfig {
                id: get("id"),
                provider_type,
                model: get("model"),
                base_url: get("base_url"),
                api_key: get("api_key"),
                api_key_env: get("api_key_env"),
                enabled: p
                    .get("enabled")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(true),
                http_protocol,
                tool_calling_mode: get("tool_calling_mode"),
                tags,
                max_concurrency: u32::try_from(
                    p.get("max_concurrency")
                        .and_then(toml::Value::as_integer)
                        .unwrap_or(3),
                )
                .unwrap_or(3),
                context_window: u64::try_from(
                    p.get("context_window")
                        .and_then(toml::Value::as_integer)
                        .unwrap_or(128_000),
                )
                .unwrap_or(128_000),
            }
        })
        .collect()
}

/// Quote/escape a value as a TOML basic string.
fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Persist the provider pool back to `providers.toml`, preserving the
/// pool-level preamble (freeze/health settings) ahead of the provider entries.
///
/// # Errors
/// Returns an error string if the rendered TOML is invalid or cannot be written.
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
        if !p.base_url.is_empty() {
            let _ = writeln!(body, "base_url = {}", toml_string(&p.base_url));
        }
        if !p.api_key.is_empty() {
            let _ = writeln!(body, "api_key = {}", toml_string(&p.api_key));
        }
        if !p.api_key_env.is_empty() {
            let _ = writeln!(body, "api_key_env = {}", toml_string(&p.api_key_env));
        }
        let _ = writeln!(body, "enabled = {}", p.enabled);
        if !p.http_protocol.is_empty() {
            let _ = writeln!(body, "http_protocol = {}", toml_string(&p.http_protocol));
        }
        if !p.tool_calling_mode.is_empty() {
            let _ = writeln!(
                body,
                "tool_calling_mode = {}",
                toml_string(&p.tool_calling_mode)
            );
        }
        let tags = p
            .tags
            .iter()
            .map(|t| toml_string(t))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(body, "tags = [{tags}]");
        let _ = writeln!(body, "max_concurrency = {}", p.max_concurrency);
        let _ = writeln!(body, "context_window = {}\n", p.context_window);
    }

    let content = format!("{preamble}{body}");
    toml::from_str::<toml::Value>(&content).map_err(|e| format!("invalid TOML: {e}"))?;
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("providers.toml"), content).map_err(|e| e.to_string())
}
