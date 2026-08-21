//! `DefectDojo` integration -- push triaged crashes as findings via the REST API.
//!
//! Maps `oxfuzz` [`Crash`]es to `DefectDojo`'s "Generic Findings Import" JSON
//! and POSTs them to `/api/v2/import-scan/` (or `/api/v2/reimport-scan/` on
//! repeat pushes, so re-found crashes update in place instead of duplicating).
//! The CWE and severity logic is reused from [`crate::sarif`] so the SARIF export
//! and the `DefectDojo` push always agree on a crash's classification.
//!
//! Secrets are handled like provider API keys: prefer `api_token_env` (the config
//! stores only the *name* of an environment variable; the token is read from the
//! environment at call time), or store the token directly in `api_token` for the
//! desktop app, which has no shell environment. A direct `api_token` wins. Tokens
//! are never logged.

use std::fmt::Write as _;

use hf_core::crash::{Crash, CrashOrigin};
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

use crate::sarif::{cwe_for, parse_location, security_severity};

/// `DefectDojo` connection + defaults, loaded from `config/defectdojo.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectDojoConfig {
    /// Base URL of the `DefectDojo` instance (no trailing `/api/v2` or `/`).
    pub url: String,
    /// API v2 token stored directly (used by the desktop app, which has no shell
    /// environment). Takes priority over [`Self::api_token_env`]; mirrors how a
    /// provider `api_key` overrides its `api_key_env`. Prefer the env var for
    /// CLI/CI so the secret never lands in a config file.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Name of the environment variable holding the API v2 token. Used when
    /// [`Self::api_token`] is not set.
    #[serde(default)]
    pub api_token_env: String,
    /// Verify the server TLS certificate (disable only for trusted self-signed).
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    /// Product the findings are filed under; defaults to the project name.
    #[serde(default)]
    pub product_name: Option<String>,
    /// Product type the product is filed under. `DefectDojo` requires this to
    /// create a brand-new product when `auto_create` is set, so it defaults to
    /// [`DEFAULT_PRODUCT_TYPE`] rather than being optional at the wire level.
    #[serde(default)]
    pub product_type_name: Option<String>,
    /// Engagement the findings are filed under.
    #[serde(default)]
    pub engagement_name: Option<String>,
    /// Let `DefectDojo` create the product/engagement on first push.
    #[serde(default = "default_true")]
    pub auto_create: bool,
    /// Use reimport-scan on repeat pushes (dedup + close-fixed) vs a fresh import.
    #[serde(default = "default_true")]
    pub reimport: bool,
    /// How the local Docker instance is started and stopped (`[lifecycle]`).
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
}

/// Lifecycle settings for a *local* Docker `DefectDojo` (`[lifecycle]` in
/// `config/defectdojo.toml`). Ignored for a remote `url`, which is never managed.
/// See [`crate::defectdojo_lifecycle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Start the local instance when the app starts.
    #[serde(default = "default_true")]
    pub autostart: bool,
    /// `docker compose` project name of the local install. Blank uses
    /// [`crate::defectdojo_lifecycle::DEFAULT_COMPOSE_PROJECT`].
    #[serde(default)]
    pub compose_project: Option<String>,
    /// Compose files of the local install. Empty discovers them from the existing
    /// project's Docker labels, which is what a standard upstream install needs.
    #[serde(default)]
    pub compose_files: Vec<String>,
    /// How long to wait for the server to answer after starting it.
    #[serde(default)]
    pub startup_timeout_secs: Option<u64>,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            autostart: true,
            compose_project: None,
            compose_files: Vec::new(),
            startup_timeout_secs: None,
        }
    }
}

const fn default_true() -> bool {
    true
}

/// Product type used when none is configured. `DefectDojo`'s auto-create path
/// needs a product type to file a new product under; it is created on demand if
/// it does not already exist.
pub const DEFAULT_PRODUCT_TYPE: &str = "oxfuzz";

impl DefectDojoConfig {
    /// The configured product type, or [`DEFAULT_PRODUCT_TYPE`] when unset/blank.
    #[must_use]
    pub fn resolved_product_type(&self) -> String {
        self.product_type_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_PRODUCT_TYPE)
            .to_owned()
    }
}

impl LifecycleConfig {
    /// The compose project name of the local install, defaulting to upstream's.
    #[must_use]
    pub fn resolved_compose_project(&self) -> String {
        self.compose_project
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(crate::defectdojo_lifecycle::DEFAULT_COMPOSE_PROJECT)
            .to_owned()
    }

    /// How long to wait for the server to answer after starting the stack.
    #[must_use]
    pub fn resolved_startup_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.startup_timeout_secs
                .unwrap_or(crate::defectdojo_lifecycle::DEFAULT_STARTUP_TIMEOUT_SECS),
        )
    }
}

/// Parse a `DefectDojo` config from TOML, validating the required fields. Pure so
/// it is testable without the filesystem.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if the TOML is invalid, `url` is
/// empty, or neither `api_token` nor `api_token_env` is set.
pub fn resolve_config(toml_str: &str) -> Result<DefectDojoConfig, ClassifiedError> {
    let cfg: DefectDojoConfig = toml::from_str(toml_str)
        .map_err(|e| ClassifiedError::Validation(format!("invalid defectdojo config: {e}")))?;
    if cfg.url.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "defectdojo `url` is empty".to_owned(),
        ));
    }
    let has_direct = cfg
        .api_token
        .as_deref()
        .is_some_and(|t| !t.trim().is_empty());
    if !has_direct && cfg.api_token_env.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "defectdojo needs either `api_token` or `api_token_env`".to_owned(),
        ));
    }
    Ok(cfg)
}

/// True when a usable (non-placeholder) `DefectDojo` config is present, so the GUI
/// can show a "configured / not configured" state without attempting a push.
#[must_use]
pub fn is_configured() -> bool {
    crate::config::read_config("defectdojo")
        .ok()
        .and_then(|raw| resolve_config(&raw).ok())
        .is_some_and(|c| !is_placeholder_url(&c.url))
}

/// RFC 2606 reserved example domains that mark an unconfigured placeholder URL.
const EXAMPLE_DOMAINS: [&str; 3] = ["example.com", "example.net", "example.org"];

/// The bundled example ships a placeholder URL; treat it as "not configured".
///
/// Matches the [`EXAMPLE_DOMAINS`] on a host-label boundary rather than by bare
/// substring, so a real instance such as `https://dojo.example.com.corp.internal`
/// is NOT misread as the placeholder.
fn is_placeholder_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }
    // Extract the host: strip the scheme, then take up to the first `/`, `:`,
    // `?`, or `#`. Lowercased for a case-insensitive host comparison.
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let host = after_scheme
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .to_ascii_lowercase();
    EXAMPLE_DOMAINS
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

/// Load the live `DefectDojo` config, rejecting the unconfigured placeholder.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if the config is missing, invalid, or
/// still the shipped placeholder.
pub fn load_config() -> Result<DefectDojoConfig, ClassifiedError> {
    let raw = crate::config::read_config("defectdojo").map_err(ClassifiedError::Validation)?;
    let cfg = resolve_config(&raw)?;
    if is_placeholder_url(&cfg.url) {
        return Err(ClassifiedError::Validation(
            "DefectDojo is not configured: set `url` and `api_token_env` in config/defectdojo.toml"
                .to_owned(),
        ));
    }
    Ok(cfg)
}

/// Resolve the API token: the directly-stored `api_token` wins (for the desktop
/// app), otherwise the env var named by `api_token_env` (for CLI/CI).
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if neither a direct token nor the
/// named environment variable yields a non-empty value.
pub fn resolve_token(cfg: &DefectDojoConfig) -> Result<String, ClassifiedError> {
    if let Some(t) = cfg.api_token.as_deref().map(str::trim) {
        if !t.is_empty() {
            return Ok(t.to_owned());
        }
    }
    let name = cfg.api_token_env.trim();
    if name.is_empty() {
        return Err(ClassifiedError::Validation(
            "DefectDojo API token not set: paste `api_token` in Settings or set `api_token_env`"
                .to_owned(),
        ));
    }
    std::env::var(name)
        .ok()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "DefectDojo API token not set: export {name} with your DefectDojo API v2 key"
            ))
        })
}

/// `DefectDojo` severity bucket for a `security-severity` score (0.0-10.0).
#[must_use]
pub fn severity_bucket(score: f64) -> &'static str {
    if score >= 9.0 {
        "Critical"
    } else if score >= 7.0 {
        "High"
    } else if score >= 4.0 {
        "Medium"
    } else if score > 0.0 {
        "Low"
    } else {
        "Info"
    }
}

/// The integer CWE id for a crash, or `None` for the uncategorized `CWE-noinfo`.
fn cwe_int(crash: &Crash) -> Option<u32> {
    cwe_for(crash)
        .id
        .trim_start_matches("CWE-")
        .parse::<u32>()
        .ok()
}

fn finding_title(crash: &Crash) -> String {
    if let Some(br) = &crash.bug_report {
        if !br.title.trim().is_empty() {
            return br.title.clone();
        }
    }
    if !crash.summary.trim().is_empty() {
        return crash.summary.clone();
    }
    format!("{:?} crash", crash.kind)
}

fn finding_description(crash: &Crash) -> String {
    let mut d = String::new();
    if let Some(br) = &crash.bug_report {
        if !br.summary.trim().is_empty() {
            d.push_str(br.summary.trim());
            d.push_str("\n\n");
        }
        if !br.repro_steps.trim().is_empty() {
            let _ = write!(d, "## Reproduction\n{}\n\n", br.repro_steps.trim());
        }
        if !br.stack.trim().is_empty() {
            let _ = write!(d, "## Stack\n```\n{}\n```\n", br.stack.trim());
        }
    } else if !crash.summary.trim().is_empty() {
        d.push_str(crash.summary.trim());
    }
    if let Some(casr) = &crash.casr {
        if !casr.stack.is_empty() {
            let _ = write!(d, "\n## CASR stack\n```\n{}\n```", casr.stack.join("\n"));
        }
    }
    if d.trim().is_empty() {
        d = format!("{:?} crash detected by oxfuzz.", crash.kind);
    }
    d
}

/// Map one triaged crash to a `DefectDojo` Generic Findings Import finding.
#[must_use]
pub fn finding_for(crash: &Crash) -> serde_json::Value {
    use serde_json::json;

    let score = security_severity(crash);
    let location = crash
        .casr
        .as_ref()
        .and_then(|c| parse_location(&c.crashline));

    let mut f = json!({
        "title": finding_title(crash),
        "description": finding_description(crash),
        "severity": severity_bucket(score),
        "cvssv3_score": score,
        // The stack signature is the dedup key: reimport-scan collapses re-found
        // crashes with the same signature instead of creating duplicates.
        "unique_id_from_tool": crash.stack_signature,
        "vuln_id_from_tool": crash.id.to_string(),
        // A crash is a real, currently-open defect (active); it is machine-triaged
        // and not yet human-confirmed (verified=false).
        "active": true,
        "verified": false,
        "dynamic_finding": true,
        "static_finding": false,
    });
    if let Some(cwe) = cwe_int(crash) {
        f["cwe"] = json!(cwe);
    }
    if let Some((file, line)) = location {
        f["file_path"] = json!(file);
        f["line"] = json!(line);
    }
    if let Some(br) = &crash.bug_report {
        if let Some(fix) = br.suggested_fix.as_ref().filter(|s| !s.trim().is_empty()) {
            f["mitigation"] = json!(fix);
        }
        if let Some(rc) = br.root_cause.as_ref().filter(|s| !s.trim().is_empty()) {
            f["impact"] = json!(rc);
        }
    }
    f
}

/// Render triaged crashes as a `DefectDojo` Generic Findings Import document.
#[must_use]
pub fn crashes_to_generic(crashes: &[Crash]) -> serde_json::Value {
    // A `DefectDojo` finding asserts a defect in the product under test. A fault
    // whose root frame is the generated harness is a harness bug to fix, not a
    // finding to file against the project, so it is dropped here rather than at
    // the call site -- this is the only mapper, and filing is not reversible.
    serde_json::json!({
        "findings": crashes
            .iter()
            .filter(|crash| crash.origin != CrashOrigin::Harness)
            .map(finding_for)
            .collect::<Vec<_>>(),
    })
}

/// Where a set of findings is filed in `DefectDojo`'s product/engagement/test tree.
#[derive(Debug, Clone)]
pub struct ImportTarget {
    pub product_name: String,
    pub product_type_name: String,
    pub engagement_name: String,
    pub test_title: Option<String>,
    pub reimport: bool,
    pub auto_create: bool,
    /// Whether a reimport should close findings absent from this upload. Only
    /// safe when the upload is the target's *complete* current crash set; a
    /// partial (single-run) push must leave it `false` so it does not close
    /// still-open bugs the run merely failed to rediscover.
    pub close_old_findings: bool,
}

/// The result of a successful push, surfaced to the presentation layers.
#[derive(Debug, Clone, Serialize)]
pub struct PushOutcome {
    /// `DefectDojo` test id the findings landed in, when the API returns one.
    pub test_id: Option<i64>,
    /// `DefectDojo` engagement id, when returned.
    pub engagement_id: Option<i64>,
    /// Number of findings sent in this push.
    pub findings_pushed: usize,
    /// Whether this went through reimport-scan (vs a fresh import-scan).
    pub reimported: bool,
    /// Deep link to the test in the `DefectDojo` UI, when a test id is known.
    pub url: Option<String>,
}

/// Normalize a base URL: trim whitespace and any trailing slashes.
fn normalize_base(url: &str) -> String {
    url.trim().trim_end_matches('/').to_owned()
}

/// The import endpoint for a push (reimport dedups; import always creates).
fn import_path(reimport: bool) -> &'static str {
    if reimport {
        "/api/v2/reimport-scan/"
    } else {
        "/api/v2/import-scan/"
    }
}

/// Classify a non-success `DefectDojo` HTTP response into a [`ClassifiedError`].
fn classify_status(
    status: reqwest::StatusCode,
    body: &str,
    ctx: &str,
) -> Result<(), ClassifiedError> {
    if status.is_success() {
        return Ok(());
    }
    let snippet: String = body.chars().take(300).collect();
    Err(match status.as_u16() {
        401 | 403 => ClassifiedError::Validation(format!(
            "DefectDojo auth failed ({ctx}): check your API token ({status})"
        )),
        400 | 404 | 422 => ClassifiedError::Validation(format!(
            "DefectDojo rejected the {ctx} request ({status}): {snippet}"
        )),
        s if s >= 500 => {
            ClassifiedError::Provider(format!("DefectDojo server error ({ctx}): {status}"))
        }
        _ => ClassifiedError::Provider(format!("DefectDojo {ctx} failed ({status}): {snippet}")),
    })
}

/// A thin REST client for a `DefectDojo` instance.
pub struct DefectDojoClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl DefectDojoClient {
    /// Build a client for `url` authenticating with `token`.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Internal`] if the HTTP client cannot be built.
    pub fn new(url: &str, token: &str, verify_tls: bool) -> Result<Self, ClassifiedError> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_tls)
            .user_agent(concat!("oxfuzz/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ClassifiedError::Internal(format!("http client: {e}")))?;
        Ok(Self {
            base_url: normalize_base(url),
            token: token.to_owned(),
            http,
        })
    }

    /// Build a client from a loaded config plus a resolved token.
    ///
    /// # Errors
    /// Propagates [`DefectDojoClient::new`] errors.
    pub fn from_config(cfg: &DefectDojoConfig, token: &str) -> Result<Self, ClassifiedError> {
        Self::new(&cfg.url, token, cfg.verify_tls)
    }

    fn auth(&self) -> String {
        format!("Token {}", self.token)
    }

    /// Verify the URL + token by hitting the authenticated profile endpoint.
    ///
    /// # Errors
    /// Returns a classified error if the server is unreachable or rejects auth.
    pub async fn test_connection(&self) -> Result<(), ClassifiedError> {
        let url = format!("{}/api/v2/user_profile/", self.base_url);
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, self.auth())
            .send()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("DefectDojo unreachable: {e}")))?;
        let status = resp.status();
        classify_status(status, "", "connection test")
    }

    /// Push a Generic Findings Import document to `DefectDojo`.
    ///
    /// # Errors
    /// Returns a classified error if the request fails or the server rejects it.
    pub async fn import(
        &self,
        target: &ImportTarget,
        findings: &serde_json::Value,
    ) -> Result<PushOutcome, ClassifiedError> {
        let count = findings
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        let url = format!("{}{}", self.base_url, import_path(target.reimport));
        let bytes = serde_json::to_vec(findings)
            .map_err(|e| ClassifiedError::Internal(format!("serialize findings: {e}")))?;
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name("oxfuzz.json")
            .mime_str("application/json")
            .map_err(|e| ClassifiedError::Internal(format!("multipart part: {e}")))?;
        let mut form = reqwest::multipart::Form::new()
            .text("scan_type", "Generic Findings Import")
            .text("product_name", target.product_name.clone())
            .text("engagement_name", target.engagement_name.clone())
            .text("active", "true")
            .text("verified", "false")
            .part("file", part);
        if target.auto_create {
            form = form.text("auto_create_context", "true");
            // DefectDojo needs a product type to create a not-yet-existing
            // product; without it auto_create_context 400s on first push.
            form = form.text("product_type_name", target.product_type_name.clone());
        }
        if target.reimport {
            // Only close absent findings when the caller pushed the target's
            // complete current crash set; a partial single-run push must not
            // close still-open bugs it merely did not rediscover.
            form = form.text(
                "close_old_findings",
                if target.close_old_findings {
                    "true"
                } else {
                    "false"
                },
            );
        }
        if let Some(t) = &target.test_title {
            form = form.text("test_title", t.clone());
        }

        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, self.auth())
            .multipart(form)
            .send()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("DefectDojo push failed: {e}")))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        classify_status(status, &body, "import-scan")?;

        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        let test_id = v
            .get("test")
            .and_then(serde_json::Value::as_i64)
            .or_else(|| v.get("test_id").and_then(serde_json::Value::as_i64));
        let engagement_id = v
            .get("engagement")
            .and_then(serde_json::Value::as_i64)
            .or_else(|| v.get("engagement_id").and_then(serde_json::Value::as_i64));
        let link = test_id.map(|id| format!("{}/test/{id}", self.base_url));
        Ok(PushOutcome {
            test_id,
            engagement_id,
            findings_pushed: count,
            reimported: target.reimport,
            url: link,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::crash::{BugReport, CasrReport, CrashKind, CrashSeverity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn base_crash() -> Crash {
        Crash {
            id: Uuid::nil(),
            run_id: Uuid::nil(),
            target_id: Uuid::nil(),
            input_path: PathBuf::from("/ws/crash-1"),
            stack_signature: "sig-abc123".to_owned(),
            kind: CrashKind::Asan,
            summary: "heap overflow in parse".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin: hf_core::crash::CrashOrigin::Unknown,
        }
    }

    fn cfg_with_product_type(pt: Option<&str>) -> DefectDojoConfig {
        DefectDojoConfig {
            url: "http://localhost:8081".to_owned(),
            api_token: None,
            api_token_env: "HF_DEFECTDOJO_TOKEN".to_owned(),
            verify_tls: true,
            product_name: Some("oxfuzz".to_owned()),
            product_type_name: pt.map(str::to_owned),
            engagement_name: Some("Fuzzing".to_owned()),
            auto_create: true,
            reimport: true,
            lifecycle: LifecycleConfig::default(),
        }
    }

    #[test]
    fn direct_api_token_wins_over_env() {
        let mut cfg = cfg_with_product_type(None);
        cfg.api_token = Some("direct-token".to_owned());
        cfg.api_token_env = "HF_DEFECTDOJO_TOKEN_DOES_NOT_EXIST".to_owned();
        // Direct token is returned without consulting the (unset) env var.
        assert_eq!(resolve_token(&cfg).unwrap(), "direct-token");
    }

    #[test]
    fn config_valid_with_only_direct_token() {
        let toml = r#"
            url = "http://localhost:8081"
            api_token = "abc123"
        "#;
        let cfg = resolve_config(toml).expect("direct token alone is valid");
        assert_eq!(cfg.api_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn config_rejects_missing_both_tokens() {
        let toml = r#"url = "http://localhost:8081""#;
        assert!(resolve_config(toml).is_err());
    }

    #[test]
    fn resolved_product_type_defaults_when_unset_or_blank() {
        assert_eq!(
            cfg_with_product_type(None).resolved_product_type(),
            DEFAULT_PRODUCT_TYPE
        );
        assert_eq!(
            cfg_with_product_type(Some("   ")).resolved_product_type(),
            DEFAULT_PRODUCT_TYPE
        );
        assert_eq!(
            cfg_with_product_type(Some("Kernel")).resolved_product_type(),
            "Kernel"
        );
    }

    #[test]
    fn harness_defects_are_not_pushed_as_findings() {
        // A DefectDojo finding asserts a defect in the product under test. A
        // fault inside the generated harness is not one.
        let mut harness_crash = base_crash();
        harness_crash.origin = CrashOrigin::Harness;
        let document = crashes_to_generic(&[base_crash(), harness_crash]);
        let findings = document["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 1, "harness defect leaked: {document}");
    }

    #[test]
    fn severity_buckets_cover_the_range() {
        assert_eq!(severity_bucket(9.0), "Critical");
        assert_eq!(severity_bucket(9.5), "Critical");
        assert_eq!(severity_bucket(7.0), "High");
        assert_eq!(severity_bucket(6.9), "Medium");
        assert_eq!(severity_bucket(4.0), "Medium");
        assert_eq!(severity_bucket(3.5), "Low");
        assert_eq!(severity_bucket(0.0), "Info");
    }

    #[test]
    fn exploitable_crash_maps_to_critical_with_cwe_and_location() {
        let mut crash = base_crash();
        crash.casr = Some(CasrReport {
            severity: CrashSeverity::Exploitable,
            severity_short: "heap-buffer-overflow(write)".to_owned(),
            crashline: "src/parse.c:42:7".to_owned(),
            stack: vec!["#0 parse".to_owned(), "#1 main".to_owned()],
            cluster: Some(3),
        });
        let f = finding_for(&crash);
        assert_eq!(f["severity"], "Critical");
        // heap-buffer-overflow(write) -> CWE-787 -> 787.
        assert_eq!(f["cwe"], 787);
        assert_eq!(f["file_path"], "src/parse.c");
        assert_eq!(f["line"], 42);
        // Dedup key is the stack signature.
        assert_eq!(f["unique_id_from_tool"], "sig-abc123");
        assert_eq!(f["active"], true);
        assert_eq!(f["verified"], false);
        assert_eq!(f["dynamic_finding"], true);
    }

    #[test]
    fn bug_report_fields_map_to_title_mitigation_impact() {
        let mut crash = base_crash();
        crash.bug_report = Some(BugReport {
            title: "OOB write in parse_value".to_owned(),
            summary: "An attacker-controlled length overruns the buffer.".to_owned(),
            repro_steps: "Run the harness on crash-1".to_owned(),
            stack: "#0 parse_value".to_owned(),
            severity_guess: "high".to_owned(),
            root_cause: Some("Missing bounds check on len".to_owned()),
            suggested_fix: Some("--- a/parse.c\n+++ b/parse.c".to_owned()),
        });
        let f = finding_for(&crash);
        assert_eq!(f["title"], "OOB write in parse_value");
        assert_eq!(f["mitigation"], "--- a/parse.c\n+++ b/parse.c");
        assert_eq!(f["impact"], "Missing bounds check on len");
        assert!(f["description"]
            .as_str()
            .unwrap()
            .contains("attacker-controlled length"));
    }

    #[test]
    fn title_falls_back_to_summary_then_kind() {
        let f = finding_for(&base_crash());
        assert_eq!(f["title"], "heap overflow in parse");
        let mut bare = base_crash();
        bare.summary = String::new();
        assert_eq!(finding_for(&bare)["title"], "Asan crash");
    }

    #[test]
    fn uncategorized_crash_omits_cwe() {
        let mut crash = base_crash();
        crash.kind = CrashKind::Other;
        crash.summary = "weird".to_owned();
        // CrashKind::Other with no CASR -> CWE-noinfo -> no integer cwe.
        let f = finding_for(&crash);
        assert!(f.get("cwe").is_none());
    }

    #[test]
    fn crashes_to_generic_wraps_findings_array() {
        let doc = crashes_to_generic(&[base_crash(), base_crash()]);
        assert_eq!(doc["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn import_path_selects_reimport() {
        assert_eq!(import_path(true), "/api/v2/reimport-scan/");
        assert_eq!(import_path(false), "/api/v2/import-scan/");
    }

    #[test]
    fn normalize_base_trims_trailing_slash() {
        assert_eq!(normalize_base("https://dd.local/"), "https://dd.local");
        assert_eq!(normalize_base("  https://dd.local//  "), "https://dd.local");
    }

    #[test]
    fn classify_status_maps_auth_and_server_errors() {
        use reqwest::StatusCode;
        assert!(classify_status(StatusCode::OK, "", "x").is_ok());
        let e = classify_status(StatusCode::UNAUTHORIZED, "", "import-scan").unwrap_err();
        assert!(matches!(e, ClassifiedError::Validation(_)));
        let e =
            classify_status(StatusCode::INTERNAL_SERVER_ERROR, "boom", "import-scan").unwrap_err();
        assert!(matches!(e, ClassifiedError::Provider(_)));
    }

    #[test]
    fn resolve_config_validates_required_fields() {
        let ok = resolve_config("url = \"https://dd.local\"\napi_token_env = \"T\"").unwrap();
        assert_eq!(ok.url, "https://dd.local");
        assert!(ok.verify_tls, "verify_tls defaults to true");
        assert!(ok.reimport, "reimport defaults to true");
        assert!(resolve_config("api_token_env = \"T\"").is_err());
        assert!(resolve_config("url = \"\"\napi_token_env = \"T\"").is_err());
    }

    #[test]
    fn placeholder_url_is_not_configured() {
        assert!(is_placeholder_url("https://defectdojo.example.com"));
        assert!(is_placeholder_url("  "));
        assert!(!is_placeholder_url("https://dd.corp.internal"));
        // A real host that merely embeds "example.com" as a non-boundary
        // substring must NOT be treated as the placeholder.
        assert!(!is_placeholder_url(
            "https://dojo.example.com.corp.internal"
        ));
        assert!(!is_placeholder_url("https://example.company.io"));
        // The reserved example domains are matched on a label boundary and
        // case-insensitively, with or without a path/port.
        assert!(is_placeholder_url("https://EXAMPLE.COM/api"));
        assert!(is_placeholder_url("http://dojo.example.org:8080/finding"));
    }
}
