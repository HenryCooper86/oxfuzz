//! Network, authentication, CORS, path, and response-redaction policy.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::{header, HeaderValue, Method, Uri};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

const DEFAULT_CORS_ORIGINS: [&str; 2] = ["http://127.0.0.1:5173", "http://localhost:5173"];
const REDACTED_PATH: &str = "<redacted-path>";

/// A validated, immutable security policy for one router instance.
///
/// The bearer token is deliberately private and this type does not implement
/// `Debug`, preventing accidental secret disclosure through diagnostics.
#[derive(Clone)]
pub struct WebSecurityConfig {
    pub(crate) auth: AuthPolicy,
    cors_origins: Arc<Vec<HeaderValue>>,
    project_roots: Arc<Vec<PathBuf>>,
}

impl WebSecurityConfig {
    /// Build a policy from explicit values.
    ///
    /// Project roots must already exist and be directories. Origins must be
    /// exact `http://` or `https://` origins without wildcard characters.
    ///
    /// # Errors
    /// Returns [`SecurityConfigError`] for malformed origins or roots.
    pub fn new(
        token: Option<String>,
        allow_open: bool,
        cors_origins: Vec<String>,
        project_roots: Vec<PathBuf>,
    ) -> Result<Self, SecurityConfigError> {
        let token = match token.filter(|value| !value.is_empty()) {
            Some(value) if value.bytes().all(|byte| byte.is_ascii_graphic()) => {
                Some(BearerToken::new(&value))
            }
            Some(_) => return Err(SecurityConfigError::InvalidToken),
            None => None,
        };
        let mut parsed_origins = Vec::with_capacity(cors_origins.len());
        for origin in cors_origins {
            let trimmed = origin.trim();
            if trimmed.contains('*')
                || trimmed.ends_with('/')
                || !(trimmed.starts_with("http://") || trimmed.starts_with("https://"))
            {
                return Err(SecurityConfigError::InvalidOrigin);
            }
            let uri: Uri = trimmed
                .parse()
                .map_err(|_| SecurityConfigError::InvalidOrigin)?;
            if !matches!(uri.scheme_str(), Some("http" | "https"))
                || uri.authority().is_none()
                || uri
                    .authority()
                    .is_some_and(|authority| authority.as_str().contains('@'))
                || !matches!(uri.path(), "" | "/")
                || uri.query().is_some()
            {
                return Err(SecurityConfigError::InvalidOrigin);
            }
            let header =
                HeaderValue::from_str(trimmed).map_err(|_| SecurityConfigError::InvalidOrigin)?;
            parsed_origins.push(header);
        }

        let mut canonical_roots = Vec::with_capacity(project_roots.len());
        for root in project_roots {
            let canonical = root
                .canonicalize()
                .map_err(|_| SecurityConfigError::InvalidProjectRoot)?;
            if !canonical.is_dir() {
                return Err(SecurityConfigError::InvalidProjectRoot);
            }
            if !canonical_roots.contains(&canonical) {
                canonical_roots.push(canonical);
            }
        }

        Ok(Self {
            auth: AuthPolicy { token, allow_open },
            cors_origins: Arc::new(parsed_origins),
            project_roots: Arc::new(canonical_roots),
        })
    }

    /// Resolve the web policy from process environment once at router startup.
    #[must_use]
    pub fn from_env() -> Self {
        let token = std::env::var("HF_WEB_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        let allow_open = std::env::var("HF_WEB_TOKEN_OPTIONAL")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        let origins = std::env::var("HF_WEB_CORS_ORIGINS").map_or_else(
            |_| {
                DEFAULT_CORS_ORIGINS
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            },
            |raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|origin| !origin.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            },
        );
        let roots = std::env::var_os("HF_WEB_PROJECT_ROOTS").map_or_else(
            || hf_service::repo_root().into_iter().collect(),
            |raw| std::env::split_paths(&raw).collect(),
        );

        match Self::new(token, allow_open, origins, roots) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(%error, "invalid hf-web security configuration; denying protected access");
                Self::deny_all()
            }
        }
    }

    pub(crate) fn deny_all() -> Self {
        Self {
            auth: AuthPolicy {
                token: None,
                allow_open: false,
            },
            cors_origins: Arc::new(Vec::new()),
            project_roots: Arc::new(Vec::new()),
        }
    }

    /// Whether a bearer token is configured.
    #[must_use]
    pub fn token_configured(&self) -> bool {
        self.auth.token.is_some()
    }

    /// Whether protected endpoints are explicitly open without authentication.
    #[must_use]
    pub fn allows_open_access(&self) -> bool {
        self.auth.allow_open && self.auth.token.is_none()
    }

    /// Number of approved canonical project roots.
    #[must_use]
    pub fn project_root_count(&self) -> usize {
        self.project_roots.len()
    }

    pub(crate) fn cors_layer(&self) -> CorsLayer {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(self.cors_origins.iter().cloned()))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    }

    pub(crate) fn origin_allowed(
        &self,
        origin: Option<&HeaderValue>,
        host: Option<&HeaderValue>,
    ) -> bool {
        let Some(origin) = origin else {
            return true;
        };
        if self.cors_origins.iter().any(|allowed| allowed == origin) {
            return true;
        }

        let Some((origin, host)) = origin
            .to_str()
            .ok()
            .zip(host.and_then(|value| value.to_str().ok()))
        else {
            return false;
        };
        // Same-origin fallback for browser access to the served UI: an Origin
        // whose authority matches the Host header. Restricted to loopback
        // hosts so a DNS-rebinding page (Origin and Host both naming an
        // attacker-controlled host) cannot pass.
        host_authority_is_loopback(host)
            && origin
                .parse::<Uri>()
                .ok()
                .and_then(|uri| uri.authority().cloned())
                .is_some_and(|authority| authority.as_str().eq_ignore_ascii_case(host))
    }

    pub(crate) fn approve_project(&self, requested: &Path) -> Result<PathBuf, PathPolicyError> {
        let canonical = requested
            .canonicalize()
            .map_err(|_| PathPolicyError::Unavailable)?;
        if !canonical.is_dir() {
            return Err(PathPolicyError::NotDirectory);
        }
        if !self
            .project_roots
            .iter()
            .any(|root| canonical == *root || canonical.starts_with(root))
        {
            return Err(PathPolicyError::OutsideApprovedRoots);
        }
        Ok(canonical)
    }

    pub(crate) fn approve_document(
        &self,
        project: &Path,
        requested: &Path,
    ) -> Result<(PathBuf, PathBuf), PathPolicyError> {
        let project = self.approve_project(project)?;
        let candidate = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            project.join(requested)
        };
        let document = candidate
            .canonicalize()
            .map_err(|_| PathPolicyError::Unavailable)?;
        if !document.is_file() {
            return Err(PathPolicyError::NotRegularFile);
        }
        if !document.starts_with(&project) {
            return Err(PathPolicyError::OutsideProject);
        }
        Ok((project, document))
    }
}

/// Whether a `Host` header authority names a loopback host (any port).
fn host_authority_is_loopback(host: &str) -> bool {
    format!("http://{host}")
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_owned))
        .is_some_and(|hostname| {
            hostname.eq_ignore_ascii_case("localhost")
                || matches!(hostname.as_str(), "127.0.0.1" | "::1" | "[::1]")
        })
}

/// Validate a server socket before binding it.
///
/// Loopback is always safe to bind. Wildcard and other non-loopback addresses
/// require a configured bearer token.
///
/// # Errors
/// Returns [`BindAddressError`] when a non-loopback address has no token.
pub fn validate_bind_addr(
    address: SocketAddr,
    token_configured: bool,
) -> Result<(), BindAddressError> {
    if address.ip().is_loopback() || token_configured {
        Ok(())
    } else {
        Err(BindAddressError)
    }
}

/// A non-loopback bind was requested without authentication.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("non-loopback web binds require a non-empty HF_WEB_TOKEN")]
pub struct BindAddressError;

/// Invalid startup security configuration.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum SecurityConfigError {
    /// The bearer token contained whitespace or non-visible bytes.
    #[error("HF_WEB_TOKEN must contain only visible ASCII characters")]
    InvalidToken,
    /// A CORS origin was malformed or contained a wildcard.
    #[error("HF_WEB_CORS_ORIGINS must contain exact http or https origins")]
    InvalidOrigin,
    /// A configured project root did not resolve to an existing directory.
    #[error("HF_WEB_PROJECT_ROOTS must contain existing directories")]
    InvalidProjectRoot,
}

#[derive(Clone)]
pub(crate) struct AuthPolicy {
    token: Option<BearerToken>,
    allow_open: bool,
}

impl AuthPolicy {
    pub(crate) fn authorize(&self, path: &str, presented: Option<&str>) -> bool {
        if path == "/health" {
            return true;
        }
        match (&self.token, presented) {
            (Some(expected), Some(presented)) => expected.matches(presented),
            (Some(_), None) => false,
            (None, _) => self.allow_open,
        }
    }
}

#[derive(Clone)]
struct BearerToken([u8; 32]);

impl BearerToken {
    fn new(value: &str) -> Self {
        Self(Sha256::digest(value.as_bytes()).into())
    }

    fn matches(&self, presented: &str) -> bool {
        let presented_digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        bool::from(self.0.ct_eq(&presented_digest))
    }
}

/// A network-supplied host path violated the configured project boundary.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(crate) enum PathPolicyError {
    #[error("requested project path is unavailable")]
    Unavailable,
    #[error("requested project path is not a directory")]
    NotDirectory,
    #[error("requested project path is outside the approved web roots")]
    OutsideApprovedRoots,
    #[error("requested document is not a regular file")]
    NotRegularFile,
    #[error("requested document is outside its approved project")]
    OutsideProject,
}

pub(crate) fn redact_public_json(mut value: serde_json::Value) -> serde_json::Value {
    redact_json_value(&mut value);
    value
}

pub(crate) fn redact_config_text(raw: &str) -> Result<String, String> {
    let mut value = toml::from_str::<toml::Value>(raw).map_err(|error| error.to_string())?;
    redact_toml_value(&mut value);
    toml::to_string_pretty(&value).map_err(|error| error.to_string())
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_json_value),
        serde_json::Value::Object(entries) => {
            for (key, item) in entries {
                if is_header_key(key) {
                    *item = serde_json::Value::Object(serde_json::Map::new());
                } else if is_secret_key(key) {
                    *item = serde_json::Value::Null;
                } else if is_path_key(key) {
                    redact_json_path_values(item);
                } else {
                    redact_json_value(item);
                }
            }
        }
        _ => {}
    }
}

fn redact_json_path_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(path) if looks_like_absolute_host_path(path) => {
            REDACTED_PATH.clone_into(path);
        }
        serde_json::Value::Array(items) => {
            items.iter_mut().for_each(redact_json_path_values);
        }
        serde_json::Value::Object(_) => redact_json_value(value),
        _ => {}
    }
}

fn redact_toml_value(value: &mut toml::Value) {
    match value {
        toml::Value::Array(items) => items.iter_mut().for_each(redact_toml_value),
        toml::Value::Table(entries) => {
            for (key, item) in entries {
                if is_header_key(key) {
                    *item = toml::Value::Table(toml::map::Map::new());
                } else if is_secret_key(key) {
                    *item = toml::Value::String("<redacted>".to_owned());
                } else if is_path_key(key) {
                    redact_toml_path_values(item);
                } else {
                    redact_toml_value(item);
                }
            }
        }
        _ => {}
    }
}

fn redact_toml_path_values(value: &mut toml::Value) {
    match value {
        toml::Value::String(path) if looks_like_absolute_host_path(path) => {
            REDACTED_PATH.clone_into(path);
        }
        toml::Value::Array(items) => {
            items.iter_mut().for_each(redact_toml_path_values);
        }
        toml::Value::Table(_) => redact_toml_value(value),
        _ => {}
    }
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "api_key"
            | "api_key_env"
            | "api_token"
            | "access_token"
            | "refresh_token"
            | "bearer_token"
            | "token"
            | "password"
            | "secret"
            | "secret_key"
            | "client_secret"
            | "private_key"
            | "ssh_key"
            | "authorization"
    ) || normalized.ends_with("_api_key")
        || normalized.ends_with("_api_key_env")
        || normalized.ends_with("_token")
        || normalized.ends_with("_token_env")
        || normalized.ends_with("_password")
        || normalized.ends_with("_password_env")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_secret_env")
        || normalized.ends_with("_secret_key")
        || normalized.ends_with("_private_key")
        || normalized.ends_with("_ssh_key")
        || normalized.ends_with("_authorization")
}

fn is_header_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized == "headers" || normalized.ends_with("_headers")
}

fn is_path_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.ends_with("_path")
        || normalized.ends_with("_paths")
        || normalized.ends_with("_dir")
        || normalized.ends_with("_dirs")
        || normalized.ends_with("_root")
        || normalized.ends_with("_roots")
        || normalized.ends_with("_file")
        || normalized.ends_with("_files")
        || matches!(
            normalized.as_str(),
            "path"
                | "paths"
                | "file"
                | "files"
                | "binary"
                | "input_path"
                | "source_path"
                | "binary_path"
                | "active_project"
                | "project"
                | "project_root"
                | "root"
                | "workspace"
                | "workspace_dir"
                | "config_dir"
                | "data_dir"
                | "corpus_dir"
                | "crash_dir"
        )
}

fn looks_like_absolute_host_path(value: &str) -> bool {
    // A Windows drive prefix is a single ASCII letter followed by `:` (e.g.
    // `C:\`). Requiring the letter avoids over-redacting unrelated values whose
    // second byte merely happens to be `:` (e.g. `a:b`).
    let drive_prefix = {
        let bytes = value.as_bytes();
        bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':')
    };
    Path::new(value).is_absolute() || value.starts_with("\\\\") || drive_prefix
}

#[cfg(test)]
mod tests {
    use super::{redact_config_text, redact_public_json, WebSecurityConfig};
    use axum::http::HeaderValue;

    #[test]
    fn public_json_redacts_secrets_and_absolute_paths_but_keeps_relative_locations() {
        let value = serde_json::json!({
            "api_key": "secret",
            "headers": { "Authorization": "Bearer hidden" },
            "project_root": "/Users/example/private",
            "source_paths": ["/Users/example/private/a.c", "src/parser.c"],
            "location": { "file": "src/parser.c", "line": 4 },
        });
        let redacted = redact_public_json(value);
        assert!(redacted["api_key"].is_null());
        assert_eq!(redacted["headers"], serde_json::json!({}));
        assert_eq!(redacted["project_root"], "<redacted-path>");
        assert_eq!(redacted["source_paths"][0], "<redacted-path>");
        assert_eq!(redacted["source_paths"][1], "src/parser.c");
        assert_eq!(redacted["location"]["file"], "src/parser.c");
    }

    #[test]
    fn raw_toml_redaction_removes_provider_credentials_and_host_paths() {
        let redacted = redact_config_text(
            "api_key = \"sk-secret\"\napi_token_env = \"HF_API_TOKEN\"\nembedding_api_key = \"embedding-secret\"\nembedding_api_key_env = \"HF_EMBEDDING_KEY\"\nworkspace_dir = \"/tmp/private\"\ncompose_files = [\"/tmp/private/docker.yml\", \"docker.yml\"]\n[headers]\nAuthorization = \"Bearer hidden\"\n",
        )
        .unwrap();
        assert!(!redacted.contains("sk-secret"));
        assert!(!redacted.contains("HF_API_TOKEN"));
        assert!(!redacted.contains("embedding-secret"));
        assert!(!redacted.contains("HF_EMBEDDING_KEY"));
        assert!(!redacted.contains("/tmp/private"));
        assert!(redacted.contains("docker.yml"));
        assert!(!redacted.contains("Bearer hidden"));
        assert!(redacted.contains("<redacted>"));
        assert!(redacted.contains("<redacted-path>"));
    }

    #[test]
    fn origin_host_fallback_rejects_dns_rebinding_on_non_loopback_hosts() {
        let config = WebSecurityConfig::new(None, true, Vec::new(), Vec::new())
            .expect("valid test security config");
        // A rebound page serves Origin and Host that agree but name an
        // attacker-controlled host; this must not pass as "same-origin".
        let origin = HeaderValue::from_static("http://attacker.com:8081");
        let host = HeaderValue::from_static("attacker.com:8081");
        assert!(!config.origin_allowed(Some(&origin), Some(&host)));
    }

    #[test]
    fn origin_host_fallback_allows_same_origin_browser_access_on_loopback() {
        let config = WebSecurityConfig::new(None, true, Vec::new(), Vec::new())
            .expect("valid test security config");
        for authority in ["localhost:8081", "127.0.0.1:8081", "[::1]:8081"] {
            let origin =
                HeaderValue::from_str(&format!("http://{authority}")).expect("valid origin header");
            let host = HeaderValue::from_str(authority).expect("valid host header");
            assert!(
                config.origin_allowed(Some(&origin), Some(&host)),
                "loopback authority {authority} must keep the same-origin fallback"
            );
        }
    }

    #[test]
    fn allowlisted_origin_is_allowed_regardless_of_host_header() {
        let config = WebSecurityConfig::new(
            None,
            true,
            vec!["http://127.0.0.1:5173".to_owned()],
            Vec::new(),
        )
        .expect("valid test security config");
        let origin = HeaderValue::from_static("http://127.0.0.1:5173");
        let host = HeaderValue::from_static("attacker.com:8081");
        assert!(config.origin_allowed(Some(&origin), Some(&host)));
    }
}
