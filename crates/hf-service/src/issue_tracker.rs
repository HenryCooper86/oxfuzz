//! Issue-tracker integration -- file triaged crashes as **GitHub** or **GitLab**
//! issues in the *fuzzed project's* repository.
//!
//! The older `workbench::gitlab_issue_export` guessed the repo from the fuzzed
//! folder's git remote, which resolves to the enclosing `oxfuzz` checkout
//! when the target is not its own repo -- so crash issues landed on the wrong
//! project. This module makes the target repo, provider, and credentials
//! **explicit config**, so issues go where they belong.
//!
//! Auth is a Personal Access Token, mirroring provider/DefectDojo secrets: a
//! direct `api_token` (desktop) or the env var named by `api_token_env` (CLI/CI);
//! never logged. There is deliberately no password field -- GitHub removed
//! password auth for its API in 2021 and GitLab's API is token-based; a
//! `username` is kept for attribution/display only, never for authentication.

use std::fmt::Write as _;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

/// Which forge the crashes are filed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    GitHub,
    GitLab,
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "github" | "gh" => Ok(Self::GitHub),
            "gitlab" | "gl" => Ok(Self::GitLab),
            other => Err(format!(
                "unknown issue-tracker provider '{other}' (expected github or gitlab)"
            )),
        }
    }
}

impl Provider {
    /// Canonical id used in config and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
        }
    }

    /// The public host when none is configured.
    #[must_use]
    pub const fn default_host(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::GitLab => "https://gitlab.com",
        }
    }

    /// Human label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::GitLab => "GitLab",
        }
    }
}

/// Issue-tracker connection + defaults, loaded from `config/issue_tracker.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTrackerConfig {
    /// `github` | `gitlab` | `none` (or blank -> disabled).
    #[serde(default)]
    pub provider: String,
    /// Base web URL. Blank uses the provider default (github.com / gitlab.com);
    /// set it for GitHub Enterprise or a self-hosted GitLab.
    #[serde(default)]
    pub host: Option<String>,
    /// Target repository of the fuzzed software: GitHub `owner/repo`; GitLab
    /// `group/project` (or a numeric project id, API-only).
    #[serde(default)]
    pub repo: String,
    /// Personal Access Token stored directly (desktop). Prefer `api_token_env`
    /// for CLI/CI so the secret never lands in a config file.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Name of the environment variable holding the token, when not stored directly.
    #[serde(default)]
    pub api_token_env: String,
    /// Optional username, for attribution/display only -- never authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// Labels applied to every filed issue.
    #[serde(default = "default_labels")]
    pub labels: Vec<String>,
    /// Verify the server TLS certificate (disable only for trusted self-signed).
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

fn default_true() -> bool {
    true
}

fn default_labels() -> Vec<String> {
    vec![
        "oxfuzz".to_owned(),
        "fuzzing".to_owned(),
        "crash".to_owned(),
    ]
}

impl IssueTrackerConfig {
    /// The configured provider, or `None` when unset/`none`/unknown.
    #[must_use]
    pub fn resolved_provider(&self) -> Option<Provider> {
        self.provider.parse().ok()
    }

    /// Base web URL: the configured host, else the provider default.
    #[must_use]
    pub fn web_base(&self) -> Option<String> {
        let provider = self.resolved_provider()?;
        let host = self
            .host
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| provider.default_host());
        Some(host.trim_end_matches('/').to_owned())
    }

    /// True when a provider and a target repo are set -- enough to open a
    /// prefilled new-issue page. Filing via the API additionally needs a token.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.resolved_provider().is_some() && !self.repo.trim().is_empty()
    }
}

/// Parse an issue-tracker config from TOML. Pure -- no filesystem.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if the TOML is invalid.
pub fn resolve_config(toml_str: &str) -> Result<IssueTrackerConfig, ClassifiedError> {
    toml::from_str(toml_str)
        .map_err(|e| ClassifiedError::Validation(format!("invalid issue_tracker config: {e}")))
}

/// Whether a usable issue-tracker config is present (provider + repo).
#[must_use]
pub fn is_configured() -> bool {
    crate::config::read_config("issue_tracker")
        .ok()
        .and_then(|raw| resolve_config(&raw).ok())
        .is_some_and(|c| c.is_ready())
}

/// Load the live config, requiring a provider + repo.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the config is missing, invalid,
/// or has no provider/repo set.
pub fn load_config() -> Result<IssueTrackerConfig, ClassifiedError> {
    let raw = crate::config::read_config("issue_tracker").map_err(ClassifiedError::Validation)?;
    let cfg = resolve_config(&raw)?;
    if !cfg.is_ready() {
        return Err(ClassifiedError::Validation(
            "issue tracker is not configured: set `provider` (github/gitlab) and `repo` in Settings > Issue Tracker".to_owned(),
        ));
    }
    Ok(cfg)
}

/// Resolve the API token: a direct `api_token` wins, else the env var named by
/// `api_token_env`.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if neither yields a non-empty value.
pub fn resolve_token(cfg: &IssueTrackerConfig) -> Result<String, ClassifiedError> {
    if let Some(t) = cfg.api_token.as_deref().map(str::trim) {
        if !t.is_empty() {
            return Ok(t.to_owned());
        }
    }
    let name = cfg.api_token_env.trim();
    if !name.is_empty() {
        if let Ok(t) = std::env::var(name) {
            if !t.trim().is_empty() {
                return Ok(t);
            }
        }
    }
    Err(ClassifiedError::Validation(
        "issue-tracker API token not set: paste a Personal Access Token in Settings, or set `api_token_env`".to_owned(),
    ))
}

/// The repo's web URL, e.g. `https://github.com/owner/repo`.
#[must_use]
pub fn repo_web_url(web_base: &str, repo: &str) -> String {
    format!(
        "{}/{}",
        web_base.trim_end_matches('/'),
        repo.trim_matches('/')
    )
}

/// A prefilled "new issue" URL for the target repo, for opening in a browser.
#[must_use]
pub fn new_issue_url(
    provider: Provider,
    web_base: &str,
    repo: &str,
    title: &str,
    body: &str,
    labels: &[String],
) -> String {
    let base = repo_web_url(web_base, repo);
    match provider {
        Provider::GitHub => {
            let mut url = format!(
                "{base}/issues/new?title={}&body={}",
                percent_encode(title),
                percent_encode(body),
            );
            if !labels.is_empty() {
                url.push_str("&labels=");
                url.push_str(&percent_encode(&labels.join(",")));
            }
            url
        }
        Provider::GitLab => {
            let mut url = format!(
                "{base}/-/issues/new?issue%5Btitle%5D={}&issue%5Bdescription%5D={}",
                percent_encode(title),
                percent_encode(body),
            );
            for label in labels {
                url.push_str("&issue%5Blabel_names%5D%5B%5D=");
                url.push_str(&percent_encode(label));
            }
            url
        }
    }
}

/// The REST endpoint that creates an issue in the target repo.
#[must_use]
pub fn api_create_endpoint(provider: Provider, web_base: &str, repo: &str) -> String {
    match provider {
        Provider::GitHub => format!(
            "{}/repos/{}/issues",
            github_api_base(web_base),
            repo.trim_matches('/')
        ),
        // GitLab addresses a project by URL-encoded path (or numeric id).
        Provider::GitLab => format!(
            "{}/api/v4/projects/{}/issues",
            web_base.trim_end_matches('/'),
            percent_encode(repo.trim_matches('/'))
        ),
    }
}

/// GitHub's API host: `api.github.com` for the public site, `{host}/api/v3` for
/// GitHub Enterprise.
fn github_api_base(web_base: &str) -> String {
    let trimmed = web_base.trim_end_matches('/');
    if trimmed == "https://github.com" || trimmed == "http://github.com" {
        "https://api.github.com".to_owned()
    } else {
        format!("{trimmed}/api/v3")
    }
}

/// The endpoint that returns the authenticated user (used by `test_connection`).
fn api_user_endpoint(provider: Provider, web_base: &str) -> String {
    match provider {
        Provider::GitHub => format!("{}/user", github_api_base(web_base)),
        Provider::GitLab => format!("{}/api/v4/user", web_base.trim_end_matches('/')),
    }
}

/// A stable, hidden marker embedded in a filed issue's body so a later filing of
/// the same crash can find it and avoid opening a duplicate. Keyed on the crash
/// stack signature, which is deterministic per distinct crash.
#[must_use]
pub fn dedup_marker(stack_signature: &str) -> String {
    format!("oxfuzz-signature:{stack_signature}")
}

/// The endpoint that searches open issues for an existing filing of a crash,
/// keyed on its [`dedup_marker`]. Best-effort: the caller treats any failure as
/// "not found" and proceeds to create.
fn api_search_endpoint(provider: Provider, web_base: &str, repo: &str, marker: &str) -> String {
    match provider {
        // GitHub issue search: restrict to this repo, open issues, body match.
        Provider::GitHub => format!(
            "{}/search/issues?q={}",
            github_api_base(web_base),
            percent_encode(&format!(
                "repo:{} in:body state:open {marker}",
                repo.trim_matches('/')
            ))
        ),
        // GitLab issue search over the project, description scope, opened state.
        Provider::GitLab => format!(
            "{}/api/v4/projects/{}/issues?state=opened&in=description&search={}",
            web_base.trim_end_matches('/'),
            percent_encode(repo.trim_matches('/')),
            percent_encode(marker)
        ),
    }
}

/// Extract the first issue from a search response whose body/description
/// actually contains `marker` (search ranking is fuzzy, so confirm the match).
fn parse_search_match(
    provider: Provider,
    json: &serde_json::Value,
    marker: &str,
) -> Option<CreatedIssue> {
    let (items, url_key, num_key, body_key) = match provider {
        Provider::GitHub => (json.get("items")?.as_array()?, "html_url", "number", "body"),
        Provider::GitLab => (json.as_array()?, "web_url", "iid", "description"),
    };
    items.iter().find_map(|item| {
        let body = item.get(body_key).and_then(|v| v.as_str()).unwrap_or("");
        if !body.contains(marker) {
            return None;
        }
        Some(CreatedIssue {
            url: item
                .get(url_key)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned(),
            number: item.get(num_key).and_then(serde_json::Value::as_u64),
        })
    })
}

/// The JSON body for creating an issue, in the provider's shape.
#[must_use]
pub fn create_body(
    provider: Provider,
    title: &str,
    body: &str,
    labels: &[String],
) -> serde_json::Value {
    match provider {
        Provider::GitHub => serde_json::json!({ "title": title, "body": body, "labels": labels }),
        // GitLab takes a comma-separated label string and `description`.
        Provider::GitLab => {
            serde_json::json!({ "title": title, "description": body, "labels": labels.join(",") })
        }
    }
}

/// Percent-encode a value for a URL query (unreserved chars pass through).
fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// The result of filing an issue via the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedIssue {
    /// Browser URL of the created issue.
    pub url: String,
    /// The issue number (GitHub) or iid (GitLab), when returned.
    pub number: Option<u64>,
}

/// REST client that files issues in the configured repository.
pub struct IssueTrackerClient {
    provider: Provider,
    web_base: String,
    repo: String,
    token: String,
    http: reqwest::Client,
}

impl IssueTrackerClient {
    /// Build a client from a loaded config plus a resolved token.
    ///
    /// # Errors
    /// Returns [`ClassifiedError`] if the config lacks a provider/repo/web base,
    /// or the HTTP client cannot be built.
    pub fn from_config(cfg: &IssueTrackerConfig, token: &str) -> Result<Self, ClassifiedError> {
        let provider = cfg.resolved_provider().ok_or_else(|| {
            ClassifiedError::Validation("issue tracker provider not set".to_owned())
        })?;
        let web_base = cfg.web_base().ok_or_else(|| {
            ClassifiedError::Validation("issue tracker host not resolvable".to_owned())
        })?;
        let repo = cfg.repo.trim().to_owned();
        if repo.is_empty() {
            return Err(ClassifiedError::Validation(
                "issue tracker `repo` is empty".to_owned(),
            ));
        }
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .user_agent(concat!("oxfuzz/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ClassifiedError::Internal(format!("http client: {e}")))?;
        Ok(Self {
            provider,
            web_base,
            repo,
            token: token.to_owned(),
            http,
        })
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.provider {
            Provider::GitHub => req
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", self.token),
                )
                .header(reqwest::header::ACCEPT, "application/vnd.github+json"),
            Provider::GitLab => req.header("PRIVATE-TOKEN", self.token.as_str()),
        }
    }

    /// File an issue and return its browser URL.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] on auth failure (401/403) and
    /// [`ClassifiedError::Provider`] on transport or server errors.
    pub async fn create_issue(
        &self,
        title: &str,
        body: &str,
        labels: &[String],
    ) -> Result<CreatedIssue, ClassifiedError> {
        let endpoint = api_create_endpoint(self.provider, &self.web_base, &self.repo);
        let payload = create_body(self.provider, title, body, labels);
        let resp = self
            .auth(self.http.post(&endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("issue tracker unreachable: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(classify_status(status));
        }
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("issue tracker bad response: {e}")))?;
        Ok(parse_created(self.provider, &json))
    }

    /// Best-effort search for an already-filed issue for this crash, keyed on
    /// its [`dedup_marker`]. Returns the existing issue when found so the caller
    /// can avoid opening a duplicate on a re-file or a retried request.
    ///
    /// Never errors: search is an optimization, so any transport/auth/parse
    /// failure yields `None` and the caller proceeds to create.
    pub async fn find_existing_issue(&self, stack_signature: &str) -> Option<CreatedIssue> {
        if stack_signature.trim().is_empty() {
            return None;
        }
        let marker = dedup_marker(stack_signature);
        let endpoint = api_search_endpoint(self.provider, &self.web_base, &self.repo, &marker);
        let resp = self.auth(self.http.get(&endpoint)).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let json: serde_json::Value = resp.json().await.ok()?;
        parse_search_match(self.provider, &json, &marker)
    }

    /// Verify the host + token by fetching the authenticated user.
    ///
    /// # Errors
    /// Returns a classified error if the server is unreachable or rejects auth.
    pub async fn test_connection(&self) -> Result<(), ClassifiedError> {
        let endpoint = api_user_endpoint(self.provider, &self.web_base);
        let resp = self
            .auth(self.http.get(&endpoint))
            .send()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("issue tracker unreachable: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(classify_status(status))
        }
    }
}

/// Read the created issue's URL + number from the provider's response JSON.
fn parse_created(provider: Provider, json: &serde_json::Value) -> CreatedIssue {
    let (url_key, num_key) = match provider {
        Provider::GitHub => ("html_url", "number"),
        Provider::GitLab => ("web_url", "iid"),
    };
    CreatedIssue {
        url: json
            .get(url_key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned(),
        number: json.get(num_key).and_then(serde_json::Value::as_u64),
    }
}

/// Map an HTTP error status to a classified error (auth vs server), token-free.
fn classify_status(status: reqwest::StatusCode) -> ClassifiedError {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        ClassifiedError::Validation(format!(
            "issue tracker rejected the token ({status}) -- check the PAT and its scopes (repo/api)"
        ))
    } else {
        ClassifiedError::Provider(format!("issue tracker error: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(provider: &str, host: &str, repo: &str) -> IssueTrackerConfig {
        let toml = format!(
            "provider = \"{provider}\"\nhost = \"{host}\"\nrepo = \"{repo}\"\napi_token_env = \"HF_ISSUE_TRACKER_TOKEN\"\n"
        );
        resolve_config(&toml).expect("valid config")
    }

    #[test]
    fn provider_parses_and_round_trips() {
        assert_eq!("github".parse(), Ok(Provider::GitHub));
        assert_eq!("GitLab".parse(), Ok(Provider::GitLab));
        assert_eq!(Provider::GitHub.as_str().parse(), Ok(Provider::GitHub));
        assert!("none".parse::<Provider>().is_err());
    }

    #[test]
    fn web_base_defaults_per_provider_and_honours_override() {
        assert_eq!(
            cfg("github", "", "o/r").web_base().as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            cfg("gitlab", "", "g/p").web_base().as_deref(),
            Some("https://gitlab.com")
        );
        assert_eq!(
            cfg("gitlab", "https://gitlab.corp.io/", "g/p")
                .web_base()
                .as_deref(),
            Some("https://gitlab.corp.io"),
        );
    }

    #[test]
    fn readiness_needs_provider_and_repo() {
        assert!(cfg("github", "", "acme/app").is_ready());
        assert!(!cfg("github", "", "").is_ready());
        assert!(!cfg("none", "", "acme/app").is_ready());
    }

    #[test]
    fn github_new_issue_url_carries_title_body_labels() {
        let url = new_issue_url(
            Provider::GitHub,
            "https://github.com",
            "acme/app",
            "Crash in parse",
            "stack trace",
            &["bug".to_owned(), "crash".to_owned()],
        );
        assert!(url.starts_with("https://github.com/acme/app/issues/new?"));
        assert!(url.contains("title=Crash%20in%20parse"));
        assert!(url.contains("body=stack%20trace"));
        assert!(url.contains("labels=bug%2Ccrash"));
    }

    #[test]
    fn gitlab_new_issue_url_uses_issue_bracket_params() {
        let url = new_issue_url(
            Provider::GitLab,
            "https://gitlab.com",
            "grp/proj",
            "Crash",
            "trace",
            &["crash".to_owned()],
        );
        assert!(url.starts_with("https://gitlab.com/grp/proj/-/issues/new?"));
        assert!(url.contains("issue%5Btitle%5D=Crash"));
        assert!(url.contains("issue%5Blabel_names%5D%5B%5D=crash"));
    }

    #[test]
    fn github_api_endpoint_public_and_enterprise() {
        assert_eq!(
            api_create_endpoint(Provider::GitHub, "https://github.com", "acme/app"),
            "https://api.github.com/repos/acme/app/issues"
        );
        assert_eq!(
            api_create_endpoint(Provider::GitHub, "https://ghe.corp.io", "acme/app"),
            "https://ghe.corp.io/api/v3/repos/acme/app/issues"
        );
    }

    #[test]
    fn gitlab_api_endpoint_url_encodes_the_project_path() {
        assert_eq!(
            api_create_endpoint(Provider::GitLab, "https://gitlab.com", "grp/proj"),
            "https://gitlab.com/api/v4/projects/grp%2Fproj/issues"
        );
        // A numeric id is passed through (no slash to encode).
        assert_eq!(
            api_create_endpoint(Provider::GitLab, "https://gitlab.com", "42"),
            "https://gitlab.com/api/v4/projects/42/issues"
        );
    }

    #[test]
    fn search_endpoint_and_match_dedup_by_signature() {
        let marker = dedup_marker("sig-abc");
        assert_eq!(marker, "oxfuzz-signature:sig-abc");

        // GitHub search restricts to the repo/open/body and encodes the marker.
        let gh = api_search_endpoint(Provider::GitHub, "https://github.com", "acme/app", &marker);
        assert!(gh.starts_with("https://api.github.com/search/issues?q="));
        assert!(gh.contains("oxfuzz-signature"));

        // A GitHub search response whose item body carries the marker matches.
        let github_json = serde_json::json!({
            "items": [
                { "html_url": "https://github.com/acme/app/issues/1", "number": 1, "body": "unrelated" },
                { "html_url": "https://github.com/acme/app/issues/7", "number": 7,
                  "body": format!("crash\n<!-- {marker} -->") }
            ]
        });
        let found = parse_search_match(Provider::GitHub, &github_json, &marker).unwrap();
        assert_eq!(found.number, Some(7));

        // No body actually containing the marker => no false-positive match.
        let none =
            serde_json::json!({ "items": [ { "html_url": "x", "number": 1, "body": "nope" } ] });
        assert!(parse_search_match(Provider::GitHub, &none, &marker).is_none());

        // GitLab returns a bare array with `description`/`web_url`/`iid`.
        let gitlab_json = serde_json::json!([
            { "web_url": "https://gitlab.com/g/p/-/issues/3", "iid": 3,
              "description": format!("d <!-- {marker} -->") }
        ]);
        let gl = parse_search_match(Provider::GitLab, &gitlab_json, &marker).unwrap();
        assert_eq!(gl.number, Some(3));
    }

    #[test]
    fn create_body_matches_each_provider_shape() {
        let labels = vec!["a".to_owned(), "b".to_owned()];
        let gh = create_body(Provider::GitHub, "t", "b", &labels);
        assert_eq!(gh["title"], "t");
        assert_eq!(gh["body"], "b");
        assert_eq!(gh["labels"], serde_json::json!(["a", "b"]));

        let gl = create_body(Provider::GitLab, "t", "b", &labels);
        assert_eq!(gl["title"], "t");
        assert_eq!(gl["description"], "b");
        assert_eq!(gl["labels"], "a,b"); // GitLab wants a CSV string
    }

    #[test]
    fn parse_created_reads_the_right_keys() {
        let gh = parse_created(
            Provider::GitHub,
            &serde_json::json!({ "html_url": "https://github.com/a/b/issues/7", "number": 7 }),
        );
        assert_eq!(gh.url, "https://github.com/a/b/issues/7");
        assert_eq!(gh.number, Some(7));
        let gl = parse_created(
            Provider::GitLab,
            &serde_json::json!({ "web_url": "https://gitlab.com/g/p/-/issues/3", "iid": 3 }),
        );
        assert_eq!(gl.url, "https://gitlab.com/g/p/-/issues/3");
        assert_eq!(gl.number, Some(3));
    }

    #[test]
    fn token_prefers_direct_then_env() {
        let mut c = cfg("github", "", "o/r");
        c.api_token = Some("direct".to_owned());
        assert_eq!(resolve_token(&c).unwrap(), "direct");
        c.api_token = None;
        c.api_token_env = "HF_ISSUE_TRACKER_TOKEN_DOES_NOT_EXIST".to_owned();
        assert!(resolve_token(&c).is_err());
    }
}
