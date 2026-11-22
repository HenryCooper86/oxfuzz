//! Issue-tracker integration -- file triaged crashes as **GitHub** or **GitLab**
//! issues in the *fuzzed project's* repository, or as **Jira** issues in the
//! project that tracks it.
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
//!
//! Jira is the one exception on `username`: Jira Cloud authenticates its REST
//! API with the account email plus an API token (HTTP Basic), so a configured
//! `username` is sent with the token. With no `username` the token is sent as
//! a Bearer Personal Access Token, which is what Jira Data Center expects.
//! Jira has no public default host, so `host` is required, and `repo` holds
//! the project key (for example `FUZZ`).

use std::fmt::Write as _;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

/// Which forge the crashes are filed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
    GitHub,
    GitLab,
    Jira,
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "github" | "gh" => Ok(Self::GitHub),
            "gitlab" | "gl" => Ok(Self::GitLab),
            "jira" => Ok(Self::Jira),
            other => Err(format!(
                "unknown issue-tracker provider '{other}' (expected github, gitlab, or jira)"
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
            Self::Jira => "jira",
        }
    }

    /// The public host when none is configured. Jira has none: every site
    /// has its own address, so the empty default leaves it unresolved.
    #[must_use]
    pub const fn default_host(self) -> &'static str {
        match self {
            Self::GitHub => "https://github.com",
            Self::GitLab => "https://gitlab.com",
            Self::Jira => "",
        }
    }

    /// Human label for the UI.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::GitLab => "GitLab",
            Self::Jira => "Jira",
        }
    }
}

/// Issue-tracker connection + defaults, loaded from `config/issue_tracker.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTrackerConfig {
    /// `github` | `gitlab` | `jira` | `none` (or blank -> disabled).
    #[serde(default)]
    pub provider: String,
    /// Base web URL. Blank uses the provider default (github.com / gitlab.com);
    /// set it for GitHub Enterprise or a self-hosted GitLab. Required for Jira
    /// (for example `https://acme.atlassian.net`).
    #[serde(default)]
    pub host: Option<String>,
    /// Target repository of the fuzzed software: GitHub `owner/repo`; GitLab
    /// `group/project` (or a numeric project id, API-only); Jira project key.
    #[serde(default)]
    pub repo: String,
    /// Personal Access Token stored directly (desktop). Prefer `api_token_env`
    /// for CLI/CI so the secret never lands in a config file.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Name of the environment variable holding the token, when not stored directly.
    #[serde(default)]
    pub api_token_env: String,
    /// Optional username, for attribution/display only -- never authentication,
    /// except on Jira, where a set username (the account email) selects HTTP
    /// Basic authentication with the token, as Jira Cloud requires.
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
        let host = host.trim_end_matches('/');
        (!host.is_empty()).then(|| host.to_owned())
    }

    /// True when a provider, a resolvable host, and a target repo are set --
    /// enough to open a new-issue page. Filing via the API additionally needs
    /// a token.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.web_base().is_some() && !self.repo.trim().is_empty()
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
            "issue tracker is not configured: set `provider` (github/gitlab/jira) and `repo` in Settings > Issue Tracker; Jira also needs `host`".to_owned(),
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

/// The web URL of the place issues are filed in: the repository for GitHub
/// and GitLab, the project for Jira.
#[must_use]
pub fn tracker_web_url(provider: Provider, web_base: &str, repo: &str) -> String {
    match provider {
        Provider::GitHub | Provider::GitLab => repo_web_url(web_base, repo),
        Provider::Jira => format!(
            "{}/browse/{}",
            web_base.trim_end_matches('/'),
            percent_encode(repo.trim())
        ),
    }
}

/// A "new issue" URL for the target repo, for opening in a browser: prefilled
/// on GitHub and GitLab. Jira's create form takes numeric project and
/// issue-type ids that a project key does not supply, so its URL opens the
/// empty create form.
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
        Provider::Jira => format!(
            "{}/secure/CreateIssue!default.jspa",
            web_base.trim_end_matches('/')
        ),
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
        Provider::Jira => format!("{}/rest/api/2/issue", web_base.trim_end_matches('/')),
    }
}

/// Whether a Jira site is Jira Cloud. Cloud removed the classic issue search
/// endpoint in favour of `/search/jql`; Data Center has only the classic one.
fn is_jira_cloud(web_base: &str) -> bool {
    reqwest::Url::parse(web_base).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| host.ends_with(".atlassian.net"))
    })
}

/// A Jira issue key (`FUZZ-12`): the only form accepted from a response
/// before it is placed in a browse URL.
fn jira_issue_number(key: &str) -> Option<u64> {
    let (project, number) = key.rsplit_once('-')?;
    let mut characters = project.chars();
    let valid_project = characters.next().is_some_and(|c| c.is_ascii_uppercase())
        && characters.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !valid_project || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok()
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
        Provider::Jira => format!("{}/rest/api/2/myself", web_base.trim_end_matches('/')),
    }
}

/// A stable, hidden marker embedded in a filed issue's body so a later filing of
/// the same crash can find it and avoid opening a duplicate. Keyed on the crash
/// stack signature, or the durable crash identity for a frameless finding.
#[must_use]
pub fn dedup_marker(stack_signature: &str) -> String {
    format!("oxfuzz-signature:{stack_signature}")
}

/// The endpoint that searches open issues for an existing filing of a crash,
/// keyed on its [`dedup_marker`]. Reconciliation requires a successful search.
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
        // Jira text search is tokenized, so the phrase match is a candidate
        // list; `parse_search_match` confirms the marker in each description.
        Provider::Jira => {
            let jql = format!(
                "project = \"{}\" AND statusCategory != Done AND description ~ \"\\\"{}\\\"\"",
                repo.trim().replace(['"', '\\'], ""),
                marker.replace(['"', '\\'], "")
            );
            let path = if is_jira_cloud(web_base) {
                "rest/api/2/search/jql"
            } else {
                "rest/api/2/search"
            };
            format!(
                "{}/{path}?jql={}&fields=description&maxResults=50",
                web_base.trim_end_matches('/'),
                percent_encode(&jql)
            )
        }
    }
}

/// Extract the first issue from a search response whose body/description
/// actually contains `marker` (search ranking is fuzzy, so confirm the match).
fn parse_search_match(
    provider: Provider,
    web_base: &str,
    json: &serde_json::Value,
    marker: &str,
) -> Result<Option<CreatedIssue>, ClassifiedError> {
    if provider == Provider::GitHub
        && json
            .get("incomplete_results")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    {
        return Err(ClassifiedError::Provider(
            "issue tracker search returned incomplete results".to_owned(),
        ));
    }
    let (items, body_key) = match provider {
        Provider::GitHub => (
            json.get("items").and_then(serde_json::Value::as_array),
            "body",
        ),
        Provider::GitLab => (json.as_array(), "description"),
        Provider::Jira => (
            json.get("issues").and_then(serde_json::Value::as_array),
            "description",
        ),
    };
    let items = items.ok_or_else(|| {
        ClassifiedError::Provider("issue tracker search response lacks its issue list".to_owned())
    })?;
    for item in items {
        // Jira nests an issue's fields one level down.
        let holder = if provider == Provider::Jira {
            item.get("fields").unwrap_or(&serde_json::Value::Null)
        } else {
            item
        };
        let body = match holder.get(body_key) {
            Some(serde_json::Value::String(body)) => body.as_str(),
            Some(serde_json::Value::Null) => "",
            _ => {
                return Err(ClassifiedError::Provider(
                    "issue tracker search item lacks a valid description".to_owned(),
                ))
            }
        };
        if body.contains(marker) {
            return parse_created(provider, web_base, item).map(Some);
        }
    }
    if provider == Provider::Jira {
        // Data Center reports `total`; Cloud's enhanced search reports
        // `isLast` and a `nextPageToken` when more results exist.
        let more_by_total = json
            .get("total")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|total| total > items.len() as u64);
        let more_by_page = json.get("isLast").and_then(serde_json::Value::as_bool) == Some(false)
            || json
                .get("nextPageToken")
                .is_some_and(|token| !token.is_null());
        if more_by_total || more_by_page {
            return Err(ClassifiedError::Provider(
                "issue tracker search has unexamined results".to_owned(),
            ));
        }
    }
    if provider == Provider::GitHub {
        let total = json
            .get("total_count")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ClassifiedError::Provider("issue tracker search lacks its total count".to_owned())
            })?;
        if total != items.len() as u64 {
            return Err(ClassifiedError::Provider(
                "issue tracker search has unexamined results".to_owned(),
            ));
        }
    }
    Ok(None)
}

/// The JSON body for creating an issue, in the provider's shape.
#[must_use]
pub fn create_body(
    provider: Provider,
    repo: &str,
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
        // Jira labels cannot contain whitespace. The body is sent as the
        // plain-text description of API v2, which both Cloud and Data Center
        // accept.
        Provider::Jira => {
            let labels: Vec<String> = labels
                .iter()
                .map(|label| label.split_whitespace().collect::<Vec<_>>().join("-"))
                .filter(|label| !label.is_empty())
                .collect();
            serde_json::json!({ "fields": {
                "project": { "key": repo.trim() },
                "summary": title,
                "description": body,
                "issuetype": { "name": "Bug" },
                "labels": labels,
            } })
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
    /// The issue number (GitHub), iid (GitLab), or the numeric part of the
    /// key (Jira), when returned.
    pub number: Option<u64>,
}

/// REST client that files issues in the configured repository.
pub struct IssueTrackerClient {
    provider: Provider,
    web_base: String,
    repo: String,
    token: String,
    /// The Jira account email for HTTP Basic authentication; unused elsewhere.
    username: Option<String>,
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
            username: cfg
                .username
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
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
            // Jira Cloud: account email + API token (Basic). Data Center: a
            // Personal Access Token (Bearer).
            Provider::Jira => match &self.username {
                Some(username) => req.basic_auth(username, Some(self.token.as_str())),
                None => req.bearer_auth(self.token.as_str()),
            },
        }
    }

    /// File an issue and return its browser URL.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] on auth failure (401/403) and
    /// [`ClassifiedError::Provider`] on transport or server errors.
    pub(crate) async fn create_issue(
        &self,
        title: &str,
        body: &str,
        labels: &[String],
    ) -> Result<CreatedIssue, ClassifiedError> {
        let endpoint = api_create_endpoint(self.provider, &self.web_base, &self.repo);
        let payload = create_body(self.provider, &self.repo, title, body, labels);
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
        parse_created(self.provider, &self.web_base, &json)
    }

    /// Search for an already-filed issue for this crash, keyed on
    /// its [`dedup_marker`]. Returns the existing issue when found so the caller
    /// can avoid opening a duplicate on a re-file or a retried request.
    ///
    /// # Errors
    /// Returns an error on transport, status, incomplete search, or malformed
    /// responses so recovery cannot interpret an outage as an absent issue.
    pub(crate) async fn find_existing_issue(
        &self,
        stack_signature: &str,
    ) -> Result<Option<CreatedIssue>, ClassifiedError> {
        if stack_signature.trim().is_empty() {
            return Err(ClassifiedError::Validation(
                "issue search requires a stack signature".to_owned(),
            ));
        }
        let marker = dedup_marker(stack_signature);
        let endpoint = api_search_endpoint(self.provider, &self.web_base, &self.repo, &marker);
        let resp = self
            .auth(self.http.get(&endpoint))
            .send()
            .await
            .map_err(|error| {
                ClassifiedError::Provider(format!("issue tracker search unreachable: {error}"))
            })?;
        if !resp.status().is_success() {
            return Err(classify_status(resp.status()));
        }
        let has_more_pages = resp
            .headers()
            .get("x-next-page")
            .is_some_and(|value| !value.as_bytes().is_empty())
            || resp
                .headers()
                .get_all(reqwest::header::LINK)
                .iter()
                .any(|value| {
                    value.to_str().map_or(true, |links| {
                        links.split(',').any(|link| {
                            link.split(';').skip(1).any(|parameter| {
                                parameter
                                    .trim()
                                    .strip_prefix("rel=")
                                    .is_some_and(|relation| {
                                        relation
                                            .trim_matches('"')
                                            .split_whitespace()
                                            .any(|name| name == "next")
                                    })
                            })
                        })
                    })
                });
        let json: serde_json::Value = resp.json().await.map_err(|error| {
            ClassifiedError::Provider(format!("issue tracker bad search response: {error}"))
        })?;
        let found = parse_search_match(self.provider, &self.web_base, &json, &marker)?;
        if found.is_none() && has_more_pages {
            return Err(ClassifiedError::Provider(
                "issue tracker search has unexamined pages".to_owned(),
            ));
        }
        Ok(found)
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
/// Jira returns only the issue key, so its browser URL is built on `web_base`.
fn parse_created(
    provider: Provider,
    web_base: &str,
    json: &serde_json::Value,
) -> Result<CreatedIssue, ClassifiedError> {
    let (url_key, num_key) = match provider {
        Provider::GitHub => ("html_url", "number"),
        Provider::GitLab => ("web_url", "iid"),
        Provider::Jira => {
            let key = json
                .get("key")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let number = jira_issue_number(key).ok_or_else(|| {
                ClassifiedError::Provider(
                    "issue tracker response lacks a valid issue key".to_owned(),
                )
            })?;
            return Ok(CreatedIssue {
                url: format!("{}/browse/{key}", web_base.trim_end_matches('/')),
                number: Some(number),
            });
        }
    };
    let url = json
        .get(url_key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            reqwest::Url::parse(value).is_ok_and(|url| {
                matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
            })
        })
        .ok_or_else(|| {
            ClassifiedError::Provider("issue tracker response lacks a valid issue URL".to_owned())
        })?;
    Ok(CreatedIssue {
        url: url.to_owned(),
        number: json.get(num_key).and_then(serde_json::Value::as_u64),
    })
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

    async fn search_fixture(
        provider: Provider,
        status: &'static str,
        body: &'static str,
        headers: &'static str,
    ) -> Result<Option<CreatedIssue>, ClassifiedError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let client = IssueTrackerClient {
            provider,
            web_base: format!("http://{address}"),
            repo: "owner/repo".to_owned(),
            token: "test-token".to_owned(),
            username: None,
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
        };
        let result = client.find_existing_issue("signature").await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn tracker_search_reports_failed_or_malformed_responses() {
        for (status, body) in [
            ("503 Service Unavailable", "{}"),
            ("200 OK", "not JSON"),
            ("200 OK", "{}"),
            ("200 OK", r#"{"items":[],"incomplete_results":true}"#),
            (
                "200 OK",
                r#"{"items":[{}],"total_count":1,"incomplete_results":false}"#,
            ),
            (
                "200 OK",
                r#"{"items":[],"total_count":1,"incomplete_results":false}"#,
            ),
        ] {
            let result = search_fixture(Provider::GitHub, status, body, "").await;
            assert!(result.is_err(), "{status}: {body}: {result:?}");
        }
    }

    #[tokio::test]
    async fn tracker_search_cannot_report_absence_with_unexamined_pages() {
        for (provider, body, headers) in [
            (
                Provider::GitHub,
                r#"{"items":[],"total_count":0,"incomplete_results":false}"#,
                "Link: <https://tracker/page/2>; rel=\"next\"\r\n",
            ),
            (Provider::GitLab, "[]", "X-Next-Page: 2\r\n"),
            (
                Provider::GitLab,
                "[]",
                "Link: <https://tracker/page/2>; rel=\"next\"\r\n",
            ),
        ] {
            let result = search_fixture(provider, "200 OK", body, headers).await;
            assert!(result.is_err(), "{provider:?}: {result:?}");
        }
        for (provider, body) in [
            (
                Provider::GitHub,
                r#"{"items":[],"total_count":0,"incomplete_results":false}"#,
            ),
            (Provider::GitLab, "[]"),
        ] {
            assert!(search_fixture(provider, "200 OK", body, "")
                .await
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn created_issue_requires_an_absolute_web_url() {
        for json in [
            serde_json::json!({}),
            serde_json::json!({"html_url":""}),
            serde_json::json!({"html_url":"javascript:alert(1)"}),
        ] {
            let result = parse_created(Provider::GitHub, "https://github.com", &json);
            assert!(result.is_err(), "{result:?}");
        }
    }

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
        let found = parse_search_match(
            Provider::GitHub,
            "https://github.com",
            &github_json,
            &marker,
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.number, Some(7));

        // No body actually containing the marker => no false-positive match.
        let none = serde_json::json!({ "total_count":1, "items": [ { "html_url": "x", "number": 1, "body": "nope" } ] });
        assert!(
            parse_search_match(Provider::GitHub, "https://github.com", &none, &marker)
                .unwrap()
                .is_none()
        );

        // GitLab returns a bare array with `description`/`web_url`/`iid`.
        let gitlab_json = serde_json::json!([
            { "web_url": "https://gitlab.com/g/p/-/issues/3", "iid": 3,
              "description": format!("d <!-- {marker} -->") }
        ]);
        let gl = parse_search_match(
            Provider::GitLab,
            "https://gitlab.com",
            &gitlab_json,
            &marker,
        )
        .unwrap()
        .unwrap();
        assert_eq!(gl.number, Some(3));
    }

    #[test]
    fn create_body_matches_each_provider_shape() {
        let labels = vec!["a".to_owned(), "b".to_owned()];
        let gh = create_body(Provider::GitHub, "o/r", "t", "b", &labels);
        assert_eq!(gh["title"], "t");
        assert_eq!(gh["body"], "b");
        assert_eq!(gh["labels"], serde_json::json!(["a", "b"]));

        let gl = create_body(Provider::GitLab, "g/p", "t", "b", &labels);
        assert_eq!(gl["title"], "t");
        assert_eq!(gl["description"], "b");
        assert_eq!(gl["labels"], "a,b"); // GitLab wants a CSV string
    }

    #[test]
    fn parse_created_reads_the_right_keys() {
        let gh = parse_created(
            Provider::GitHub,
            "https://github.com",
            &serde_json::json!({ "html_url": "https://github.com/a/b/issues/7", "number": 7 }),
        )
        .unwrap();
        assert_eq!(gh.url, "https://github.com/a/b/issues/7");
        assert_eq!(gh.number, Some(7));
        let gl = parse_created(
            Provider::GitLab,
            "https://gitlab.com",
            &serde_json::json!({ "web_url": "https://gitlab.com/g/p/-/issues/3", "iid": 3 }),
        )
        .unwrap();
        assert_eq!(gl.url, "https://gitlab.com/g/p/-/issues/3");
        assert_eq!(gl.number, Some(3));
    }

    #[test]
    fn jira_needs_a_host_and_files_into_a_project_key() {
        assert_eq!("Jira".parse(), Ok(Provider::Jira));
        // No public default host: a blank host is not ready.
        assert!(cfg("jira", "", "FUZZ").web_base().is_none());
        assert!(!cfg("jira", "", "FUZZ").is_ready());
        let ready = cfg("jira", "https://acme.atlassian.net/", "FUZZ");
        assert!(ready.is_ready());
        let base = ready.web_base().unwrap();
        assert_eq!(base, "https://acme.atlassian.net");
        assert_eq!(
            api_create_endpoint(Provider::Jira, &base, "FUZZ"),
            "https://acme.atlassian.net/rest/api/2/issue"
        );
        assert_eq!(
            api_user_endpoint(Provider::Jira, &base),
            "https://acme.atlassian.net/rest/api/2/myself"
        );
        assert_eq!(
            tracker_web_url(Provider::Jira, &base, "FUZZ"),
            "https://acme.atlassian.net/browse/FUZZ"
        );
        assert_eq!(
            tracker_web_url(Provider::GitHub, "https://github.com", "o/r"),
            "https://github.com/o/r"
        );
        assert_eq!(
            new_issue_url(Provider::Jira, &base, "FUZZ", "t", "b", &[]),
            "https://acme.atlassian.net/secure/CreateIssue!default.jspa"
        );

        let labels = vec!["oxfuzz".to_owned(), "heap overflow".to_owned()];
        let body = create_body(Provider::Jira, " FUZZ ", "title", "text", &labels);
        assert_eq!(body["fields"]["project"]["key"], "FUZZ");
        assert_eq!(body["fields"]["summary"], "title");
        assert_eq!(body["fields"]["description"], "text");
        assert_eq!(body["fields"]["issuetype"]["name"], "Bug");
        assert_eq!(
            body["fields"]["labels"],
            serde_json::json!(["oxfuzz", "heap-overflow"])
        );
    }

    #[test]
    fn jira_search_uses_the_endpoint_its_deployment_has() {
        let marker = dedup_marker("abc123");
        let cloud = api_search_endpoint(
            Provider::Jira,
            "https://acme.atlassian.net",
            "FUZZ",
            &marker,
        );
        assert!(
            cloud.starts_with("https://acme.atlassian.net/rest/api/2/search/jql?jql="),
            "{cloud}"
        );
        let server = api_search_endpoint(Provider::Jira, "https://jira.corp.io", "FUZZ", &marker);
        assert!(
            server.starts_with("https://jira.corp.io/rest/api/2/search?jql="),
            "{server}"
        );
        for endpoint in [&cloud, &server] {
            assert!(endpoint.ends_with("&fields=description&maxResults=50"));
            assert!(endpoint.contains("oxfuzz-signature%3Aabc123"), "{endpoint}");
            assert!(
                endpoint.contains("project%20%3D%20%22FUZZ%22"),
                "{endpoint}"
            );
        }
        // A quote in the key cannot close the JQL string.
        let hostile =
            api_search_endpoint(Provider::Jira, "https://jira.corp.io", "F\" OR 1", &marker);
        assert!(!hostile.contains("%22F%22%20OR"), "{hostile}");
    }

    #[test]
    fn jira_issues_are_read_by_key_and_confirmed_by_description() {
        let base = "https://jira.corp.io";
        let created = parse_created(
            Provider::Jira,
            base,
            &serde_json::json!({"id":"10000","key":"FUZZ-12"}),
        )
        .unwrap();
        assert_eq!(created.url, "https://jira.corp.io/browse/FUZZ-12");
        assert_eq!(created.number, Some(12));
        for key in ["", "fuzz-1", "FUZZ-", "FUZZ-1/../x", "FUZZ-1?x", "-3"] {
            assert!(
                parse_created(Provider::Jira, base, &serde_json::json!({ "key": key })).is_err(),
                "{key}"
            );
        }

        let marker = dedup_marker("abc123");
        let found = parse_search_match(
            Provider::Jira,
            base,
            &serde_json::json!({ "total": 2, "issues": [
                { "key": "FUZZ-3", "fields": { "description": "abc123 mentioned in passing" } },
                { "key": "FUZZ-7", "fields": { "description": format!("crash\n{marker}") } }
            ] }),
            &marker,
        )
        .unwrap()
        .unwrap();
        assert_eq!(found.url, "https://jira.corp.io/browse/FUZZ-7");
        // A null description is an issue without the marker, not an error.
        let none = parse_search_match(
            Provider::Jira,
            base,
            &serde_json::json!({ "issues": [ { "key": "FUZZ-3", "fields": { "description": null } } ], "isLast": true }),
            &marker,
        )
        .unwrap();
        assert!(none.is_none());
        // More results than were examined cannot be read as "not filed".
        for partial in [
            serde_json::json!({ "total": 90, "issues": [] }),
            serde_json::json!({ "issues": [], "isLast": false }),
            serde_json::json!({ "issues": [], "nextPageToken": "t" }),
        ] {
            assert!(parse_search_match(Provider::Jira, base, &partial, &marker).is_err());
        }
        assert!(parse_search_match(Provider::Jira, base, &serde_json::json!({}), &marker).is_err());
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
