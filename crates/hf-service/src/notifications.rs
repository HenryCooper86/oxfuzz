//! Outbound crash alerts: post a short message to an operator-configured
//! webhook when an unattended campaign finds crashes.
//!
//! The payload names the project directory (not its path), the target, and
//! the crash count. It never carries crash inputs, stack traces, or source.
//! The secret, when one is used, follows the provider and `DefectDojo`
//! integrations: a direct `bearer_token` or the environment variable named by
//! `bearer_token_env`; it is never logged.

use std::path::Path;
use std::time::Duration;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

/// How long one delivery may take before it is abandoned.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// The body a webhook receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    /// A flat JSON object with one field per fact.
    #[default]
    Json,
    /// `{"text": "..."}`, the incoming-webhook body Slack and Mattermost
    /// accept.
    Slack,
}

/// Alert settings, loaded from `config/notifications.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    /// Where alerts are posted. Empty disables alerts.
    #[serde(default)]
    pub webhook_url: String,
    /// Body format.
    #[serde(default)]
    pub format: WebhookFormat,
    /// Bearer token stored directly. Takes priority over
    /// [`Self::bearer_token_env`].
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Name of the environment variable holding the bearer token. Empty
    /// means the request carries no `Authorization` header.
    #[serde(default)]
    pub bearer_token_env: String,
    /// Verify the server TLS certificate.
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

const fn default_true() -> bool {
    true
}

/// What happened, as an alert states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashAlert {
    /// The project directory name. Never the full path, which can carry a
    /// user name.
    pub project: String,
    pub target: String,
    pub crashes: usize,
    /// The schedule that ran the campaign, when one did.
    pub schedule_id: Option<String>,
}

impl CrashAlert {
    /// Build an alert for `project`, reducing it to its directory name.
    #[must_use]
    pub fn new(project: &Path, target: &str, crashes: usize, schedule_id: Option<&str>) -> Self {
        let name = project.file_name().map_or_else(
            || project.to_string_lossy().into_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        Self {
            project: name,
            target: target.to_owned(),
            crashes,
            schedule_id: schedule_id.map(str::to_owned),
        }
    }
}

/// Parse and validate a `notifications.toml` body.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if the TOML is invalid, or a
/// non-empty `webhook_url` is not an `https` URL (plain `http` is accepted
/// for a loopback host only, where no network path can read the request).
pub fn resolve_config(toml_str: &str) -> Result<NotificationsConfig, ClassifiedError> {
    let cfg: NotificationsConfig = toml::from_str(toml_str)
        .map_err(|e| ClassifiedError::Validation(format!("invalid notifications config: {e}")))?;
    if !cfg.webhook_url.trim().is_empty() {
        validated_url(&cfg.webhook_url)?;
    }
    Ok(cfg)
}

fn validated_url(raw: &str) -> Result<reqwest::Url, ClassifiedError> {
    let url = reqwest::Url::parse(raw.trim()).map_err(|e| {
        ClassifiedError::Validation(format!("notifications `webhook_url` is not a URL: {e}"))
    })?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        "http" => Err(ClassifiedError::Validation(
            "notifications `webhook_url` must use https: plain http would send the alert \
             and any bearer token unencrypted"
                .to_owned(),
        )),
        other => Err(ClassifiedError::Validation(format!(
            "notifications `webhook_url` has unsupported scheme '{other}'"
        ))),
    }
}

/// True when a usable (non-placeholder) webhook is configured.
#[must_use]
pub fn is_configured() -> bool {
    load_config().is_ok()
}

/// Load the live config, rejecting an empty or placeholder webhook.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if the config is missing, invalid,
/// or names no real webhook.
pub fn load_config() -> Result<NotificationsConfig, ClassifiedError> {
    let raw = crate::config::read_config("notifications").map_err(ClassifiedError::Validation)?;
    let cfg = resolve_config(&raw)?;
    if crate::defectdojo::is_placeholder_url(&cfg.webhook_url) {
        return Err(ClassifiedError::Validation(
            "notifications are not configured: set `webhook_url` in config/notifications.toml"
                .to_owned(),
        ));
    }
    Ok(cfg)
}

/// Resolve the optional bearer token: the direct value wins, then the named
/// environment variable. `Ok(None)` means the config asks for no token.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] if `bearer_token_env` names a
/// variable that is unset or empty: a configured secret that silently went
/// missing would post unauthenticated.
pub fn resolve_token(cfg: &NotificationsConfig) -> Result<Option<String>, ClassifiedError> {
    if let Some(token) = cfg.bearer_token.as_deref().map(str::trim) {
        if !token.is_empty() {
            return Ok(Some(token.to_owned()));
        }
    }
    let name = cfg.bearer_token_env.trim();
    if name.is_empty() {
        return Ok(None);
    }
    match std::env::var(name) {
        Ok(token) if !token.trim().is_empty() => Ok(Some(token)),
        _ => Err(ClassifiedError::Validation(format!(
            "notification bearer token not set: export {name}"
        ))),
    }
}

/// The request body for `alert` in `format`.
#[must_use]
pub fn payload(alert: &CrashAlert, format: WebhookFormat) -> serde_json::Value {
    match format {
        WebhookFormat::Json => serde_json::json!({
            "event": "crashes_found",
            "source": "oxfuzz",
            "project": alert.project,
            "target": alert.target,
            "crashes": alert.crashes,
            "schedule_id": alert.schedule_id,
        }),
        WebhookFormat::Slack => serde_json::json!({ "text": message(alert) }),
    }
}

/// The body of a connection test: it states that it is a test and carries no
/// project data.
#[must_use]
pub fn test_payload(format: WebhookFormat) -> serde_json::Value {
    match format {
        WebhookFormat::Json => serde_json::json!({ "event": "test", "source": "oxfuzz" }),
        WebhookFormat::Slack => serde_json::json!({ "text": TEST_MESSAGE }),
    }
}

const TEST_MESSAGE: &str = "oxfuzz notification test: this webhook is configured correctly.";

/// The one-line message a chat webhook shows.
#[must_use]
pub fn message(alert: &CrashAlert) -> String {
    let noun = if alert.crashes == 1 {
        "crash"
    } else {
        "crashes"
    };
    let origin = alert
        .schedule_id
        .as_deref()
        .map(|id| format!(" (schedule {id})"))
        .unwrap_or_default();
    format!(
        "oxfuzz found {} {noun} in target {} of project {}{origin}.",
        alert.crashes, alert.target, alert.project
    )
}

/// Posts alerts to the configured webhook.
pub struct WebhookClient {
    url: reqwest::Url,
    format: WebhookFormat,
    token: Option<String>,
    http: reqwest::Client,
}

impl WebhookClient {
    /// Build a client from a loaded config plus its resolved token.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] for an invalid URL and
    /// [`ClassifiedError::Internal`] if the HTTP client cannot be built.
    pub fn from_config(
        cfg: &NotificationsConfig,
        token: Option<String>,
    ) -> Result<Self, ClassifiedError> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .user_agent(concat!("oxfuzz/", env!("CARGO_PKG_VERSION")))
            .timeout(DELIVERY_TIMEOUT)
            // A redirect would forward the bearer token to a host the
            // operator did not configure.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ClassifiedError::Internal(format!("http client: {e}")))?;
        Ok(Self {
            url: validated_url(&cfg.webhook_url)?,
            format: cfg.format,
            token,
            http,
        })
    }

    /// Post one alert.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Internal`] if the request cannot be sent or
    /// the webhook answers with a non-success status. The error names the
    /// host and status, never the full URL: chat webhook URLs embed their
    /// secret in the path.
    pub async fn send(&self, alert: &CrashAlert) -> Result<(), ClassifiedError> {
        self.post(&payload(alert, self.format)).await
    }

    /// Post a connection test that carries no project data.
    ///
    /// # Errors
    /// As [`Self::send`].
    pub async fn send_test(&self) -> Result<(), ClassifiedError> {
        self.post(&test_payload(self.format)).await
    }

    async fn post(&self, body: &serde_json::Value) -> Result<(), ClassifiedError> {
        let host = self.url.host_str().unwrap_or("webhook").to_owned();
        let mut request = self.http.post(self.url.clone()).json(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|error| {
            ClassifiedError::Internal(format!(
                "notification to {host} failed: {}",
                error.without_url()
            ))
        })?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(ClassifiedError::Internal(format!(
                "notification to {host} was rejected with HTTP {}",
                status.as_u16()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> CrashAlert {
        CrashAlert::new(
            Path::new("/Users/someone/src/libwidget"),
            "src/parse.c::parse_header",
            3,
            Some("nightly"),
        )
    }

    #[test]
    fn alert_names_the_project_directory_not_its_path() {
        let alert = alert();
        assert_eq!(alert.project, "libwidget");
        let json = payload(&alert, WebhookFormat::Json).to_string();
        assert!(!json.contains("someone"), "{json}");
    }

    #[test]
    fn json_payload_carries_each_fact_as_a_field() {
        let value = payload(&alert(), WebhookFormat::Json);
        assert_eq!(value["event"], "crashes_found");
        assert_eq!(value["project"], "libwidget");
        assert_eq!(value["target"], "src/parse.c::parse_header");
        assert_eq!(value["crashes"], 3);
        assert_eq!(value["schedule_id"], "nightly");
    }

    #[test]
    fn slack_payload_is_one_text_field() {
        let value = payload(&alert(), WebhookFormat::Slack);
        assert_eq!(
            value["text"],
            "oxfuzz found 3 crashes in target src/parse.c::parse_header of project \
             libwidget (schedule nightly)."
        );
        let mut one = alert();
        one.crashes = 1;
        one.schedule_id = None;
        assert_eq!(
            message(&one),
            "oxfuzz found 1 crash in target src/parse.c::parse_header of project libwidget."
        );
    }

    #[test]
    fn the_connection_test_carries_no_project_data() {
        assert_eq!(
            test_payload(WebhookFormat::Json),
            serde_json::json!({ "event": "test", "source": "oxfuzz" })
        );
        assert_eq!(test_payload(WebhookFormat::Slack)["text"], TEST_MESSAGE);
    }

    #[test]
    fn config_requires_https_except_on_loopback() {
        resolve_config("webhook_url = \"https://hooks.corp.internal/a/b\"\n").unwrap();
        resolve_config("webhook_url = \"http://127.0.0.1:9000/hook\"\n").unwrap();
        resolve_config("webhook_url = \"http://localhost:9000/hook\"\n").unwrap();
        resolve_config("webhook_url = \"http://[::1]:9000/hook\"\n").unwrap();
        // Empty means disabled, which is a valid configuration.
        resolve_config("webhook_url = \"\"\n").unwrap();

        let error = resolve_config("webhook_url = \"http://hooks.corp.internal/a\"\n").unwrap_err();
        assert!(error.to_string().contains("https"), "{error}");
        let error = resolve_config("webhook_url = \"file:///etc/passwd\"\n").unwrap_err();
        assert!(error.to_string().contains("scheme"), "{error}");
        assert!(resolve_config("webhook_url = \"not a url\"\n").is_err());
        // A misspelled key is a misconfiguration, not a silently ignored one.
        assert!(resolve_config("webhook = \"https://hooks.corp.internal/a\"\n").is_err());
        assert!(resolve_config("format = \"teams\"\n").is_err());
    }

    #[test]
    fn a_named_but_unset_token_variable_fails_loud() {
        let mut cfg = resolve_config("webhook_url = \"https://hooks.corp.internal/a\"\n").unwrap();
        assert_eq!(resolve_token(&cfg).unwrap(), None);
        cfg.bearer_token = Some(" direct ".to_owned());
        assert_eq!(resolve_token(&cfg).unwrap().as_deref(), Some("direct"));
        cfg.bearer_token = None;
        cfg.bearer_token_env = "OXFUZZ_TEST_NOTIFY_TOKEN_THAT_IS_NEVER_SET".to_owned();
        let error = resolve_token(&cfg).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("OXFUZZ_TEST_NOTIFY_TOKEN_THAT_IS_NEVER_SET"),
            "{error}"
        );
    }

    async fn deliver(status: &'static str, token: Option<&str>) -> (Result<(), String>, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let read = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&request[..read]).into_owned()
        });
        let cfg = resolve_config(&format!(
            "webhook_url = \"http://{address}/services/SECRETPATH\"\nformat = \"slack\"\n"
        ))
        .unwrap();
        let client = WebhookClient {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            ..WebhookClient::from_config(&cfg, token.map(str::to_owned)).unwrap()
        };
        let result = client.send(&alert()).await.map_err(|e| e.to_string());
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn delivery_posts_the_payload_with_the_bearer_token() {
        let (result, request) = deliver("200 OK", Some("s3cret")).await;
        result.unwrap();
        assert!(
            request.starts_with("POST /services/SECRETPATH "),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer s3cret"), "{request}");
        assert!(request.contains("oxfuzz found 3 crashes"), "{request}");
    }

    #[tokio::test]
    async fn a_rejected_delivery_names_the_status_but_not_the_secret_path() {
        let (result, _) = deliver("403 Forbidden", None).await;
        let error = result.unwrap_err();
        assert!(error.contains("403"), "{error}");
        assert!(!error.contains("SECRETPATH"), "{error}");
    }
}
