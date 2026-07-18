//! Lifecycle for a *local* Docker `DefectDojo` instance: adopt it, start it with
//! the app, and report what state it is in.
//!
//! `hobot_fuzz` still ships no `DefectDojo` server and no compose file (see
//! `docs/design/defectdojo-integration.md`). What it does is *adopt* a compose
//! project that already exists on the machine -- the one the operator created by
//! following upstream's install -- and supervise it, so the embedded web view and
//! the crash push have something to talk to without the operator remembering to
//! `docker compose up` first.
//!
//! Two invariants shape this module:
//!
//! * **Only a local instance is ever managed.** A `url` pointing at a shared or
//!   hosted `DefectDojo` is somebody else's server; we probe it and never touch it.
//! * **The app owns the published port.** Upstream's compose publishes
//!   `${DD_PORT:-8080}`, so a stack started without `DD_PORT` would come up on a
//!   port the app is not configured for. The port is therefore derived from the
//!   configured `url` and passed into `docker compose`.
//!
//! Fuzzing never depends on any of this: every entry point is best-effort and
//! failure is reported, never fatal.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

use crate::defectdojo::{self, DefectDojoConfig};

/// Compose project name used by upstream `DefectDojo`'s `docker compose`.
pub const DEFAULT_COMPOSE_PROJECT: &str = "defectdojo";

/// How long to wait for the server to answer after starting the stack. Django
/// migrations on a cold volume are slow; uwsgi commonly needs 30-60s.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 300;

/// Per-probe HTTP timeout. Short: the point is liveness, not throughput.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Where the local `DefectDojo` compose project lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeSpec {
    /// `docker compose -p` project name.
    pub project: String,
    /// Compose files, in the order they must be layered.
    pub files: Vec<PathBuf>,
    /// Directory relative paths inside the compose files resolve against.
    pub dir: PathBuf,
}

/// Coarse state of the `DefectDojo` instance the app is pointed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefectDojoState {
    /// No usable config: missing file, or still the shipped placeholder URL.
    NotConfigured,
    /// Configured, but the URL is not on this machine, so it is never managed.
    Remote,
    /// A local instance, but the Docker daemon is not reachable.
    DockerDown,
    /// Docker is up, but no `DefectDojo` compose project exists to start.
    NotInstalled,
    /// The compose project exists but its containers are not running.
    Stopped,
    /// Containers are running; the server is not answering yet (uwsgi booting).
    Starting,
    /// The server answers on the configured URL.
    Ready,
}

impl DefectDojoState {
    /// Whether the web UI can be embedded / the API pushed to right now.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Full status of the `DefectDojo` instance, for the Health panel and the
/// embedded web view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectDojoStatus {
    pub state: DefectDojoState,
    /// The configured base URL, when there is one.
    pub url: Option<String>,
    /// Human-readable explanation of [`Self::state`], suitable for direct display.
    pub message: String,
    /// True when `hobot_fuzz` can start and stop this instance itself.
    pub managed: bool,
}

impl DefectDojoStatus {
    fn new(state: DefectDojoState, url: Option<String>, message: impl Into<String>) -> Self {
        Self {
            state,
            url,
            message: message.into(),
            managed: false,
        }
    }

    const fn managed(mut self) -> Self {
        self.managed = true;
        self
    }
}

/// Whether `url` points at this machine. Only a local instance is ever managed:
/// a hosted `DefectDojo` belongs to somebody else's operations team.
#[must_use]
pub fn is_local(url: &str) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|u| {
        matches!(
            u.host_str(),
            Some("localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "[::1]")
        )
    })
}

/// The host port the stack must publish for the app to reach it at `url`.
///
/// Upstream's compose publishes `${DD_PORT:-8080}`; passing this back in as
/// `DD_PORT` is what keeps "the port the app talks to" and "the port the server
/// listens on" the same number.
#[must_use]
pub fn dd_port(url: &str) -> Option<u16> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.port_or_known_default())
}

/// Parse one `docker ps` row of compose labels: `<config_files>|<working_dir>`,
/// where `config_files` is comma-separated. Returns `None` for a row without the
/// labels (a container not started by compose).
fn parse_compose_labels(project: &str, line: &str) -> Option<ComposeSpec> {
    let (files, dir) = line.split_once('|')?;
    let dir = dir.trim();
    if dir.is_empty() {
        return None;
    }
    let files: Vec<PathBuf> = files
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(PathBuf::from)
        .collect();
    if files.is_empty() {
        return None;
    }
    Some(ComposeSpec {
        project: project.to_owned(),
        files,
        dir: PathBuf::from(dir),
    })
}

/// Build a [`ComposeSpec`] from explicitly configured compose files. The project
/// directory is the first file's parent, matching `docker compose`'s own default.
fn spec_from_config(project: &str, files: &[String]) -> Option<ComposeSpec> {
    let files: Vec<PathBuf> = files
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .map(PathBuf::from)
        .collect();
    let dir = files.first()?.parent()?.to_path_buf();
    Some(ComposeSpec {
        project: project.to_owned(),
        files,
        dir,
    })
}

/// Run a `docker` subcommand, returning stdout on success.
///
/// Uses [`hf_runtime::docker_bin`] rather than bare `docker`: a Finder-launched
/// `.app` inherits a stripped `PATH` that does not include Docker's install dir.
fn docker(args: &[&str]) -> Option<String> {
    let out = Command::new(hf_runtime::docker_bin())
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Locate the compose project: the configured files if set, else whatever Docker
/// already knows about a project of this name -- its containers carry the compose
/// files they were created from, so an existing install needs no configuration.
fn discover_compose(cfg: &DefectDojoConfig) -> Option<ComposeSpec> {
    let project = cfg.lifecycle.resolved_compose_project();
    if let Some(spec) = spec_from_config(&project, &cfg.lifecycle.compose_files) {
        return Some(spec);
    }
    let out = docker(&[
        "ps",
        "-a",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
        "--format",
        r#"{{.Label "com.docker.compose.project.config_files"}}|{{.Label "com.docker.compose.project.working_dir"}}"#,
    ])?;
    out.lines()
        .find_map(|line| parse_compose_labels(&project, line))
}

/// Whether any container of the compose project is currently running.
fn containers_running(project: &str) -> bool {
    docker(&[
        "ps",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
        "--format",
        "{{.Names}}",
    ])
    .is_some_and(|out| !out.trim().is_empty())
}

/// Ask the server whether it is serving. Any answer below 500 counts: a fresh
/// `DefectDojo` redirects `/` to the login page (302), while nginx returns 502
/// for the first half-minute while uwsgi boots -- which is "starting", not "up".
async fn probe(cfg: &DefectDojoConfig) -> bool {
    let Ok(http) = reqwest::Client::builder()
        .danger_accept_invalid_certs(!cfg.verify_tls)
        .timeout(PROBE_TIMEOUT)
        .build()
    else {
        return false;
    };
    http.get(cfg.url.trim_end_matches('/'))
        .send()
        .await
        .is_ok_and(|r| r.status().as_u16() < 500)
}

/// Whether the configured `DefectDojo` is answering. Cheap enough for the status
/// bar's poll: unconfigured short-circuits, and a dead port refuses instantly.
pub async fn reachable() -> bool {
    match defectdojo::load_config() {
        Ok(cfg) => probe(&cfg).await,
        Err(_) => false,
    }
}

/// Current state of the configured `DefectDojo`.
pub async fn status() -> DefectDojoStatus {
    let Ok(cfg) = defectdojo::load_config() else {
        return DefectDojoStatus::new(
            DefectDojoState::NotConfigured,
            None,
            "DefectDojo is not configured -- set its URL and API token in Settings > Integrations.",
        );
    };
    status_of(&cfg).await
}

/// Current state of a specific config. Split out so the start path can re-check
/// without re-reading the config file.
async fn status_of(cfg: &DefectDojoConfig) -> DefectDojoStatus {
    let url = Some(cfg.url.clone());
    if !is_local(&cfg.url) {
        // Somebody else's server: report whether it answers, never touch it.
        return if probe(cfg).await {
            DefectDojoStatus::new(DefectDojoState::Ready, url, "DefectDojo is reachable.")
        } else {
            DefectDojoStatus::new(
                DefectDojoState::Remote,
                url,
                format!(
                    "{} is a remote DefectDojo and is not answering -- hobot_fuzz does not start or stop it.",
                    cfg.url
                ),
            )
        };
    }

    if probe(cfg).await {
        return DefectDojoStatus::new(DefectDojoState::Ready, url, "DefectDojo is running.")
            .managed();
    }

    if !hf_runtime::docker_daemon_ready() {
        return DefectDojoStatus::new(
            DefectDojoState::DockerDown,
            url,
            "Docker is not running -- DefectDojo cannot start until it is.",
        );
    }

    let Some(spec) = discover_compose(cfg) else {
        return DefectDojoStatus::new(
            DefectDojoState::NotInstalled,
            url,
            format!(
                "No local DefectDojo install found. Clone DefectDojo and bring it up once \
                 (docker compose -p {} up -d), or point `compose_files` at its docker-compose.yml.",
                cfg.lifecycle.resolved_compose_project()
            ),
        );
    };

    if containers_running(&spec.project) {
        DefectDojoStatus::new(
            DefectDojoState::Starting,
            url,
            "DefectDojo is starting -- the server is not answering yet.",
        )
        .managed()
    } else {
        DefectDojoStatus::new(
            DefectDojoState::Stopped,
            url,
            "DefectDojo is installed but not running.",
        )
        .managed()
    }
}

/// Bring the local `DefectDojo` stack up and wait for it to answer.
///
/// The published port is pinned to the one in the configured `url`, so the stack
/// always comes up where the app is pointed. Returns as soon as the server
/// answers, or once `startup_timeout_secs` elapses (state `Starting`, not an
/// error: a cold database can outlast any timeout worth blocking on).
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `DefectDojo` is unconfigured,
/// remote, or not installed, and [`ClassifiedError::Provider`] when Docker is
/// unavailable or `docker compose up` fails.
pub async fn start() -> Result<DefectDojoStatus, ClassifiedError> {
    let cfg = defectdojo::load_config()?;
    let current = status_of(&cfg).await;
    match current.state {
        DefectDojoState::Ready => return Ok(current),
        DefectDojoState::NotConfigured
        | DefectDojoState::Remote
        | DefectDojoState::NotInstalled => {
            return Err(ClassifiedError::Validation(current.message));
        }
        DefectDojoState::DockerDown => {
            return Err(ClassifiedError::Provider(current.message));
        }
        DefectDojoState::Stopped | DefectDojoState::Starting => {}
    }

    let spec = discover_compose(&cfg).ok_or_else(|| {
        ClassifiedError::Validation("no local DefectDojo compose project found".to_owned())
    })?;
    let port = dd_port(&cfg.url).ok_or_else(|| {
        ClassifiedError::Validation(format!("DefectDojo url '{}' has no port", cfg.url))
    })?;

    compose_up(&spec, port).await?;
    wait_ready(&cfg, cfg.lifecycle.resolved_startup_timeout()).await;
    Ok(status_of(&cfg).await)
}

/// Start the local instance on app launch, when the config asks for it.
///
/// Best-effort by design (`docs/design/defectdojo-integration.md`: fuzzing is
/// never gated on `DefectDojo`): a failure becomes a reported status, not an
/// error. `on_status` is called for each transition so the UI can narrate the
/// minute or so the server takes to boot.
///
/// Returns `None` when there is nothing to do -- unconfigured, remote, or
/// `autostart = false`. Call it *after* Docker is up, or it will only ever
/// report [`DefectDojoState::DockerDown`].
pub async fn autostart(
    on_status: &(dyn Fn(&DefectDojoStatus) + Send + Sync),
) -> Option<DefectDojoStatus> {
    let cfg = defectdojo::load_config().ok()?;
    if !cfg.lifecycle.autostart || !is_local(&cfg.url) {
        return None;
    }
    let current = status_of(&cfg).await;
    if !matches!(
        current.state,
        DefectDojoState::Stopped | DefectDojoState::Starting
    ) {
        on_status(&current);
        return Some(current);
    }

    let starting = DefectDojoStatus::new(
        DefectDojoState::Starting,
        Some(cfg.url.clone()),
        "Starting DefectDojo...",
    )
    .managed();
    on_status(&starting);

    let settled = match start().await {
        Ok(status) => status,
        Err(e) => DefectDojoStatus::new(
            DefectDojoState::Stopped,
            Some(cfg.url.clone()),
            e.to_string(),
        )
        .managed(),
    };
    on_status(&settled);
    Some(settled)
}

/// Stop the local stack, leaving containers and volumes intact so the next start
/// is a restart rather than a fresh install.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when there is no local install to stop.
pub async fn stop() -> Result<DefectDojoStatus, ClassifiedError> {
    let cfg = defectdojo::load_config()?;
    let spec = discover_compose(&cfg).ok_or_else(|| {
        ClassifiedError::Validation("no local DefectDojo compose project found".to_owned())
    })?;
    let args = compose_args(&spec, &["stop"]);
    let spec_dir = spec.dir.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(hf_runtime::docker_bin())
            .args(&args)
            .current_dir(&spec_dir)
            .output()
    })
    .await
    .map_err(|e| ClassifiedError::Internal(format!("docker compose stop: {e}")))?
    .map_err(|e| ClassifiedError::Internal(format!("docker compose stop: {e}")))?;
    if !output.status.success() {
        // A failed stop was previously swallowed and reported as success.
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(ClassifiedError::Internal(format!(
            "docker compose stop failed: {}",
            err.trim()
        )));
    }
    Ok(status_of(&cfg).await)
}

/// `docker compose -p <project> --project-directory <dir> -f <file>... <tail>`
fn compose_args(spec: &ComposeSpec, tail: &[&str]) -> Vec<String> {
    let mut args = vec![
        "compose".to_owned(),
        "-p".to_owned(),
        spec.project.clone(),
        "--project-directory".to_owned(),
        spec.dir.display().to_string(),
    ];
    for file in &spec.files {
        args.push("-f".to_owned());
        args.push(file.display().to_string());
    }
    args.extend(tail.iter().map(|s| (*s).to_owned()));
    args
}

/// `docker compose up -d` with the port pinned to the configured URL's.
async fn compose_up(spec: &ComposeSpec, port: u16) -> Result<(), ClassifiedError> {
    let args = compose_args(spec, &["up", "-d"]);
    let dir = spec.dir.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(hf_runtime::docker_bin())
            .args(&args)
            .current_dir(&dir)
            .env("DD_PORT", port.to_string())
            .output()
    })
    .await
    .map_err(|e| ClassifiedError::Internal(format!("docker compose up: {e}")))?
    .map_err(|e| ClassifiedError::Provider(format!("docker compose up failed: {e}")))?;

    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(ClassifiedError::Provider(format!(
        "docker compose up failed: {}",
        stderr.trim().lines().last().unwrap_or("unknown error")
    )))
}

/// Poll until the server answers or `timeout` elapses.
async fn wait_ready(cfg: &DefectDojoConfig, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if probe(cfg).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(url: &str) -> DefectDojoConfig {
        let toml = format!(
            "url = \"{url}\"\napi_token = \"t\"\napi_token_env = \"HF_DEFECTDOJO_TOKEN\"\n"
        );
        defectdojo::resolve_config(&toml).expect("valid config")
    }

    #[test]
    fn local_urls_are_managed_remote_ones_are_not() {
        assert!(is_local("http://localhost:8081"));
        assert!(is_local("http://127.0.0.1:8081"));
        assert!(is_local("https://localhost"));
        assert!(!is_local("https://defectdojo.example.com"));
        assert!(!is_local("https://dojo.internal.corp:8081"));
        assert!(!is_local("not a url"));
    }

    #[test]
    fn dd_port_comes_from_the_configured_url() {
        // The whole point: the stack must publish the port the app talks to.
        assert_eq!(dd_port("http://localhost:8081"), Some(8081));
        assert_eq!(dd_port("http://localhost"), Some(80));
        assert_eq!(dd_port("https://localhost"), Some(443));
        assert_eq!(dd_port("nonsense"), None);
    }

    #[test]
    fn compose_labels_parse_into_a_spec() {
        let spec = parse_compose_labels(
            "defectdojo",
            "/Users/x/defectdojo/docker-compose.yml,/Users/x/defectdojo/docker-compose.override.yml|/Users/x/defectdojo",
        )
        .expect("labels parse");
        assert_eq!(spec.project, "defectdojo");
        assert_eq!(spec.dir, PathBuf::from("/Users/x/defectdojo"));
        assert_eq!(
            spec.files,
            vec![
                PathBuf::from("/Users/x/defectdojo/docker-compose.yml"),
                PathBuf::from("/Users/x/defectdojo/docker-compose.override.yml"),
            ]
        );
    }

    #[test]
    fn compose_labels_reject_non_compose_containers() {
        // A container not created by compose has empty labels.
        assert!(parse_compose_labels("defectdojo", "|").is_none());
        assert!(parse_compose_labels("defectdojo", "").is_none());
        assert!(parse_compose_labels("defectdojo", "/a/docker-compose.yml|").is_none());
    }

    #[test]
    fn configured_compose_files_win_over_discovery() {
        let spec = spec_from_config(
            "dd",
            &["/opt/dd/docker-compose.yml".to_owned(), String::new()],
        )
        .expect("spec");
        assert_eq!(
            spec.files,
            vec![PathBuf::from("/opt/dd/docker-compose.yml")]
        );
        assert_eq!(spec.dir, PathBuf::from("/opt/dd"));
        assert!(spec_from_config("dd", &[]).is_none());
    }

    #[test]
    fn compose_args_layer_files_in_order() {
        let spec = ComposeSpec {
            project: "defectdojo".to_owned(),
            files: vec![PathBuf::from("/d/a.yml"), PathBuf::from("/d/b.yml")],
            dir: PathBuf::from("/d"),
        };
        assert_eq!(
            compose_args(&spec, &["up", "-d"]),
            vec![
                "compose",
                "-p",
                "defectdojo",
                "--project-directory",
                "/d",
                "-f",
                "/d/a.yml",
                "-f",
                "/d/b.yml",
                "up",
                "-d",
            ]
        );
    }

    #[tokio::test]
    async fn a_remote_instance_is_never_managed() {
        let status = status_of(&cfg_with("https://defectdojo.example.org")).await;
        assert!(!status.managed);
        assert!(matches!(
            status.state,
            DefectDojoState::Remote | DefectDojoState::Ready
        ));
    }

    #[test]
    fn only_ready_is_ready() {
        assert!(DefectDojoState::Ready.is_ready());
        assert!(!DefectDojoState::Starting.is_ready());
        assert!(!DefectDojoState::Stopped.is_ready());
    }
}
