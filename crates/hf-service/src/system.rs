//! System health/status probes shared by GUI and web presentation layers.

use serde::{Serialize, Serializer};

/// A boolean status flag that serializes as a JSON boolean.
#[derive(Debug, Clone, Copy)]
pub struct StatusFlag(bool);

impl StatusFlag {
    /// Return the underlying readiness value for non-JSON presentation layers.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.0
    }
}

impl From<bool> for StatusFlag {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl Serialize for StatusFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(self.0)
    }
}

/// System status surfaced to frontends.
#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    /// Docker daemon is reachable, not merely installed.
    pub docker: StatusFlag,
    /// The sandbox image is loaded locally.
    pub sandbox_image: StatusFlag,
    /// libFuzzer tooling is present in the sandbox image.
    pub libfuzzer: StatusFlag,
    /// AFL++ tooling is present in the sandbox image.
    pub aflplusplus: StatusFlag,
    /// honggfuzz tooling is present in the sandbox image.
    pub honggfuzz: StatusFlag,
    /// syzkaller tooling is present in the sandbox image.
    pub syzkaller: StatusFlag,
    /// The configured `DefectDojo` instance is answering. False when it is not
    /// configured at all -- [`crate::defectdojo_lifecycle::status`] tells the two
    /// apart for a panel that needs to explain itself.
    pub defectdojo: StatusFlag,
    /// How to obtain the sandbox image when it is missing: the one-step CLI
    /// build plus `scripts/build-sandbox.sh` or the canonical `docker build`
    /// command. `None` when the image is present (the field is omitted from
    /// the JSON shape then -- additive for existing consumers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_image_remedy: Option<String>,
}

impl SystemStatus {
    /// Whether the mandatory sandbox boundary and at least one engine are
    /// available. Optional integrations do not affect core fuzzing readiness.
    #[must_use]
    pub const fn fuzzing_ready(&self) -> bool {
        self.docker.is_ready()
            && self.sandbox_image.is_ready()
            && (self.libfuzzer.is_ready()
                || self.aflplusplus.is_ready()
                || self.honggfuzz.is_ready()
                || self.syzkaller.is_ready())
    }
}

/// Read-only setup observation; completing the wizard never authorizes execution.
#[derive(Debug, Clone, Serialize)]
pub struct SetupReadiness {
    /// Individual observations from the existing system probe.
    pub status: SystemStatus,
    /// Service-owned core runtime readiness, excluding optional integrations.
    pub runtime_ready: bool,
}

impl From<SystemStatus> for SetupReadiness {
    fn from(status: SystemStatus) -> Self {
        let runtime_ready = status.fuzzing_ready();
        Self {
            status,
            runtime_ready,
        }
    }
}

/// Inspect setup prerequisites without preparing or executing a target.
pub async fn setup_readiness() -> SetupReadiness {
    system_status().await.into()
}

/// Compute the current system status by probing Docker, the sandbox image, and
/// the configured `DefectDojo`.
pub async fn system_status() -> SystemStatus {
    let docker = crate::container::docker_runtime_enabled() && hf_runtime::docker_daemon_ready();
    let sandbox_image = docker && hf_runtime::sandbox_image_present();
    let engines = if sandbox_image {
        hf_runtime::sandbox_engine_probe()
    } else {
        hf_runtime::SandboxEngines::default()
    };
    SystemStatus {
        docker: docker.into(),
        sandbox_image: sandbox_image.into(),
        libfuzzer: engines
            .supports(hf_core::engine::EngineKind::LibFuzzer)
            .into(),
        aflplusplus: engines
            .supports(hf_core::engine::EngineKind::AflPlusPlus)
            .into(),
        honggfuzz: engines
            .supports(hf_core::engine::EngineKind::Honggfuzz)
            .into(),
        syzkaller: engines
            .supports(hf_core::engine::EngineKind::Syzkaller)
            .into(),
        defectdojo: crate::defectdojo_lifecycle::reachable().await.into(),
        sandbox_image_remedy: (!sandbox_image).then(sandbox_image_remedy),
    }
}

/// The operator-facing remedy for a missing sandbox image.
pub fn sandbox_image_remedy() -> String {
    sandbox_image_remedy_from(
        crate::container::repo_root().as_deref(),
        &hf_runtime::host_platform(),
    )
}

/// Compose the one-line remedy: the source tree's build script when it has
/// one, else the canonical `docker build` command when the tree carries the
/// sandbox build inputs, else the generic form -- never name a tree as the
/// build context when it has neither `scripts/build-sandbox.sh` nor
/// `docker/sandbox/Dockerfile`, since the build cannot run there. Without a
/// buildable checkout the CLI build has nothing to run either, so only the
/// canonical command applies.
fn sandbox_image_remedy_from(source_root: Option<&std::path::Path>, platform: &str) -> String {
    let docker_build = format!(
        "docker build --platform {platform} -t {} -f docker/sandbox/Dockerfile .",
        hf_runtime::SANDBOX_IMAGE
    );
    match source_root {
        Some(root) if root.join("scripts/build-sandbox.sh").is_file() => format!(
            "build it with `oxfuzz doctor --build-image` or `scripts/build-sandbox.sh` (from {})",
            root.display()
        ),
        Some(root) if root.join("docker/sandbox/Dockerfile").is_file() => format!(
            "build it with `oxfuzz doctor --build-image`, or run `{docker_build}` from {}",
            root.display()
        ),
        _ => format!("run `{docker_build}` from an oxfuzz source checkout"),
    }
}

/// Preflight for a sandbox image build, in probe order: each failure names the
/// exact blocker (Engineering Protocol 2.16). Returns the source checkout to
/// build from.
fn build_preflight(
    docker_enabled: bool,
    docker_cli_present: bool,
    docker_daemon_ready: bool,
    source_root: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, hf_core::error::ClassifiedError> {
    use hf_core::error::ClassifiedError;
    if !docker_enabled {
        return Err(ClassifiedError::Validation(
            "Docker is disabled (HF_USE_DOCKER=0); building the sandbox image requires Docker"
                .to_owned(),
        ));
    }
    if !docker_cli_present {
        return Err(ClassifiedError::Validation(
            "Docker CLI not found; install OrbStack or Docker Desktop first".to_owned(),
        ));
    }
    if !docker_daemon_ready {
        return Err(ClassifiedError::Validation(
            "Docker daemon is not running; start it first".to_owned(),
        ));
    }
    let root = source_root.ok_or_else(|| {
        ClassifiedError::Validation(
            "no oxfuzz source checkout found above the current directory or the executable; \
             run `oxfuzz doctor --build-image` from a source checkout, or `docker build` with \
             docker/sandbox/Dockerfile directly"
                .to_owned(),
        )
    })?;
    if !root.join("docker/sandbox/Dockerfile").is_file() {
        return Err(ClassifiedError::Validation(format!(
            "the source checkout at {} has no docker/sandbox/Dockerfile to build from",
            root.display()
        )));
    }
    Ok(root.to_path_buf())
}

/// Build the sandbox image for the host platform via the same
/// [`crate::container::build_sandbox_image`] operation the desktop app uses.
///
/// The build streams its output to the caller's terminal (inherited stdio),
/// matching the GUI's behavior; it can take several minutes on first run.
///
/// # Errors
/// Returns `ClassifiedError::Validation` naming the exact blocker when Docker
/// is disabled, the CLI or daemon is absent, or no source checkout with
/// `docker/sandbox/Dockerfile` is found; `ClassifiedError::Internal` when the
/// build itself fails.
pub fn build_sandbox_image_for_host() -> Result<(), hf_core::error::ClassifiedError> {
    let root = build_preflight(
        crate::container::docker_runtime_enabled(),
        hf_runtime::docker_cli_present(),
        hf_runtime::docker_daemon_ready(),
        crate::container::repo_root().as_deref(),
    )?;
    crate::container::build_sandbox_image(&root, &hf_runtime::host_platform())
}

/// Readiness of one selected campaign, without authoring or executing a target.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzingPreflight {
    /// Selected engine whose toolchain and policy were checked.
    pub engine: hf_core::engine::EngineKind,
    /// Current sandbox and installed-tool evidence.
    pub status: SystemStatus,
    /// Whether a provider pool was constructible, if requested. No model was called.
    pub provider_configured: Option<bool>,
    /// True when every requested prerequisite passed.
    pub ready: bool,
    /// Named missing prerequisites or invalid campaign settings.
    pub problems: Vec<String>,
}

/// Probe one campaign's engine, duration policy and optional provider configuration.
///
/// Does not bootstrap persistence, contact a model, or authorize execution.
/// Provider authentication and reachability are established only by later calls.
#[tracing::instrument]
pub async fn fuzzing_preflight(
    engine: hf_core::engine::EngineKind,
    duration_secs: Option<u64>,
    require_provider: bool,
) -> FuzzingPreflight {
    let policy =
        crate::config::resolve_fuzzing_run(Some(engine), duration_secs, None, None, None, None)
            .map(|_| ());
    let provider_configured = require_provider.then(|| {
        crate::container::provider_pool_from_config()
            .or_else(crate::container::provider_pool_from_env)
            .is_some()
    });
    assess_fuzzing_preflight(system_status().await, engine, provider_configured, policy)
}

fn assess_fuzzing_preflight(
    status: SystemStatus,
    engine: hf_core::engine::EngineKind,
    provider_configured: Option<bool>,
    policy: Result<(), String>,
) -> FuzzingPreflight {
    use hf_core::engine::EngineKind;
    let mut problems = Vec::new();
    if !status.docker.is_ready() {
        problems.push("Docker is unavailable or disabled".to_owned());
    }
    if !status.sandbox_image.is_ready() {
        problems.push("sandbox image is unavailable".to_owned());
    }
    let engine_ready = match engine {
        EngineKind::AflPlusPlus => status.aflplusplus,
        EngineKind::Honggfuzz => status.honggfuzz,
        EngineKind::LibFuzzer => status.libfuzzer,
        EngineKind::Syzkaller | EngineKind::GoNative => status.syzkaller,
    };
    if !engine_ready.is_ready() {
        problems.push(format!(
            "selected engine {} is unavailable in the sandbox",
            engine.as_str()
        ));
    }
    if let Err(error) = policy {
        problems.push(error);
    }
    if provider_configured == Some(false) {
        problems.push(
            "no usable provider configuration; configure a provider before authoring".to_owned(),
        );
    }
    FuzzingPreflight {
        engine,
        status,
        provider_configured,
        ready: problems.is_empty(),
        problems,
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusFlag, SystemStatus};
    use crate::container::docker_runtime_enabled_from;

    fn status(docker: bool, image: bool, libfuzzer: bool) -> SystemStatus {
        SystemStatus {
            docker: StatusFlag(docker),
            sandbox_image: StatusFlag(image),
            libfuzzer: StatusFlag(libfuzzer),
            aflplusplus: StatusFlag(false),
            honggfuzz: StatusFlag(false),
            syzkaller: StatusFlag(false),
            defectdojo: StatusFlag(false),
            sandbox_image_remedy: None,
        }
    }

    #[test]
    fn setup_view_serializes_service_owned_readiness_without_optional_integrations() {
        for (docker, image, engine, expected) in [
            (true, true, true, true),
            (true, true, false, false),
            (false, true, true, false),
        ] {
            let view = super::SetupReadiness::from(status(docker, image, engine));
            let json = serde_json::to_value(view).unwrap();
            assert_eq!(json["runtime_ready"], expected);
            assert_eq!(json["status"]["defectdojo"], false);
        }
    }

    #[test]
    fn the_remedy_field_is_additive_in_the_json_shape() {
        let mut ready = status(true, true, true);
        ready.sandbox_image_remedy = None;
        assert!(serde_json::to_value(&ready).unwrap()["sandbox_image_remedy"].is_null());

        let mut missing = status(true, false, false);
        missing.sandbox_image_remedy = Some("build it".to_owned());
        assert_eq!(
            serde_json::to_value(&missing).unwrap()["sandbox_image_remedy"],
            "build it"
        );
    }

    #[test]
    fn remedy_names_the_build_script_when_the_checkout_has_one() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("scripts")).unwrap();
        std::fs::write(root.path().join("scripts/build-sandbox.sh"), "#!/bin/sh\n").unwrap();

        let remedy = super::sandbox_image_remedy_from(Some(root.path()), "linux/arm64");

        assert!(remedy.contains("scripts/build-sandbox.sh"), "{remedy}");
        assert!(remedy.contains("doctor --build-image"), "{remedy}");
        assert_eq!(remedy.lines().count(), 1, "one line: {remedy}");
    }

    #[test]
    fn remedy_falls_back_to_the_canonical_docker_build_command() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("docker/sandbox")).unwrap();
        std::fs::write(
            root.path().join("docker/sandbox/Dockerfile"),
            "FROM scratch\n",
        )
        .unwrap();

        let remedy = super::sandbox_image_remedy_from(Some(root.path()), "linux/arm64");

        assert!(
            remedy.contains(
                "docker build --platform linux/arm64 -t oxfuzz/fuzz-sandbox:0.2.1 -f docker/sandbox/Dockerfile ."
            ),
            "{remedy}"
        );
        assert!(
            remedy.contains(root.path().to_string_lossy().as_ref()),
            "{remedy}"
        );
    }

    #[test]
    fn remedy_never_names_a_tree_that_cannot_build_the_image() {
        // A tree that has neither the script nor the Dockerfile (e.g. a foreign
        // project bound by the config walk-up) is not a usable build context.
        let root = tempfile::tempdir().unwrap();

        let remedy = super::sandbox_image_remedy_from(Some(root.path()), "linux/arm64");

        assert!(remedy.contains("docker build"), "{remedy}");
        assert!(remedy.contains("oxfuzz source checkout"), "{remedy}");
        assert!(
            !remedy.contains(root.path().to_string_lossy().as_ref()),
            "{remedy}"
        );
        assert!(!remedy.contains("doctor --build-image"), "{remedy}");
    }

    #[test]
    fn remedy_without_a_checkout_names_the_canonical_build_and_its_context() {
        let remedy = super::sandbox_image_remedy_from(None, "linux/amd64");

        assert!(
            remedy.contains("docker build --platform linux/amd64"),
            "{remedy}"
        );
        assert!(remedy.contains("oxfuzz/fuzz-sandbox:0.2.1"), "{remedy}");
        assert!(remedy.contains("docker/sandbox/Dockerfile"), "{remedy}");
        // Without a source checkout the CLI build has nothing to run.
        assert!(!remedy.contains("doctor --build-image"), "{remedy}");
    }

    #[test]
    fn build_preflight_fails_loud_in_probe_order() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("docker/sandbox")).unwrap();
        std::fs::write(
            root.path().join("docker/sandbox/Dockerfile"),
            "FROM scratch\n",
        )
        .unwrap();
        let bare = tempfile::tempdir().unwrap();

        let disabled = super::build_preflight(false, true, true, Some(root.path())).unwrap_err();
        assert!(disabled.to_string().contains("HF_USE_DOCKER"), "{disabled}");

        let no_cli = super::build_preflight(true, false, true, Some(root.path())).unwrap_err();
        assert!(no_cli.to_string().contains("Docker CLI"), "{no_cli}");

        let no_daemon = super::build_preflight(true, true, false, Some(root.path())).unwrap_err();
        assert!(no_daemon.to_string().contains("not running"), "{no_daemon}");

        let no_root = super::build_preflight(true, true, true, None).unwrap_err();
        assert!(no_root.to_string().contains("source checkout"), "{no_root}");

        let no_dockerfile =
            super::build_preflight(true, true, true, Some(bare.path())).unwrap_err();
        assert!(
            no_dockerfile
                .to_string()
                .contains("docker/sandbox/Dockerfile"),
            "{no_dockerfile}"
        );

        let resolved = super::build_preflight(true, true, true, Some(root.path())).unwrap();
        assert_eq!(resolved, root.path());
    }

    #[test]
    fn fuzzing_readiness_requires_docker_image_and_an_engine() {
        assert!(status(true, true, true).fuzzing_ready());
        assert!(!status(false, true, true).fuzzing_ready());
        assert!(!status(true, false, true).fuzzing_ready());
        assert!(!status(true, true, false).fuzzing_ready());
    }

    #[test]
    fn runtime_and_readiness_share_the_docker_enablement_decision() {
        assert!(docker_runtime_enabled_from(None));
        assert!(docker_runtime_enabled_from(Some("1")));
        assert!(docker_runtime_enabled_from(Some("true")));
        assert!(!docker_runtime_enabled_from(Some("0")));
        assert!(!docker_runtime_enabled_from(Some("false")));
    }
    #[test]
    fn selected_preflight_refuses_missing_requested_engine_even_if_another_is_ready() {
        let report = super::assess_fuzzing_preflight(
            status(true, true, true),
            hf_core::engine::EngineKind::Honggfuzz,
            Some(true),
            Ok(()),
        );
        assert!(!report.ready);
        assert!(report
            .problems
            .iter()
            .any(|problem| problem.contains("honggfuzz")));
    }

    #[test]
    fn selected_preflight_names_policy_provider_and_sandbox_failures() {
        let report = super::assess_fuzzing_preflight(
            status(false, false, false),
            hf_core::engine::EngineKind::LibFuzzer,
            Some(false),
            Err("engine disabled by policy".to_owned()),
        );
        assert!(!report.ready);
        for expected in ["Docker", "image", "provider", "engine disabled by policy"] {
            assert!(
                report
                    .problems
                    .iter()
                    .any(|problem| problem.contains(expected)),
                "missing problem: {expected}"
            );
        }
    }

    #[test]
    fn selected_preflight_does_not_require_an_unrequested_provider() {
        for configured in [None, Some(true)] {
            let report = super::assess_fuzzing_preflight(
                status(true, true, true),
                hf_core::engine::EngineKind::LibFuzzer,
                configured,
                Ok(()),
            );
            assert!(report.ready);
            assert!(report.problems.is_empty());
            assert_eq!(report.provider_configured, configured);
        }
        let report = super::assess_fuzzing_preflight(
            status(true, true, true),
            hf_core::engine::EngineKind::LibFuzzer,
            Some(false),
            Ok(()),
        );
        assert!(!report.ready);
    }
}
