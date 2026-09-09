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
    }
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
    let policy = crate::config::resolve_fuzzing_run(Some(engine), duration_secs).map(|_| ());
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
        EngineKind::Syzkaller => status.syzkaller,
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
        }
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
