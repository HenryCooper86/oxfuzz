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
    let docker = hf_runtime::docker_daemon_ready();
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

#[cfg(test)]
mod tests {
    use super::{StatusFlag, SystemStatus};

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
}
