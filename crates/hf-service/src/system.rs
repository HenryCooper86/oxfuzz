//! System health/status probes shared by GUI and web presentation layers.

use serde::{Serialize, Serializer};

/// A boolean status flag that serializes as a JSON boolean.
#[derive(Debug, Clone, Copy)]
pub struct StatusFlag(bool);

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
    /// `ClusterFuzzLite` tooling is present in the sandbox image.
    pub clusterfuzzlite: StatusFlag,
    /// syzkaller tooling is present in the sandbox image.
    pub syzkaller: StatusFlag,
}

/// Compute the current system status by probing Docker and the sandbox image.
#[must_use]
pub fn system_status() -> SystemStatus {
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
        libfuzzer: engines.libfuzzer.into(),
        aflplusplus: engines.aflplusplus.into(),
        honggfuzz: engines.honggfuzz.into(),
        clusterfuzzlite: engines.clusterfuzzlite.into(),
        syzkaller: engines.syzkaller.into(),
    }
}
