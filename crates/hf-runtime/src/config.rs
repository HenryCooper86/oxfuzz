//! Runtime configuration.

use hf_core::runtime::ResourceLimits;
use std::collections::HashMap;

/// Which backend the runtime uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackend {
    Docker,
    Native,
}

/// Configuration for the sandbox runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub backend: RuntimeBackend,
    pub image: String,
    pub container_workspace: String,
    pub default_limits: ResourceLimits,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend: RuntimeBackend::Docker,
            image: "hobot/fuzz-sandbox:latest".to_owned(),
            container_workspace: "/work".to_owned(),
            default_limits: ResourceLimits {
                max_mem_mb: 4096,
                max_cpus: 2,
                max_duration_secs: 7200,
                env: HashMap::new(),
            },
        }
    }
}
