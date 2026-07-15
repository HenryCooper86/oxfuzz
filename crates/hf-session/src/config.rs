//! Session configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the session manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Maximum tree depth for branching sessions.
    #[serde(default = "default_max_depth")]
    pub max_depth: u32,
}

fn default_max_depth() -> u32 {
    10
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_depth: default_max_depth(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SessionConfig::default();
        assert_eq!(config.max_depth, 10);
    }

    #[test]
    fn unsupported_session_knobs_are_rejected() {
        let error =
            toml::from_str::<SessionConfig>("max_depth = 4\ncompaction_threshold_pct = 50\n")
                .expect_err("unsupported session knobs must not silently no-op");

        assert!(error.to_string().contains("compaction_threshold_pct"));
    }
}
