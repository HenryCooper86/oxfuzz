//! Finite resource allowances for source inspection with Grep.
use serde::{Deserialize, Serialize};

/// Deployment settings resolved before constructing the search tool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RawLimits")]
pub struct GrepLimitsConfig {
    /// Maximum retained result text and filename bytes.
    pub output_bytes: usize,
    /// Maximum searcher reader buffer bytes.
    pub heap_bytes: usize,
    /// Cooperative search timeout in seconds.
    pub timeout_secs: u64,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLimits {
    output_bytes: usize,
    heap_bytes: usize,
    timeout_secs: u64,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            output_bytes: 10_000,
            heap_bytes: 16 * 1024 * 1024,
            timeout_secs: 30,
        }
    }
}

impl Default for GrepLimitsConfig {
    fn default() -> Self {
        let raw = RawLimits::default();
        Self {
            output_bytes: raw.output_bytes,
            heap_bytes: raw.heap_bytes,
            timeout_secs: raw.timeout_secs,
        }
    }
}

impl TryFrom<RawLimits> for GrepLimitsConfig {
    type Error = String;
    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        let config = Self {
            output_bytes: raw.output_bytes,
            heap_bytes: raw.heap_bytes,
            timeout_secs: raw.timeout_secs,
        };
        config.resolve()?;
        Ok(config)
    }
}

/// Immutable validated search allowances.
#[derive(Debug, Clone, Copy)]
pub struct GrepLimits {
    output_bytes: usize,
    heap_bytes: usize,
    timeout_secs: u64,
}

impl GrepLimitsConfig {
    /// Validate and resolve settings at construction.
    ///
    /// # Errors
    /// Rejects zero or excessive allowances.
    pub fn resolve(self) -> Result<GrepLimits, String> {
        for (name, value, ceiling) in [
            ("output_bytes", self.output_bytes as u64, 1024 * 1024),
            ("heap_bytes", self.heap_bytes as u64, 256 * 1024 * 1024),
            ("timeout_secs", self.timeout_secs, 300),
        ] {
            if value == 0 || value > ceiling {
                return Err(format!("grep {name} must be within 1..={ceiling}"));
            }
        }
        Ok(GrepLimits {
            output_bytes: self.output_bytes,
            heap_bytes: self.heap_bytes,
            timeout_secs: self.timeout_secs,
        })
    }
}

impl GrepLimits {
    /// Maximum retained result bytes.
    #[must_use]
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }
    /// Maximum reader buffer bytes.
    #[must_use]
    pub const fn heap_bytes(self) -> usize {
        self.heap_bytes
    }
    /// Cooperative timeout in seconds.
    #[must_use]
    pub const fn timeout_secs(self) -> u64 {
        self.timeout_secs
    }
}
