use serde::{Deserialize, Serialize};

/// Configurable byte budgets for successful and failed HTTP response bodies.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RawLimits")]
pub struct ResponseBodyLimitsConfig {
    /// Maximum successful response bytes, before text or JSON decoding.
    pub success_bytes: usize,
    /// Maximum failed response bytes, before text or JSON decoding.
    pub error_bytes: usize,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLimits {
    success_bytes: usize,
    error_bytes: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            success_bytes: 16 * 1024 * 1024,
            error_bytes: 64 * 1024,
        }
    }
}

impl Default for ResponseBodyLimitsConfig {
    fn default() -> Self {
        let raw = RawLimits::default();
        Self {
            success_bytes: raw.success_bytes,
            error_bytes: raw.error_bytes,
        }
    }
}

impl TryFrom<RawLimits> for ResponseBodyLimitsConfig {
    type Error = String;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        let config = Self {
            success_bytes: raw.success_bytes,
            error_bytes: raw.error_bytes,
        };
        config.resolve()?;
        Ok(config)
    }
}

/// Immutable, validated response byte budgets passed to receive operations.
#[derive(Debug, Clone, Copy)]
pub struct ResponseBodyLimits {
    success_bytes: usize,
    error_bytes: usize,
}

impl ResponseBodyLimitsConfig {
    /// Resolve configuration before constructing an HTTP adapter.
    ///
    /// # Errors
    /// Rejects zero or excessive budgets, including values set by typed callers.
    pub fn resolve(self) -> Result<ResponseBodyLimits, String> {
        for (name, value, ceiling) in [
            ("success_bytes", self.success_bytes, 256 * 1024 * 1024),
            ("error_bytes", self.error_bytes, 1024 * 1024),
        ] {
            if value == 0 || value > ceiling {
                return Err(format!("response body {name} must be within 1..={ceiling}"));
            }
        }
        Ok(ResponseBodyLimits {
            success_bytes: self.success_bytes,
            error_bytes: self.error_bytes,
        })
    }
}

impl ResponseBodyLimits {
    /// Budget for a successful HTTP response.
    #[must_use]
    pub const fn success_bytes(self) -> usize {
        self.success_bytes
    }

    /// Budget for an HTTP error response.
    #[must_use]
    pub const fn error_bytes(self) -> usize {
        self.error_bytes
    }
}
