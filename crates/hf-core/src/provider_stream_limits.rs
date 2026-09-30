use serde::{Deserialize, Serialize};

/// Configurable cumulative wire/decoded bytes and per-frame decoded bytes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RawLimits")]
pub struct ResponseStreamLimitsConfig {
    /// Maximum cumulative HTTP stream bytes.
    pub wire_bytes: usize,
    /// Maximum cumulative decoded UTF-8 bytes, including replacement characters.
    pub decoded_bytes: usize,
    /// Maximum unfinished frame bytes, including framing and incomplete UTF-8.
    pub frame_bytes: usize,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLimits {
    wire_bytes: usize,
    decoded_bytes: usize,
    frame_bytes: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            wire_bytes: 64 * 1024 * 1024,
            decoded_bytes: 64 * 1024 * 1024,
            frame_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Default for ResponseStreamLimitsConfig {
    fn default() -> Self {
        let raw = RawLimits::default();
        Self {
            wire_bytes: raw.wire_bytes,
            decoded_bytes: raw.decoded_bytes,
            frame_bytes: raw.frame_bytes,
        }
    }
}

impl TryFrom<RawLimits> for ResponseStreamLimitsConfig {
    type Error = String;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        let config = Self {
            wire_bytes: raw.wire_bytes,
            decoded_bytes: raw.decoded_bytes,
            frame_bytes: raw.frame_bytes,
        };
        config.resolve()?;
        Ok(config)
    }
}

/// Immutable validated budgets passed to successful stream receivers.
#[derive(Debug, Clone, Copy)]
pub struct ResponseStreamLimits {
    wire_bytes: usize,
    decoded_bytes: usize,
    frame_bytes: usize,
}

impl ResponseStreamLimitsConfig {
    /// Resolve configuration before constructing a streaming adapter.
    ///
    /// # Errors
    /// Rejects zero or excessive budgets, including values from typed callers.
    pub fn resolve(self) -> Result<ResponseStreamLimits, String> {
        for (name, value, ceiling) in [
            ("wire_bytes", self.wire_bytes, 256 * 1024 * 1024),
            ("decoded_bytes", self.decoded_bytes, 768 * 1024 * 1024),
            ("frame_bytes", self.frame_bytes, 256 * 1024 * 1024),
        ] {
            if value == 0 || value > ceiling {
                return Err(format!(
                    "response stream {name} must be within 1..={ceiling}"
                ));
            }
        }
        Ok(ResponseStreamLimits {
            wire_bytes: self.wire_bytes,
            decoded_bytes: self.decoded_bytes,
            frame_bytes: self.frame_bytes,
        })
    }
}

impl ResponseStreamLimits {
    /// Maximum cumulative HTTP stream bytes.
    #[must_use]
    pub const fn wire_bytes(self) -> usize {
        self.wire_bytes
    }

    /// Maximum cumulative decoded UTF-8 bytes.
    #[must_use]
    pub const fn decoded_bytes(self) -> usize {
        self.decoded_bytes
    }

    /// Maximum unfinished frame bytes.
    #[must_use]
    pub const fn frame_bytes(self) -> usize {
        self.frame_bytes
    }
}

/// The receive operation whose byte allowance was exceeded.
#[derive(Debug, Clone, Copy)]
pub enum ResponseStreamBudget {
    /// Cumulative incoming transport bytes.
    Wire,
    /// Cumulative decoded UTF-8 bytes.
    Decoded,
    /// Decoded unfinished frame bytes and incomplete UTF-8 bytes.
    Frame,
}

impl std::fmt::Display for ResponseStreamBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wire => "wire_bytes",
            Self::Decoded => "decoded_bytes",
            Self::Frame => "frame_bytes",
        })
    }
}
