//! Engine registry: maps `EngineKind` -> adapter instance.

use hf_core::engine::EngineKind;
use std::collections::HashMap;

/// A registry of engine adapters (stub).
pub struct EngineRegistry {
    #[allow(dead_code)]
    builders: HashMap<EngineKind, fn()>,
}

impl EngineRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            builders: HashMap::new(),
        }
    }
}

impl Default for EngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}
