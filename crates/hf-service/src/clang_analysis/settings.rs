//! Validated deployment limits for optional Clang analysis.
use hf_core::clang_analysis::ClangLimits;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deployment choices resolved before operation admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClangAnalysisSettings {
    /// Accepted range: 1 through 64.
    pub max_targets: usize,
    /// Accepted range: 1 through 10000.
    pub max_translation_units: usize,
    /// Accepted range: 1 through 1073741824.
    pub max_snapshot_bytes: u64,
    /// Accepted range: 1 through 67108864.
    pub max_output_bytes: usize,
    /// Accepted range: 1 through 500000.
    pub max_functions: usize,
    /// Accepted range: 1 through 2000000.
    pub max_calls: usize,
    /// Accepted range: 1 through 3600.
    pub timeout_secs: u64,
    /// Accepted range: 128 through 16384.
    pub memory_mb: u64,
    /// Accepted range: 1 through 8.
    pub cpus: u32,
    /// Accepted range: 1024 through 65536.
    pub max_context_bytes: usize,
    /// Bundled analyzer image used without a saved build profile.
    pub image: String,
    /// Optional project-relative linked-program manifest.
    pub scope_file: Option<PathBuf>,
}
impl Default for ClangAnalysisSettings {
    fn default() -> Self {
        Self {
            max_targets: 16,
            max_translation_units: 1024,
            max_snapshot_bytes: 268_435_456,
            max_output_bytes: 16_777_216,
            max_functions: 100_000,
            max_calls: 500_000,
            timeout_secs: 600,
            memory_mb: 2048,
            cpus: 1,
            max_context_bytes: 16_384,
            image: hf_runtime::SANDBOX_IMAGE.to_owned(),
            scope_file: None,
        }
    }
}
impl ClangAnalysisSettings {
    /// Resolve validated settings into an explicit operation budget.
    ///
    /// # Errors
    /// Rejects out-of-range settings or unsafe manifest paths.
    pub fn resolve(&self) -> Result<ClangLimits, String> {
        if !(1..=64).contains(&self.max_targets) {
            return Err("clang_analysis.max_targets is outside its accepted range".into());
        }
        if !(1..=10_000).contains(&self.max_translation_units) {
            return Err(
                "clang_analysis.max_translation_units is outside its accepted range".into(),
            );
        }
        if !(1..=1_073_741_824).contains(&self.max_snapshot_bytes) {
            return Err("clang_analysis.max_snapshot_bytes is outside its accepted range".into());
        }
        if !(1..=67_108_864).contains(&self.max_output_bytes) {
            return Err("clang_analysis.max_output_bytes is outside its accepted range".into());
        }
        if !(1..=500_000).contains(&self.max_functions) {
            return Err("clang_analysis.max_functions is outside its accepted range".into());
        }
        if !(1..=2_000_000).contains(&self.max_calls) {
            return Err("clang_analysis.max_calls is outside its accepted range".into());
        }
        if !(1..=3600).contains(&self.timeout_secs) {
            return Err("clang_analysis.timeout_secs is outside its accepted range".into());
        }
        if !(128..=16_384).contains(&self.memory_mb) {
            return Err("clang_analysis.memory_mb is outside its accepted range".into());
        }
        if !(1..=8).contains(&self.cpus) {
            return Err("clang_analysis.cpus is outside its accepted range".into());
        }
        if !(1024..=65_536).contains(&self.max_context_bytes) {
            return Err("clang_analysis.max_context_bytes is outside its accepted range".into());
        }
        if self.image.is_empty()
            || self.image.len() > 256
            || self.image.starts_with('-')
            || self.image.chars().any(char::is_whitespace)
        {
            return Err("invalid Clang analysis image".into());
        }
        if let Some(path) = &self.scope_file {
            if !path
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
                || path.as_os_str().is_empty()
            {
                return Err("clang_analysis.scope_file must be a relative project file".into());
            }
        }
        Ok(ClangLimits {
            max_targets: self.max_targets,
            max_translation_units: self.max_translation_units,
            max_snapshot_bytes: self.max_snapshot_bytes,
            max_output_bytes: self.max_output_bytes,
            max_functions: self.max_functions,
            max_calls: self.max_calls,
            timeout_secs: self.timeout_secs,
            memory_mb: self.memory_mb,
            cpus: self.cpus,
            max_context_bytes: self.max_context_bytes,
        })
    }
}
