//! libFuzzer engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::{BuildArtifact, EngineKind, FuzzRunConfig};

/// Construct the libFuzzer argument list for a fuzz run.
///
/// libFuzzer runs the harness binary directly (no separate `fuzz` binary),
/// so the first element is the harness binary path itself.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![binary.to_owned()];
    if duration > 0 {
        args.push(format!("-max_total_time={duration}"));
    }
    // libFuzzer writes crashes to the corpus dir by default; use -artifact_prefix
    // to direct them to the out dir.
    args.push(format!("-artifact_prefix={out}"));
    args.push(corpus.to_owned());
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    args.extend(cfg.extra_args.iter().cloned());
    args
}

/// The libFuzzer engine adapter (stub for the `FuzzEngine` trait).
pub struct LibFuzzer;

impl LibFuzzer {
    #[must_use]
    pub const fn kind() -> EngineKind {
        EngineKind::LibFuzzer
    }
}

use async_trait::async_trait;
use hf_core::coverage::CoverageReport;
use hf_core::crash::Crash;
use hf_core::engine::{FuzzEngine, FuzzRunHandle};
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetLanguage};

#[async_trait]
impl FuzzEngine for LibFuzzer {
    fn kind(&self) -> EngineKind {
        EngineKind::LibFuzzer
    }

    fn supports(&self, lang: TargetLanguage, _san: Sanitizer) -> bool {
        matches!(
            lang,
            TargetLanguage::C | TargetLanguage::Cpp | TargetLanguage::Rust
        )
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "libfuzzer build: not implemented".to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "libfuzzer run: not implemented".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "libfuzzer minimize: not implemented".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "libfuzzer coverage: not implemented".to_owned(),
        ))
    }
}
