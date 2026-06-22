//! AFL++ engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::{BuildArtifact, EngineKind, FuzzRunConfig};

/// Construct the `afl-fuzz` argument list for a fuzz run.
///
/// Returns the full command tail: `["afl-fuzz", "-i", corpus, "-o", out, ...]`.
/// The caller (`EngineRunner`) wraps this in a `docker run` invocation.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![
        "afl-fuzz".to_owned(),
        "-i".to_owned(),
        corpus.to_owned(),
        "-o".to_owned(),
        out.to_owned(),
    ];
    if duration > 0 {
        args.push("-V".to_owned());
        args.push(duration.to_string());
    }
    // Env vars as AFL_ prefixed options are set by the runtime; we pass them
    // as `--env` equivalents via the command environment. Here we emit them
    // as a leading `env` command so the docker exec applies them.
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    // Extra args (e.g. -dict=...).
    args.extend(cfg.extra_args.iter().cloned());
    // The binary to fuzz.
    args.push("--".to_owned());
    args.push(binary.to_owned());
    args
}

/// The AFL++ engine adapter (stub for the `FuzzEngine` trait).
pub struct AflPlusPlus;

impl AflPlusPlus {
    #[must_use]
    pub const fn kind() -> EngineKind {
        EngineKind::AflPlusPlus
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
use uuid::Uuid;

#[async_trait]
impl FuzzEngine for AflPlusPlus {
    fn kind(&self) -> EngineKind {
        EngineKind::AflPlusPlus
    }

    fn supports(&self, lang: TargetLanguage, _san: Sanitizer) -> bool {
        matches!(lang, TargetLanguage::C | TargetLanguage::Cpp)
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "afl build: not implemented".to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "afl run: not implemented".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "afl minimize: not implemented".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "afl coverage: not implemented".to_owned(),
        ))
    }
}

#[allow(dead_code)]
fn _ensure_uuid_used(_u: Uuid) {}
