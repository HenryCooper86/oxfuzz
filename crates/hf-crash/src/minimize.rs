//! Minimization command construction.

use hf_core::engine::EngineKind;

/// Construct the minimization command args for an engine.
///
/// Returns `None` if the engine has no built-in minimizer.
#[must_use]
pub fn build_minimize_args(
    engine: EngineKind,
    binary: &str,
    crash_input: &str,
    output: &str,
) -> Option<Vec<String>> {
    match engine {
        EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite => Some(vec![
            binary.to_owned(),
            "-minimize_crash=1".to_owned(),
            format!("-exact_artifact_path={crash_input}"),
            format!("-artifact_prefix={output}"),
        ]),
        EngineKind::AflPlusPlus => Some(vec![
            "afl-tmin".to_owned(),
            "-i".to_owned(),
            crash_input.to_owned(),
            "-o".to_owned(),
            output.to_owned(),
        ]),
        EngineKind::Honggfuzz => None,
    }
}
