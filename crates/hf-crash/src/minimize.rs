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
        // `binary -minimize_crash=1 -exact_artifact_path=<output> <crash>`:
        // libFuzzer takes the crash file as a positional argument and writes the
        // minimized result to `-exact_artifact_path`. `-runs` bounds the search
        // so a stubborn crash cannot minimize forever.
        EngineKind::LibFuzzer => Some(vec![
            binary.to_owned(),
            "-minimize_crash=1".to_owned(),
            "-runs=10000".to_owned(),
            format!("-exact_artifact_path={output}"),
            crash_input.to_owned(),
        ]),
        // `afl-tmin -i <crash> -o <output> -- <binary> @@`: the instrumented
        // target and its `@@` file-argument placeholder must follow `--`, or
        // afl-tmin has no program to run.
        EngineKind::AflPlusPlus => Some(vec![
            "afl-tmin".to_owned(),
            "-i".to_owned(),
            crash_input.to_owned(),
            "-o".to_owned(),
            output.to_owned(),
            "--".to_owned(),
            binary.to_owned(),
            "@@".to_owned(),
        ]),
        // No built-in raw-binary minimizer for these engines:
        // - ClusterFuzzLite is driven through `infra/helper.py` (see
        //   `hf_engine::clusterfuzzlite`), not a raw libFuzzer binary, so the
        //   `binary -minimize_crash=1` form does not apply; minimization goes
        //   through oss-fuzz tooling (`helper.py reproduce`).
        // - honggfuzz has no inline minimizer.
        // - syzkaller uses `syz-repro` on the crash log, driven separately from
        //   a harness binary.
        EngineKind::ClusterFuzzLite | EngineKind::Honggfuzz | EngineKind::Syzkaller => None,
    }
}
