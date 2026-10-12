//! Fuzzing harness model.
//!
//! See `docs/standards/HARNESS_STANDARD.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::engine::EngineKind;
use crate::target::{Sanitizer, TargetLanguage};

/// The status of a harness in the generation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HarnessStatus {
    Draft,
    Compiled,
    SmokePassed,
    Promoted,
    Failed,
}

/// A build command for a harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCommand {
    pub compiler: String,
    pub args: Vec<String>,
    pub output: PathBuf,
    /// Project-derived compile flags (include directories, defines, language
    /// standard), already validated by `hf_discovery::build_context` and
    /// expressed as container-internal paths. Empty when the project ships no
    /// compile database.
    ///
    /// Carried on the build command rather than passed alongside it so the
    /// flags a harness was built with travel with the harness record.
    #[serde(default)]
    pub extra_flags: Vec<String>,
}

/// Summary of a smoke fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeRunSummary {
    pub duration_secs: u64,
    pub execs_per_sec: f64,
    pub crashes: u32,
    pub passed: bool,
    /// Full SHA-256 of the exact harness source exercised by this smoke run.
    #[serde(default)]
    pub source_sha256: Option<String>,
    /// Full SHA-256 of the exact executable exercised by this smoke run.
    #[serde(default)]
    pub binary_sha256: Option<String>,
    /// Persisted run that owns the qualification evidence.
    #[serde(default)]
    pub run_id: Option<Uuid>,
}

/// A generated fuzzing harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Harness {
    pub id: Uuid,
    pub target_id: Uuid,
    pub engine: EngineKind,
    pub source: String,
    pub language: TargetLanguage,
    pub build_cmd: BuildCommand,
    pub sanitizer: Sanitizer,
    pub status: HarnessStatus,
    pub smoke_run: Option<SmokeRunSummary>,
    /// The AFL++ `CmpLog` companion build recorded for this revision when it was
    /// compiled with `--cmplog`; absent on revisions built without one (and on
    /// every record persisted before `CmpLog` existed). See
    /// `docs/standards/ENGINE_ADAPTER_STANDARD.md` (`CmpLog` section).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmplog: Option<CmpLogCompanion>,
}

/// The recorded AFL++ `CmpLog` companion build of a harness revision.
///
/// The companion is the same harness source compiled by the same
/// afl-clang-fast driver with the same sanitizer flags, differing from the
/// main build only in the `AFL_LLVM_CMPLOG=1` compile-time environment (the
/// definition of a `CmpLog` build) and the output name (`<main
/// output>.cmplog`). afl-fuzz learns about the companion through `-c` and runs
/// redqueen input-to-state solving over it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmpLogCompanion {
    /// The companion's build invocation. Its `output` names the companion
    /// binary next to the main harness binary in the target workspace.
    pub build_cmd: BuildCommand,
    /// Full SHA-256 of the compiled companion binary, recorded at build time
    /// so a `CmpLog` run stages exactly the reviewed build. `None` only in the
    /// in-memory record between construction and a successful compile; a
    /// persisted revision always carries the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
}

/// An in-progress harness draft before compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessDraft {
    pub target_id: Uuid,
    pub engine: EngineKind,
    pub source: String,
    pub rationale: String,
    /// The command that will build this draft. Carried on the draft so every
    /// presentation layer shows the same command instead of re-deriving it (and
    /// drifting from) the harness naming convention.
    pub build_cmd: BuildCommand,
    /// Which generator produced [`HarnessDraft::source`].
    ///
    /// Recorded rather than inferred: the two generators produce materially
    /// different harnesses, and an operator who asked for the model's needs to
    /// know when a fallback answered instead. Defaults so drafts stored before
    /// this field existed still decode.
    #[serde(default)]
    pub generator: DraftGenerator,
}

/// Which generator wrote a harness draft.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftGenerator {
    /// An LLM wrote it.
    Llm,
    /// The built-in template wrote it: signature-driven, no model involved.
    #[default]
    Heuristic,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness(cmplog: Option<CmpLogCompanion>) -> Harness {
        Harness {
            id: Uuid::nil(),
            target_id: Uuid::nil(),
            engine: EngineKind::AflPlusPlus,
            source: "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}".to_owned(),
            language: TargetLanguage::C,
            build_cmd: BuildCommand {
                compiler: "afl-clang-fast".to_owned(),
                args: vec!["-fsanitize=fuzzer".to_owned()],
                output: PathBuf::from("fuzz_t"),
                extra_flags: Vec::new(),
            },
            sanitizer: Sanitizer::Address,
            status: HarnessStatus::Compiled,
            smoke_run: None,
            cmplog,
        }
    }

    #[test]
    fn harness_cmplog_is_absent_on_the_wire_without_a_companion() {
        // Harness records persisted before CmpLog existed carry no `cmplog`
        // key; they must decode unchanged and re-encode identically.
        let harness = harness(None);
        let encoded = serde_json::to_value(&harness).unwrap();
        assert!(encoded.get("cmplog").is_none(), "{encoded}");
        let restored: Harness = serde_json::from_value(encoded).unwrap();
        assert!(restored.cmplog.is_none());
    }

    #[test]
    fn harness_cmplog_round_trips_the_companion_record() {
        let companion = CmpLogCompanion {
            build_cmd: BuildCommand {
                compiler: "afl-clang-fast".to_owned(),
                args: vec!["-fsanitize=fuzzer".to_owned()],
                output: PathBuf::from("fuzz_t.cmplog"),
                extra_flags: vec!["-DHAVE_CONFIG_H=1".to_owned()],
            },
            binary_sha256: Some("ab".repeat(32)),
        };
        let harness = harness(Some(companion));
        let encoded = serde_json::to_value(&harness).unwrap();
        assert_eq!(
            encoded["cmplog"]["build_cmd"]["output"],
            serde_json::json!("fuzz_t.cmplog")
        );
        assert_eq!(
            encoded["cmplog"]["binary_sha256"],
            serde_json::json!("ab".repeat(32))
        );
        let restored: Harness = serde_json::from_value(encoded).unwrap();
        let companion = restored.cmplog.expect("companion record");
        assert_eq!(companion.build_cmd.compiler, "afl-clang-fast");
        assert_eq!(
            companion.build_cmd.extra_flags,
            ["-DHAVE_CONFIG_H=1".to_owned()]
        );
        assert_eq!(
            companion.binary_sha256.as_deref(),
            Some(&"ab".repeat(32)[..])
        );
    }
}
