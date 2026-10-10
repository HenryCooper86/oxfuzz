//! Source-function evidence from the exact campaign binary and its raw profiles.

use hf_core::error::ClassifiedError;
use uuid::Uuid;

use super::ServiceContainer;

/// Environment variable naming the raw LLVM profile destination.
///
/// The service assigns the value per run -- a campaign's shared profile mount,
/// or the qualification run's own output directory -- so it routes this run's
/// evidence and never describes the experimental setup. The value stays
/// verbatim in the persisted run config (Engineering Protocol 2.13), and the
/// auto-revert comparability check excludes the key through
/// [`super::RUN_SCOPED_ENV_KEYS`].
///
/// The literal is load-bearing: it names a key inside persisted run configs
/// and sealed input manifests, so changing it changes a durable format.
pub(super) const PROFILE_ENV_KEY: &str = "LLVM_PROFILE_FILE";

/// Decimal counters preserve the full LLVM integer range in browser clients.
#[derive(Debug, serde::Serialize)]
pub struct FunctionMeasurement {
    pub name: String,
    pub count: String,
    pub files: Vec<String>,
}

/// Historical function counters, with absence represented explicitly.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RunFunctionCoverage {
    Available {
        run_id: Uuid,
        binary_sha256: String,
        export_sha256: String,
        functions: Vec<FunctionMeasurement>,
        observed_functions: usize,
        /// Interrupted workers may not have flushed their counters.
        limitation: &'static str,
    },
    Unavailable {
        run_id: Uuid,
        reason: &'static str,
    },
}

/// Whether one run's retained profile shows the selected target symbol entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::container) enum TargetEntryEvidence {
    /// The profile carries a positive counter for the target symbol.
    Entered,
    /// The profile was read and the target symbol was never entered.
    NotEntered,
    /// No profile was retained, so entry is unverified rather than absent.
    /// Instrumentation is an operator choice, so an unmeasured run says nothing
    /// about whether the harness reached the target.
    Unverified,
}

/// LLVM reports mangled C++ symbols, so a target is matched by containment.
fn names_target(function: &str, target: &str) -> bool {
    function.contains(target)
}

/// Counters are decimal strings so a browser client keeps the full LLVM range;
/// an unparseable value is not a positive observation.
fn counter_is_positive(count: &str) -> bool {
    count.trim().parse::<u128>().is_ok_and(|value| value > 0)
}

impl ServiceContainer {
    /// Read retained function measurements without rebuilding or executing a harness.
    ///
    /// # Errors
    /// Rejects missing runs, corrupted evidence, and storage failures.
    pub async fn run_function_coverage(
        &self,
        run_id: Uuid,
    ) -> Result<RunFunctionCoverage, ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("function evidence requires persistent storage".to_owned())
        })?;
        if store.get_run(run_id).await?.is_none() {
            return Err(ClassifiedError::Validation(format!(
                "run not found: {run_id}"
            )));
        }
        let Some(record) = store.run_function_coverage(run_id).await? else {
            return Ok(RunFunctionCoverage::Unavailable { run_id, reason: "No exact campaign profile export was retained. Instrument and requalify a C/C++ harness before a new campaign." });
        };
        let functions = hf_coverage::parse_llvm_function_coverage(&record.export_json)
            .map_err(ClassifiedError::Validation)?;
        let observed_functions = functions
            .iter()
            .filter(|function| function.count > 0)
            .count();
        let functions = functions
            .into_iter()
            .map(|function| FunctionMeasurement {
                name: function.name,
                count: function.count.to_string(),
                files: function.files,
            })
            .collect();
        Ok(RunFunctionCoverage::Available { observed_functions, run_id, binary_sha256: record.binary_sha256, export_sha256: record.export_sha256, functions,
            limitation: "Positive counters show observed entry. Zero counters do not prove non-entry: interrupted workers may not flush profiles, and uninstrumented libraries are excluded." })
    }

    /// Whether one run's retained profile shows the selected target entered.
    ///
    /// # Errors
    /// Rejects a missing run or storage failures.
    pub(in crate::container) async fn target_entry_evidence(
        &self,
        target: &str,
        run_id: Uuid,
    ) -> Result<TargetEntryEvidence, ClassifiedError> {
        Ok(match self.run_function_coverage(run_id).await? {
            RunFunctionCoverage::Unavailable { .. } => TargetEntryEvidence::Unverified,
            RunFunctionCoverage::Available { functions, .. } => {
                let entered = functions.iter().any(|function| {
                    names_target(&function.name, target) && counter_is_positive(&function.count)
                });
                if entered {
                    TargetEntryEvidence::Entered
                } else {
                    TargetEntryEvidence::NotEntered
                }
            }
        })
    }
}

#[cfg(feature = "proof-carrying")]
mod collection {
    use super::{ClassifiedError, ServiceContainer, PROFILE_ENV_KEY};
    use crate::container::staging::RunArtifacts;
    use hf_core::{
        engine::{EngineKind, FuzzRunConfig},
        harness::Harness,
        runtime::{CommandTermination, ResourceLimits, SandboxMount, SandboxOptions},
    };
    use std::path::{Path, PathBuf};

    pub(super) const FLAGS: [&str; 3] = [
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
        "-fprofile-update=atomic",
    ];
    const PROFILE_FILE: &str = "/work/function-coverage/%m.profraw";
    const MAX_BYTES: u64 = 8 * 1024 * 1024;

    pub(super) fn profile_tools(
        engine: EngineKind,
    ) -> Result<(&'static str, &'static str), ClassifiedError> {
        match engine {
            EngineKind::AflPlusPlus => Ok(("llvm-profdata-17", "llvm-cov-17")),
            EngineKind::LibFuzzer | EngineKind::Honggfuzz => {
                Ok(("llvm-profdata-18", "llvm-cov-18"))
            }
            EngineKind::Syzkaller => Err(ClassifiedError::Validation(
                "userspace LLVM function profiles are unavailable for syzkaller".to_owned(),
            )),
            // Go's native coverage counters are not LLVM profiles.
            EngineKind::GoNative => Err(ClassifiedError::Validation(
                "userspace LLVM function profiles are unavailable for Go native fuzzing".to_owned(),
            )),
        }
    }

    pub(in crate::container) fn configure(
        config: &mut FuzzRunConfig,
        harness: &Harness,
        smoke: bool,
    ) {
        if FLAGS.iter().all(|flag| {
            harness
                .build_cmd
                .extra_flags
                .iter()
                .any(|value| value == flag)
        }) {
            config
                .env
                .push((PROFILE_ENV_KEY.to_owned(), PROFILE_FILE.to_owned()));
            if !smoke && config.engine == EngineKind::AflPlusPlus {
                config
                    .env
                    .push(("AFL_FUZZER_LOOPCOUNT".to_owned(), "100".to_owned()));
            }
        }
    }

    /// Move this run's raw profile into its own writable output directory.
    ///
    /// A campaign mounts `/work/function-coverage` through [`prepare`], but a
    /// qualification run builds its sandbox in `hf-harness`, which mounts only
    /// the run's output directory writable and keeps the workspace read-only.
    /// Writing under that directory puts the profile on the host at
    /// `function-coverage/raw/`, where [`ServiceContainer::collect_run_function_coverage`]
    /// reads it, and needs no second mount.
    ///
    /// [`prepare`]: Self::prepare
    /// [`ServiceContainer::collect_run_function_coverage`]: super::ServiceContainer::collect_run_function_coverage
    pub(in crate::container) fn relocate_profiles_to_run_output(
        config: &mut FuzzRunConfig,
        output_relative: &Path,
    ) {
        let directory = hf_core::runtime::posix_relative(output_relative);
        let value = format!("/work/{directory}/function-coverage/raw/%m.profraw");
        for (key, existing) in &mut config.env {
            if key == PROFILE_ENV_KEY {
                *existing = value;
                return;
            }
        }
    }

    /// Whether this run asked for raw function profiles, wherever it writes them.
    ///
    /// The directory differs between a campaign and a qualification run, so this
    /// matches on the owned directory rather than on one exact path.
    pub(super) fn requested(config: &FuzzRunConfig) -> bool {
        config
            .env
            .iter()
            .any(|(key, value)| key == PROFILE_ENV_KEY && value.contains("function-coverage"))
    }

    pub(in crate::container) fn stage_input_workspace(
        config: &FuzzRunConfig,
        workspace: &Path,
        historical: bool,
    ) -> Result<(), ClassifiedError> {
        if !requested(config) {
            return Ok(());
        }
        let mountpoint = workspace.join("function-coverage");
        if historical {
            let metadata = std::fs::symlink_metadata(&mountpoint).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "retained function-coverage mountpoint is missing: {error}"
                ))
            })?;
            if !metadata.file_type().is_dir() {
                return Err(ClassifiedError::Validation(
                    "retained function-coverage mountpoint is not a directory".to_owned(),
                ));
            }
            let mut entries = std::fs::read_dir(&mountpoint).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "read retained function-coverage mountpoint: {error}"
                ))
            })?;
            if entries.next().is_some() {
                return Err(ClassifiedError::Validation(
                    "retained function-coverage mountpoint is not empty".to_owned(),
                ));
            }
        } else {
            std::fs::create_dir(&mountpoint).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "reserved function-coverage path cannot be created: {error}"
                ))
            })?;
        }
        Ok(())
    }

    pub(in crate::container) fn prepare(
        config: &FuzzRunConfig,
        artifacts: &RunArtifacts,
        sandbox: &mut SandboxOptions,
    ) -> Result<(), ClassifiedError> {
        if requested(config) {
            let raw = super::super::workspace::ensure_workspace_directory(
                &artifacts.output_host,
                Path::new("function-coverage/raw"),
            )?;
            sandbox
                .extra_mounts
                .push(SandboxMount::writable(raw, "/work/function-coverage"));
        }
        Ok(())
    }

    fn bounded_bytes(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
        use std::io::Read as _;
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            ClassifiedError::Validation(format!("inspect function coverage artifact: {error}"))
        })?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_BYTES {
            return Err(ClassifiedError::Validation(
                "function coverage artifact is not a bounded regular file".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|error| {
                ClassifiedError::Validation(format!("open function coverage artifact: {error}"))
            })?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                ClassifiedError::Validation(format!("read function coverage artifact: {error}"))
            })?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ClassifiedError::Validation(
                "function coverage artifact grew beyond its limit".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn raw_profiles(raw: &Path) -> Result<Vec<PathBuf>, ClassifiedError> {
        let mut profiles = Vec::new();
        for entry in std::fs::read_dir(raw)
            .map_err(|error| ClassifiedError::Validation(format!("read raw profiles: {error}")))?
        {
            let entry = entry.map_err(|error| {
                ClassifiedError::Validation(format!("read raw profile entry: {error}"))
            })?;
            if entry
                .path()
                .extension()
                .is_some_and(|value| value == "profraw")
            {
                let metadata = std::fs::symlink_metadata(entry.path()).map_err(|error| {
                    ClassifiedError::Validation(format!("inspect raw profile: {error}"))
                })?;
                if !metadata.file_type().is_file()
                    || metadata.len() > MAX_BYTES
                    || profiles.len() >= 256
                {
                    return Err(ClassifiedError::Validation(
                        "raw profile inputs exceed the bounded regular-file policy".to_owned(),
                    ));
                }
                profiles.push(entry.path());
            }
        }
        profiles.sort();
        if profiles.is_empty() {
            return Err(ClassifiedError::Validation(
                "no raw function profile was flushed by this campaign".to_owned(),
            ));
        }
        Ok(profiles)
    }

    impl ServiceContainer {
        pub(in crate::container) async fn close_function_coverage(
            &self,
            record: &hf_storage::RunRecord,
            artifacts: &RunArtifacts,
            cancel: &tokio_util::sync::CancellationToken,
        ) {
            if let Err(error) = self
                .collect_run_function_coverage(record, artifacts, cancel)
                .await
            {
                self.run_journal.note(
                    record.id,
                    "function_coverage_unavailable",
                    &error.to_string(),
                );
                tracing::warn!(run_id = %record.id, %error, "campaign function coverage is unavailable");
            }
        }

        pub(in crate::container) async fn collect_run_function_coverage(
            &self,
            record: &hf_storage::RunRecord,
            artifacts: &RunArtifacts,
            cancel: &tokio_util::sync::CancellationToken,
        ) -> Result<(), ClassifiedError> {
            use sha2::{Digest, Sha256};

            let Some(config) = record.config.as_ref().filter(|config| requested(config)) else {
                return Ok(());
            };
            let image = super::super::retained_inputs::verify(&artifacts.input_host, config)?;
            let raw = super::super::workspace::resolve_workspace_directory(
                &artifacts.output_host,
                Path::new("function-coverage/raw"),
            )?;
            let profiles = raw_profiles(&raw)?;
            let output = super::super::workspace::ensure_workspace_directory(
                &artifacts.output_host,
                Path::new("function-coverage/export"),
            )?;
            let options = SandboxOptions {
                image: Some(image),
                workspace_read_only: true,
                max_file_size_bytes: Some(MAX_BYTES),
                extra_mounts: vec![
                    SandboxMount::read_only(raw, "/profiles/input"),
                    SandboxMount::writable(output.clone(), "/profiles/output"),
                    SandboxMount::read_only(
                        artifacts.input_host.clone(),
                        format!("/work/runs/{}/input", record.id),
                    ),
                ],
                ..SandboxOptions::default()
            };
            let limits = ResourceLimits {
                max_mem_mb: config.max_mem_mb,
                max_cpus: config.max_cpus,
                max_duration_secs: 120,
                env: std::collections::HashMap::new(),
                ptrace: false,
            };
            let (profdata, cov) = profile_tools(record.engine)?;
            let mut merge = vec![
                profdata.to_owned(),
                "merge".to_owned(),
                "-sparse".to_owned(),
            ];
            for profile in profiles {
                let name = profile
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ClassifiedError::Validation("raw profile filename is not UTF-8".to_owned())
                    })?;
                merge.push(format!("/profiles/input/{name}"));
            }
            merge.extend([
                "-o".to_owned(),
                "/profiles/output/merged.profdata".to_owned(),
            ]);
            let export = vec![
                "sh".to_owned(),
                "-c".to_owned(),
                format!("{cov} export \"$1\" -instr-profile=\"$2\" > \"$3\""),
                "oxfuzz-coverage".to_owned(),
                artifacts.binary_container.clone(),
                "/profiles/output/merged.profdata".to_owned(),
                "/profiles/output/export.json".to_owned(),
            ];
            for command in [merge, export] {
                let result = self
                    .runtime
                    .run_command_streaming_opts(
                        &command,
                        &artifacts.input_host.join("workspace"),
                        &limits,
                        &options,
                        cancel,
                        &|_| {},
                    )
                    .await?;
                if result.termination != CommandTermination::Completed || result.exit_code != 0 {
                    return Err(ClassifiedError::Validation(format!(
                        "function coverage tool failed with exit {}: {}",
                        result.exit_code,
                        result.stderr.chars().take(1024).collect::<String>()
                    )));
                }
            }
            let indexed = bounded_bytes(&output.join("merged.profdata"))?;
            let exported = bounded_bytes(&output.join("export.json"))?;
            let export_json = String::from_utf8(exported).map_err(|error| {
                ClassifiedError::Validation(format!("function export is not UTF-8: {error}"))
            })?;
            hf_coverage::parse_llvm_function_coverage(&export_json)
                .map_err(ClassifiedError::Validation)?;
            let evidence = hf_storage::RunFunctionCoverageRecord {
                run_id: record.id,
                binary_sha256: artifacts.binary_sha256.clone(),
                sandbox_rev: record.sandbox_rev.clone().ok_or_else(|| {
                    ClassifiedError::Validation("run image identity is missing".to_owned())
                })?,
                profile_sha256: format!("{:x}", Sha256::digest(indexed)),
                export_sha256: format!("{:x}", Sha256::digest(export_json.as_bytes())),
                export_json,
                collected_at: chrono::Utc::now(),
            };
            self.store
                .as_ref()
                .ok_or_else(|| {
                    ClassifiedError::Validation(
                        "function evidence requires persistent storage".to_owned(),
                    )
                })?
                .record_run_function_coverage(&evidence)
                .await?;
            Ok(())
        }
    }
}

#[cfg(feature = "proof-carrying")]
pub(super) use collection::{
    configure, prepare, relocate_profiles_to_run_output, stage_input_workspace,
};
#[cfg(feature = "proof-carrying")]
pub(super) const PROFILE_FLAGS: [&str; 3] = collection::FLAGS;

#[cfg(all(test, feature = "proof-carrying"))]
mod staging_tests {
    use super::collection::{configure, profile_tools, stage_input_workspace, FLAGS};
    use hf_core::{
        engine::{EngineKind, FuzzRunConfig},
        harness::{BuildCommand, Harness, HarnessStatus},
        target::{Sanitizer, TargetLanguage},
    };

    fn config(profile: bool) -> FuzzRunConfig {
        let mut config: FuzzRunConfig = serde_json::from_value(serde_json::json!({
            "harness_id": uuid::Uuid::nil(), "engine": "libfuzzer",
            "duration": {"secs": 1, "nanos": 0}, "max_mem_mb": 512, "max_cpus": 1,
            "seed_corpus": null, "sanitizer": "Address", "env": [], "extra_args": []
        }))
        .unwrap();
        if profile {
            config.env.push((
                "LLVM_PROFILE_FILE".to_owned(),
                "/work/function-coverage/%m.profraw".to_owned(),
            ));
        }
        config
    }

    #[test]
    fn profiled_afl_campaign_bounds_persistent_loop_to_flush_counters() {
        let mut run_config = config(false);
        run_config.engine = EngineKind::AflPlusPlus;
        let harness = Harness {
            id: uuid::Uuid::new_v4(),
            target_id: uuid::Uuid::new_v4(),
            engine: EngineKind::AflPlusPlus,
            source: String::new(),
            language: TargetLanguage::C,
            build_cmd: BuildCommand {
                compiler: "afl-clang-fast".to_owned(),
                args: Vec::new(),
                output: std::path::PathBuf::from("/work/harness"),
                extra_flags: FLAGS.iter().map(|flag| (*flag).to_owned()).collect(),
            },
            sanitizer: Sanitizer::Address,
            status: HarnessStatus::Promoted,
            smoke_run: None,
        };
        configure(&mut run_config, &harness, false);
        assert!(run_config
            .env
            .iter()
            .any(|(key, value)| key == "AFL_FUZZER_LOOPCOUNT" && value == "100"));
        assert!(run_config
            .env
            .iter()
            .any(|(key, _)| key == "LLVM_PROFILE_FILE"));

        let mut smoke = config(false);
        smoke.engine = EngineKind::AflPlusPlus;
        configure(&mut smoke, &harness, true);
        assert!(!smoke
            .env
            .iter()
            .any(|(key, _)| key == "AFL_FUZZER_LOOPCOUNT"));

        let mut unprofiled = config(false);
        unprofiled.engine = EngineKind::AflPlusPlus;
        let mut unprofiled_harness = harness;
        unprofiled_harness.build_cmd.extra_flags.clear();
        configure(&mut unprofiled, &unprofiled_harness, false);
        assert!(!unprofiled
            .env
            .iter()
            .any(|(key, _)| key == "AFL_FUZZER_LOOPCOUNT"));
    }

    #[test]
    fn profile_tools_match_each_engines_compiler_version() {
        assert_eq!(
            profile_tools(EngineKind::AflPlusPlus).unwrap(),
            ("llvm-profdata-17", "llvm-cov-17")
        );
        assert_eq!(
            profile_tools(EngineKind::LibFuzzer).unwrap(),
            ("llvm-profdata-18", "llvm-cov-18")
        );
        assert_eq!(
            profile_tools(EngineKind::Honggfuzz).unwrap(),
            ("llvm-profdata-18", "llvm-cov-18")
        );
    }

    #[test]
    fn new_profile_run_stages_an_empty_mountpoint_before_sealing() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let mut config = config(true);
        stage_input_workspace(&config, &workspace, false).unwrap();
        assert!(workspace.join("function-coverage").is_dir());
        assert_eq!(
            std::fs::read_dir(workspace.join("function-coverage"))
                .unwrap()
                .count(),
            0
        );
        super::super::retained_inputs::seal(root.path(), "image", &mut config).unwrap();
        super::super::retained_inputs::verify(root.path(), &config).unwrap();
        std::fs::remove_dir(workspace.join("function-coverage")).unwrap();
        assert!(super::super::retained_inputs::verify(root.path(), &config).is_err());
    }

    #[test]
    fn new_profile_run_rejects_an_existing_project_path() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("function-coverage");
        std::fs::write(&path, "project data").unwrap();
        let error = stage_input_workspace(&config(true), root.path(), false).unwrap_err();
        assert!(error.to_string().contains("reserved function-coverage"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "project data");
    }

    #[test]
    fn replay_requires_the_retained_empty_mountpoint() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("function-coverage");
        let error = stage_input_workspace(&config(true), root.path(), true).unwrap_err();
        assert!(error.to_string().contains("retained function-coverage"));
        std::fs::create_dir(&path).unwrap();
        stage_input_workspace(&config(true), root.path(), true).unwrap();
        std::fs::write(path.join("unexpected"), "data").unwrap();
        assert!(stage_input_workspace(&config(true), root.path(), true).is_err());
    }

    #[test]
    fn runs_without_profiles_leave_the_workspace_unchanged() {
        let root = tempfile::tempdir().unwrap();
        stage_input_workspace(&config(false), root.path(), false).unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod target_entry_tests {
    use super::{counter_is_positive, names_target};

    #[test]
    fn a_mangled_cpp_symbol_still_names_its_target() {
        // llvm-cov reports the mangled symbol, so equality would never match a
        // C++ target and every C++ harness would look unentered.
        assert!(names_target("_Z11parse_entryPKhm", "parse_entry"));
        assert!(names_target("parse_entry", "parse_entry"));
        assert!(!names_target("parse_entry_extra", "unrelated"));
    }

    #[test]
    fn only_a_parseable_positive_counter_is_an_observation() {
        assert!(counter_is_positive("1"));
        assert!(counter_is_positive(
            "340282366920938463463374607431768211455"
        ));
        // Absence of entry, and values this reader cannot interpret, are both
        // "not observed" rather than a positive observation.
        assert!(!counter_is_positive("0"));
        assert!(!counter_is_positive(""));
        assert!(!counter_is_positive("not-a-number"));
    }
}

#[cfg(all(test, feature = "proof-carrying"))]
mod relocation_tests {
    use super::collection::relocate_profiles_to_run_output;
    use hf_core::engine::{EngineKind, FuzzRunConfig};
    use std::path::Path;
    use uuid::Uuid;

    fn smoked_config() -> FuzzRunConfig {
        FuzzRunConfig {
            harness_id: Uuid::new_v4(),
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(60)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: hf_core::target::Sanitizer::Address,
            env: vec![(
                "LLVM_PROFILE_FILE".to_owned(),
                "/work/function-coverage/%m.profraw".to_owned(),
            )],
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
        }
    }

    fn profile_of(config: &FuzzRunConfig) -> String {
        config
            .env
            .iter()
            .find(|(key, _)| key == "LLVM_PROFILE_FILE")
            .map(|(_, value)| value.clone())
            .expect("the config names a profile file")
    }

    #[test]
    fn a_qualification_profile_moves_under_the_run_output_directory() {
        let mut config = smoked_config();

        relocate_profiles_to_run_output(&mut config, Path::new("runs/abc/out"));

        // The campaign path is unwritable during qualification: the smoke
        // sandbox keeps the workspace read-only and mounts only this directory.
        assert_eq!(
            profile_of(&config),
            "/work/runs/abc/out/function-coverage/raw/%m.profraw"
        );
    }

    #[test]
    fn the_collector_recognizes_a_relocated_profile() {
        let mut config = smoked_config();
        relocate_profiles_to_run_output(&mut config, Path::new("runs/abc/out"));

        // `requested` gates staging and collection, so if it stopped matching a
        // relocated path the run would silently produce no evidence at all.
        assert!(super::collection::requested(&config));
    }

    #[test]
    fn relocation_leaves_a_config_without_a_profile_alone() {
        let mut config = smoked_config();
        config.env.clear();

        relocate_profiles_to_run_output(&mut config, Path::new("runs/abc/out"));

        assert!(config.env.is_empty());
        assert!(!super::collection::requested(&config));
    }
}
