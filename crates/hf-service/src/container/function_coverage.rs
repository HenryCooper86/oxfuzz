//! Source-function evidence from the exact campaign binary and its raw profiles.

use hf_core::error::ClassifiedError;
use uuid::Uuid;

use super::ServiceContainer;

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
}

#[cfg(feature = "proof-carrying")]
mod collection {
    use super::{ClassifiedError, ServiceContainer};
    use crate::container::staging::RunArtifacts;
    use hf_core::{
        engine::FuzzRunConfig,
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
            config.env.push((
                "LLVM_PROFILE_FILE".to_owned(),
                if smoke {
                    "/tmp/oxfuzz-smoke-%m.profraw"
                } else {
                    PROFILE_FILE
                }
                .to_owned(),
            ));
        }
    }

    fn requested(config: &FuzzRunConfig) -> bool {
        config
            .env
            .iter()
            .any(|(key, value)| key == "LLVM_PROFILE_FILE" && value == PROFILE_FILE)
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
            let mut merge = vec![
                "llvm-profdata".to_owned(),
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
                "llvm-cov export \"$1\" -instr-profile=\"$2\" > \"$3\"".to_owned(),
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
pub(super) use collection::{configure, prepare};
#[cfg(feature = "proof-carrying")]
pub(super) const PROFILE_FLAGS: [&str; 3] = collection::FLAGS;
