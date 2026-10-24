//! Service lifecycle and immutable staging for native custom mutators.

use super::{staging::RunArtifacts, ServiceContainer};
use hf_core::{
    engine::{EngineKind, FuzzRunConfig},
    error::ClassifiedError,
    harness::{Harness, HarnessStatus},
    mutator::{ManagedMutatorArtifact, MutatorApi},
    target::TargetLanguage,
};
use serde::Serialize;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

/// Exact active revision and its imported native mutator, for all presentations.
#[derive(Debug, Clone, Serialize)]
pub struct ManagedMutatorStatus {
    pub harness_id: Uuid,
    pub engine: EngineKind,
    pub language: TargetLanguage,
    pub status: HarnessStatus,
    pub mutator: Option<ManagedMutatorArtifact>,
    pub source: Option<String>,
}

fn invalid(message: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("managed mutator: {message}"))
}

/// Environment keys only a harness carrying a reviewed custom mutator may set.
///
/// Launch ([`stage`]) and guided review ([`rebind_review_mutator_env`]) must
/// reject the same set, or a baseline carrying `AFL_CUSTOM_MUTATOR_ONLY` (or
/// `AFL_PYTHON_MODULE`) passes review only to be refused when the run
/// launches.
fn requests_absent_plugin_env(config: &FuzzRunConfig) -> bool {
    config.env.iter().any(|(key, _)| {
        matches!(
            key.as_str(),
            hf_engine::managed_mutator::LIBRARY_ENV
                | hf_engine::managed_mutator::DIGEST_ENV
                | hf_engine::managed_mutator::IMAGE_ENV
                | "AFL_CUSTOM_MUTATOR_ONLY"
                | "AFL_PYTHON_MODULE"
        )
    })
}
fn enabled() -> Result<(), ClassifiedError> {
    if cfg!(feature = "managed-mutators") {
        Ok(())
    } else {
        Err(invalid("managed-mutators feature is disabled"))
    }
}

impl ServiceContainer {
    /// Import native source by compiling a new, unpromoted revision of the selected harness.
    pub async fn attach_managed_mutator(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        expected_harness_id: Uuid,
        source: String,
    ) -> Result<ManagedMutatorStatus, ClassifiedError> {
        enabled()?;
        let active = self.active_harness(project, target, engine).await?;
        if active.id != expected_harness_id {
            return Err(invalid(
                "active harness changed; review the selected revision again",
            ));
        }
        let parsed = hf_harness::managed_mutator::inspect(&active.source, engine, active.language)?;
        let base = parsed
            .as_ref()
            .map_or(active.source.as_str(), |source| source.base);
        let composed =
            hf_harness::managed_mutator::compose(base, &source, engine, active.language)?;
        if composed.len() > crate::harness_review::MAX_HARNESS_REVIEW_SOURCE_BYTES {
            return Err(invalid(
                "combined source exceeds the 64 KiB review allowance",
            ));
        }
        let compiled = self
            .harness_compile_with_expected(
                composed,
                project,
                engine,
                target,
                active.language,
                Some(active.sanitizer),
                active.cmplog.is_some(),
                Some(expected_harness_id),
            )
            .await?;
        let harness = self
            .compilation_store()?
            .get_harness(compiled.harness_id)
            .await?
            .ok_or_else(|| invalid("compiled revision disappeared"))?;
        status(harness)
    }

    /// Read active mutator source, immutable identity and retained self-test evidence.
    pub async fn managed_mutator_status(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<ManagedMutatorStatus, ClassifiedError> {
        enabled()?;
        status(self.active_harness(project, target, engine).await?)
    }
}

fn status(harness: Harness) -> Result<ManagedMutatorStatus, ClassifiedError> {
    let source =
        hf_harness::managed_mutator::inspect(&harness.source, harness.engine, harness.language)?
            .map(|source| source.mutator.to_owned());
    Ok(ManagedMutatorStatus {
        harness_id: harness.id,
        engine: harness.engine,
        language: harness.language,
        status: harness.status,
        mutator: harness.custom_mutator,
        source,
    })
}

fn artifact_path(harness: &Harness) -> Result<PathBuf, ClassifiedError> {
    let record = harness
        .custom_mutator
        .as_ref()
        .ok_or_else(|| invalid("missing artifact record"))?;
    let name = Path::new(&record.artifact_name);
    if name.components().count() != 1
        || !name
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid("artifact filename is not one normal component"));
    }
    Ok(harness
        .build_cmd
        .output
        .parent()
        .ok_or_else(|| invalid("compiled target has no workspace"))?
        .join(name))
}

pub(super) fn verify_live(harness: &Harness) -> Result<(), ClassifiedError> {
    if harness.custom_mutator.is_none() {
        if hf_harness::managed_mutator::inspect(&harness.source, harness.engine, harness.language)?
            .is_some()
        {
            return Err(invalid("managed source lacks compiled artifact evidence"));
        }
        return Ok(());
    }
    enabled()?;
    hf_harness::managed_mutator::verify_artifact(harness, &artifact_path(harness)?, None)
}

pub(super) fn verify_image(harness: &Harness, image: Option<&str>) -> Result<(), ClassifiedError> {
    if let Some(record) = &harness.custom_mutator {
        enabled()?;
        if image != Some(record.sandbox_image_id.as_str()) {
            return Err(invalid(
                "execution image differs from the compiled mutator image",
            ));
        }
    }
    Ok(())
}

pub(super) fn require_self_test(harness: &Harness) -> Result<(), ClassifiedError> {
    if let Some(record) = &harness.custom_mutator {
        enabled()?;
        if !record
            .self_test
            .as_ref()
            .is_some_and(|test| test.exit_code == 0 && test.mutation_observed)
        {
            return Err(invalid("native mutation callback has no successful bounded self-test; run smoke qualification"));
        }
    }
    Ok(())
}

/// Stage exact artifacts, replace only managed environment entries, then seal with run inputs.
pub(super) fn stage(
    harness: &Harness,
    artifacts: &RunArtifacts,
    config: &mut FuzzRunConfig,
    image: &str,
    historical: bool,
    qualification: bool,
) -> Result<(), ClassifiedError> {
    let Some(record) = &harness.custom_mutator else {
        if requests_absent_plugin_env(config) {
            return Err(invalid(
                "run environment requests a plugin absent from its reviewed harness",
            ));
        }
        return Ok(());
    };
    enabled()?;
    verify_image(harness, Some(image))?;
    if !qualification {
        require_self_test(harness)?;
    }
    let path = if record.api == MutatorApi::AflPlusPlus {
        let staged = artifacts.input_host.join("harness.mutator.so");
        if !historical {
            let original = artifact_path(harness)?;
            hf_harness::managed_mutator::verify_artifact(harness, &original, Some(image))?;
            std::fs::copy(original, &staged)
                .map_err(|error| invalid(&format!("stage native library: {error}")))?;
        }
        staged
    } else {
        artifacts.binary_host.clone()
    };
    hf_harness::managed_mutator::verify_artifact(harness, &path, Some(image))?;
    if record.api == MutatorApi::AflPlusPlus {
        let keys = [
            hf_engine::managed_mutator::LIBRARY_ENV,
            hf_engine::managed_mutator::DIGEST_ENV,
            hf_engine::managed_mutator::IMAGE_ENV,
            "AFL_CUSTOM_MUTATOR_ONLY",
        ];
        config.env.retain(|(key, _)| !keys.contains(&key.as_str()));
        config.env.extend([
            (
                hf_engine::managed_mutator::LIBRARY_ENV.into(),
                format!(
                    "{}{}",
                    artifacts.binary_container,
                    hf_harness::managed_mutator::LIBRARY_SUFFIX
                ),
            ),
            (
                hf_engine::managed_mutator::DIGEST_ENV.into(),
                record.artifact_sha256.clone(),
            ),
            (
                hf_engine::managed_mutator::IMAGE_ENV.into(),
                record.sandbox_image_id.clone(),
            ),
        ]);
        if qualification {
            config
                .env
                .push(("AFL_CUSTOM_MUTATOR_ONLY".into(), "1".into()));
        }
    }
    Ok(())
}

/// Normalize a run-owned path only for a guided review, retaining digest and image evidence.
#[cfg(feature = "coverage-experiments")]
pub(super) fn normalize_review_paths(config: &mut FuzzRunConfig) {
    for (key, value) in &mut config.env {
        if key == hf_engine::managed_mutator::LIBRARY_ENV {
            *value = "/work/runs/<run>/input/harness.mutator.so".into();
        }
    }
}

/// Re-derive the managed-mutator environment for a guided review from the
/// CURRENT harness record, exactly as [`stage`] will at launch, without
/// staging artifacts. The launch-side rewrite happens after this review binds
/// its digest, so a mutator change between review and launch must not make
/// the two digests diverge by construction.
#[cfg(feature = "coverage-experiments")]
pub(super) fn rebind_review_mutator_env(
    harness: &Harness,
    config: &mut FuzzRunConfig,
) -> Result<(), ClassifiedError> {
    let Some(record) = &harness.custom_mutator else {
        if requests_absent_plugin_env(config) {
            return Err(invalid(
                "run environment requests a plugin absent from its reviewed harness",
            ));
        }
        return Ok(());
    };
    enabled()?;
    if record.api == MutatorApi::AflPlusPlus {
        let keys = [
            hf_engine::managed_mutator::LIBRARY_ENV,
            hf_engine::managed_mutator::DIGEST_ENV,
            hf_engine::managed_mutator::IMAGE_ENV,
            "AFL_CUSTOM_MUTATOR_ONLY",
        ];
        config.env.retain(|(key, _)| !keys.contains(&key.as_str()));
        config.env.extend([
            // The launch side writes a run-specific container path here that
            // `normalize_review_paths` then normalizes; bind that normalized
            // form directly.
            (
                hf_engine::managed_mutator::LIBRARY_ENV.into(),
                "/work/runs/<run>/input/harness.mutator.so".into(),
            ),
            (
                hf_engine::managed_mutator::DIGEST_ENV.into(),
                record.artifact_sha256.clone(),
            ),
            (
                hf_engine::managed_mutator::IMAGE_ENV.into(),
                record.sandbox_image_id.clone(),
            ),
        ]);
    }
    Ok(())
}

#[cfg(test)]
#[cfg(feature = "coverage-experiments")]
mod tests {
    use super::*;
    use hf_core::harness::BuildCommand;
    use std::path::PathBuf;

    fn baseline(env: (&str, &str)) -> (Harness, FuzzRunConfig) {
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            engine: EngineKind::AflPlusPlus,
            source: "int main(void) { return 0; }".to_owned(),
            language: TargetLanguage::C,
            build_cmd: BuildCommand {
                compiler: "clang".to_owned(),
                args: Vec::new(),
                output: PathBuf::from("fuzz_baseline"),
                extra_flags: Vec::new(),
            },
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Promoted,
            smoke_run: None,
            custom_mutator: None,
            cmplog: None,
        };
        let config = FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::AflPlusPlus,
            duration: Some(std::time::Duration::from_secs(60)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: hf_core::target::Sanitizer::Address,
            env: vec![(env.0.to_owned(), env.1.to_owned())],
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
            cmplog: false,
        };
        (harness, config)
    }

    /// A guided review must reject the same plugin-environment keys launch
    /// rejects for a harness with no custom mutator; otherwise a baseline
    /// carrying `AFL_CUSTOM_MUTATOR_ONLY` (or `AFL_PYTHON_MODULE`) sails
    /// through review only to be refused when the run launches.
    #[test]
    fn review_rejects_plugin_env_for_a_harness_without_a_custom_mutator() {
        for key in ["AFL_CUSTOM_MUTATOR_ONLY", "AFL_PYTHON_MODULE"] {
            let (harness, mut config) = baseline((key, "1"));
            let error = rebind_review_mutator_env(&harness, &mut config).unwrap_err();
            assert!(
                error.to_string().contains("plugin absent"),
                "review must reject {key} like launch: {error}"
            );
        }
    }
}
