//! Gathering for the Harness Work Order.
//!
//! The packet itself is pure (`crate::harness_work_order`); this reads the
//! discovery candidate, the resolved compile context, a bounded source
//! excerpt, and any retained corpus entries worth seeding from.
//!
//! Calls no provider, performs no build, and starts no process.

use std::path::Path;

use hf_core::build::BuildContext;
use hf_core::engine::EngineKind;
use hf_core::target::{TargetCandidate, TargetLanguage};
use sha2::Digest;

use crate::container::ServiceContainer;
use crate::harness_work_order::{
    build_work_order, HarnessWorkOrder, HarnessWorkOrderPayload, WorkOrderCompileContext,
    WorkOrderSeedReference, WorkOrderSourceEvidence, WorkOrderStep, WorkOrderTargetEvidence,
    MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES, MAX_WORK_ORDER_SOURCE_EXCERPT_LINES,
};
use crate::ClassifiedError;

/// Source lines carried around the candidate's definition.
///
/// The declaration plus body is what an author needs; the whole file is
/// unbounded and comes from an untrusted project.
/// Largest source file read for an excerpt. A project under test is untrusted
/// input, so the read is bounded rather than trusting the file to be sane.
const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

impl ServiceContainer {
    /// Assemble the provider-free authoring packet for one candidate.
    ///
    /// # Errors
    /// Returns a discovery error, or `ClassifiedError::Validation` when the
    /// target is unknown.
    pub async fn harness_work_order(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
        engine: EngineKind,
    ) -> Result<HarnessWorkOrder, ClassifiedError> {
        super::require_fuzzing_harness_engine(engine, lang)?;
        let inventory = self.discover(project, lang).await?;
        let candidate = inventory
            .candidates
            .iter()
            .find(|candidate| candidate.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?;

        // A present-but-broken compile database is a configuration fault the
        // operator must see; an absent one is stated in the packet.
        let build_context = self
            .resolve_build_context(project)
            .unwrap_or_default()
            .unwrap_or_else(empty_build_context);

        let payload = HarnessWorkOrderPayload {
            target: WorkOrderTargetEvidence {
                symbol: candidate.symbol.clone(),
                signature: candidate.signature.clone(),
                language: lang,
                relative_source: project_relative_path(project, &candidate.location.file)?,
                line: candidate.location.line,
                rationale: candidate.rationale.clone(),
            },
            engine,
            source: source_evidence(project, candidate)?,
            compile_context: work_order_compile_context(project, build_context)?,
            compile_context_sha256: String::new(),
            harness_rules: crate::harness_work_order::work_order_rules(lang),
            seeds: self.seed_references(candidate.id).await?,
            validation_steps: vec![
                WorkOrderStep::Import,
                WorkOrderStep::Qualify,
                WorkOrderStep::Rank,
                WorkOrderStep::Promote,
                WorkOrderStep::RunCampaign { duration_secs: 300 },
                WorkOrderStep::Coverage,
            ],
        };
        build_work_order(payload).map_err(Into::into)
    }

    /// Retained corpus content references for a new packet.
    async fn seed_references(
        &self,
        target_id: uuid::Uuid,
    ) -> Result<Vec<WorkOrderSeedReference>, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage(
                "storage_required: work order export requires storage".to_owned(),
            )
        })?;
        let entries = store
            .list_corpus_entries(target_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(entries
            .iter()
            .map(|entry| WorkOrderSeedReference {
                sha256: entry.sha256.clone(),
                size: entry.size,
            })
            .collect())
    }
}

fn empty_build_context() -> BuildContext {
    BuildContext {
        include_dirs: Vec::new(),
        defines: Vec::new(),
        std_flag: None,
        extra_flags: Vec::new(),
        entry_count: 0,
        dropped: Vec::new(),
    }
}

/// Read bounded source evidence for the candidate.
fn source_evidence(
    project: &Path,
    candidate: &TargetCandidate,
) -> Result<WorkOrderSourceEvidence, ClassifiedError> {
    let path = if candidate.location.file.is_absolute() {
        candidate.location.file.clone()
    } else {
        project.join(&candidate.location.file)
    };
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| ClassifiedError::Validation(format!("read candidate source: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return Err(ClassifiedError::Validation(
            "candidate source must be a bounded regular non-symlink file".to_owned(),
        ));
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| ClassifiedError::Validation(format!("read candidate source: {error}")))?;
    let source_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    let text = String::from_utf8(bytes).map_err(|error| {
        ClassifiedError::Validation(format!("candidate source is not UTF-8: {error}"))
    })?;
    let lines: Vec<&str> = text.lines().collect();
    let start = (candidate.location.line as usize).saturating_sub(1);
    if start >= lines.len() {
        return Err(ClassifiedError::Validation(format!(
            "source line {} is past the end of {}",
            candidate.location.line,
            candidate.location.file.display()
        )));
    }
    let mut excerpt = String::new();
    let mut truncated = false;
    for line in lines
        .iter()
        .skip(start)
        .take(MAX_WORK_ORDER_SOURCE_EXCERPT_LINES + 1)
    {
        let separator = usize::from(!excerpt.is_empty());
        if excerpt.len() + separator + line.len() > MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES {
            truncated = true;
            break;
        }
        if !excerpt.is_empty() {
            excerpt.push('\n');
        }
        excerpt.push_str(line);
    }
    if lines.len() > start + MAX_WORK_ORDER_SOURCE_EXCERPT_LINES {
        truncated = true;
    }
    Ok(WorkOrderSourceEvidence {
        excerpt,
        excerpt_truncated: truncated,
        sha256: source_sha256,
    })
}

fn work_order_compile_context(
    project: &Path,
    build_context: BuildContext,
) -> Result<WorkOrderCompileContext, ClassifiedError> {
    let include_dirs = build_context
        .include_dirs
        .iter()
        .map(|include_dir| project_relative_path(project, include_dir))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkOrderCompileContext {
        include_dirs,
        defines: build_context
            .defines
            .into_iter()
            .map(|define| define.strip_prefix("-D").unwrap_or(&define).to_owned())
            .collect(),
        std_flag: build_context.std_flag,
        extra_flags: build_context.extra_flags,
        compile_units: build_context.entry_count,
        dropped_flags: build_context.dropped,
    })
}

fn project_relative_path(project: &Path, path: &Path) -> Result<String, ClassifiedError> {
    let relative = if path.is_absolute() {
        path.strip_prefix(project).map_err(|_| {
            ClassifiedError::Validation(
                "work order evidence path is outside the project".to_owned(),
            )
        })?
    } else {
        path
    };
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err(ClassifiedError::Validation(
            "work order evidence path escapes the project".to_owned(),
        ));
    }
    relative.to_str().map(str::to_owned).ok_or_else(|| {
        ClassifiedError::Validation("work order evidence path is not UTF-8".to_owned())
    })
}
