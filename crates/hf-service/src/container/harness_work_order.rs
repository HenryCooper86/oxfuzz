//! Gathering for the Harness Work Order.
//!
//! The packet itself is pure (`crate::harness_work_order`); this reads the
//! discovery candidate, the resolved compile context, a bounded source
//! excerpt, and any retained corpus entries worth seeding from.
//!
//! Calls no provider, performs no build, and starts no process.

use std::path::Path;

use hf_core::build::BuildContext;
use hf_core::target::{TargetCandidate, TargetLanguage};

use crate::container::ServiceContainer;
use crate::harness_work_order::{build_work_order, HarnessWorkOrder, WorkOrderInputs};
use crate::ClassifiedError;

/// Source lines carried around the candidate's definition.
///
/// The declaration plus body is what an author needs; the whole file is
/// unbounded and comes from an untrusted project.
const EXCERPT_LINES: usize = 60;

/// Largest source file read for an excerpt. A project under test is untrusted
/// input, so the read is bounded rather than trusting the file to be sane.
const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

/// Seed suggestions carried, so a large corpus cannot flood the packet.
const MAX_SEED_SUGGESTIONS: usize = 20;

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
    ) -> Result<HarnessWorkOrder, ClassifiedError> {
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

        Ok(build_work_order(&WorkOrderInputs {
            target_symbol: candidate.symbol.clone(),
            signature: candidate.signature.clone(),
            location: format!(
                "{}:{}",
                candidate.location.file.display(),
                candidate.location.line
            ),
            rationale: candidate.rationale.clone(),
            language: format!("{lang:?}").to_lowercase(),
            source_excerpt: source_excerpt(project, candidate),
            build_context,
            seed_suggestions: self.seed_suggestions(candidate.id).await,
            project_display: project.display().to_string(),
        }))
    }

    /// Retained corpus entries worth seeding a new harness from.
    ///
    /// Best effort: with no store, or a store read failure, the packet says
    /// there are no seed candidates, which is the honest reading. A failure to
    /// list seeds must not fail an export that needs no store to be useful.
    async fn seed_suggestions(&self, target_id: uuid::Uuid) -> Vec<String> {
        let Some(store) = self.store() else {
            return Vec::new();
        };
        let Ok(entries) = store.list_corpus_entries(target_id).await else {
            return Vec::new();
        };
        let mut paths: Vec<String> = entries
            .iter()
            .map(|entry| entry.path.display().to_string())
            .collect();
        // Sorted and capped so the same retained state renders the same bytes.
        paths.sort_unstable();
        paths.dedup();
        paths.truncate(MAX_SEED_SUGGESTIONS);
        paths
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

/// A bounded excerpt around the candidate's definition.
///
/// Returns a stated placeholder rather than an error when the file cannot be
/// read: a packet missing its source excerpt is still worth having, and the
/// author can open the file themselves.
fn source_excerpt(project: &Path, candidate: &TargetCandidate) -> String {
    let path = if candidate.location.file.is_absolute() {
        candidate.location.file.clone()
    } else {
        project.join(&candidate.location.file)
    };
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        return format!("source not readable: {}", candidate.location.file.display());
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_SOURCE_BYTES {
        return format!(
            "source not readable as a bounded regular file: {}",
            candidate.location.file.display()
        );
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return format!("source not readable: {}", candidate.location.file.display());
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = (candidate.location.line as usize).saturating_sub(1);
    let end = start.saturating_add(EXCERPT_LINES).min(lines.len());
    if start >= lines.len() {
        return format!(
            "source line {} is past the end of {}",
            candidate.location.line,
            candidate.location.file.display()
        );
    }
    lines[start..end].join("\n")
}
