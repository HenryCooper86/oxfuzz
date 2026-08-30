//! Gathering for the Harness Work Order.
//!
//! The packet itself is pure (`crate::harness_work_order`); this reads the
//! discovery candidate, the resolved compile context, a bounded source
//! excerpt, and any retained corpus entries worth seeding from.
//!
//! Calls no provider, performs no build, and starts no process.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use hf_core::build::BuildContext;
use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
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
            .resolve_build_context(project)?
            .unwrap_or_else(empty_build_context);

        let project_root = canonical_project_root(project)?;
        let candidate_source = resolve_candidate_source(&project_root, &candidate.location.file)?;
        let source = source_evidence(&project_root, &candidate_source, candidate.location.line)?;
        let relative_source = project_relative_path(&project_root, &candidate_source)?;

        let payload = HarnessWorkOrderPayload {
            target: WorkOrderTargetEvidence {
                symbol: candidate.symbol.clone(),
                signature: candidate.signature.clone(),
                language: lang,
                relative_source,
                line: candidate.location.line,
                rationale: candidate.rationale.clone(),
            },
            engine,
            source,
            compile_context: work_order_compile_context(&project_root, build_context)?,
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

/// Resolve a project root to a canonical directory before collecting evidence.
fn canonical_project_root(project: &Path) -> Result<PathBuf, ClassifiedError> {
    let project_root = std::fs::canonicalize(project).map_err(|error| {
        ClassifiedError::Validation(format!("canonicalize project root: {error}"))
    })?;
    if !project_root.is_dir() {
        return Err(ClassifiedError::Validation(
            "project root is not a directory".to_owned(),
        ));
    }
    Ok(project_root)
}

/// Resolve a candidate source file and confine it beneath the canonical root.
fn resolve_candidate_source(
    project_root: &Path,
    candidate_file: &Path,
) -> Result<PathBuf, ClassifiedError> {
    let candidate_path = if candidate_file.is_absolute() {
        candidate_file.to_path_buf()
    } else {
        project_root.join(candidate_file)
    };
    let metadata = std::fs::symlink_metadata(&candidate_path).map_err(|error| {
        ClassifiedError::Validation(format!("inspect candidate source: {error}"))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(
            "candidate source must be a regular non-symlink file".to_owned(),
        ));
    }
    let resolved = std::fs::canonicalize(&candidate_path).map_err(|error| {
        ClassifiedError::Validation(format!("canonicalize candidate source: {error}"))
    })?;
    if resolved.strip_prefix(project_root).is_err() {
        return Err(ClassifiedError::Validation(
            "candidate source resolves outside the project".to_owned(),
        ));
    }
    Ok(resolved)
}

/// Read bounded source evidence from the file opened beneath the project root.
fn source_evidence(
    project_root: &Path,
    candidate_source: &Path,
    line: u32,
) -> Result<WorkOrderSourceEvidence, ClassifiedError> {
    let relative_source = candidate_source.strip_prefix(project_root).map_err(|_| {
        ClassifiedError::Validation("candidate source resolves outside the project".to_owned())
    })?;
    let mut file = open_regular_file_beneath(project_root, relative_source)?;
    let metadata = file.metadata().map_err(|error| {
        ClassifiedError::Validation(format!("inspect opened candidate source: {error}"))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(
            "candidate source must be a regular file".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ClassifiedError::Validation(format!("read candidate source: {error}")))?;
    if bytes.len() > MAX_SOURCE_BYTES as usize {
        return Err(ClassifiedError::Validation(
            "candidate source exceeds the maximum size".to_owned(),
        ));
    }
    let source_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    let text = String::from_utf8(bytes).map_err(|error| {
        ClassifiedError::Validation(format!("candidate source is not UTF-8: {error}"))
    })?;
    let lines: Vec<&str> = text.lines().collect();
    let start = (line as usize).saturating_sub(1);
    if start >= lines.len() {
        return Err(ClassifiedError::Validation(format!(
            "source line {} is past the end of {}",
            line,
            candidate_source.display()
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

#[cfg(unix)]
fn open_regular_file_beneath(
    project_root: &Path,
    relative_source: &Path,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let components = relative_source
        .components()
        .map(|component| match component {
            std::path::Component::Normal(component) => Ok(component),
            _ => Err(ClassifiedError::Validation(
                "candidate source has an unsafe path component".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| ClassifiedError::Validation("candidate source path is empty".to_owned()))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(project_root, directory_flags, Mode::empty()).map_err(|error| {
        ClassifiedError::Validation(format!(
            "open project root without following links: {error}"
        ))
    })?;
    let mut directory = File::from(root);
    for parent in parents {
        let next =
            openat(&directory, *parent, directory_flags, Mode::empty()).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "open candidate source directory without following links: {error}"
                ))
            })?;
        directory = File::from(next);
    }
    let file = openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        ClassifiedError::Validation(format!(
            "open candidate source without following links: {error}"
        ))
    })?;
    Ok(File::from(file))
}

#[cfg(not(unix))]
fn open_regular_file_beneath(
    project_root: &Path,
    relative_source: &Path,
) -> Result<File, ClassifiedError> {
    File::open(project_root.join(relative_source))
        .map_err(|error| ClassifiedError::Validation(format!("open candidate source: {error}")))
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
    let defines = build_context
        .defines
        .into_iter()
        .map(|define| portable_define(&define))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkOrderCompileContext {
        include_dirs,
        defines,
        std_flag: build_context.std_flag,
        extra_flags: build_context.extra_flags,
        compile_units: build_context.entry_count,
        dropped_flags: dropped_flag_categories(&build_context.dropped),
    })
}

fn portable_define(define: &str) -> Result<String, ClassifiedError> {
    let value = define.strip_prefix("-D").unwrap_or(define);
    if value
        .split_once('=')
        .is_some_and(|(_, value)| is_absolute_path(value))
    {
        return Err(ClassifiedError::Validation(
            "compile definition contains an absolute host path".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn is_absolute_path(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']);
    let windows_drive = value.len() >= 3
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'/' | b'\\');
    Path::new(value).is_absolute() || value.starts_with('\\') || windows_drive
}

fn dropped_flag_categories(dropped: &[String]) -> Vec<String> {
    let mut categories = dropped
        .iter()
        .map(|flag| {
            if flag.starts_with("-I")
                || flag.starts_with("-isystem")
                || flag.starts_with("-include")
                || flag.starts_with('/')
                || flag.contains('\\')
            {
                "path_bearing_flag"
            } else {
                "unsupported_flag"
            }
            .to_owned()
        })
        .collect::<Vec<_>>();
    categories.sort_unstable();
    categories.dedup();
    categories
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use hf_core::build::BuildContext;
    use hf_core::target::{
        InputSurface, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };

    use super::{
        canonical_project_root, open_regular_file_beneath, resolve_candidate_source,
        work_order_compile_context,
    };

    #[test]
    fn compile_context_replaces_rejected_host_paths_with_safe_categories() {
        let context = BuildContext {
            include_dirs: vec![PathBuf::from("include")],
            defines: Vec::new(),
            std_flag: None,
            extra_flags: Vec::new(),
            entry_count: 1,
            dropped: vec!["-I/Users/operator/private-headers".to_owned()],
        };

        let evidence = work_order_compile_context(Path::new("/project"), context)
            .expect("convert compile context");
        let json = serde_json::to_string(&evidence).expect("serialize compile context");

        assert_eq!(evidence.dropped_flags, vec!["path_bearing_flag".to_owned()]);
        assert!(!json.contains("/Users/operator"));
    }

    #[test]
    fn compile_context_rejects_defines_with_absolute_host_paths() {
        let context = BuildContext {
            include_dirs: Vec::new(),
            defines: vec!["-DPRIVATE_ROOT=/Users/operator/private".to_owned()],
            std_flag: None,
            extra_flags: Vec::new(),
            entry_count: 1,
            dropped: Vec::new(),
        };

        assert!(work_order_compile_context(Path::new("/project"), context).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn source_evidence_refuses_a_symlinked_parent_outside_the_project() {
        let project = tempfile::tempdir().expect("create project");
        let outside = tempfile::tempdir().expect("create outside directory");
        let source = outside.path().join("secret.c");
        std::fs::write(&source, "int parse_packet(void) { return 0; }")
            .expect("write outside source");
        std::os::unix::fs::symlink(outside.path(), project.path().join("linked"))
            .expect("create symlinked parent");
        let candidate = TargetCandidate {
            id: uuid::Uuid::nil(),
            project_root: project.path().to_path_buf(),
            language: TargetLanguage::C,
            symbol: "parse_packet".to_owned(),
            kind: TargetKind::Function,
            location: SourceLocation {
                file: PathBuf::from("linked/secret.c"),
                line: 1,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: 0.0,
            sanitizers: Vec::new(),
            rationale: "test".to_owned(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        };

        let project_root = canonical_project_root(project.path()).expect("canonical project root");
        assert!(resolve_candidate_source(&project_root, &candidate.location.file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn source_file_handle_refuses_a_final_symlink() {
        let project = tempfile::tempdir().expect("create project");
        let outside = tempfile::tempdir().expect("create outside directory");
        let target = outside.path().join("secret.c");
        std::fs::write(&target, "int outside;").expect("write outside source");
        std::os::unix::fs::symlink(&target, project.path().join("source.c"))
            .expect("create final symlink");

        assert!(open_regular_file_beneath(project.path(), Path::new("source.c")).is_err());
    }
}
