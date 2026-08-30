//! Durable provider-free Harness Work Order export and retrieval.

use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

use chrono::Utc;
use hf_core::{
    build::BuildContext,
    engine::EngineKind,
    runtime::{classify_fixed_sandbox_include_path, FixedSandboxIncludePath},
    target::{TargetCandidate, TargetLanguage},
};
use hf_storage::HarnessWorkOrderRecord;
use sha2::Digest;

use crate::{
    container::{
        project_identity::{canonical_project_root, select_target_candidate},
        require_fuzzing_harness_engine, ServiceContainer,
    },
    harness_work_order::{
        build_work_order, verify_work_order, HarnessWorkOrder, HarnessWorkOrderError,
        HarnessWorkOrderErrorCode, HarnessWorkOrderPayload, WorkOrderCompileContext,
        WorkOrderSeedReference, WorkOrderSourceEvidence, WorkOrderStep, WorkOrderTargetEvidence,
        MAX_WORK_ORDER_SEEDS, MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES,
        MAX_WORK_ORDER_SOURCE_EXCERPT_LINES,
    },
};

const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

/// Provider-free request for one durable authoring packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderExportRequest {
    pub project: PathBuf,
    pub target: String,
    pub language: TargetLanguage,
    pub engine: EngineKind,
}

impl ServiceContainer {
    /// Export retained target evidence as an immutable durable work order.
    pub async fn export_harness_work_order(
        &self,
        request: HarnessWorkOrderExportRequest,
    ) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
        let project = canonical_project_root(&request.project).map_err(service_validation)?;
        let store = self.store().ok_or_else(|| {
            HarnessWorkOrderError::storage("work order export requires durable storage")
        })?;
        require_fuzzing_harness_engine(request.engine, request.language)
            .map_err(service_validation)?;
        let project_text = project.to_str().ok_or_else(|| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidProjectPath,
                "project path is not UTF-8",
            )
        })?;
        let retained = store
            .list_targets(project_text)
            .await
            .map_err(storage_error)?;
        let candidates = retained
            .into_iter()
            .filter(|candidate| candidate.language == request.language)
            .collect::<Vec<_>>();
        let candidate = select_target_candidate(&candidates, &request.target)
            .map_err(service_validation)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::WorkOrderNotFound,
                    "retained target was not found for this project and language",
                )
            })?;

        let build_context = self
            .resolve_build_context(&project)
            .map_err(service_validation)?
            .unwrap_or_else(empty_build_context);
        let relative_source =
            project_relative_regular_file(&project, &candidate.location.file, MAX_SOURCE_BYTES)?;
        let payload = HarnessWorkOrderPayload {
            target: WorkOrderTargetEvidence {
                symbol: candidate.symbol.clone(),
                signature: candidate.signature.clone(),
                language: candidate.language,
                relative_source: relative_source.to_str().map(str::to_owned).ok_or_else(|| {
                    HarnessWorkOrderError::validation(
                        HarnessWorkOrderErrorCode::InvalidProjectPath,
                        "candidate source path is not UTF-8",
                    )
                })?,
                line: candidate.location.line,
                rationale: candidate.rationale.clone(),
            },
            engine: request.engine,
            source: source_evidence(&project, candidate)?,
            compile_context: normalized_build_context(&project, build_context)?,
            compile_context_sha256: String::new(),
            harness_rules: crate::harness_work_order::work_order_rules(candidate.language),
            seeds: seed_references(store, candidate.id).await?,
            validation_steps: vec![
                WorkOrderStep::Import,
                WorkOrderStep::Qualify,
                WorkOrderStep::Rank,
                WorkOrderStep::Promote,
                WorkOrderStep::RunCampaign { duration_secs: 300 },
                WorkOrderStep::Coverage,
            ],
        };
        let packet = build_work_order(payload)?;
        let packet_json = serde_json::to_string(&packet).map_err(serialization_error)?;

        if let Some(existing) = store
            .harness_work_order(&packet.id)
            .await
            .map_err(storage_error)?
        {
            return retained_packet(&existing, Some((&project, candidate.id)));
        }
        let record = HarnessWorkOrderRecord {
            id: packet.id.clone(),
            target_id: candidate.id,
            project_root: project_text.to_owned(),
            schema_version: packet.schema_version,
            packet_json,
            created_at: Utc::now(),
        };
        if let Ok(persisted) = store.insert_harness_work_order(&record).await {
            retained_packet(&persisted, Some((&project, candidate.id)))
        } else {
            let existing = store
                .harness_work_order(&packet.id)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| HarnessWorkOrderError::storage("persist work order"))?;
            retained_packet(&existing, Some((&project, candidate.id)))
        }
    }

    /// Read and verify one immutable durable packet.
    pub async fn harness_work_order_by_id(
        &self,
        id: &str,
    ) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
        let store = self.store().ok_or_else(|| {
            HarnessWorkOrderError::storage("work order retrieval requires durable storage")
        })?;
        let record = store
            .harness_work_order(id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::WorkOrderNotFound,
                    "work order was not found",
                )
            })?;
        retained_packet(&record, None)
    }

    /// List verified durable packets, optionally scoped to a canonical project.
    pub async fn list_harness_work_orders(
        &self,
        project: Option<&Path>,
    ) -> Result<Vec<HarnessWorkOrder>, HarnessWorkOrderError> {
        let store = self.store().ok_or_else(|| {
            HarnessWorkOrderError::storage("work order listing requires durable storage")
        })?;
        let canonical = project
            .map(canonical_project_root)
            .transpose()
            .map_err(service_validation)?;
        let project_text = canonical
            .as_deref()
            .map(|path| {
                path.to_str().ok_or_else(|| {
                    HarnessWorkOrderError::validation(
                        HarnessWorkOrderErrorCode::InvalidProjectPath,
                        "project path is not UTF-8",
                    )
                })
            })
            .transpose()?;
        store
            .list_harness_work_orders(project_text)
            .await
            .map_err(storage_error)?
            .into_iter()
            .map(|record| retained_packet(&record, None))
            .collect()
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

async fn seed_references(
    store: &hf_storage::Store,
    target_id: uuid::Uuid,
) -> Result<Vec<WorkOrderSeedReference>, HarnessWorkOrderError> {
    let mut seeds = store
        .list_corpus_entries(target_id)
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(|entry| WorkOrderSeedReference {
            sha256: entry.sha256,
            size: entry.size,
        })
        .collect::<Vec<_>>();
    seeds.sort_unstable();
    seeds.dedup();
    seeds.truncate(MAX_WORK_ORDER_SEEDS);
    Ok(seeds)
}

fn retained_packet(
    record: &HarnessWorkOrderRecord,
    expected: Option<(&Path, uuid::Uuid)>,
) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
    if let Some((project, target_id)) = expected {
        if record.target_id != target_id || record.project_root != project.to_string_lossy() {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable work order identity conflicts with retained target evidence",
            ));
        }
    }
    let packet = serde_json::from_str::<HarnessWorkOrder>(&record.packet_json).map_err(|_| {
        HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable work order packet is malformed",
        )
    })?;
    if packet.id != record.id || packet.schema_version != record.schema_version {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable work order metadata does not match its packet",
        ));
    }
    verify_work_order(&packet)?;
    Ok(packet)
}

fn project_relative_regular_file(
    project: &Path,
    candidate: &Path,
    max_bytes: u64,
) -> Result<PathBuf, HarnessWorkOrderError> {
    let relative = if candidate.is_absolute() {
        candidate
            .strip_prefix(project)
            .map_err(|_| invalid_project_path())?
    } else {
        candidate
    };
    if relative.components().next().is_none()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_project_path());
    }
    let file = open_regular_file_beneath(project, relative)?;
    let metadata = file.metadata().map_err(|_| invalid_project_path())?;
    if !metadata.file_type().is_file() {
        return Err(invalid_project_path());
    }
    if metadata.len() > max_bytes {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            "candidate source exceeds the maximum size",
        ));
    }
    Ok(relative.to_path_buf())
}

fn source_evidence(
    project: &Path,
    target: &TargetCandidate,
) -> Result<WorkOrderSourceEvidence, HarnessWorkOrderError> {
    let relative = project_relative_regular_file(project, &target.location.file, MAX_SOURCE_BYTES)?;
    let mut file = open_regular_file_beneath(project, &relative)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidProjectPath,
                "candidate source cannot be read",
            )
        })?;
    if bytes.len() > MAX_SOURCE_BYTES as usize {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            "candidate source exceeds the maximum size",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "candidate source is not UTF-8",
        )
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    let start = usize::try_from(target.location.line.saturating_sub(1)).unwrap_or(usize::MAX);
    if start >= lines.len() {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "retained target line is outside its source file",
        ));
    }
    let (excerpt, excerpt_truncated) = bounded_excerpt(&lines[start..]);
    Ok(WorkOrderSourceEvidence {
        excerpt,
        excerpt_truncated,
        sha256: hex::encode(sha2::Sha256::digest(text.as_bytes())),
    })
}

fn bounded_excerpt(lines: &[&str]) -> (String, bool) {
    let mut excerpt = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index == MAX_WORK_ORDER_SOURCE_EXCERPT_LINES {
            return (excerpt, true);
        }
        let separator = usize::from(index > 0);
        let available = MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES.saturating_sub(excerpt.len());
        if separator + line.len() > available {
            if line.is_empty() {
                return (excerpt, true);
            }
            let line_bytes = available.saturating_sub(separator);
            let prefix_len = utf8_prefix_len(line, line_bytes);
            if prefix_len == 0 {
                return (excerpt, true);
            }
            if separator == 1 {
                excerpt.push('\n');
            }
            excerpt.push_str(&line[..prefix_len]);
            return (excerpt, true);
        }
        if separator == 1 {
            excerpt.push('\n');
        }
        excerpt.push_str(line);
    }
    (excerpt, false)
}

fn utf8_prefix_len(value: &str, max_bytes: usize) -> usize {
    value
        .char_indices()
        .take_while(|(index, character)| index + character.len_utf8() <= max_bytes)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0)
}

fn normalized_build_context(
    project: &Path,
    context: BuildContext,
) -> Result<WorkOrderCompileContext, HarnessWorkOrderError> {
    let include_dirs = context
        .include_dirs
        .iter()
        .map(|path| normalized_include_path(project, path))
        .collect::<Result<Vec<_>, _>>()?;
    let defines = context
        .defines
        .iter()
        .map(|define| portable_define(define))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkOrderCompileContext {
        include_dirs,
        defines,
        std_flag: context.std_flag,
        extra_flags: context.extra_flags,
        compile_units: context.entry_count,
        dropped_flags: dropped_flag_categories(&context.dropped),
    })
}

fn normalized_include_path(project: &Path, path: &Path) -> Result<String, HarnessWorkOrderError> {
    match path.to_str().map(classify_fixed_sandbox_include_path) {
        Some(FixedSandboxIncludePath::Canonical) => {
            return path
                .to_str()
                .map(str::to_owned)
                .ok_or_else(invalid_project_path);
        }
        Some(FixedSandboxIncludePath::Invalid) => return Err(invalid_project_path()),
        Some(FixedSandboxIncludePath::Outside) | None => {}
    }
    let relative = if path.is_absolute() {
        path.strip_prefix(project)
            .map_err(|_| invalid_project_path())?
    } else {
        path
    };
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(invalid_project_path());
    }
    if relative.as_os_str().is_empty() {
        return Ok(".".to_owned());
    }
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(invalid_project_path)
}

fn portable_define(define: &str) -> Result<String, HarnessWorkOrderError> {
    let value = define.strip_prefix("-D").unwrap_or(define);
    if value
        .split_once('=')
        .is_some_and(|(_, value)| is_absolute_path(value))
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "compile definition contains an absolute path",
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

fn invalid_project_path() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidProjectPath,
        "path must name a regular file beneath the project root",
    )
}

fn service_validation(_error: crate::ClassifiedError) -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "work order request or retained evidence is invalid",
    )
}

fn storage_error(_error: hf_storage::StorageError) -> HarnessWorkOrderError {
    HarnessWorkOrderError::storage("durable work order storage is unavailable")
}

fn serialization_error(_error: serde_json::Error) -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "work order packet cannot be serialized",
    )
}

#[cfg(unix)]
fn open_regular_file_beneath(
    project: &Path,
    relative: &Path,
) -> Result<File, HarnessWorkOrderError> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(invalid_project_path()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, parents) = components.split_last().ok_or_else(invalid_project_path)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(project, directory_flags, Mode::empty()).map_err(|_| invalid_project_path())?;
    let mut directory = File::from(root);
    for parent in parents {
        directory = File::from(
            openat(&directory, *parent, directory_flags, Mode::empty())
                .map_err(|_| invalid_project_path())?,
        );
    }
    Ok(File::from(
        openat(
            &directory,
            *leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| invalid_project_path())?,
    ))
}

#[cfg(not(unix))]
fn open_regular_file_beneath(
    _project: &Path,
    _relative: &Path,
) -> Result<File, HarnessWorkOrderError> {
    Err(HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidProjectPath,
        "descriptor-confined project reads are unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::bounded_excerpt;
    use crate::harness_work_order::{
        MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES, MAX_WORK_ORDER_SOURCE_EXCERPT_LINES,
    };

    #[test]
    fn bounded_excerpt_honors_byte_and_line_limits_on_utf8_edges() {
        let exact = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        assert_eq!(bounded_excerpt(&[&exact]), (exact, false));

        let first = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        let (next_line, truncated) = bounded_excerpt(&[&first, "next"]);
        assert_eq!(next_line.len(), MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        assert!(!next_line.ends_with('\n'));
        assert!(truncated);

        let prefix = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 4);
        let (multibyte, truncated) = bounded_excerpt(&[&prefix, "éé"]);
        assert_eq!(multibyte.len(), MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 1);
        assert!(multibyte.ends_with("\né"));
        assert!(truncated);

        let lines = std::iter::repeat_n("line", MAX_WORK_ORDER_SOURCE_EXCERPT_LINES + 1)
            .collect::<Vec<_>>();
        let (line_limited, truncated) = bounded_excerpt(&lines);
        assert_eq!(
            line_limited.lines().count(),
            MAX_WORK_ORDER_SOURCE_EXCERPT_LINES
        );
        assert!(truncated);
    }

    #[test]
    fn bounded_excerpt_preserves_leading_empty_lines_without_separator_only_truncation() {
        assert_eq!(
            bounded_excerpt(&["", "first"]),
            ("\nfirst".to_owned(), false)
        );

        let prefix = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 2);
        let (excerpt, truncated) = bounded_excerpt(&[&prefix, "é"]);
        assert_eq!(excerpt, prefix);
        assert!(truncated);
    }

    #[test]
    fn normalized_include_rejects_invalid_fixed_paths_under_work_root() {
        assert!(super::normalized_include_path(
            std::path::Path::new("/work"),
            std::path::Path::new("/work/./include")
        )
        .is_err());
    }
}
