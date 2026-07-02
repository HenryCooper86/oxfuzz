//! File-backed editable report drafts for the internal workbench.

use std::path::PathBuf;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Editable Markdown report saved by the workbench.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDraft {
    /// Stable report identifier.
    pub id: String,
    /// Human-readable report title.
    pub title: String,
    /// Project root this report belongs to.
    pub project: String,
    /// Optional target symbol this report summarizes.
    pub target: Option<String>,
    /// Workflow status such as `Draft`, `Needs Review`, or `Approved`.
    pub status: String,
    /// RFC3339 timestamp for the latest write.
    pub updated_at: String,
    /// Markdown body.
    pub content: String,
}

/// Return every saved report draft, newest first.
///
/// # Errors
/// Returns a storage error when the report directory cannot be read or a draft
/// file cannot be decoded.
pub fn list_report_drafts() -> Result<Vec<ReportDraft>, ClassifiedError> {
    let dir = ensure_reports_dir()?;
    let mut drafts = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| storage_err(&e))? {
        let entry = entry.map_err(|e| storage_err(&e))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| storage_err(&e))?;
        let draft: ReportDraft = serde_json::from_str(&text)
            .map_err(|e| ClassifiedError::Storage(format!("decode report draft: {e}")))?;
        drafts.push(draft);
    }
    drafts.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(drafts)
}

/// Save a new or existing Markdown report draft.
///
/// # Errors
/// Returns validation errors for empty title/content or unsafe ids, and storage
/// errors for filesystem writes.
pub fn save_report_draft(
    id: Option<String>,
    title: &str,
    project: &str,
    target: Option<&str>,
    status: &str,
    content: &str,
) -> Result<ReportDraft, ClassifiedError> {
    let title = title.trim();
    let content = content.trim_end();
    if title.is_empty() {
        return Err(ClassifiedError::Validation(
            "report title is required".to_owned(),
        ));
    }
    if content.trim().is_empty() {
        return Err(ClassifiedError::Validation(
            "report content is required".to_owned(),
        ));
    }

    let id = id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_id(&id)?;

    let draft = ReportDraft {
        id,
        title: title.to_owned(),
        project: project.trim().to_owned(),
        target: target
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        status: normalize_status(status),
        updated_at: Utc::now().to_rfc3339(),
        content: content.to_owned(),
    };

    let dir = ensure_reports_dir()?;
    let path = report_path(&draft.id)?;
    let temp_path = dir.join(format!("{}.tmp", draft.id));
    let json = serde_json::to_string_pretty(&draft)
        .map_err(|e| ClassifiedError::Internal(format!("encode report draft: {e}")))?;
    std::fs::write(&temp_path, json).map_err(|e| storage_err(&e))?;
    std::fs::rename(temp_path, path).map_err(|e| storage_err(&e))?;
    Ok(draft)
}

/// Delete one saved report draft.
///
/// # Errors
/// Returns validation errors for unsafe ids and storage errors for failed
/// deletion. Deleting a missing report is a no-op.
pub fn delete_report_draft(id: &str) -> Result<(), ClassifiedError> {
    validate_id(id)?;
    let path = report_path(id)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(storage_err(&e)),
    }
}

fn ensure_reports_dir() -> Result<PathBuf, ClassifiedError> {
    let dir = reports_dir();
    std::fs::create_dir_all(&dir).map_err(|e| storage_err(&e))?;
    Ok(dir)
}

fn report_path(id: &str) -> Result<PathBuf, ClassifiedError> {
    validate_id(id)?;
    Ok(reports_dir().join(format!("{id}.json")))
}

fn reports_dir() -> PathBuf {
    std::env::var_os("HF_REPORTS_DIR").map_or_else(
        || crate::init::user_app_dir().join("reports"),
        PathBuf::from,
    )
}

fn validate_id(id: &str) -> Result<(), ClassifiedError> {
    let valid = !id.is_empty()
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    if valid {
        Ok(())
    } else {
        Err(ClassifiedError::Validation(
            "report id must contain only ASCII letters, digits, '-' or '_'".to_owned(),
        ))
    }
}

fn normalize_status(status: &str) -> String {
    let trimmed = status.trim();
    if trimmed.is_empty() {
        "Draft".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn storage_err(error: &std::io::Error) -> ClassifiedError {
    ClassifiedError::Storage(format!("report drafts: {error}"))
}
