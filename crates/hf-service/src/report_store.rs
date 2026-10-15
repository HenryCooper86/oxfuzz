//! File-backed editable report drafts for the internal workbench.

use std::path::{Path, PathBuf};

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

/// A saved report resolved once for publication.
///
/// Captures the stored owner and target before authorization. Execution does not
/// reload the editable draft, so replacing its saved project or target cannot
/// change an in-flight publication.
#[derive(Debug, Clone)]
pub struct ReportPublication {
    project: PathBuf,
    target: Option<String>,
}

impl ReportPublication {
    /// Wrap a draft loaded from the store.
    pub(crate) fn from_draft(report: ReportDraft) -> Self {
        Self {
            project: PathBuf::from(report.project),
            target: report.target,
        }
    }

    /// The saved owning project root. A transport authorizes this value (or
    /// its canonical resolution) before publishing.
    #[must_use]
    pub fn project(&self) -> &Path {
        &self.project
    }

    /// The saved target selector, when the report summarizes one target.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Bind an authorization resolver's canonical owner into this snapshot.
    ///
    /// Consumes and returns the publication with `project` replaced by
    /// `canonical`, preserving the saved target: the value a transport
    /// executes is then exactly the canonical owner its project
    /// policy approved -- no alias spelling, and no re-read of the editable
    /// draft. `canonical` is a trusted same-process resolver result and is
    /// deliberately not re-validated here.
    #[must_use]
    pub fn with_canonical_project(self, canonical: PathBuf) -> Self {
        Self {
            project: canonical,
            ..self
        }
    }
}

/// Return every saved report draft, newest first.
///
/// A single unreadable or undecodable draft file is logged and skipped rather
/// than failing the whole listing, so one corrupt/partially-written file cannot
/// hide every valid draft.
///
/// # Errors
/// Returns a storage error when the report directory itself cannot be read.
pub fn list_report_drafts() -> Result<Vec<ReportDraft>, ClassifiedError> {
    let dir = ensure_reports_dir()?;
    let mut drafts = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| storage_err(&e))? {
        let entry = entry.map_err(|e| storage_err(&e))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable report draft");
                continue;
            }
        };
        match serde_json::from_str::<ReportDraft>(&text) {
            Ok(draft) => drafts.push(draft),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping undecodable report draft");
            }
        }
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

/// Load one saved report draft by its stable id.
///
/// A direct `{id}.json` lookup -- no directory listing -- so resolving one
/// report never depends on (or walks) the other stored drafts.
///
/// # Errors
/// Returns a validation error for an unsafe id or an unknown report id, and
/// a storage error when the stored draft cannot be read or decoded. Decode
/// failures report bounded text only: serde's own detail can echo field
/// literals from the stored file, and those carry the saved owner path.
pub fn report_draft(id: &str) -> Result<ReportDraft, ClassifiedError> {
    let path = report_path(id)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ClassifiedError::Validation(format!(
                "report '{id}' not found"
            )));
        }
        Err(e) => return Err(storage_err(&e)),
    };
    serde_json::from_str(&text).map_err(|_| {
        ClassifiedError::Storage(format!("report drafts: report '{id}' could not be decoded"))
    })
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
