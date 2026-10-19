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
    stage_draft(&dir, &draft)?.publish()?;
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
    tracing::warn!(error = %error, "report draft storage operation failed");
    ClassifiedError::Storage(format!("report drafts: {}", error.kind()))
}

/// One save's staged-but-unpublished draft bytes.
///
/// Owns an exclusive same-directory temporary file, so two saves of one id
/// never share staging: each publishes exactly the bytes it staged, and
/// dropping the owner on any error path removes the staging file.
struct StagedDraft {
    temporary: tempfile::NamedTempFile,
    dest_path: PathBuf,
}

/// Stage one save's encoded bytes in this save's own exclusive temporary
/// file (`.{id}.<random>.tmp`) inside `dir`.
fn stage_draft(dir: &Path, draft: &ReportDraft) -> Result<StagedDraft, ClassifiedError> {
    use std::io::Write as _;

    let json = serde_json::to_string_pretty(draft)
        .map_err(|e| ClassifiedError::Internal(format!("encode report draft: {e}")))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".{}.", draft.id))
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|e| storage_err(&e))?;
    temporary
        .write_all(json.as_bytes())
        .map_err(|e| storage_err(&e))?;
    Ok(StagedDraft {
        temporary,
        dest_path: dir.join(format!("{}.json", draft.id)),
    })
}

impl StagedDraft {
    /// Atomically replace the stored draft with the staged bytes.
    ///
    /// `persist` renames this save's own temporary over `{id}.json`
    /// (complete-file replacement, last writer wins). A failed persist
    /// returns the error and drops the owned temporary, removing the
    /// staging file; the previously stored draft is left untouched.
    fn publish(self) -> Result<(), ClassifiedError> {
        self.temporary
            .persist(&self.dest_path)
            .map(|_| ())
            .map_err(|e| storage_err(&e.error))
    }
}

#[cfg(test)]
mod tests {
    use super::{stage_draft, ReportDraft};

    fn draft(id: &str, content: &str) -> ReportDraft {
        ReportDraft {
            id: id.to_owned(),
            title: "Campaign report".to_owned(),
            project: "/proj".to_owned(),
            target: None,
            status: "Draft".to_owned(),
            updated_at: "2026-10-19T00:00:00Z".to_owned(),
            content: content.to_owned(),
        }
    }

    /// Overlapping saves of one report id must each publish exactly the bytes
    /// they staged, and neither save may fail because the other's rename
    /// consumed its temporary file. The two saves interleave deterministically
    /// at the write/rename seam -- no threads, no retries, no timing
    /// dependence.
    #[test]
    fn overlapping_same_id_saves_each_publish_their_own_content() {
        let dir = tempfile::tempdir().expect("create reports dir");
        let staged_first =
            stage_draft(dir.path(), &draft("shared", "first body")).expect("stage first save");
        let staged_second =
            stage_draft(dir.path(), &draft("shared", "second body")).expect("stage second save");

        // The second save completes fully while the first is still staged.
        staged_second.publish().expect("second save publishes");
        let after_second = std::fs::read_to_string(dir.path().join("shared.json"))
            .expect("read stored draft after second save");
        let after_second: ReportDraft =
            serde_json::from_str(&after_second).expect("second save publishes a complete draft");
        assert_eq!(after_second.content, "second body");

        // The first save must still publish its own staged bytes afterwards.
        staged_first
            .publish()
            .expect("first save publishes its own staged content");
        let after_first = std::fs::read_to_string(dir.path().join("shared.json"))
            .expect("read stored draft after first save");
        let after_first: ReportDraft =
            serde_json::from_str(&after_first).expect("first save publishes a complete draft");
        assert_eq!(after_first.content, "first body");
    }

    #[test]
    fn staging_errors_do_not_disclose_the_storage_directory() {
        let root = tempfile::tempdir().expect("create test root");
        let missing = root.path().join("private-report-storage");
        let Err(error) = stage_draft(&missing, &draft("private-report", "body")) else {
            panic!("staging into a missing directory must fail");
        };
        assert!(matches!(error, hf_core::error::ClassifiedError::Storage(_)));
        let public = error.to_string();
        assert!(!public.contains(root.path().to_string_lossy().as_ref()));
        assert!(!public.contains("private-report"));
        assert!(public.contains(&std::io::ErrorKind::NotFound.to_string()));
    }
}
