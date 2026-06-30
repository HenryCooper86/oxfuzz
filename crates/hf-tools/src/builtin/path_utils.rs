use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hf_core::tool::ToolError;

/// Sets the inner `AtomicBool` to `true` when dropped, signalling
/// a blocking worker thread to stop early.
pub(super) struct DropGuard(pub Option<Arc<AtomicBool>>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

pub(super) fn resolve_workspace_path(
    tool_name: &str,
    path: Option<&str>,
    working_dir: Option<&str>,
) -> Result<PathBuf, ToolError> {
    resolve_path_with_read_dirs(tool_name, path, working_dir, &[])
}

pub(super) fn resolve_read_path(
    tool_name: &str,
    path: Option<&str>,
    working_dir: Option<&str>,
    additional_read_dirs: &[String],
) -> Result<PathBuf, ToolError> {
    resolve_path_with_read_dirs(tool_name, path, working_dir, additional_read_dirs)
}

fn resolve_path_with_read_dirs(
    tool_name: &str,
    path: Option<&str>,
    working_dir: Option<&str>,
    additional_read_dirs: &[String],
) -> Result<PathBuf, ToolError> {
    let workspace = working_dir.filter(|value| !value.is_empty()).map(Path::new);
    let resolved = match (path.filter(|value| !value.is_empty()), workspace) {
        (Some(path), Some(workspace)) => {
            let path = Path::new(path);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                workspace.join(path)
            }
        }
        (Some(path), None) => PathBuf::from(path),
        (None, Some(workspace)) => workspace.to_path_buf(),
        (None, None) => PathBuf::from("."),
    };

    let resolved = normalize_lexically(&resolved);
    let workspace_root = workspace.map(normalize_lexically);
    let additional_roots = additional_read_dirs
        .iter()
        .filter(|value| !value.is_empty())
        .map(|value| normalize_lexically(Path::new(value)))
        .collect::<Vec<_>>();
    let has_workspace_root = workspace_root.is_some();
    let has_additional_roots = !additional_roots.is_empty();
    let temporary_roots = if has_workspace_root || has_additional_roots {
        system_temporary_roots()
    } else {
        Vec::new()
    };

    let mut allowed_roots = Vec::with_capacity(
        workspace_root.as_ref().map_or(0, |_| 1) + additional_roots.len() + temporary_roots.len(),
    );
    if let Some(workspace) = workspace_root {
        allowed_roots.push(workspace);
    }
    allowed_roots.extend(additional_roots);
    allowed_roots.extend(temporary_roots);

    if !allowed_roots.is_empty() {
        let is_allowed = allowed_roots
            .iter()
            .any(|root| path_is_within_root(&resolved, root));
        if !is_allowed {
            if has_workspace_root && !has_additional_roots {
                return Err(ToolError::PermissionDenied {
                    name: tool_name.to_string(),
                    reason: format!(
                        "path '{}' is outside workspace '{}'",
                        resolved.display(),
                        allowed_roots[0].display()
                    ),
                });
            }

            let allowed = allowed_roots
                .iter()
                .map(|root| format!("'{}'", root.display()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ToolError::PermissionDenied {
                name: tool_name.to_string(),
                reason: format!(
                    "path '{}' is outside allowed roots {allowed}",
                    resolved.display()
                ),
            });
        }

        // Defense in depth: the lexical check above can be fooled by a symlink
        // that lives inside an allowed root but points outside it (e.g. an
        // untrusted fuzz target plants `<workspace>/link -> /etc`). Resolve
        // symlinks in the existing portion of the path and confirm the real
        // target is still within a canonicalized allowed root. Roots are
        // canonicalized too so equivalent paths (e.g. macOS `/tmp` ->
        // `/private/tmp`) compare correctly. When nothing on the path exists
        // yet, both sides fall back to lexical form, preserving prior behavior.
        let real_target = canonicalize_existing_ancestor(&resolved);
        let within_real_root = allowed_roots.iter().any(|root| {
            let real_root = root.canonicalize().unwrap_or_else(|_| root.clone());
            path_is_within_root(&real_target, &real_root)
        });
        if !within_real_root {
            return Err(ToolError::PermissionDenied {
                name: tool_name.to_string(),
                reason: format!(
                    "path '{}' resolves through a symlink to outside the allowed roots",
                    resolved.display()
                ),
            });
        }
    }

    Ok(resolved)
}

/// Canonicalize `path`, tolerating a leaf (or tail) that does not exist yet.
///
/// Resolves the longest existing ancestor with `std::fs::canonicalize` (which
/// follows symlinks -- where any escape must live, since the symlink has to
/// exist to be followed) and re-appends the remaining components. Falls back to
/// lexical normalization when no ancestor exists.
fn canonicalize_existing_ancestor(path: &Path) -> PathBuf {
    let mut ancestor = path;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(real) = ancestor.canonicalize() {
            let mut result = real;
            for part in tail.iter().rev() {
                result.push(part);
            }
            return result;
        }
        match (ancestor.parent(), ancestor.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                ancestor = parent;
            }
            // Reached a root/prefix with nothing existing: no symlink can be
            // involved, so the lexical form is authoritative.
            _ => return normalize_lexically(path),
        }
    }
}

fn system_temporary_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let temp_dir = std::env::temp_dir();
    push_unique_root(&mut roots, &temp_dir);

    #[cfg(unix)]
    {
        push_unique_root(&mut roots, Path::new("/tmp"));
        push_unique_root(&mut roots, Path::new("/var/tmp"));
        push_unique_root(&mut roots, Path::new("/private/tmp"));
    }

    roots
}

fn push_unique_root(roots: &mut Vec<PathBuf>, root: &Path) {
    let root = normalize_lexically(root);
    if !roots.iter().any(|existing| existing == &root) {
        roots.push(root);
    }
}

fn path_is_within_root(path: &Path, root: &Path) -> bool {
    if path == root {
        return true;
    }

    match std::fs::metadata(root) {
        Ok(metadata) if metadata.is_file() => false,
        _ => path.starts_with(root),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn symlink_escaping_workspace_is_denied() {
        let ws = tempfile::tempdir().unwrap();

        // A symlink inside the workspace that points at a sensitive host dir
        // outside any allowed root (/etc, not the shared temp scratch).
        let link = ws.path().join("escape");
        std::os::unix::fs::symlink("/etc", &link).unwrap();

        let ws_str = ws.path().to_str().unwrap();
        // Reading through the symlink must be denied even though "escape/hosts"
        // is lexically inside the workspace.
        let result = resolve_read_path("FileRead", Some("escape/hosts"), Some(ws_str), &[]);
        assert!(result.is_err(), "symlink escape was allowed: {result:?}");
    }

    #[test]
    fn ordinary_workspace_paths_still_resolve() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir(ws.path().join("src")).unwrap();
        std::fs::write(ws.path().join("src/a.c"), "int main(){}").unwrap();
        let ws_str = ws.path().to_str().unwrap();

        // An existing in-workspace file resolves.
        assert!(resolve_read_path("FileRead", Some("src/a.c"), Some(ws_str), &[]).is_ok());
        // A not-yet-created file under an existing dir resolves (for writes).
        assert!(resolve_workspace_path("FileWrite", Some("src/new.txt"), Some(ws_str)).is_ok());
    }
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }

    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}
