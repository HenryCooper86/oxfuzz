//! Bounded source capture shared with freshness verification.
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

pub(crate) fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(format!("Clang analysis: {}", message.into()))
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputFingerprint {
    pub schema_version: u32,
    pub files: BTreeMap<String, String>,
    pub database_sha256: String,
    pub profile_sha256: Option<String>,
    pub scope_sha256: Option<String>,
    pub request_sha256: String,
}

pub(crate) fn capture(
    project: &Path,
    destination: Option<&Path>,
    max_bytes: u64,
) -> Result<BTreeMap<String, String>, ClassifiedError> {
    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    let walk = ignore::WalkBuilder::new(project)
        .hidden(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .filter_entry(|entry| {
            entry.depth() == 0
                || ![
                    ".git",
                    "target",
                    "node_modules",
                    "fuzz_workspace",
                    ".superpowers",
                    ".claude",
                    ".codex",
                ]
                .iter()
                .any(|name| entry.file_name() == *name)
        })
        .build();
    for entry in walk {
        let entry = entry.map_err(|e| invalid(e.to_string()))?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| invalid(e.to_string()))?;
        if meta.is_dir() {
            continue;
        }
        if !meta.file_type().is_file() {
            return Err(invalid("snapshot refuses links and special files"));
        }
        if files.len() >= 100_000 {
            return Err(invalid("snapshot file count limit"));
        }
        let path = std::fs::canonicalize(entry.path()).map_err(|e| invalid(e.to_string()))?;
        if !path.starts_with(project) {
            return Err(invalid("snapshot path escape"));
        }
        let relative_path = path
            .strip_prefix(project)
            .map_err(|e| invalid(e.to_string()))?;
        relative_path
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 source path"))?;
        let relative = hf_core::runtime::posix_relative(relative_path);
        if relative.contains(['\\', ':']) {
            return Err(invalid("snapshot path is not portable"));
        }
        let remaining = max_bytes.saturating_sub(total);
        if meta.len() > remaining {
            return Err(invalid("snapshot byte limit"));
        }
        let mut data = Vec::new();
        std::fs::File::open(&path)
            .map_err(|e| invalid(e.to_string()))?
            .take(remaining + 1)
            .read_to_end(&mut data)
            .map_err(|e| invalid(e.to_string()))?;
        total += data.len() as u64;
        if total > max_bytes {
            return Err(invalid("snapshot byte limit"));
        }
        if let Some(root) = destination {
            let output = root.join(&relative);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent).map_err(|e| invalid(e.to_string()))?;
            }
            std::fs::write(output, &data).map_err(|e| invalid(e.to_string()))?;
        }
        files.insert(relative, digest(&data));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_header_changes_are_visible_and_snapshot_budget_is_enforced() {
        let root = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("build")).unwrap();
        std::fs::write(root.path().join("build/config.h"), "#define FEATURE 1\n").unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let first = capture(&project, Some(staged.path()), 1024).unwrap();
        assert_eq!(
            std::fs::read_to_string(staged.path().join("build/config.h")).unwrap(),
            "#define FEATURE 1\n"
        );
        std::fs::write(root.path().join("build/config.h"), "#define FEATURE 0\n").unwrap();
        assert_ne!(capture(&project, None, 1024).unwrap(), first);
        assert!(capture(&project, None, 1).is_err());
    }
}

#[cfg(all(test, unix))]
mod portable_path_tests {
    use super::*;
    #[test]
    fn literal_backslash_filenames_are_refused_instead_of_aliasing_a_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("bad\\name.c"), "int x;").unwrap();
        assert!(capture(&std::fs::canonicalize(root.path()).unwrap(), None, 1024).is_err());
    }
}
