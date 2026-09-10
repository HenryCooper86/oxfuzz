//! Document ownership and exclusion shared by indexing, ingestion, and deletion.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use sha2::{Digest, Sha256};

pub(super) fn identity(project: &Path) -> String {
    let project = crate::container::project_lookup_identity(project);
    format!(
        "{:x}",
        Sha256::digest(project.as_os_str().as_encoded_bytes())
    )
}

pub(crate) struct KnowledgeOperation {
    pub(crate) project: PathBuf,
    pub(crate) docs: PathBuf,
    _lease: File,
}

impl KnowledgeOperation {
    pub(crate) fn acquire(project: &Path) -> Result<Self, ClassifiedError> {
        let project = crate::container::project_lookup_identity(project);
        let docs = super::docs_dir(&project);
        let locks = docs
            .parent()
            .expect("versioned knowledge root")
            .join(".locks");
        std::fs::create_dir_all(&locks).map_err(|error| storage_error(&error))?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(locks.join(identity(&project)))
            .map_err(|error| storage_error(&error))?;
        match lease.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(ClassifiedError::Validation(
                "project knowledge is busy; retry after indexing, ingestion, or deletion finishes"
                    .to_owned(),
            )),
            Err(std::fs::TryLockError::Error(error)) => return Err(storage_error(&error)),
        }
        Ok(Self {
            project,
            docs,
            _lease: lease,
        })
    }

    pub(super) fn generation(&self) -> Result<String, ClassifiedError> {
        std::fs::create_dir_all(&self.docs).map_err(|error| storage_error(&error))?;
        let marker = self.docs.join(".generation");
        match std::fs::read_to_string(&marker) {
            Ok(generation) => {
                uuid::Uuid::parse_str(&generation).map_err(|error| {
                    ClassifiedError::Internal(format!("invalid knowledge generation: {error}"))
                })?;
                Ok(generation)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let generation = uuid::Uuid::new_v4().to_string();
                std::fs::write(marker, &generation).map_err(|error| storage_error(&error))?;
                Ok(generation)
            }
            Err(error) => Err(storage_error(&error)),
        }
    }

    pub(crate) fn remove(&self) -> Result<(), ClassifiedError> {
        match std::fs::remove_dir_all(&self.docs) {
            Ok(()) => {}
            // A project with no ingested documents has nothing to remove.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(storage_error(&error)),
        }
        super::cache()
            .lock()
            .map_err(|_| ClassifiedError::Internal("knowledge cache poisoned".to_owned()))?
            .remove(&self.docs);
        Ok(())
    }
}

fn storage_error(error: &std::io::Error) -> ClassifiedError {
    ClassifiedError::Internal(format!("project knowledge storage: {error}"))
}

pub(super) fn legacy_documents_preserved(project: &Path) -> bool {
    let root = super::docs_root_from(std::env::var_os("HF_WORKSPACE_DIR"));
    [
        project.to_path_buf(),
        crate::container::project_lookup_identity(project),
    ]
    .iter()
    .any(|path| {
        let key: String = path
            .to_string_lossy()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        root.join(key).is_dir()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexing_and_deletion_require_exclusive_project_ownership() {
        let _guard = super::super::test_guard();
        let project = tempfile::tempdir().unwrap();
        let lease = KnowledgeOperation::acquire(project.path()).unwrap();
        assert!(KnowledgeOperation::acquire(project.path()).is_err());
        assert!(super::super::index_project(project.path()).is_err());
        drop(lease);
        assert!(super::super::index_project(project.path()).is_ok());
    }
}
