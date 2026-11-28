//! Which process owns a long-running operation.
//!
//! Every `oxfuzz` process -- the desktop app, `oxfuzz serve`, each CLI
//! command -- shares one database, and each sweeps operations it finds
//! active at startup into an interrupted state, since the process that ran
//! them is gone after a crash or quit. With two processes alive that sweep
//! also took the other's live work (a ranked discovery lost all of its
//! assessments when an unrelated command started). An operation's owner
//! therefore holds an exclusive lock on a per-operation file for as long as
//! the operation runs; the OS releases it if the owner dies, and a sweep
//! leaves alone every operation whose lock is still held.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Directory, under the per-user app directory, of operation owner locks.
const OWNER_DIR: &str = "operation-owners";

/// An operation's owner lock, released and removed on drop.
#[derive(Debug)]
pub(crate) struct OperationOwner {
    _file: File,
    path: PathBuf,
}

impl Drop for OperationOwner {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_path(root: &Path, kind: &str, id: Uuid) -> PathBuf {
    root.join(OWNER_DIR).join(kind).join(format!("{id}.lock"))
}

/// Take the owner lock of operation `id` of `kind` under `root`. `None` when
/// the lock could not be taken: the operation then runs as it did before
/// owner locks existed, unprotected from another process's sweep.
fn hold_under(root: &Path, kind: &str, id: Uuid) -> Option<OperationOwner> {
    let path = lock_path(root, kind, id);
    let opened = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
        })
        .and_then(|file| file.try_lock().map(|()| file).map_err(std::io::Error::from));
    match opened {
        Ok(file) => Some(OperationOwner { _file: file, path }),
        Err(error) => {
            tracing::warn!(%error, kind, %id, "could not take the operation's owner lock");
            None
        }
    }
}

/// Whether a live process holds the owner lock of operation `id` of `kind`.
fn is_owned_under(root: &Path, kind: &str, id: Uuid) -> bool {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path(root, kind, id))
    else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// Take this process's owner lock for an operation.
pub(crate) fn hold(kind: &str, id: Uuid) -> Option<OperationOwner> {
    hold_under(&crate::init::user_app_dir(), kind, id)
}

/// Whether another live process owns the operation.
pub(crate) fn is_owned(kind: &str, id: Uuid) -> bool {
    is_owned_under(&crate::init::user_app_dir(), kind, id)
}

/// Owner-lock kind of a ranked AI discovery operation.
#[cfg(feature = "ai-target-ranking")]
pub(crate) const AI_DISCOVERY: &str = "ai-discovery";
/// Owner-lock kind of a remediation verification operation.
#[cfg(feature = "patch-to-proof")]
pub(crate) const REMEDIATION: &str = "remediation";

#[cfg(test)]
mod tests {
    use super::{hold_under, is_owned_under};

    #[test]
    fn an_operation_is_owned_while_its_lock_is_held_and_lost_after() {
        let root = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4();
        assert!(
            !is_owned_under(root.path(), "ai-discovery", id),
            "never started"
        );

        let owner = hold_under(root.path(), "ai-discovery", id).expect("lock taken");
        assert!(is_owned_under(root.path(), "ai-discovery", id));
        assert!(
            !is_owned_under(root.path(), "remediation", id),
            "kinds are separate"
        );

        drop(owner);
        assert!(!is_owned_under(root.path(), "ai-discovery", id));
    }
}
