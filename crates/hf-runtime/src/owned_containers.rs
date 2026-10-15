//! Durable names and workspace identity for Docker cleanup after process loss.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORD_LIMIT_BYTES: u64 = 4096;
const REMOVAL_TIMEOUT: Duration = Duration::from_secs(10);
const AUTO_REMOVAL_TIMEOUT: Duration = Duration::from_secs(3);
const ABSENT_RECHECK_DELAY: Duration = Duration::from_secs(10);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(10);

fn sandbox_error(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Sandbox(message.into())
}

fn container_name(name: &str) -> Result<(), ClassifiedError> {
    let uuid = name
        .strip_prefix("hf-run-")
        .ok_or_else(|| sandbox_error("owned container name has no hf-run prefix"))?;
    let parsed = uuid::Uuid::parse_str(uuid)
        .map_err(|_| sandbox_error("owned container name has no valid UUID"))?;
    if parsed.to_string() != uuid {
        return Err(sandbox_error("owned container name is not canonical"));
    }
    Ok(())
}

fn checked_directory(path: &Path) -> Result<(), ClassifiedError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(sandbox_error(format!(
                        "runtime inventory directory is accessible to other users: {}",
                        path.display()
                    )));
                }
            }
            Ok(())
        }
        Ok(_) => Err(sandbox_error(format!(
            "runtime inventory path is not a regular directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder
            };
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            builder.create(path).map_err(|error| {
                sandbox_error(format!(
                    "create runtime inventory {}: {error}",
                    path.display()
                ))
            })
        }
        Err(error) => Err(sandbox_error(format!(
            "inspect runtime inventory {}: {error}",
            path.display()
        ))),
    }
}

#[derive(Serialize, Deserialize)]
struct Record {
    name: String,
    workspace_digest: String,
}

/// Docker operations required to verify a recorded container's identity.
#[async_trait]
pub trait ContainerControl: Send + Sync {
    /// Return the workspace label, or `None` if the exact container is absent.
    async fn inspect_workspace_label(&self, name: &str) -> Result<Option<String>, ClassifiedError>;
    /// Force-remove only the verified, named container.
    async fn remove(&self, name: &str) -> Result<(), ClassifiedError>;
}

/// Holds the per-container file lock while a Docker invocation is active.
pub struct ActiveContainer {
    _file: File,
    path: PathBuf,
    record: Record,
}

impl ActiveContainer {
    pub(crate) fn cid_path(&self) -> PathBuf {
        self.path.with_extension("cid")
    }

    fn confirmation_path(&self) -> PathBuf {
        self.path.with_extension("created")
    }
}

/// Persisted per-workspace Docker invocation inventory.
pub struct OwnedContainerRegistry {
    directory: PathBuf,
    workspace_digest: String,
}

impl OwnedContainerRegistry {
    /// Open or create the owner-only inventory beside an approved workspace root.
    pub fn new(workspace: &Path) -> Result<Self, ClassifiedError> {
        let root = fs::canonicalize(workspace).map_err(|error| {
            sandbox_error(format!(
                "resolve approved workspace {}: {error}",
                workspace.display()
            ))
        })?;
        let root_text = root
            .to_str()
            .ok_or_else(|| sandbox_error("approved workspace path is not UTF-8"))?;
        let workspace_digest = format!(
            "{:x}",
            Sha256::digest([b"oxfuzz-workspace-v1\0".as_slice(), root_text.as_bytes()].concat())
        );
        let parent = root
            .parent()
            .ok_or_else(|| sandbox_error("approved workspace has no parent directory"))?;
        let directory = parent.join(format!(".oxfuzz-runtime-{workspace_digest}"));
        checked_directory(&directory)?;
        #[cfg(unix)]
        sync_directory(parent)?;
        Ok(Self {
            directory,
            workspace_digest,
        })
    }

    /// Identity copied into the Docker workspace label.
    #[must_use]
    pub fn workspace_digest(&self) -> &str {
        &self.workspace_digest
    }

    /// Persist an invocation before Docker can create the named container.
    pub fn register(&self, name: &str) -> Result<ActiveContainer, ClassifiedError> {
        container_name(name)?;
        let path = self.directory.join(format!("{name}.json"));
        for extension in ["cid", "created"] {
            let checkpoint = path.with_extension(extension);
            match fs::symlink_metadata(&checkpoint) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => return Err(sandbox_error("owned container checkpoint already exists")),
                Err(error) => {
                    return Err(sandbox_error(format!(
                        "inspect owned container checkpoint: {error}"
                    )));
                }
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| sandbox_error(format!("create owned container record: {error}")))?;
        file.lock()
            .map_err(|error| sandbox_error(format!("lock owned container record: {error}")))?;
        let record = Record {
            name: name.to_owned(),
            workspace_digest: self.workspace_digest.clone(),
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| sandbox_error(format!("encode owned container record: {error}")))?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|error| sandbox_error(format!("sync owned container record: {error}")))?;
        #[cfg(unix)]
        sync_directory(&self.directory)?;
        Ok(ActiveContainer {
            _file: file,
            path,
            record,
        })
    }

    /// List the names retained for this exact workspace, including active work.
    pub fn pending_names(&self) -> Result<Vec<String>, ClassifiedError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| sandbox_error(format!("list owned containers: {error}")))?
        {
            let entry = entry
                .map_err(|error| sandbox_error(format!("read owned container entry: {error}")))?;
            let filename = entry.file_name();
            let Some(name) = filename
                .to_str()
                .and_then(|value| value.strip_suffix(".json"))
            else {
                continue;
            };
            container_name(name)?;
            names.push(name.to_owned());
        }
        names.sort();
        Ok(names)
    }

    /// Inspect and remove only abandoned containers with the matching label.
    pub async fn reconcile(&self, docker: &impl ContainerControl) -> Result<(), ClassifiedError> {
        for name in self.pending_names()? {
            let path = self.directory.join(format!("{name}.json"));
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|error| sandbox_error(format!("open owned container record: {error}")))?;
            match file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => continue,
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(sandbox_error(format!(
                        "lock owned container record: {error}"
                    )));
                }
            }
            let metadata = file
                .metadata()
                .map_err(|error| sandbox_error(format!("inspect owned record: {error}")))?;
            if !metadata.is_file() || metadata.len() > RECORD_LIMIT_BYTES {
                return Err(sandbox_error(
                    "owned container record is not a bounded regular file",
                ));
            }
            let mut encoded = Vec::new();
            file.read_to_end(&mut encoded)
                .map_err(|error| sandbox_error(format!("read owned record: {error}")))?;
            let record: Record = serde_json::from_slice(&encoded)
                .map_err(|error| sandbox_error(format!("decode owned record: {error}")))?;
            if record.name != name || record.workspace_digest != self.workspace_digest {
                return Err(sandbox_error(
                    "owned container record has a different identity",
                ));
            }
            let mut active = ActiveContainer {
                _file: file,
                path,
                record,
            };
            self.finish_stopped(&mut active, docker).await?;
        }
        Ok(())
    }

    /// Clear one completed invocation only after creation and absence are confirmed.
    pub async fn finish(
        &self,
        mut active: ActiveContainer,
        docker: &impl ContainerControl,
    ) -> Result<(), ClassifiedError> {
        self.finish_active(&mut active, docker).await
    }

    pub(crate) async fn finish_active(
        &self,
        active: &mut ActiveContainer,
        docker: &impl ContainerControl,
    ) -> Result<(), ClassifiedError> {
        self.observe_creation(active, docker).await?;
        wait_until_absent(docker, &active.record.name, AUTO_REMOVAL_TIMEOUT).await?;
        self.clear(active)
    }

    pub(crate) async fn finish_stopped(
        &self,
        active: &mut ActiveContainer,
        docker: &impl ContainerControl,
    ) -> Result<(), ClassifiedError> {
        if self.observe_creation(active, docker).await? {
            tokio::time::timeout(REMOVAL_TIMEOUT, docker.remove(&active.record.name))
                .await
                .map_err(|_| {
                    sandbox_error(format!(
                        "container {} removal timed out",
                        active.record.name
                    ))
                })??;
            wait_until_absent(docker, &active.record.name, REMOVAL_TIMEOUT).await?;
        }
        self.clear(active)
    }

    /// A spawn failure is the only path that can prove no create was submitted.
    pub(crate) fn finish_unlaunched(active: &ActiveContainer) -> Result<(), ClassifiedError> {
        remove_record(&active.path)
    }

    async fn observe_creation(
        &self,
        active: &mut ActiveContainer,
        docker: &impl ContainerControl,
    ) -> Result<bool, ClassifiedError> {
        let mut label = inspect_bounded(docker, &active.record.name).await?;
        if label
            .as_ref()
            .is_some_and(|label| label != &self.workspace_digest)
        {
            return Err(sandbox_error(format!(
                "container {} has a different workspace label",
                active.record.name
            )));
        }
        let confirmation = active.confirmation_path();
        let confirmed = creation_confirmed(&confirmation)?;
        let acknowledged = match cid_acknowledged(&active.cid_path()) {
            Ok(acknowledged) => acknowledged,
            Err(error) if label.is_some() || confirmed => {
                tracing::warn!(%error, container = %active.record.name,
                    "Ignoring invalid CID after independent creation confirmation");
                false
            }
            Err(error) => return Err(error),
        };
        if label.is_none() && !confirmed && !acknowledged {
            // Elapsed time does not prove an unacknowledged create is finished.
            tokio::time::sleep(ABSENT_RECHECK_DELAY).await;
            label = inspect_bounded(docker, &active.record.name).await?;
            match label.as_deref() {
                Some(label) if label == self.workspace_digest => {}
                Some(_) => {
                    return Err(sandbox_error(format!(
                        "container {} has a different workspace label",
                        active.record.name
                    )))
                }
                None => {
                    return Err(sandbox_error(format!(
                        "container {} creation is unresolved; ownership retained",
                        active.record.name
                    )))
                }
            }
        }
        confirm_creation(&confirmation)?;
        Ok(label.is_some())
    }

    fn clear(&self, active: &ActiveContainer) -> Result<(), ClassifiedError> {
        // Commit retirement before deleting the only positive checkpoints.
        remove_record(&active.path)?;
        for checkpoint in [active.cid_path(), active.confirmation_path()] {
            match fs::remove_file(checkpoint) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(sandbox_error(format!(
                        "remove owned container checkpoint: {error}"
                    )));
                }
            }
        }
        #[cfg(unix)]
        sync_directory(&self.directory)?;
        Ok(())
    }
}

fn creation_confirmed(path: &Path) -> Result<bool, ClassifiedError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0 =>
        {
            Ok(true)
        }
        Ok(_) => Err(sandbox_error(
            "owned container confirmation is not an empty regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(sandbox_error(format!(
            "inspect container confirmation: {error}"
        ))),
    }
}

fn confirm_creation(path: &Path) -> Result<(), ClassifiedError> {
    let file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !creation_confirmed(path)? {
                return Err(sandbox_error("container confirmation disappeared"));
            }
            OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|error| sandbox_error(format!("open container confirmation: {error}")))?
        }
        Err(error) => {
            return Err(sandbox_error(format!(
                "create container confirmation: {error}"
            )))
        }
    };
    file.sync_all()
        .map_err(|error| sandbox_error(format!("sync container confirmation: {error}")))?;
    #[cfg(unix)]
    sync_directory(
        path.parent()
            .expect("confirmation has an inventory directory"),
    )?;
    Ok(())
}

/// Docker writes the raw ID only after `ContainerCreate` returns successfully.
/// Missing/empty checkpoints are not evidence that creation never happened.
fn cid_acknowledged(path: &Path) -> Result<bool, ClassifiedError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(sandbox_error(format!(
                "inspect owned container CID file: {error}"
            )))
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 {
        return Err(sandbox_error(
            "owned container CID file is not a bounded regular file",
        ));
    }
    if metadata.len() == 0 {
        return Ok(false);
    }
    if metadata.len() != 64 {
        return Err(sandbox_error(
            "owned container CID file has an invalid length",
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| sandbox_error(format!("open owned container CID file: {error}")))?;
    let mut id = [0_u8; 64];
    file.read_exact(&mut id)
        .map_err(|error| sandbox_error(format!("read owned container CID file: {error}")))?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| sandbox_error(format!("read owned container CID file: {error}")))?
        != 0
        || !id
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(sandbox_error(
            "owned container CID file is not a complete container ID",
        ));
    }
    Ok(true)
}

async fn wait_until_absent(
    docker: &impl ContainerControl,
    name: &str,
    deadline: Duration,
) -> Result<(), ClassifiedError> {
    tokio::time::timeout(deadline, async {
        loop {
            if inspect_bounded(docker, name).await?.is_none() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| sandbox_error(format!("container {name} removal was not confirmed")))?
}

async fn inspect_bounded(
    docker: &impl ContainerControl,
    name: &str,
) -> Result<Option<String>, ClassifiedError> {
    tokio::time::timeout(INSPECT_TIMEOUT, docker.inspect_workspace_label(name))
        .await
        .map_err(|_| sandbox_error(format!("inspect owned container {name} timed out")))?
}

fn remove_record(path: &Path) -> Result<(), ClassifiedError> {
    fs::remove_file(path)
        .map_err(|error| sandbox_error(format!("remove owned container record: {error}")))?;
    #[cfg(unix)]
    sync_directory(path.parent().expect("record has parent"))?;
    Ok(())
}

/// Durably commit an inventory directory mutation. Unix syncs the directory
/// entry so a crash cannot lose a just-created or just-removed record; other
/// platforms have no directory-handle sync and rely on the filesystem's own
/// crash consistency, so the call sites compile it out there.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), ClassifiedError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| sandbox_error(format!("sync runtime inventory: {error}")))
}
