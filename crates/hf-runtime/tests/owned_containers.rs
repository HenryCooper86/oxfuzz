//! Recovery decisions use durable workspace identity and never select other roots.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_runtime::owned_containers::{ContainerControl, OwnedContainerRegistry};

const OWNED: &str = "hf-run-11111111-1111-4111-8111-111111111111";
const FOREIGN: &str = "hf-run-22222222-2222-4222-8222-222222222222";

fn cleanup(root: &std::path::Path, registry: &OwnedContainerRegistry) {
    assert!(registry.pending_names().unwrap().is_empty());
    let directory = root
        .parent()
        .unwrap()
        .join(format!(".oxfuzz-runtime-{}", registry.workspace_digest()));
    std::fs::remove_dir(directory).unwrap();
}

#[derive(Default)]
struct FakeDocker {
    labels: Mutex<HashMap<String, String>>,
    removed: Mutex<Vec<String>>,
    remove_error: AtomicBool,
}

#[async_trait]
impl ContainerControl for FakeDocker {
    async fn inspect_workspace_label(&self, name: &str) -> Result<Option<String>, ClassifiedError> {
        Ok(self.labels.lock().unwrap().get(name).cloned())
    }

    async fn remove(&self, name: &str) -> Result<(), ClassifiedError> {
        if self.remove_error.load(Ordering::SeqCst) {
            return Err(ClassifiedError::Sandbox("refused removal".to_owned()));
        }
        self.removed.lock().unwrap().push(name.to_owned());
        self.labels.lock().unwrap().remove(name);
        Ok(())
    }
}

#[tokio::test]
async fn recovery_skips_active_owned_containers_then_removes_abandoned_ones() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let docker = FakeDocker::default();
    let active = registry.register(OWNED).unwrap();
    docker
        .labels
        .lock()
        .unwrap()
        .insert(OWNED.to_owned(), registry.workspace_digest().to_owned());

    registry.reconcile(&docker).await.unwrap();
    assert!(docker.removed.lock().unwrap().is_empty());
    assert_eq!(registry.pending_names().unwrap(), vec![OWNED]);

    drop(active);
    registry.reconcile(&docker).await.unwrap();
    assert_eq!(docker.removed.lock().unwrap().as_slice(), [OWNED]);
    assert!(registry.pending_names().unwrap().is_empty());
    cleanup(root.path(), &registry);
}

#[tokio::test(start_paused = true)]
async fn recovery_refuses_a_foreign_label_and_preserves_the_record() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    drop(registry.register(FOREIGN).unwrap());
    let docker = FakeDocker::default();
    docker
        .labels
        .lock()
        .unwrap()
        .insert(FOREIGN.to_owned(), "other-workspace".to_owned());

    assert!(registry.reconcile(&docker).await.is_err());
    assert!(docker.removed.lock().unwrap().is_empty());
    assert_eq!(registry.pending_names().unwrap(), vec![FOREIGN]);
    drop(docker);
    let docker = FakeDocker::default();
    registry.reconcile(&docker).await.unwrap();
    cleanup(root.path(), &registry);
}

#[tokio::test(start_paused = true)]
async fn recovery_clears_a_record_only_after_the_container_is_absent() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    drop(registry.register(OWNED).unwrap());
    let docker = FakeDocker::default();

    registry.reconcile(&docker).await.unwrap();
    assert!(registry.pending_names().unwrap().is_empty());
    assert!(docker.removed.lock().unwrap().is_empty());
    cleanup(root.path(), &registry);
}

struct LateContainer {
    digest: String,
    checks: AtomicUsize,
    removed: AtomicBool,
}

#[async_trait]
impl ContainerControl for LateContainer {
    async fn inspect_workspace_label(
        &self,
        _name: &str,
    ) -> Result<Option<String>, ClassifiedError> {
        let check = self.checks.fetch_add(1, Ordering::SeqCst);
        Ok((check > 0 && !self.removed.load(Ordering::SeqCst)).then(|| self.digest.clone()))
    }

    async fn remove(&self, _name: &str) -> Result<(), ClassifiedError> {
        self.removed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn recovery_rechecks_absence_before_erasing_a_recent_launch_record() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    drop(registry.register(OWNED).unwrap());
    let docker = LateContainer {
        digest: registry.workspace_digest().to_owned(),
        checks: AtomicUsize::new(0),
        removed: AtomicBool::new(false),
    };

    registry.reconcile(&docker).await.unwrap();
    assert!(docker.removed.load(Ordering::SeqCst));
    assert!(docker.checks.load(Ordering::SeqCst) >= 3);
    cleanup(root.path(), &registry);
}

#[tokio::test]
async fn completed_client_does_not_erase_a_record_for_a_still_present_container() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let active = registry.register(OWNED).unwrap();
    let docker = FakeDocker::default();
    docker
        .labels
        .lock()
        .unwrap()
        .insert(OWNED.to_owned(), registry.workspace_digest().to_owned());

    assert!(registry.finish(active, &docker).await.is_err());
    assert_eq!(registry.pending_names().unwrap(), vec![OWNED]);
    registry.reconcile(&docker).await.unwrap();
    assert_eq!(docker.removed.lock().unwrap().as_slice(), [OWNED]);
    cleanup(root.path(), &registry);
}

#[tokio::test]
async fn failed_removal_preserves_ownership_for_a_later_recovery() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    drop(registry.register(OWNED).unwrap());
    let docker = FakeDocker::default();
    docker
        .labels
        .lock()
        .unwrap()
        .insert(OWNED.to_owned(), registry.workspace_digest().to_owned());
    docker.remove_error.store(true, Ordering::SeqCst);

    assert!(registry.reconcile(&docker).await.is_err());
    assert_eq!(registry.pending_names().unwrap(), vec![OWNED]);
    docker.remove_error.store(false, Ordering::SeqCst);
    registry.reconcile(&docker).await.unwrap();
    cleanup(root.path(), &registry);
}

struct DelayedRemoval {
    checks: AtomicUsize,
}

#[async_trait]
impl ContainerControl for DelayedRemoval {
    async fn inspect_workspace_label(
        &self,
        _name: &str,
    ) -> Result<Option<String>, ClassifiedError> {
        Ok((self.checks.fetch_add(1, Ordering::SeqCst) == 0).then(|| "owned".to_owned()))
    }

    async fn remove(&self, _name: &str) -> Result<(), ClassifiedError> {
        unreachable!("normal completion waits for Docker auto-removal")
    }
}

#[tokio::test]
async fn completion_waits_for_docker_auto_removal_before_erasing_ownership() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let active = registry.register(OWNED).unwrap();
    let docker = DelayedRemoval {
        checks: AtomicUsize::new(0),
    };

    registry.finish(active, &docker).await.unwrap();
    assert!(docker.checks.load(Ordering::SeqCst) >= 2);
    cleanup(root.path(), &registry);
}

struct HungDocker;

#[async_trait]
impl ContainerControl for HungDocker {
    async fn inspect_workspace_label(
        &self,
        _name: &str,
    ) -> Result<Option<String>, ClassifiedError> {
        std::future::pending().await
    }

    async fn remove(&self, _name: &str) -> Result<(), ClassifiedError> {
        unreachable!("inspection never completed")
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_docker_inspection_keeps_ownership_and_rejects_admission() {
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    drop(registry.register(OWNED).unwrap());

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(11),
        registry.reconcile(&HungDocker),
    )
    .await;
    assert!(matches!(outcome, Ok(Err(ClassifiedError::Sandbox(_)))));
    assert_eq!(registry.pending_names().unwrap(), vec![OWNED]);
    registry.reconcile(&FakeDocker::default()).await.unwrap();
    cleanup(root.path(), &registry);
}
