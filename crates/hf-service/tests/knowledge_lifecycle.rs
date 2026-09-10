//! Project-owned knowledge storage and cleanup regressions.
use std::path::PathBuf;
use std::sync::OnceLock;

fn isolate() {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = tempfile::tempdir().unwrap().keep();
        std::env::set_var("HF_CONFIG_DIR", root.join("config"));
        std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
        hf_service::initialize_workspace_root().unwrap();
        root
    });
}

#[test]
fn punctuation_distinct_projects_do_not_share_ingested_documents() {
    isolate();
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("project-a");
    let second = root.path().join("project_a");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let docs = hf_service::knowledge::docs_dir(&first);
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("spec.md"), "unique_first_project_protocol").unwrap();
    assert_ne!(docs, hf_service::knowledge::docs_dir(&second));
    hf_service::knowledge::index_project(&second).unwrap();
    assert!(
        hf_service::knowledge::search_project(&second, "unique_first_project_protocol", 10)
            .is_empty()
    );
}

#[tokio::test]
async fn project_deletion_removes_documents_and_cached_results_only_for_its_owner() {
    isolate();
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("owner");
    let other = root.path().join("other");
    for path in [&project, &other] {
        std::fs::create_dir_all(path).unwrap();
        let docs = hf_service::knowledge::docs_dir(path);
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("spec.md"), "unique_protocol_spec").unwrap();
        hf_service::knowledge::index_project(path).unwrap();
    }
    let service = hf_service::ServiceContainer::stubbed()
        .with_store_path(root.path().join("store.db"))
        .await
        .unwrap();
    service.delete_project(&project).await.unwrap();
    assert!(!hf_service::knowledge::is_indexed(&project));
    assert!(!hf_service::knowledge::docs_dir(&project).exists());
    assert!(hf_service::knowledge::search_project(&project, "unique_protocol_spec", 10).is_empty());
    assert!(hf_service::knowledge::is_indexed(&other));
    assert!(hf_service::knowledge::docs_dir(&other)
        .join("spec.md")
        .is_file());
    assert!(project.is_dir());
}

#[test]
fn recreated_document_storage_invalidates_a_cached_generation() {
    isolate();
    let project = tempfile::tempdir().unwrap();
    let docs = hf_service::knowledge::docs_dir(project.path());
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("spec.md"), "unique_old_generation").unwrap();
    hf_service::knowledge::index_project(project.path()).unwrap();
    assert!(hf_service::knowledge::is_indexed(project.path()));
    // Simulate deletion/recreation by another process holding the storage lease.
    std::fs::remove_dir_all(&docs).unwrap();
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join(".generation"), uuid::Uuid::new_v4().to_string()).unwrap();
    assert!(!hf_service::knowledge::is_indexed(project.path()));
    assert!(
        hf_service::knowledge::search_project(project.path(), "unique_old_generation", 10)
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_documents_are_reported_preserved_and_excluded_from_search() {
    isolate();
    let project = tempfile::tempdir().unwrap();
    let identity = std::fs::canonicalize(project.path()).unwrap();
    let key: String = identity
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let legacy = PathBuf::from(std::env::var_os("HF_WORKSPACE_DIR").unwrap())
        .join("knowledge")
        .join(key);
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("spec.md"), "ambiguous_old_protocol").unwrap();
    hf_service::knowledge::index_project(project.path()).unwrap();
    assert!(hf_service::knowledge::stats_project(project.path()).legacy_documents_preserved);
    assert!(
        hf_service::knowledge::search_project(project.path(), "ambiguous_old_protocol", 10)
            .is_empty()
    );
    hf_service::ServiceContainer::stubbed()
        .delete_project(project.path())
        .await
        .unwrap();
    assert!(legacy.join("spec.md").exists());
}

#[cfg(unix)]
#[test]
fn canonical_aliases_share_documents_and_cache() {
    isolate();
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let alias = root.path().join("alias");
    std::fs::create_dir_all(&project).unwrap();
    std::os::unix::fs::symlink(&project, &alias).unwrap();
    assert_eq!(
        hf_service::knowledge::docs_dir(&project),
        hf_service::knowledge::docs_dir(&alias)
    );
    hf_service::knowledge::index_project(&alias).unwrap();
    assert!(hf_service::knowledge::is_indexed(&project));
}

#[tokio::test]
async fn busy_knowledge_rejects_deletion_and_ingestion_before_mutation() {
    isolate();
    let project = tempfile::tempdir().unwrap();
    let source = project.path().join("source.txt");
    std::fs::write(&source, "source document").unwrap();
    hf_service::knowledge::index_project(project.path()).unwrap();
    let docs = hf_service::knowledge::docs_dir(project.path());
    let lock_path = docs
        .parent()
        .unwrap()
        .join(".locks")
        .join(docs.file_name().unwrap());
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lease.try_lock().unwrap();
    let service = hf_service::ServiceContainer::stubbed();
    assert!(service
        .delete_project(project.path())
        .await
        .unwrap_err()
        .to_string()
        .contains("knowledge is busy"));
    assert!(service
        .ingest_document(project.path(), &source)
        .await
        .unwrap_err()
        .to_string()
        .contains("knowledge is busy"));
    assert!(docs.exists());
    assert!(hf_service::knowledge::is_indexed(project.path()));
    drop(lease);
    service.delete_project(project.path()).await.unwrap();
    assert!(!docs.exists());
}
