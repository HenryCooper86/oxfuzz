//! `corpus_seed` must not wipe the target's persisted corpus inventory:
//! seeding relists the corpus directory and persists that inventory (mirroring
//! `generate_seeds`), so campaign-grown entries survive a later seeding pass
//! and the reported count is the relisted corpus, not only the new seeds.

use hf_service::ServiceContainer;

const FIXTURE: &str = r"
int parse_value(const unsigned char *data, unsigned long len) {
    return len == 0 ? 0 : (int)data[0];
}
";

fn fixture_project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("parser.c"), FIXTURE).unwrap();
    project
}

/// Redirect the fuzz workspace to a temp dir for the duration of the test
/// process, so corpus operations don't pollute the real per-user data dir.
fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_corpus_seed_it_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        let initialized = hf_service::initialize_workspace_root()
            .expect("initialize managed integration-test workspace");
        assert_eq!(initialized, std::fs::canonicalize(&root).unwrap());
    });
}

#[tokio::test]
async fn seeding_preserves_existing_corpus_inventory() {
    isolate_workspace();
    let project = fixture_project();
    let store_dir = tempfile::tempdir().unwrap();
    let container = ServiceContainer::stubbed()
        .with_store_path(store_dir.path().join("store.db"))
        .await
        .unwrap();
    let target = "parse_value";

    assert_eq!(
        container.corpus_seed(project.path(), target).await.unwrap(),
        2
    );

    // A campaign-grown entry on disk, as `corpus_grow`/crash absorption would
    // leave it: present in the directory and in the persisted inventory.
    let corpus_dir = hf_service::workspace_dir(project.path(), target).join("corpus");
    std::fs::write(corpus_dir.join("grown_input"), b"campaign-grown").unwrap();
    container.corpus_grow(project.path(), target).await.unwrap();

    let reseeded = container.corpus_seed(project.path(), target).await.unwrap();
    assert_eq!(
        reseeded, 3,
        "seeding reports the relisted corpus, not only the newly seeded inputs"
    );

    let persisted = container
        .project_corpus_entries(project.path())
        .await
        .unwrap();
    assert_eq!(persisted.len(), 3, "persisted entries: {persisted:?}");
    assert!(
        persisted.iter().any(|entry| entry
            .path
            .file_name()
            .is_some_and(|name| name == "grown_input")),
        "the campaign-grown entry must survive a later seeding pass: {persisted:?}"
    );
}
