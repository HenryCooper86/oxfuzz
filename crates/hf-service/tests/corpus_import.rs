//! Executor tests for external corpus import (`corpus_import`): an OSS-Fuzz
//! corpus directory enters a target's corpus bounded and deduplicated, a
//! re-import adds nothing, and a mistyped source path fails loudly.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_service::ServiceContainer;

#[derive(Default)]
struct ImportRuntime {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RuntimeAdapter for ImportRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

async fn import_fixture(target: &str) -> (tempfile::TempDir, ServiceContainer, Arc<ImportRuntime>) {
    common::install_managed_workspace("oxfuzz_corpus_import_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("importproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        format!(
            "#include <stddef.h>\nint {target}(const unsigned char *data, size_t size) {{ return size && data[0]; }}\n"
        ),
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("import.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(ImportRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store);
    (dir, container, runtime)
}

#[tokio::test]
async fn corpus_import_is_deduplicating_and_idempotent() {
    let (dir, container, runtime) = import_fixture("parse_import").await;
    let project = dir.path().join("importproj");
    let workspace = hf_service::workspace_dir(&project, "parse_import");
    let corpus_dir = workspace.join("corpus");
    std::fs::create_dir_all(&corpus_dir).unwrap();
    std::fs::write(corpus_dir.join("seed_a"), b"retained content").unwrap();

    let external = dir.path().join("oss_corpus");
    std::fs::create_dir_all(&external).unwrap();
    std::fs::write(external.join("hashname1"), b"new oss-fuzz input").unwrap();
    std::fs::write(external.join("hashname2"), b"another new input").unwrap();
    // Content the corpus already retains, under an OSS-Fuzz-style name.
    std::fs::write(external.join("hashname3"), b"retained content").unwrap();

    let imported = container
        .corpus_import(&project, "parse_import", &external)
        .await
        .expect("import should run");
    assert_eq!(imported.inspected, 3);
    assert_eq!(imported.eligible, 3);
    assert_eq!(imported.duplicates, 1);
    assert_eq!(imported.skipped, 0);
    assert_eq!(imported.added, 2, "only genuinely new content is imported");
    assert_eq!(imported.added_bytes, 35);
    assert_eq!(imported.before.inputs, 1);
    assert_eq!(imported.before.bytes, 16);
    assert_eq!(imported.after.inputs, 3);
    assert_eq!(imported.after.bytes, 51);

    // Re-importing the same directory adds nothing: content-addressed names
    // and hash dedup make the operation idempotent.
    let again = container
        .corpus_import(&project, "parse_import", &external)
        .await
        .expect("re-import should run");
    assert_eq!(again.added, 0, "re-import must be a no-op");
    assert_eq!(again.added_bytes, 0);
    assert_eq!(again.before, imported.after);
    assert_eq!(again.after, imported.after);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn corpus_import_fails_loudly_on_a_missing_source() {
    let (dir, container, runtime) = import_fixture("parse_missing").await;
    let project = dir.path().join("importproj");

    let missing = dir.path().join("no-such-corpus");
    let error = container
        .corpus_import(&project, "parse_missing", &missing)
        .await
        .expect_err("a mistyped source path must not silently import nothing");
    assert!(
        error.to_string().contains("no-such-corpus"),
        "the denial must name the source: {error}"
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn corpus_import_resolves_the_target_before_creating_or_writing_its_corpus() {
    let (dir, container, runtime) = import_fixture("parse_present").await;
    let project = dir.path().join("importproj");
    let source = dir.path().join("external");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("seed"), b"must not be imported").unwrap();
    let missing_workspace = hf_service::workspace_dir(&project, "parse_absent");

    let error = container
        .corpus_import(&project, "parse_absent", &source)
        .await
        .expect_err("a missing target must be rejected before corpus mutation");

    assert!(error.to_string().contains("parse_absent"), "{error}");
    assert!(!missing_workspace.exists());
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn byte_prune_resolves_the_target_before_deleting_duplicate_inputs() {
    let (dir, container, runtime) = import_fixture("parse_present").await;
    let project = dir.path().join("importproj");
    let workspace = hf_service::workspace_dir(&project, "parse_absent");
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("first"), b"same bytes").unwrap();
    std::fs::write(corpus.join("second"), b"same bytes").unwrap();

    let error = container
        .corpus_prune(&project, "parse_absent")
        .await
        .expect_err("a missing target must be rejected before byte pruning");

    assert!(error.to_string().contains("parse_absent"), "{error}");
    assert_eq!(std::fs::read(corpus.join("first")).unwrap(), b"same bytes");
    assert_eq!(std::fs::read(corpus.join("second")).unwrap(), b"same bytes");
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn byte_prune_reports_exact_before_and_after_inventories() {
    let (dir, container, runtime) = import_fixture("parse_present").await;
    let project = dir.path().join("importproj");
    let corpus = hf_service::workspace_dir(&project, "parse_present").join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("first"), b"same bytes").unwrap();
    std::fs::write(corpus.join("second"), b"same bytes").unwrap();
    std::fs::write(corpus.join("unique"), b"unique").unwrap();

    let outcome = container
        .corpus_prune(&project, "parse_present")
        .await
        .expect("byte pruning should run");

    assert_eq!(outcome.before, 3);
    assert_eq!(outcome.before_bytes, 26);
    assert_eq!(outcome.after, 2);
    assert_eq!(outcome.after_bytes, 16);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn corpus_capabilities_do_not_discover_or_persist_a_fresh_project() {
    common::install_managed_workspace("oxfuzz_corpus_capabilities_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("fresh-project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "int parse_fresh(const unsigned char *data, unsigned long size) { return size && data[0]; }",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fresh.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(ImportRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());

    let error = container
        .corpus_capabilities(&project, "parse_fresh")
        .await
        .expect_err("readiness requires retained target identity");

    assert!(error.to_string().contains("retained target"), "{error}");
    assert!(store.list_all_targets().await.unwrap().is_empty());
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn corpus_capabilities_without_a_store_are_explicitly_unavailable() {
    common::install_managed_workspace("oxfuzz_corpus_capabilities_no_store_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("fresh-project");
    std::fs::create_dir_all(&project).unwrap();
    let runtime = Arc::new(ImportRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None);

    let capabilities = container
        .corpus_capabilities(&project, "parse_fresh")
        .await
        .expect("missing storage is a named unavailable capability");

    assert_eq!(
        capabilities.seed_survival.reason_code.as_deref(),
        Some("persistent_store_required")
    );
    assert!(!capabilities.seed_survival.available);
    assert!(!capabilities.coverage_prune.available);
    assert!(!capabilities.minimize.available);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}
