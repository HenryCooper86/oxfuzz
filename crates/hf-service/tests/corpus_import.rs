//! Executor tests for external corpus import (`corpus_import`): an OSS-Fuzz
//! corpus directory enters a target's corpus bounded and deduplicated, a
//! re-import adds nothing, and a mistyped source path fails loudly.

mod common;

use std::path::Path;
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_service::ServiceContainer;

struct ImportRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for ImportRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

async fn import_fixture(target: &str) -> (tempfile::TempDir, ServiceContainer) {
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
    let container = ServiceContainer::new(Arc::new(ImportRuntime), None).with_store(store);
    (dir, container)
}

#[tokio::test]
async fn corpus_import_is_deduplicating_and_idempotent() {
    let (dir, container) = import_fixture("parse_import").await;
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

    let added = container
        .corpus_import(&project, "parse_import", &external)
        .await
        .expect("import should run");
    assert_eq!(added, 2, "only genuinely new content is imported");

    // Re-importing the same directory adds nothing: content-addressed names
    // and hash dedup make the operation idempotent.
    let again = container
        .corpus_import(&project, "parse_import", &external)
        .await
        .expect("re-import should run");
    assert_eq!(again, 0, "re-import must be a no-op");
}

#[tokio::test]
async fn corpus_import_fails_loudly_on_a_missing_source() {
    let (dir, container) = import_fixture("parse_missing").await;
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
}
