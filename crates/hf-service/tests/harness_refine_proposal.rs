//! Coverage-plateau refine proposals compile beside the target workspace, so
//! the promoted revision a campaign runs stays active; a human adopts a
//! proposal explicitly, which recompiles its exact source as a new revision
//! that is reviewed, smoke-qualified and promoted like any other.

mod common;

use std::path::Path;
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

const SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

/// Every command succeeds and leaves the compiled binary in place.
struct CompilingRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for CompilingRuntime {
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
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
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

fn refined(index: usize, _prompt: &str) -> String {
    format!(
        "```c\n/* refined {index} */\nint parse_entry(const unsigned char *, unsigned long);\nint LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {{ if (size > 1) parse_entry(data + 1, size - 1); return 0; }}\n```"
    )
}

async fn fixture() -> (
    tempfile::TempDir,
    Arc<hf_storage::Store>,
    ServiceContainer,
    uuid::Uuid,
) {
    common::install_managed_workspace("oxfuzz_refine_proposal_it");
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("proposal.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(CompilingRuntime),
        Some(hf_test_utils::RecordingHarnessPool::new(refined)),
    )
    .with_store(Arc::clone(&store));
    let active = container
        .harness_compile(
            SOURCE.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap()
        .harness_id;
    (project, store, container, active)
}

fn active_marker(project: &Path) -> String {
    std::fs::read_to_string(
        hf_service::workspace_dir(project, "parse_entry").join("harness.active"),
    )
    .unwrap()
}

#[tokio::test]
async fn a_refine_proposal_leaves_the_active_revision_in_place() {
    let (project, store, container, active) = fixture().await;

    let proposal = container
        .harness_refine_proposal(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("the proposal compiles");

    assert_eq!(active_marker(project.path()).trim(), active.to_string());
    assert_ne!(proposal.harness_id, active);
    let stored = store
        .get_harness(proposal.harness_id)
        .await
        .unwrap()
        .expect("the proposal is a persisted revision");
    assert_eq!(stored.status, HarnessStatus::Compiled);
    assert!(stored.source.contains("refined"), "{}", stored.source);
    let workspace_source = std::fs::read_to_string(
        hf_service::workspace_dir(project.path(), "parse_entry").join("harness.source"),
    )
    .unwrap();
    assert_eq!(
        workspace_source, SOURCE,
        "the target workspace keeps its source"
    );
}

#[tokio::test]
async fn adopting_a_proposal_compiles_its_exact_source_as_a_new_active_revision() {
    let (project, store, container, _active) = fixture().await;
    let proposal = container
        .harness_refine_proposal(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap();

    let adopted = container
        .harness_adopt_revision(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            proposal.harness_id,
        )
        .await
        .expect("a compiled proposal of this target can be adopted");

    assert_ne!(
        adopted.harness_id, proposal.harness_id,
        "adoption is a new revision"
    );
    assert_eq!(
        active_marker(project.path()).trim(),
        adopted.harness_id.to_string()
    );
    let stored = store
        .get_harness(adopted.harness_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.source, proposal.source);
    assert_eq!(
        stored.status,
        HarnessStatus::Compiled,
        "adoption never promotes"
    );
}

#[tokio::test]
async fn adoption_refuses_a_revision_it_cannot_identify_with_the_target() {
    let (project, _store, container, active) = fixture().await;

    let wrong_engine = container
        .harness_adopt_revision(
            project.path(),
            "parse_entry",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            active,
        )
        .await
        .expect_err("a libFuzzer revision is not an AFL++ harness");
    assert!(
        matches!(wrong_engine, ClassifiedError::Validation(_)),
        "{wrong_engine}"
    );

    let unknown = container
        .harness_adopt_revision(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            uuid::Uuid::new_v4(),
        )
        .await
        .expect_err("an unknown revision cannot be adopted");
    assert!(
        matches!(unknown, ClassifiedError::Validation(_)),
        "{unknown}"
    );
}
