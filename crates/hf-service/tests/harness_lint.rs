//! Tests for the harness lint gate in front of sandbox compilation.

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

/// `StubRuntime` fails every sandbox operation with "stub runtime: not
/// implemented", which makes it a usable witness: if the lint gate
/// short-circuits, the error names the rule; if it does not, the error is the
/// stub's.
fn test_container() -> ServiceContainer {
    common::install_managed_workspace("oxfuzz-harness-lint");
    ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
}

async fn compile(
    source: &str,
) -> Result<hf_service::CompileOutcome, hf_core::error::ClassifiedError> {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("a.c"), "int a(void){return 0;}").unwrap();
    test_container()
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "a",
            TargetLanguage::C,
        )
        .await
}

#[tokio::test]
async fn a_harness_calling_exit_never_reaches_the_sandbox() {
    let error = compile(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){ if(!n) exit(1); return 0; }",
    )
    .await
    .expect_err("a lint error must fail the compile");

    let text = format!("{error}");
    assert!(text.contains("no-process-exit"), "{text}");
    assert!(
        !text.contains("stub runtime"),
        "reached the sandbox: {text}"
    );
}

#[tokio::test]
async fn a_harness_opening_a_socket_never_reaches_the_sandbox() {
    let error = compile(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){ socket(1,2,3); return 0; }",
    )
    .await
    .expect_err("a lint error must fail the compile");

    assert!(format!("{error}").contains("no-network"), "{error}");
}

#[tokio::test]
async fn a_lint_warning_does_not_block_the_compile() {
    let error = compile(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long n){ srand(1); return (int)(n % 2); }",
    )
    .await
    .expect_err("the stub sandbox always fails the build");

    // It got past the lint and died in the stub sandbox, which is the pass
    // condition: a warning must not short-circuit.
    let text = format!("{error}");
    assert!(
        !text.contains("no-nondeterminism"),
        "warning blocked: {text}"
    );
}
