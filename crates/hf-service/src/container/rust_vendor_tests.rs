//! A Rust crate that carries its crates.io dependencies in a `vendor/` tree
//! builds and fuzzes in the sandbox with no network.
//!
//! The live test needs the pinned sandbox image.

use std::path::Path;

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{Sanitizer, TargetLanguage};
use uuid::Uuid;

use super::harness_workspace::copy_project_sources;

const CRATE_TOML: &str = "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntinydep = \"1\"\n";

/// The crate under test hands an input byte to its dependency as an index.
const CRATE_LIB: &str = "pub fn parse(data: &[u8]) -> u8 {\n    if data.len() > 2 && data[0] == b'R' {\n        return tinydep::at(data[1] as usize);\n    }\n    0\n}\n";

const DEP_TOML: &str = "[package]\nname = \"tinydep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n";

/// The dependency indexes a three-entry table without a bounds check of its
/// own, so the planted panic is inside the vendored crate.
const DEP_LIB: &str =
    "const TABLE: [u8; 3] = [1, 2, 3];\npub fn at(index: usize) -> u8 {\n    TABLE[index]\n}\n";

/// What `cargo vendor` records for a crate; no file checksums to verify.
const DEP_CHECKSUM: &str = "{\"files\":{},\"package\":null}";

const HARNESS: &str = "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\nfuzz_target!(|data: &[u8]| {\n    let _ = demo::parse(data);\n});\n";

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn harness() -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: HARNESS.to_owned(),
        language: TargetLanguage::Rust,
        build_cmd: BuildCommand {
            compiler: "cargo".to_owned(),
            args: Vec::new(),
            output: "fuzz_parse".into(),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    }
}

async fn build(
    runtime: &hf_runtime::docker::DockerRuntime,
    project: &Path,
    workspace: &Path,
) -> hf_harness::CompileResult {
    std::fs::create_dir_all(workspace).unwrap();
    copy_project_sources(project, workspace);
    hf_harness::try_compile_with_options(
        harness(),
        runtime,
        workspace,
        &hf_core::runtime::SandboxOptions::default(),
    )
    .await
    .unwrap()
}

/// Without the vendored crate the offline build cannot resolve the
/// dependency and says so; with it, the crate builds, and the fuzzer finds
/// the panic planted inside the vendored crate.
#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_cargo_fuzz_builds_against_a_vendored_crate() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let project = tempfile::tempdir().unwrap();
    write(project.path(), "Cargo.toml", CRATE_TOML);
    write(project.path(), "src/lib.rs", CRATE_LIB);

    let hf_harness::CompileResult::Failed(failure) =
        build(&runtime, project.path(), &root.path().join("bare")).await
    else {
        panic!("the build must fail without the vendored crate");
    };
    let message = format!("{}{}", failure.stdout, failure.stderr);
    assert!(message.contains("tinydep"), "{message}");

    write(project.path(), "vendor/tinydep/Cargo.toml", DEP_TOML);
    write(project.path(), "vendor/tinydep/src/lib.rs", DEP_LIB);
    write(
        project.path(),
        "vendor/tinydep/.cargo-checksum.json",
        DEP_CHECKSUM,
    );
    let workspace = root.path().join("ws");
    let built = match build(&runtime, project.path(), &workspace).await {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("cargo fuzz failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    let config = FuzzRunConfig {
        harness_id: built.id,
        engine: built.engine,
        duration: Some(std::time::Duration::from_secs(30)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: built.sanitizer,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    };
    let smoked = hf_harness::generator::smoke_fuzz_in_paths_with_config_and_sandbox_image(
        built,
        &runtime,
        &workspace,
        Path::new("corpus"),
        Path::new("out"),
        &config,
        None,
    )
    .await
    .unwrap();
    let summary = smoked.smoke_run.clone().unwrap();
    println!("vendored smoke: {summary:?}");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed, "the harness ran");
    assert!(summary.crashes > 0, "the planted defect was found");
}
