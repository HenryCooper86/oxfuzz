//! `MemorySanitizer` for C++ targets against the sandbox image's instrumented
//! libc++: the admitted engines report a planted uninitialized read and keep
//! a control that uses the standard library clean.

use std::path::Path;

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::{Sanitizer, TargetLanguage};
use uuid::Uuid;

/// A classifier that leans on `std::map`, `std::vector`, and string streams.
/// `PLANTED` adds a branch on a stack slot that was never written.
const HARNESS_BODY: &str = "#include <cstddef>\n#include <cstdint>\n#include <map>\n#include <sstream>\n#include <string>\n#include <vector>\n\n__attribute__((noinline)) static int classify(const std::string &text) {\n  int table[4];\n  table[0] = 1;\n  std::vector<int> seen;\n  std::map<std::string, int> counts;\n  std::istringstream stream(text);\n  std::string word;\n  while (stream >> word) {\n    counts[word]++;\n    seen.push_back(static_cast<int>(word.size()));\n  }\n#ifdef PLANTED\n  if (text.size() > 2 && text[0] == 'M' && text[1] == 'S') {\n    if (table[1 + text.size() % 3]) return 7;\n  }\n#endif\n  return static_cast<int>(counts.size() + seen.size()) + table[0];\n}\n\nextern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  static volatile int sink;\n  sink = classify(std::string(reinterpret_cast<const char *>(data), size));\n  return 0;\n}\n";

fn harness(engine: EngineKind, planted: bool) -> Harness {
    let source = if planted {
        format!("#define PLANTED 1\n{HARNESS_BODY}")
    } else {
        HARNESS_BODY.to_owned()
    };
    let build_cmd = hf_harness::build_command_for_source(
        engine,
        TargetLanguage::Cpp,
        "fuzz_classify",
        Sanitizer::Memory,
        &source,
    )
    .unwrap();
    Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine,
        source,
        language: TargetLanguage::Cpp,
        build_cmd,
        sanitizer: Sanitizer::Memory,
        status: HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    }
}

async fn build_and_smoke(
    runtime: &hf_runtime::docker::DockerRuntime,
    workspace: &Path,
    engine: EngineKind,
    planted: bool,
) -> Harness {
    std::fs::create_dir_all(workspace).unwrap();
    let built = match hf_harness::try_compile_with_options(
        harness(engine, planted),
        runtime,
        workspace,
        &hf_core::runtime::SandboxOptions::default(),
    )
    .await
    .unwrap()
    {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("build failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    let config = FuzzRunConfig {
        harness_id: built.id,
        engine,
        duration: Some(std::time::Duration::from_secs(30)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::Memory,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    };
    hf_harness::generator::smoke_fuzz_in_paths_with_config_and_sandbox_image(
        built,
        runtime,
        workspace,
        Path::new("corpus"),
        Path::new("out"),
        &config,
        None,
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_cpp_memory_sanitizer_reports_a_planted_read_and_keeps_a_control_clean() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    for engine in [EngineKind::LibFuzzer, EngineKind::Honggfuzz] {
        let name = engine.as_str();
        let planted = build_and_smoke(
            &runtime,
            &root.path().join(format!("{name}-planted")),
            engine,
            true,
        )
        .await;
        let summary = planted.smoke_run.clone().unwrap();
        println!("{name} planted: {summary:?}");
        assert!(summary.crashes > 0, "{name}: the planted read was reported");

        let control = build_and_smoke(
            &runtime,
            &root.path().join(format!("{name}-control")),
            engine,
            false,
        )
        .await;
        let summary = control.smoke_run.clone().unwrap();
        println!("{name} control: {summary:?}");
        assert_eq!(summary.crashes, 0, "{name}: the control is clean");
        assert!(summary.passed, "{name}: the control smoke passed");
    }
}
