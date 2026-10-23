#![cfg(feature = "managed-mutators")]

use hf_core::{engine::EngineKind, target::TargetLanguage};
use hf_harness::managed_mutator::{compose, inspect};

const BASE: &str = "#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return n && d[0]; }";
const AFL: &str = "void *afl_custom_init(void *afl,unsigned int seed){return afl;} void afl_custom_deinit(void *state){} size_t afl_custom_fuzz(void *s, unsigned char *b, size_t n, unsigned char **o, unsigned char *a, size_t z, size_t m) { *o=b; return n; }";
const LLVM: &str = "size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) { return size; }";

#[test]
fn import_binds_native_source_and_survives_roundtrip() {
    for (engine, source) in [
        (EngineKind::AflPlusPlus, AFL),
        (EngineKind::LibFuzzer, LLVM),
    ] {
        let composed = compose(BASE, source, engine, TargetLanguage::C).unwrap();
        let parsed = inspect(&composed, engine, TargetLanguage::C)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.base, BASE);
        assert_eq!(parsed.mutator, source);
        assert!(composed.contains("oxfuzz_user_mutate"));
        assert_eq!(parsed.source_sha256.len(), 64);
        let modified = composed.replacen("return n;", "return 0;", 1);
        if modified != composed {
            assert!(inspect(&modified, engine, TargetLanguage::C).is_err());
        }
    }
}

#[test]
fn unsupported_engines_and_partial_trim_callbacks_fail_before_compile() {
    assert!(compose(BASE, AFL, EngineKind::Honggfuzz, TargetLanguage::C).is_err());
    assert!(compose(BASE, LLVM, EngineKind::LibFuzzer, TargetLanguage::Rust).is_err());
    assert!(compose(
        BASE,
        &format!(
            "{AFL}\nint afl_custom_init_trim(void *s, unsigned char*b, size_t n){{return 1;}}"
        ),
        EngineKind::AflPlusPlus,
        TargetLanguage::C
    )
    .is_err());
    assert!(compose(
        BASE,
        &"x".repeat(65537),
        EngineKind::AflPlusPlus,
        TargetLanguage::C
    )
    .is_err());
}

struct Runtime {
    calls: std::sync::Mutex<Vec<(Vec<String>, Option<String>)>>,
    witness: bool,
    smoke_exit: i32,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for Runtime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.run_command_opts(
            cmd,
            cwd,
            limits,
            &hf_core::runtime::SandboxOptions::default(),
        )
        .await
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
        options: &hf_core::runtime::SandboxOptions,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.calls
            .lock()
            .unwrap()
            .push((cmd.to_vec(), options.image.clone()));
        if cmd.first().is_some_and(|value| value == "bash") {
            let name = if cmd.join(" ").contains("-DOXFUZZ_MUTATOR_BUILD") {
                "fuzz_test.mutator.so"
            } else {
                "fuzz_test"
            };
            std::fs::write(cwd.join(name), format!("built:{name}")).unwrap();
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code: if cmd.first().is_some_and(|value| value == "bash") {
                0
            } else {
                self.smoke_exit
            },
            stdout: String::new(),
            stderr: format!(
                "exec/s: 20\n{}",
                if self.witness {
                    "OXFUZZ_NATIVE_MUTATION_OK_V1"
                } else {
                    ""
                }
            ),
            workspace: cwd.into(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        std::fs::write(path, content).unwrap();
        Ok(())
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap())
    }
}

fn harness(engine: EngineKind) -> hf_core::harness::Harness {
    let mutator = if engine == EngineKind::AflPlusPlus {
        AFL
    } else {
        LLVM
    };
    hf_core::harness::Harness {
        id: uuid::Uuid::new_v4(),
        target_id: uuid::Uuid::new_v4(),
        engine,
        source: compose(BASE, mutator, engine, TargetLanguage::C).unwrap(),
        language: TargetLanguage::C,
        build_cmd: hf_harness::build_command(
            engine,
            TargetLanguage::C,
            "fuzz_test",
            hf_core::target::Sanitizer::Address,
        )
        .unwrap(),
        sanitizer: hf_core::target::Sanitizer::Address,
        status: hf_core::harness::HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    }
}

#[tokio::test]
async fn afl_library_build_uses_the_pinned_sandbox_and_retains_identity() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime {
        calls: std::sync::Mutex::new(vec![]),
        witness: true,
        smoke_exit: 0,
    };
    let image = format!("sha256:{}", "a".repeat(64));
    let options = hf_core::runtime::SandboxOptions {
        image: Some(image.clone()),
        ..Default::default()
    };
    let built = hf_harness::compile_with_options(
        harness(EngineKind::AflPlusPlus),
        &runtime,
        directory.path(),
        &options,
    )
    .await
    .unwrap();
    let record = built.custom_mutator.unwrap();
    assert_eq!(record.sandbox_image_id, image);
    assert_eq!(record.artifact_name, "fuzz_test.mutator.so");
    assert_eq!(record.artifact_sha256.len(), 64);
    let calls = runtime.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls[1].0.join(" ").contains("-shared"));
    assert!(calls[1].0.join(" ").contains("-DOXFUZZ_MUTATOR_BUILD"));
    assert!(calls.iter().all(|(_, image)| image == &options.image));
}

#[tokio::test]
async fn libfuzzer_mutator_is_linked_into_the_existing_target_build() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime {
        calls: std::sync::Mutex::new(vec![]),
        witness: true,
        smoke_exit: 0,
    };
    let options = hf_core::runtime::SandboxOptions {
        image: Some(format!("sha256:{}", "b".repeat(64))),
        ..Default::default()
    };
    let built = hf_harness::compile_with_options(
        harness(EngineKind::LibFuzzer),
        &runtime,
        directory.path(),
        &options,
    )
    .await
    .unwrap();
    assert_eq!(built.custom_mutator.unwrap().artifact_name, "fuzz_test");
    assert_eq!(runtime.calls.lock().unwrap().len(), 1);
}

fn smoke_config(harness: &hf_core::harness::Harness) -> hf_core::engine::FuzzRunConfig {
    hf_core::engine::FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(std::time::Duration::from_secs(2)),
        max_mem_mb: 4096,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: harness.sanitizer,
        env: vec![],
        extra_args: vec![],
        seed: Some(42),
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    }
}

#[tokio::test]
async fn native_smoke_needs_a_callback_observation_and_successful_engine_exit() {
    for (witness, smoke_exit, passed) in [(false, 0, false), (true, 1, false), (true, 0, true)] {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Runtime {
            calls: std::sync::Mutex::new(vec![]),
            witness,
            smoke_exit,
        };
        let options = hf_core::runtime::SandboxOptions {
            image: Some(format!("sha256:{}", "b".repeat(64))),
            ..Default::default()
        };
        let built = hf_harness::compile_with_options(
            harness(EngineKind::LibFuzzer),
            &runtime,
            directory.path(),
            &options,
        )
        .await
        .unwrap();
        let config = smoke_config(&built);
        let smoked = hf_harness::smoke_fuzz_in_paths_with_config_and_sandbox_image(
            built,
            &runtime,
            directory.path(),
            std::path::Path::new("corpus"),
            std::path::Path::new("out"),
            &config,
            options.image,
        )
        .await
        .unwrap();
        assert_eq!(
            smoked.smoke_run.unwrap().passed,
            passed,
            "witness={witness}, exit={smoke_exit}"
        );
        assert!(smoked.custom_mutator.unwrap().self_test.is_some());
    }
}

#[tokio::test]
async fn native_smoke_rejects_a_different_image_before_runtime_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime {
        calls: std::sync::Mutex::new(vec![]),
        witness: true,
        smoke_exit: 0,
    };
    let options = hf_core::runtime::SandboxOptions {
        image: Some(format!("sha256:{}", "b".repeat(64))),
        ..Default::default()
    };
    let built = hf_harness::compile_with_options(
        harness(EngineKind::LibFuzzer),
        &runtime,
        directory.path(),
        &options,
    )
    .await
    .unwrap();
    let config = smoke_config(&built);
    let before = runtime.calls.lock().unwrap().len();
    let denied = hf_harness::smoke_fuzz_in_paths_with_config_and_sandbox_image(
        built,
        &runtime,
        directory.path(),
        std::path::Path::new("corpus"),
        std::path::Path::new("out"),
        &config,
        Some(format!("sha256:{}", "c".repeat(64))),
    )
    .await;
    assert!(denied.is_err());
    assert_eq!(before, runtime.calls.lock().unwrap().len());
}

#[test]
fn afl_import_requires_native_lifecycle_and_libfuzzer_rejects_afl_trim_hooks() {
    assert!(compose(
        BASE,
        "size_t afl_custom_fuzz(void);",
        EngineKind::AflPlusPlus,
        TargetLanguage::C
    )
    .is_err());
    assert!(compose(
        BASE,
        &format!("{LLVM} afl_custom_init_trim afl_custom_trim afl_custom_post_trim"),
        EngineKind::LibFuzzer,
        TargetLanguage::C
    )
    .is_err());
}

#[test]
fn native_import_preserves_existing_afl_persistent_configuration_macros() {
    let base = format!("#define OXFUZZ_PERSISTENT_LOOP_DEFAULT 1000\n{BASE}");
    let source = compose(&base, AFL, EngineKind::AflPlusPlus, TargetLanguage::C).unwrap();
    assert_eq!(
        inspect(&source, EngineKind::AflPlusPlus, TargetLanguage::C)
            .unwrap()
            .unwrap()
            .base,
        base
    );
}
