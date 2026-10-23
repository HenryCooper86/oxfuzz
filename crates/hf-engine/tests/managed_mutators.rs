//! Denials are exercised through the dispatcher that would invoke AFL++.
use hf_core::{
    engine::{EngineKind, FuzzRunConfig},
    error::ClassifiedError,
    runtime::{CommandResult, ResourceLimits, RuntimeAdapter, SandboxMount, SandboxOptions},
    target::Sanitizer,
};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Runtime(AtomicUsize);
#[async_trait::async_trait]
impl RuntimeAdapter for Runtime {
    async fn run_command(
        &self,
        _: &[String],
        _: &Path,
        _: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ClassifiedError::Internal(
            "unexpected runtime dispatch".into(),
        ))
    }
    async fn write_file(&self, _: &Path, _: &str) -> Result<(), ClassifiedError> {
        panic!("unexpected write")
    }
    async fn read_file(&self, _: &Path) -> Result<String, ClassifiedError> {
        panic!("unexpected read")
    }
}
fn config() -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: uuid::Uuid::new_v4(),
        engine: EngineKind::AflPlusPlus,
        duration: Some(std::time::Duration::from_secs(1)),
        max_mem_mb: 4096,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::Address,
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
async fn dispatcher_rejects_foreign_plugins_before_calling_runtime() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"retained native library";
    std::fs::write(root.path().join("plugin.so"), bytes).unwrap();
    let image = format!("sha256:{}", "a".repeat(64));
    let base = vec![
        (
            "AFL_CUSTOM_MUTATOR_LIBRARY".into(),
            "/work/plugin.so".into(),
        ),
        (
            "OXFUZZ_MUTATOR_SHA256".into(),
            format!("{:x}", Sha256::digest(bytes)),
        ),
        ("OXFUZZ_MUTATOR_IMAGE_ID".into(), image.clone()),
    ];
    for scenario in [
        "digest",
        "image",
        "writable",
        "foreign_path",
        "duplicate",
        "unsupported",
        "writable_mount",
        "duplicate_mount",
        "python",
    ] {
        let mut config = config();
        config.env = base.clone();
        let mut sandbox = SandboxOptions {
            image: Some(image.clone()),
            workspace_read_only: true,
            ..Default::default()
        };
        match scenario {
            "digest" => config.env[1].1 = "0".repeat(64),
            "image" => sandbox.image = Some(format!("sha256:{}", "b".repeat(64))),
            "writable" => sandbox.workspace_read_only = false,
            "foreign_path" => config.env[0].1 = "/work/../plugin.so".into(),
            "duplicate" => config.env.push(config.env[0].clone()),
            "unsupported" => config.engine = EngineKind::Honggfuzz,
            "writable_mount" => sandbox.extra_mounts.push(SandboxMount::writable(
                root.path().into(),
                "/work/plugin.so",
            )),
            "duplicate_mount" => {
                config.env[0].1 = "/work/lib/plugin.so".into();
                sandbox.extra_mounts.push(SandboxMount {
                    host_path: root.path().into(),
                    container_path: "/work/lib".into(),
                    read_only: true,
                });
                sandbox
                    .extra_mounts
                    .push(SandboxMount::writable(root.path().into(), "/work/lib"));
            }
            "python" => config
                .env
                .push(("AFL_PYTHON_MODULE".into(), "foreign".into())),
            _ => unreachable!(),
        }
        let runtime = Runtime(AtomicUsize::new(0));
        let result = hf_engine::runner::EngineRunner::new()
            .run_streaming_opts(
                config.engine,
                &config,
                "/work/target",
                "/work/corpus",
                "/work/out",
                &runtime,
                root.path(),
                &sandbox,
                &tokio_util::sync::CancellationToken::new(),
                &|_| {},
            )
            .await;
        assert!(
            matches!(result, Err(error) if error.to_string().contains("managed mutator")),
            "{scenario}"
        );
        assert_eq!(runtime.0.load(Ordering::SeqCst), 0, "{scenario}");
    }
}

#[cfg(not(feature = "managed-mutators"))]
#[tokio::test]
async fn feature_disabled_dispatch_rejects_native_plugin_requests() {
    let root = tempfile::tempdir().unwrap();
    let mut config = config();
    config.env.push((
        "AFL_CUSTOM_MUTATOR_LIBRARY".into(),
        "/work/plugin.so".into(),
    ));
    let runtime = Runtime(AtomicUsize::new(0));
    let error = hf_engine::runner::EngineRunner::new()
        .run_streaming_opts(
            config.engine,
            &config,
            "/work/target",
            "/work/corpus",
            "/work/out",
            &runtime,
            root.path(),
            &SandboxOptions::default(),
            &tokio_util::sync::CancellationToken::new(),
            &|_| {},
        )
        .await;
    assert!(matches!(error, Err(error) if error.to_string().contains("feature is disabled")));
    assert_eq!(runtime.0.load(Ordering::SeqCst), 0);
}
