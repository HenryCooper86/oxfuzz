//! Exact-source-approved Rust cargo-fuzz qualification.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};

const SOURCES: [(&str, &str); 5] = [
    (
        "Cargo.toml",
        include_str!("../../../examples/qualification/rust/Cargo.toml"),
    ),
    (
        "src/lib.rs",
        include_str!("../../../examples/qualification/rust/src/lib.rs"),
    ),
    (
        "crates/codec/Cargo.toml",
        include_str!("../../../examples/qualification/rust/crates/codec/Cargo.toml"),
    ),
    (
        "crates/codec/src/lib.rs",
        include_str!("../../../examples/qualification/rust/crates/codec/src/lib.rs"),
    ),
    (
        "harness.rs",
        include_str!("../../../examples/qualification/rust/harness.rs"),
    ),
];

fn approved_sources(value: &str) -> bool {
    let mut hash = Sha256::new();
    for (path, source) in SOURCES {
        hash.update(path.as_bytes());
        hash.update(b"\0");
        hash.update(source.as_bytes());
        hash.update(b"\0");
    }
    value == format!("{:x}", hash.finalize())
}

#[test]
fn rust_approval_is_bound_to_every_workspace_source() {
    assert!(approved_sources(
        "d3bdffb5321b4012f42e7827b996fdee7e0ea8583917cf2d1f55f726d7cd2380"
    ));
    assert!(!approved_sources("yes"));
    assert!(!approved_sources(""));
}

async fn sandbox_names() -> BTreeSet<String> {
    let mut command = tokio::process::Command::new(hf_runtime::docker_bin());
    command
        .args([
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            "name=hf-run-",
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bounded Docker inventory")
        .expect("Docker inventory");
    assert!(output.status.success(), "Docker inventory failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
#[ignore = "requires exact Rust source approval, provider, Docker, and sandbox image"]
async fn approved_rust_workspace_completes_userspace_lifecycle() {
    let approval =
        std::env::var("OXFUZZ_RUST_APPROVAL_SHA256").expect("approve exact Rust sources first");
    assert!(approved_sources(&approval), "Rust source approval mismatch");
    assert!(
        hf_runtime::docker_daemon_ready(),
        "Docker must be available"
    );
    let pool = hf_service::provider_pool_from_config()
        .or_else(hf_service::provider_pool_from_env)
        .expect("real configured provider required for independent review");
    let parent = std::env::var_os("OXFUZZ_LIVE_EVIDENCE_ROOT")
        .expect("select a durable disposable evidence directory");
    let root = Path::new(&parent).join(format!("rust-qualification-{}", uuid::Uuid::new_v4()));
    let project = root.join("project");
    for (path, source) in SOURCES.iter().filter(|(path, _)| *path != "harness.rs") {
        let destination = project.join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, source).unwrap();
    }
    std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    hf_service::initialize_workspace_root().unwrap();
    hf_service::config::write_config("oxfuzz", "[fuzzing]\ncollect_function_coverage = true\nenabled_engines = [\"libfuzzer\"]\ndefault_engine = \"libfuzzer\"\ndefault_duration_secs = 10\n[fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 10\n").unwrap();
    let runtime = Arc::new(hf_runtime::docker::DockerRuntime::new(
        hf_runtime::RuntimeConfig::default(),
        &root.join("workspace"),
    ));
    let store = Arc::new(
        hf_storage::Store::connect(root.join("qualification.db"))
            .await
            .unwrap(),
    );
    let service = Arc::new(ServiceContainer::new(runtime, Some(pool)).with_store(store));
    let before = sandbox_names().await;
    let compiled = service
        .harness_compile(
            SOURCES[4].1.to_owned(),
            &project,
            EngineKind::LibFuzzer,
            "parse_record",
            TargetLanguage::Rust,
            None,
        )
        .await
        .expect("sandbox cargo-fuzz build");
    let workspace = hf_service::workspace_dir(&project, "parse_record");
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join("corpus/seed"), b"OX\x03abc").unwrap();
    let smoke = service
        .harness_smoke(
            &project,
            "parse_record",
            EngineKind::LibFuzzer,
            TargetLanguage::Rust,
        )
        .await
        .expect("provider review and sandbox smoke");
    assert_eq!(
        smoke.verdict.level,
        hf_service::verification::VerdictLevel::Pass
    );
    let promoted = service
        .harness_promote(&project, "parse_record", EngineKind::LibFuzzer)
        .await
        .expect("explicit promotion after smoke");
    assert_eq!(promoted.id, compiled.harness_id);

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress = Arc::new(tokio::sync::Notify::new());
    let mut runner = {
        let service = Arc::clone(&service);
        let project = project.clone();
        let progress = Arc::clone(&progress);
        tokio::spawn(async move {
            service
                .run_fuzzer_observed(
                    &project,
                    "parse_record",
                    EngineKind::LibFuzzer,
                    10,
                    None,
                    None,
                    None,
                    None,
                    &|event| {
                        if matches!(event, FuzzProgress::ExecsPerSec(value) if value > 0.0) {
                            progress.notify_one();
                        }
                    },
                    &|id| {
                        started_tx.send(id).unwrap();
                    },
                )
                .await
        })
    };
    let run_id = tokio::time::timeout(Duration::from_secs(30), started_rx.recv())
        .await
        .expect("durable run admission deadline")
        .expect("durable run id");
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), progress.notified()) => {
            result.expect("measured engine progress");
        }
        result = &mut runner => panic!("campaign ended before progress: {result:?}"),
    }
    let cancel_started = Instant::now();
    assert!(service.cancel_run(run_id), "Stop addresses the live run");
    let summary = tokio::time::timeout(Duration::from_secs(15), runner)
        .await
        .expect("Stop deadline")
        .expect("campaign task")
        .expect("cancelled campaign closeout");
    assert_eq!(summary.run_id, run_id);
    let stop_ms = cancel_started.elapsed().as_millis();
    let replay = service
        .replay_run(run_id, &|_| {})
        .await
        .expect("sandbox retained-input replay");
    assert_ne!(replay.run_id, run_id);
    let function_coverage =
        serde_json::to_value(service.run_function_coverage(replay.run_id).await.unwrap()).unwrap();
    assert_eq!(function_coverage["status"], "unavailable");
    let after = sandbox_names().await;
    assert!(
        after.difference(&before).next().is_none(),
        "new sandbox containers remain: {after:?}"
    );
    std::fs::write(
        root.join("qualification.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "harness_id": compiled.harness_id,
            "smoke": smoke,
            "campaign_run_id": run_id,
            "replay_run_id": replay.run_id,
            "stop_ms": stop_ms,
            "function_coverage": function_coverage,
            "crash_reproduction": "not_exercised_no_crash",
            "observed_at": chrono::Utc::now(),
        }))
        .unwrap(),
    )
    .unwrap();
}
