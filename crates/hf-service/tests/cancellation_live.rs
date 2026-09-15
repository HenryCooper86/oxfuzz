//! Explicitly approved live userspace-engine qualification. See examples/qualification/README.md.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};

const TARGET: &str = include_str!("../../../examples/qualification/parser.c");
const HARNESS: &str = include_str!("../../../examples/qualification/harness.c");

fn approved_sources(value: &str) -> bool {
    let mut hash = Sha256::new();
    hash.update(TARGET.as_bytes());
    hash.update(b"\0");
    hash.update(HARNESS.as_bytes());
    value == format!("{:x}", hash.finalize())
}

#[test]
fn live_approval_is_bound_to_both_source_files() {
    assert!(approved_sources(
        "a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591"
    ));
    assert!(!approved_sources("yes"));
    assert!(!approved_sources(""));
}

async fn sandbox_names() -> BTreeSet<String> {
    let mut command = tokio::process::Command::new(hf_runtime::docker_bin());
    command
        .args(["ps", "--format", "{{.Names}}", "--filter", "name=hf-run-"])
        .kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bounded Docker inventory")
        .expect("Docker inventory");
    assert!(result.status.success(), "Docker inventory failed");
    String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

async fn qualify_engine(container: Arc<ServiceContainer>, root: &Path, engine: EngineKind) {
    let project = root.join(engine.as_str());
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("parser.c"), TARGET).unwrap();
    let compiled = container
        .harness_compile(
            HARNESS.to_owned(),
            &project,
            engine,
            "qualification_parse",
            TargetLanguage::C,
        )
        .await
        .expect("sandbox compile");
    let workspace = hf_service::workspace_dir(&project, "qualification_parse");
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join("corpus/seed"), b"OX\0\xff").unwrap();
    let smoke = container
        .harness_smoke(&project, "qualification_parse", engine, TargetLanguage::C)
        .await
        .expect("real provider review and sandbox smoke");
    assert_eq!(
        smoke.verdict.level,
        hf_service::verification::VerdictLevel::Pass
    );
    let promoted = container
        .harness_promote(&project, "qualification_parse", engine)
        .await
        .expect("promotion after source approval and measured smoke");
    assert_eq!(promoted.id, compiled.harness_id);

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress = Arc::new(tokio::sync::Notify::new());
    let runner = {
        let container = Arc::clone(&container);
        let project = project.clone();
        let progress = Arc::clone(&progress);
        tokio::spawn(async move {
            container
                .run_fuzzer_observed(
                    &project,
                    "qualification_parse",
                    engine,
                    10,
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
        .expect("run admission deadline")
        .expect("durable run id");
    tokio::time::timeout(Duration::from_secs(30), progress.notified())
        .await
        .expect("measured engine progress");
    let cancel_started = Instant::now();
    assert!(
        container.cancel_run(run_id),
        "Stop addresses the exact live run"
    );
    let summary = tokio::time::timeout(Duration::from_secs(15), runner)
        .await
        .expect("Stop completes within 15 seconds")
        .expect("campaign task")
        .expect("cancelled campaign closeout");
    let stop_ms = cancel_started.elapsed().as_millis();
    assert_eq!(summary.run_id, run_id);
    assert!(container.active_run_ids().is_empty());
    let replay = container
        .replay_run(run_id, &|_| {})
        .await
        .expect("retained-input sandbox replay");
    assert_ne!(replay.run_id, run_id);
    #[cfg(feature = "proof-carrying")]
    {
        let coverage = serde_json::to_value(
            container
                .run_function_coverage(replay.run_id)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(coverage["status"], "available");
        assert!(coverage["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["name"]
                .as_str()
                .is_some_and(|name| name.contains("qualification_parse"))
                && function["count"].as_str().is_some_and(|count| count != "0")));
    }
    let evidence = serde_json::json!({
        "engine": engine.as_str(), "harness_id": compiled.harness_id,
        "smoke": smoke, "campaign_run_id": run_id, "replay_run_id": replay.run_id,
        "stop_ms": stop_ms, "observed_at": chrono::Utc::now(),
    });
    std::fs::write(
        project.join("qualification.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    eprintln!(
        "{} qualification retained at {}",
        engine.as_str(),
        project.display()
    );
}

#[tokio::test]
#[ignore = "requires explicit source approval, configured review provider, Docker, and sandbox image"]
async fn stop_button_cancels_a_real_fuzz_run() {
    let approval =
        std::env::var("OXFUZZ_LIVE_APPROVAL_SHA256").expect("approve the concrete sources first");
    assert!(
        approved_sources(&approval),
        "approval must match the exact target and harness source digest"
    );
    assert!(
        hf_runtime::docker_daemon_ready(),
        "Docker must be available; no stub fallback"
    );
    let pool = hf_service::provider_pool_from_config()
        .or_else(hf_service::provider_pool_from_env)
        .expect("a real configured provider must review the exact source before smoke");
    let parent = std::env::var_os("OXFUZZ_LIVE_EVIDENCE_ROOT")
        .expect("select a durable disposable evidence directory");
    let root = Path::new(&parent).join(format!("qualification-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    hf_service::initialize_workspace_root().unwrap();
    hf_service::config::write_config("oxfuzz", "[fuzzing]\ncollect_function_coverage = true\nenabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\"]\ndefault_engine = \"libfuzzer\"\ndefault_duration_secs = 10\n[fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 10\n").unwrap();
    let runtime = Arc::new(hf_runtime::docker::DockerRuntime::new(
        hf_runtime::RuntimeConfig::default(),
        &root.join("workspace"),
    ));
    let store = Arc::new(
        hf_storage::Store::connect(root.join("qualification.db"))
            .await
            .unwrap(),
    );
    let container = Arc::new(ServiceContainer::new(runtime, Some(pool)).with_store(store));
    let before = sandbox_names().await;
    eprintln!("Live qualification evidence: {}", root.display());
    for engine in [
        EngineKind::LibFuzzer,
        EngineKind::AflPlusPlus,
        EngineKind::Honggfuzz,
    ] {
        qualify_engine(Arc::clone(&container), &root, engine).await;
        let after = sandbox_names().await;
        assert!(
            after.difference(&before).next().is_none(),
            "new sandbox containers remain after closeout: {after:?}"
        );
    }
}
