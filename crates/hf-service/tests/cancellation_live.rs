//! Live, Docker-backed cancellation test.
//!
//! Exercises the exact path the GUI Stop button triggers: a real `run_fuzzer`
//! campaign through `EngineRunner` + `DockerRuntime`, cancelled mid-run via
//! `cancel_all_runs` (what the `cancel_run` Tauri command calls). Ignored by
//! default because it needs a running Docker daemon and the
//! `oxfuzz/fuzz-sandbox` image; run explicitly with:
//!
//! ```text
//! cargo test -p hf-service --test cancellation_live -- --ignored --nocapture
//! ```

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hf_service::ServiceContainer;

/// Keep the (now persistent) fuzz workspace out of the real per-user data dir
/// by redirecting it to a temp dir for this test.
fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_cancel_live_workspace_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().expect("initialize managed live-test workspace");
    });
}

#[tokio::test]
#[ignore = "requires Docker + oxfuzz/fuzz-sandbox image"]
async fn stop_button_cancels_a_real_fuzz_run() {
    isolate_workspace();
    let project = std::env::temp_dir().join("hf_cancel_live_proj");
    std::fs::create_dir_all(&project).unwrap();
    let target = "demo";
    std::fs::write(
        project.join("demo.c"),
        "#include <stddef.h>\nint demo(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    // Lay down a workspace with a trivial-but-real libFuzzer harness and a seed.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("seed"), b"hello").unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.join("cancel-live.db"))
            .await
            .unwrap(),
    );
    let container =
        Arc::new(ServiceContainer::new(hf_service::runtime_from_env(), None).with_store(store));
    let source = "#include <stdint.h>\n#include <stddef.h>\n\
        int demo(const unsigned char *data, size_t size);\n\
        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return demo(data, size); }\n";
    container
        .harness_compile(
            source.to_owned(),
            &project,
            hf_core::engine::EngineKind::LibFuzzer,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("sandbox compile");
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::LibFuzzer,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("sandbox smoke");
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::LibFuzzer)
        .await
        .expect("explicit test approval");

    // Start a 600s campaign; without cancellation it would run for ten minutes.
    let runner = {
        let container = Arc::clone(&container);
        let project = project.clone();
        tokio::spawn(async move {
            container
                .run_fuzzer(
                    &project,
                    target,
                    hf_core::engine::EngineKind::LibFuzzer,
                    600,
                    &|_| {},
                )
                .await
        })
    };

    // Wait until the run registers, then let the container actually spin up.
    let mut found = false;
    for _ in 0..400 {
        if !container.active_run_ids().is_empty() {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found, "run never registered as active");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // This is exactly what the GUI `cancel_run` command does.
    let started = Instant::now();
    let signalled = container.cancel_all_runs();
    assert_eq!(signalled, 1, "one run should be signalled");

    // The run must return far sooner than its 600s budget.
    let summary = tokio::time::timeout(Duration::from_secs(90), runner)
        .await
        .expect("run should stop promptly after cancel")
        .expect("task join")
        .expect("run_fuzzer returns Ok on cancel");
    let elapsed = started.elapsed();
    eprintln!(
        "cancel -> stop took {:?}; summary: edges={} crashes={} execs={:.0}",
        elapsed, summary.edges, summary.crashes, summary.execs
    );
    assert!(
        elapsed < Duration::from_secs(90),
        "cancel did not stop the run promptly"
    );
    assert!(
        container.active_run_ids().is_empty(),
        "registry should be empty after the run returns"
    );

    // No sandbox container should be left running.
    let ps = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}", "--filter", "name=hf-run-"])
        .output()
        .expect("docker ps");
    let names = String::from_utf8_lossy(&ps.stdout);
    assert!(
        names.trim().is_empty(),
        "a sandbox container leaked after cancel: {names}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
