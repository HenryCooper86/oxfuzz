//! A campaign, Stop, and resume without a provider: an AFL++ harness is built
//! in the sandbox, fuzzed until the host can read measured progress from the
//! engine's own files, stopped on request, and continued from the same output
//! tree. The sources are constants and nothing asks a model for anything, so
//! this runs on any host with Docker and the pinned image.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::runtime::{CommandTermination, SandboxMount, SandboxOptions};
use hf_core::target::{Sanitizer, TargetLanguage};
use uuid::Uuid;

/// A clean scanner with enough branches that the queue keeps growing.
const HARNESS: &str = "#include <stddef.h>\n#include <stdint.h>\n\n__attribute__((noinline)) static int scan(const uint8_t *data, size_t size) {\n  int score = 0;\n  if (size > 0 && data[0] == 'O') {\n    score += 1;\n    if (size > 1 && data[1] == 'X') {\n      score += 2;\n      if (size > 2 && data[2] == 'F') {\n        score += 4;\n        if (size > 3 && data[3] == 'Z') score += 8;\n      }\n    }\n  }\n  for (size_t at = 0; at < size; at++) {\n    switch (data[at] & 7) {\n      case 0: score += 1; break;\n      case 1: score ^= 3; break;\n      case 2: score -= 2; break;\n      case 3: score *= 3; break;\n      case 4: score += data[at] >> 4; break;\n      case 5: if (at + 1 < size && data[at + 1] == data[at]) score += 16; break;\n      case 6: if (at > 2 && data[at - 2] == 'K') score -= 9; break;\n      default: score += 5; break;\n    }\n  }\n  return score;\n}\n\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  static volatile int sink;\n  sink = scan(data, size);\n  return 0;\n}\n";

/// The longest a requested Stop may take, as the qualification runbook has it.
const STOP_LIMIT: Duration = Duration::from_secs(15);

fn run_config(harness: &Harness, seconds: u64, resume: bool) -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(Duration::from_secs(seconds)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: harness.sanitizer,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: None,
        replay_of: None,
        input_manifest_sha256: None,
        input_timeout: None,
        resume,
        cmplog: false,
    }
}

/// The campaign's sandbox contract, as the smoke run has it: the workspace is
/// read-only and only the corpus and output directories are writable.
fn campaign_sandbox(workspace: &Path) -> SandboxOptions {
    SandboxOptions {
        extra_mounts: vec![
            SandboxMount::writable(workspace.join("corpus"), "/work/corpus".to_owned()),
            SandboxMount::writable(workspace.join("out"), "/work/out".to_owned()),
        ],
        workspace_read_only: true,
        max_file_size_bytes: Some(hf_engine::runner::run_file_size_limit_bytes(
            EngineKind::AflPlusPlus,
        )),
        ..SandboxOptions::default()
    }
}

/// Queue entries as the host lists them. A Windows host shows the engine's
/// colons as another character; the names are only compared with each other.
fn queue_names(workspace: &Path) -> BTreeSet<String> {
    std::fs::read_dir(workspace.join("out/default/queue"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// What AFL++ carries over when it re-imports a queue entry: the text after
/// `orig` and its separator for an entry that has one (`...,orig:seed`), and
/// the whole name for an entry the campaign discovered.
fn carried_name(name: &str) -> &str {
    name.split_once(",orig")
        .and_then(|(_, rest)| {
            let mut characters = rest.chars();
            characters.next()?;
            Some(characters.as_str())
        })
        .unwrap_or(name)
}

/// `execs_done` from the engine's statistics file, read on the host.
fn executions(workspace: &Path) -> Option<u64> {
    let stats = std::fs::read_to_string(workspace.join("out/default/fuzzer_stats")).ok()?;
    stats.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "execs_done")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

async fn sandbox_containers() -> BTreeSet<String> {
    let output = tokio::process::Command::new(hf_runtime::docker_bin())
        .args([
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            "label=org.oxfuzz.workspace-sha256",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success(), "container inventory failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_resumed_entry_is_matched_to_the_entry_it_came_from() {
    // A discovered entry is re-imported under a new id, its old name kept.
    let discovered = "id:000003,src:000000,time:1,execs:24,op:havoc,rep:3,+cov";
    assert_eq!(carried_name(discovered), discovered);
    assert_eq!(
        carried_name(&format!("id:000041,time:0,execs:0,orig:{discovered}")),
        discovered
    );
    // The seed keeps the name it was imported from.
    assert_eq!(carried_name("id:000000,time:0,execs:0,orig:seed"), "seed");
    assert_eq!(carried_name("id:000057,time:0,execs:0,orig:seed"), "seed");
    // A Windows host lists each colon as U+F03A.
    assert_eq!(
        carried_name("id\u{f03a}000057,time\u{f03a}0,orig\u{f03a}seed"),
        "seed"
    );
    assert_eq!(carried_name("id:000001,orig"), "id:000001,orig");
}

#[test]
fn progress_is_read_from_the_output_tree_on_the_host() {
    let root = tempfile::tempdir().unwrap();
    assert!(queue_names(root.path()).is_empty());
    assert_eq!(executions(root.path()), None);

    let instance = root.path().join("out/default");
    std::fs::create_dir_all(instance.join("queue/.state")).unwrap();
    std::fs::write(instance.join("queue/id_000000,orig_seed"), b"a").unwrap();
    std::fs::write(instance.join("queue/id_000001,src_000000"), b"b").unwrap();
    std::fs::write(
        instance.join("fuzzer_stats"),
        "start_time        : 1\nexecs_done        : 25716\nexecs_per_sec     : 99.5\n",
    )
    .unwrap();
    assert_eq!(
        queue_names(root.path()).into_iter().collect::<Vec<_>>(),
        ["id_000000,orig_seed", "id_000001,src_000000"],
        "the state directory is not an entry"
    );
    assert_eq!(executions(root.path()), Some(25716));

    std::fs::write(instance.join("fuzzer_stats"), "execs_done : soon\n").unwrap();
    assert_eq!(executions(root.path()), None);
}

#[test]
fn the_campaign_writes_only_to_its_corpus_and_output() {
    let workspace = Path::new("campaign");
    let sandbox = campaign_sandbox(workspace);
    assert!(sandbox.workspace_read_only);
    let mounts: Vec<(&Path, &str, bool)> = sandbox
        .extra_mounts
        .iter()
        .map(|mount| {
            (
                mount.host_path.as_path(),
                mount.container_path.as_str(),
                mount.read_only,
            )
        })
        .collect();
    assert_eq!(
        mounts,
        [
            (workspace.join("corpus").as_path(), "/work/corpus", false),
            (workspace.join("out").as_path(), "/work/out", false),
        ]
    );
}

#[tokio::test]
#[ignore = "requires a local Docker daemon and the pinned sandbox image"]
async fn live_stop_and_resume_keeps_the_queue_of_a_stopped_campaign() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("campaign");
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::create_dir_all(workspace.join("out")).unwrap();
    std::fs::write(workspace.join("corpus/seed"), b"OX\0\xff").unwrap();
    let runtime =
        hf_runtime::docker::DockerRuntime::new(hf_runtime::RuntimeConfig::default(), root.path());
    let containers_before = sandbox_containers().await;

    let engine = EngineKind::AflPlusPlus;
    let build_cmd = hf_harness::build_command_for_source(
        engine,
        TargetLanguage::C,
        "fuzz_scan",
        Sanitizer::Address,
        HARNESS,
    )
    .unwrap();
    let draft = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine,
        source: HARNESS.to_owned(),
        language: TargetLanguage::C,
        build_cmd,
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
        cmplog: None,
        custom_mutator: None,
    };
    let harness = match hf_harness::try_compile_with_options(
        draft,
        &runtime,
        &workspace,
        &SandboxOptions::default(),
    )
    .await
    .unwrap()
    {
        hf_harness::CompileResult::Ok(harness) => *harness,
        hf_harness::CompileResult::Failed(failure) => {
            panic!("build failed: {}\n{}", failure.stdout, failure.stderr)
        }
    };
    let binary = format!(
        "/work/{}",
        harness
            .build_cmd
            .output
            .file_name()
            .unwrap()
            .to_string_lossy()
    );
    let sandbox = campaign_sandbox(&workspace);
    let runner = hf_engine::runner::EngineRunner::new();

    // The campaign: far longer than the test waits, so only Stop ends it.
    let cancel = tokio_util::sync::CancellationToken::new();
    let stopper = {
        let cancel = cancel.clone();
        let workspace = workspace.clone();
        tokio::spawn(async move {
            let waiting = Instant::now();
            loop {
                let found = queue_names(&workspace).len();
                let done = executions(&workspace).unwrap_or(0);
                if found >= 3 && done >= 1000 {
                    break;
                }
                if waiting.elapsed() > Duration::from_secs(120) {
                    // End the campaign either way; the test fails below.
                    cancel.cancel();
                    return Err(format!(
                        "no measured progress in two minutes: {found} queue entries, {done} executions"
                    ));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            cancel.cancel();
            Ok(Instant::now())
        })
    };
    let campaign = runner
        .run_streaming_opts(
            engine,
            &run_config(&harness, 600, false),
            &binary,
            "/work/corpus",
            "/work/out",
            &runtime,
            &workspace,
            &sandbox,
            &cancel,
            &|_| {},
        )
        .await
        .unwrap();
    let returned = Instant::now();
    let requested = stopper.await.unwrap().unwrap();
    let stop_latency = returned.saturating_duration_since(requested);
    let stopped_queue = queue_names(&workspace);
    let stopped_executions = executions(&workspace).unwrap_or(0);
    println!(
        "stopped after {stop_latency:?}: {} queue entries, {stopped_executions} executions",
        stopped_queue.len()
    );
    assert_eq!(campaign.termination, CommandTermination::Cancelled);
    assert!(stop_latency < STOP_LIMIT, "Stop took {stop_latency:?}");
    assert_eq!(
        sandbox_containers().await,
        containers_before,
        "Stop left a container behind"
    );

    // The resume: a short run over the same output tree.
    let resumed = runner
        .run_streaming_opts(
            engine,
            &run_config(&harness, 15, true),
            &binary,
            "/work/corpus",
            "/work/out",
            &runtime,
            &workspace,
            &sandbox,
            &tokio_util::sync::CancellationToken::new(),
            &|_| {},
        )
        .await
        .unwrap();
    let resumed_queue = queue_names(&workspace);
    let resumed_executions = executions(&workspace).unwrap_or(0);
    println!(
        "resumed: {} queue entries, {resumed_executions} executions",
        resumed_queue.len()
    );
    assert_eq!(resumed.termination, CommandTermination::Completed);
    // AFL++ re-imports the earlier queue on resume under new ids, each
    // carrying the name it came from. A cold start would have discarded the
    // old tree, and no discovered entry of the stopped campaign would remain.
    let carried: BTreeSet<&str> = resumed_queue
        .iter()
        .map(|name| carried_name(name))
        .collect();
    let lost: Vec<&String> = stopped_queue
        .iter()
        .filter(|old| !carried.contains(carried_name(old)))
        .collect();
    assert!(
        lost.is_empty(),
        "the resumed run dropped queue entries of the stopped campaign: {lost:?}"
    );
    assert!(
        resumed_queue.len() >= stopped_queue.len(),
        "the resumed queue is smaller than the stopped one"
    );
    assert!(resumed_executions > 0, "the resumed run executed inputs");
    assert_eq!(
        sandbox_containers().await,
        containers_before,
        "the resumed run left a container behind"
    );
}
