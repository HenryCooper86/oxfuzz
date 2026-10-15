//! Consumer-visible teardown regressions use an isolated fake Docker CLI only.
#![cfg(unix)]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_runtime::docker::DockerRuntime;
use hf_runtime::owned_containers::OwnedContainerRegistry;
use hf_runtime::RuntimeConfig;
use tokio_util::sync::CancellationToken;

const FIXTURE_ROOT: &str = "OXFUZZ_DOCKER_TEARDOWN_FIXTURE";

// A pending create is daemon-side work, not a descendant of the CLI. The first
// stop/absence request races it: it observes absence, then creation completes.
// No target command is interpreted or executed by this fixture.
const DOCKER: &str = r#"#!/bin/sh
set -eu
root=${0%/*}
verb=$1
shift
case "$verb" in
    --version) echo 'Docker fixture';;
    run)
        for arg do
            case "$arg" in
                --name=*) printf '%s\n' "${arg#--name=}" > "$root/name";;
                --cidfile=*) cidfile=${arg#--cidfile=};;
                --label=org.oxfuzz.workspace-sha256=*)
                    printf '%s\n' "${arg#--label=org.oxfuzz.workspace-sha256=}" > "$root/label";;
            esac
        done
        if [ -f "$root/complete-next-run" ]; then
            printf '%064d' 1 > "$cidfile"
            rm -f "$root/pending"
            exit 0
        fi
        if [ -f "$root/foreign-label" ]; then
            printf '%s\n' 'another-workspace' > "$root/label"
        fi
        if [ -f "$root/already-created" ]; then
            cp "$root/label" "$root/container"
            : > "$root/created"
            if [ -n "${cidfile:-}" ]; then printf '%064d' 1 > "$cidfile"; fi
        fi
        if [ -f "$root/acknowledged-absent" ]; then
            if [ -n "${cidfile:-}" ]; then printf '%064d' 1 > "$cidfile"; fi
            : > "$root/created"
        fi
        : > "$root/pending"
        if [ -f "$root/unknown-exit" ]; then
            echo 'fixture transport failed with creation unresolved' >&2
            exit 125
        fi
        echo 'creation pending'
        while :; do sleep 0.02; done;;
    kill)
        if [ -f "$root/unresolved-create" ] || [ -f "$root/acknowledged-absent" ]; then
            echo 'Error response from daemon: No such container' >&2
            exit 1
        fi
        if [ ! -f "$root/container" ]; then
            cp "$root/label" "$root/container"
            : > "$root/created"
            echo 'Error response from daemon: No such container' >&2
        else
            echo 'Error response from daemon: container is not running' >&2
        fi
        exit 1;;
    ps)
        if [ -f "$root/unresolved-create" ] || [ -f "$root/acknowledged-absent" ] || [ -f "$root/unknown-exit" ]; then exit 0; fi
        if [ -f "$root/container" ]; then
            cat "$root/name"
        elif [ -f "$root/pending" ] && [ ! -f "$root/created" ]; then
            # This response is absent even though the daemon completes create
            # before the caller receives it. A second absence check is needed.
            cp "$root/label" "$root/container"
            : > "$root/created"
            : > "$root/initially-absent"
        fi;;
    inspect) cat "$root/container";;
    rm)
        : > "$root/removal-attempted"
        if [ -f "$root/refuse-removal" ]; then
            echo 'fixture daemon refused removal' >&2
            exit 1
        fi
        rm -f "$root/container";;
    *) echo "unexpected Docker fixture command: $verb" >&2; exit 2;;
esac
"#;

#[derive(Clone, Copy, PartialEq)]
enum Case {
    Deadline,
    Cancel,
    Created,
    Refused,
    Unresolved,
    Foreign,
    AcknowledgedAbsent,
    UnknownExit,
    Dropped,
}

fn run_case(test_name: &str, case: Case) {
    if let Some(root) = std::env::var_os(FIXTURE_ROOT) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(assert_teardown(Path::new(&root), case));
        return;
    }

    // PATH and docker_bin's OnceLock are isolated from concurrent tests.
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    std::fs::write(root.join("docker"), DOCKER).unwrap();
    std::fs::set_permissions(root.join("docker"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(root.join("workspace")).unwrap();
    let marker = match case {
        Case::Created => Some("already-created"),
        Case::Refused => Some("refuse-removal"),
        Case::Unresolved => Some("unresolved-create"),
        Case::Foreign => Some("foreign-label"),
        Case::AcknowledgedAbsent => Some("acknowledged-absent"),
        Case::UnknownExit => Some("unknown-exit"),
        Case::Deadline | Case::Cancel | Case::Dropped => None,
    };
    if let Some(marker) = marker {
        std::fs::write(root.join(marker), b"").unwrap();
    }
    let inherited_path = std::env::var_os("PATH").unwrap_or_default();
    let paths = std::iter::once(root.to_path_buf()).chain(std::env::split_paths(&inherited_path));
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(FIXTURE_ROOT, root)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated regression failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn assert_teardown(root: &Path, case: Case) {
    let cancel_run = case != Case::Deadline;
    let workspace = root.join("workspace");
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &workspace);
    let registry = OwnedContainerRegistry::new(&workspace).unwrap();
    let limits = ResourceLimits {
        max_mem_mb: 256,
        max_cpus: 1,
        max_duration_secs: if cancel_run { 30 } else { 1 },
        env: HashMap::new(),
        ptrace: false,
    };
    if case == Case::Dropped {
        let ready = tokio::sync::Notify::new();
        let on_line = |line: &str| {
            if line == "creation pending" {
                ready.notify_one();
            }
        };
        let command = ["fixture-command-never-executed".to_owned()];
        let cancel = CancellationToken::new();
        let record = {
            let run =
                runtime.run_command_streaming(&command, &workspace, &limits, &cancel, &on_line);
            tokio::pin!(run);
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::select! {
                    result = &mut run => panic!("fixture returned before drop: {result:?}"),
                    () = ready.notified() => {}
                }
            })
            .await
            .expect("fixture actually began creation");
            open_owned_record(&workspace, &registry)
        };
        let _record = await_record_unlock(record).await;
        assert!(root.join("created").is_file());
        assert!(!root.join("container").exists());
        assert!(registry.pending_names().unwrap().is_empty());
        return;
    }
    let cancel = CancellationToken::new();
    let on_line = |line: &str| {
        if cancel_run && line == "creation pending" {
            cancel.cancel();
        }
    };
    let started = Instant::now();
    let command = ["fixture-command-never-executed".to_owned()];
    let run = runtime.run_command_streaming(&command, &workspace, &limits, &cancel, &on_line);
    let result = tokio::time::timeout(Duration::from_secs(45), run)
        .await
        .expect("teardown must be bounded");
    assert!(started.elapsed() < Duration::from_secs(45));
    if matches!(case, Case::Unresolved | Case::UnknownExit) {
        let error = result.expect_err("unacknowledged creation must not report clean completion");
        assert!(matches!(&error, ClassifiedError::Sandbox(_)));
        if case == Case::UnknownExit {
            assert!(
                error.to_string().contains("fixture transport failed"),
                "{error}"
            );
        }
        let name = std::fs::read_to_string(root.join("name")).unwrap();
        assert_eq!(registry.pending_names().unwrap(), vec![name.trim()]);
        let command = ["fixture-command-never-executed".to_owned()];
        // A fresh executor must not erase uncertainty after another grace
        // interval, nor admit another run that loses the old container's name.
        let error = tokio::time::timeout(
            Duration::from_secs(45),
            runtime.run_command(&command, &workspace, &limits),
        )
        .await
        .expect("recovery must be bounded")
        .expect_err("absent but unresolved create must block admission");
        assert!(matches!(error, ClassifiedError::Sandbox(_)));
        assert_eq!(registry.pending_names().unwrap(), vec![name.trim()]);
        assert!(!root.join("removal-attempted").exists());
        // Only now does the daemon finish the request, beyond both observation
        // intervals. Recovery still has its durable identity and can remove it.
        std::fs::copy(root.join("label"), root.join("container")).unwrap();
        std::fs::write(root.join("created"), b"").unwrap();
        let marker = if case == Case::UnknownExit {
            "unknown-exit"
        } else {
            "unresolved-create"
        };
        std::fs::remove_file(root.join(marker)).unwrap();
        std::fs::write(root.join("complete-next-run"), b"").unwrap();
        let result = runtime
            .run_command(&command, &workspace, &limits)
            .await
            .unwrap();
        assert_eq!(result.termination, CommandTermination::Completed);
        assert!(!root.join("container").exists());
        assert!(registry.pending_names().unwrap().is_empty());
        return;
    }
    if case == Case::Foreign {
        let error = result.expect_err("foreign label must refuse cleanup");
        assert!(
            error.to_string().contains("different workspace label"),
            "{error}"
        );
        // Acquiring the ownership lock is a deterministic barrier for any
        // dropped-future cleanup, which must hold this same lock until done.
        let _record = await_record_unlock(open_owned_record(&workspace, &registry)).await;
        assert!(root.join("container").is_file());
        assert_eq!(registry.pending_names().unwrap().len(), 1);
        assert!(!root.join("removal-attempted").exists());
        return;
    }
    assert!(root.join("created").is_file(), "create actually completed");
    if case == Case::Refused {
        let error = result.expect_err("genuine Docker removal errors must remain observable");
        assert!(matches!(&error, ClassifiedError::Sandbox(_)), "{error}");
        assert!(
            error.to_string().contains("fixture daemon refused removal"),
            "{error}"
        );
        assert!(root.join("container").is_file());
        let name = std::fs::read_to_string(root.join("name")).unwrap();
        assert_eq!(registry.pending_names().unwrap(), vec![name.trim()]);
    } else {
        let result = result.expect("forced stop must remove even a not-yet-started container");
        assert_eq!(
            result.termination,
            if cancel_run {
                CommandTermination::Cancelled
            } else {
                CommandTermination::TimedOut
            }
        );
        assert_eq!(result.exit_code, -1);
        if case != Case::AcknowledgedAbsent {
            assert!(result.stdout.contains("creation pending"));
        }
        assert!(!root.join("container").exists(), "owned container remains");
        assert!(registry.pending_names().unwrap().is_empty());
    }
    if case != Case::AcknowledgedAbsent {
        assert!(root.join("removal-attempted").is_file());
    }
}

fn open_owned_record(workspace: &Path, registry: &OwnedContainerRegistry) -> std::fs::File {
    let names = registry.pending_names().unwrap();
    assert_eq!(names.len(), 1);
    let path = workspace
        .parent()
        .unwrap()
        .join(format!(".oxfuzz-runtime-{}", registry.workspace_digest()))
        .join(format!("{}.json", names[0]));
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

async fn await_record_unlock(record: std::fs::File) -> std::fs::File {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            match record.try_lock() {
                Ok(()) => return record,
                Err(std::fs::TryLockError::WouldBlock) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    panic!("acquire owned cleanup record lock: {error}");
                }
            }
        }
    })
    .await
    .expect("owned cleanup released its record lock")
}

#[test]
fn deadline_during_delayed_creation_waits_for_owned_removal() {
    run_case(
        "deadline_during_delayed_creation_waits_for_owned_removal",
        Case::Deadline,
    );
}

#[test]
fn cancellation_during_delayed_creation_waits_for_owned_removal() {
    run_case(
        "cancellation_during_delayed_creation_waits_for_owned_removal",
        Case::Cancel,
    );
}

#[test]
fn cancellation_removes_a_created_not_running_container() {
    run_case(
        "cancellation_removes_a_created_not_running_container",
        Case::Created,
    );
}

#[test]
fn delayed_creation_removal_error_retains_owned_record() {
    run_case(
        "delayed_creation_removal_error_retains_owned_record",
        Case::Refused,
    );
}

#[test]
fn creation_beyond_cleanup_window_retains_ownership_and_blocks_admission() {
    run_case(
        "creation_beyond_cleanup_window_retains_ownership_and_blocks_admission",
        Case::Unresolved,
    );
}

#[test]
fn foreign_container_is_not_removed_by_cleanup_or_drop_guard() {
    run_case(
        "foreign_container_is_not_removed_by_cleanup_or_drop_guard",
        Case::Foreign,
    );
}

#[test]
fn acknowledged_creation_can_be_cleared_after_auto_removal() {
    run_case(
        "acknowledged_creation_can_be_cleared_after_auto_removal",
        Case::AcknowledgedAbsent,
    );
}

#[test]
fn failed_client_without_creation_ack_retains_ownership_and_stderr() {
    run_case(
        "failed_client_without_creation_ack_retains_ownership_and_stderr",
        Case::UnknownExit,
    );
}

#[test]
fn dropped_future_checkpoints_creation_before_owned_removal() {
    run_case(
        "dropped_future_checkpoints_creation_before_owned_removal",
        Case::Dropped,
    );
}
