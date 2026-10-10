//! Binary-level smoke tests for the `runs` command group against a seeded
//! `SQLite` store. No Docker, no live engines: runs exist only as durable rows,
//! exactly the state a headless operator inspects after the fact.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hf_service::test_support::{RunRecord, RunStatus, Store};
use hf_service::EngineKind;
use uuid::Uuid;

/// A throwaway oxfuzz environment: config, database, workspace, and a private
/// HOME so the child process's run journal and app data stay inside it.
struct Fixture {
    directory: tempfile::TempDir,
    project_a: PathBuf,
    project_b: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary fixture root");
        let project_a = directory.path().join("project-a");
        let project_b = directory.path().join("project-b");
        std::fs::create_dir_all(&project_a).unwrap();
        std::fs::create_dir_all(&project_b).unwrap();
        std::fs::create_dir_all(directory.path().join("home")).unwrap();
        Self {
            database: directory.path().join("oxfuzz.db"),
            project_a,
            project_b,
            directory,
        }
    }

    fn oxfuzz(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
            .args(args)
            .env("HF_CONFIG_DIR", self.directory.path().join("config"))
            .env("HF_DB_PATH", &self.database)
            .env("HF_WORKSPACE_DIR", self.directory.path().join("workspace"))
            .env("HOME", self.directory.path().join("home"))
            .env("HF_USE_DOCKER", "0")
            .env_remove("HF_PROVIDER_API_KEY")
            .output()
            .expect("spawn oxfuzz")
    }

    fn seed(&self, runs: &[RunRecord]) {
        let database = self.database.clone();
        let runs = runs.to_vec();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let store = Store::connect(&database).await.unwrap();
                for run in &runs {
                    store.insert_run(run).await.unwrap();
                }
            });
    }
}

fn stored_run(
    project: &Path,
    engine: EngineKind,
    status: RunStatus,
    id: Uuid,
    started_secs: i64,
) -> RunRecord {
    let started_at = chrono::DateTime::from_timestamp(started_secs, 0).unwrap();
    let mut run = RunRecord::new(project.to_string_lossy(), engine, None, started_at);
    run.id = id;
    run.status = status;
    if matches!(
        status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
    ) {
        run.ended_at = Some(started_at + chrono::Duration::seconds(60));
    }
    run
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn runs_list_on_an_empty_store_prints_no_runs_and_empty_json() {
    let fixture = Fixture::new();

    let text = fixture.oxfuzz(&["runs", "list"]);
    assert!(text.status.success(), "{}", stderr(&text));
    assert!(stdout(&text).contains("No runs recorded."));

    let json = fixture.oxfuzz(&["runs", "list", "--json"]);
    assert!(json.status.success(), "{}", stderr(&json));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn runs_list_orders_newest_first_and_filters_by_project_and_activity() {
    let fixture = Fixture::new();
    let old_done = Uuid::parse_str("00000000-0000-0000-0000-0000000000a1").unwrap();
    let running = Uuid::parse_str("11111111-0000-0000-0000-0000000000b2").unwrap();
    let new_done = Uuid::parse_str("22222222-0000-0000-0000-0000000000c3").unwrap();
    let other_project = Uuid::parse_str("33333333-0000-0000-0000-0000000000d4").unwrap();
    fixture.seed(&[
        stored_run(
            &fixture.project_a,
            EngineKind::LibFuzzer,
            RunStatus::Done,
            old_done,
            100,
        ),
        stored_run(
            &fixture.project_a,
            EngineKind::AflPlusPlus,
            RunStatus::Running,
            running,
            200,
        ),
        stored_run(
            &fixture.project_a,
            EngineKind::Honggfuzz,
            RunStatus::Done,
            new_done,
            300,
        ),
        stored_run(
            &fixture.project_b,
            EngineKind::LibFuzzer,
            RunStatus::Done,
            other_project,
            400,
        ),
    ]);

    let all = fixture.oxfuzz(&["runs", "list"]);
    assert!(all.status.success(), "{}", stderr(&all));
    let lines: Vec<String> = stdout(&all).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 5, "header + 4 rows: {lines:?}");
    assert!(lines[0].starts_with("ID"));
    let order: Vec<&str> = lines[1..]
        .iter()
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(
        order,
        ["33333333", "22222222", "11111111", "00000000"],
        "newest first: {lines:?}"
    );

    let active = fixture.oxfuzz(&["runs", "list", "--active"]);
    assert!(active.status.success(), "{}", stderr(&active));
    let active_text = stdout(&active);
    assert!(active_text.contains("Running"), "{active_text}");
    assert!(active_text.contains("11111111"), "{active_text}");
    assert!(!active_text.contains("Done"), "{active_text}");

    let scoped = fixture.oxfuzz(&[
        "runs",
        "list",
        "--project",
        fixture.project_a.to_str().unwrap(),
    ]);
    assert!(scoped.status.success(), "{}", stderr(&scoped));
    let scoped_lines: Vec<String> = stdout(&scoped).lines().map(str::to_owned).collect();
    assert_eq!(scoped_lines.len(), 4, "header + 3 project-a rows");

    let limited = fixture.oxfuzz(&["runs", "list", "--limit", "2"]);
    assert!(limited.status.success(), "{}", stderr(&limited));
    let limited_lines: Vec<String> = stdout(&limited).lines().map(str::to_owned).collect();
    assert_eq!(limited_lines.len(), 3, "header + 2 rows");
    assert!(limited_lines[1].starts_with("33333333"));
    assert!(limited_lines[2].starts_with("22222222"));

    let json = fixture.oxfuzz(&["runs", "list", "--json"]);
    assert!(json.status.success(), "{}", stderr(&json));
    let rows = serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["id"], other_project.to_string(), "newest first");
    assert_eq!(rows[1]["id"], new_done.to_string());
    assert_eq!(rows[2]["id"], running.to_string());
    assert_eq!(rows[2]["status"], "Running");
    assert_eq!(rows[2]["engine"], "AflPlusPlus");
}

#[test]
fn runs_status_prints_the_detail_view_for_a_full_id_or_prefix() {
    let fixture = Fixture::new();
    let id = Uuid::parse_str("aaaaaaaa-1111-2222-3333-444444444444").unwrap();
    fixture.seed(&[stored_run(
        &fixture.project_a,
        EngineKind::LibFuzzer,
        RunStatus::Done,
        id,
        100,
    )]);
    {
        let database = fixture.database.clone();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                Store::connect(&database)
                    .await
                    .unwrap()
                    .set_run_stats(id, 1523, 842.5, 3)
                    .await
                    .unwrap();
            });
    }

    let status = fixture.oxfuzz(&["runs", "status", &id.to_string()]);
    assert!(status.status.success(), "{}", stderr(&status));
    let text = stdout(&status);
    assert!(text.contains(&format!("run:        {id}")), "{text}");
    assert!(text.contains("status:     Done"), "{text}");
    assert!(text.contains("crashes:    3"), "{text}");
    assert!(text.contains("edges:      1523"), "{text}");
    assert!(text.contains("execs/s:    842.5"), "{text}");
    assert!(text.contains("duration:   60s"), "{text}");

    let by_prefix = fixture.oxfuzz(&["runs", "status", "aaaaaaaa"]);
    assert!(by_prefix.status.success(), "{}", stderr(&by_prefix));
    assert!(stdout(&by_prefix).contains(&format!("run:        {id}")));

    let json = fixture.oxfuzz(&["runs", "status", &id.to_string(), "--json"]);
    assert!(json.status.success(), "{}", stderr(&json));
    let detail = serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
    assert_eq!(detail["id"], id.to_string());
    assert_eq!(detail["edges"], 1523);
    assert_eq!(detail["crashes"], 3);
    assert_eq!(detail["active_in_this_process"], false);

    let unknown = fixture.oxfuzz(&["runs", "status", &Uuid::new_v4().to_string()]);
    assert!(!unknown.status.success());
    assert!(
        stderr(&unknown).contains("not found"),
        "{}",
        stderr(&unknown)
    );
}

#[test]
fn runs_stop_fails_loudly_for_terminal_unknown_ambiguous_and_foreign_runs() {
    let fixture = Fixture::new();
    let done = Uuid::parse_str("aaaaaaaa-1111-2222-3333-444444444444").unwrap();
    let running = Uuid::parse_str("bbbbbbbb-1111-2222-3333-444444444444").unwrap();
    let ambiguous_a = Uuid::parse_str("cccccccc-1111-2222-3333-444444444444").unwrap();
    let ambiguous_b = Uuid::parse_str("cccccccc-9999-2222-3333-444444444444").unwrap();
    fixture.seed(&[
        stored_run(
            &fixture.project_a,
            EngineKind::LibFuzzer,
            RunStatus::Done,
            done,
            100,
        ),
        stored_run(
            &fixture.project_a,
            EngineKind::LibFuzzer,
            RunStatus::Running,
            running,
            200,
        ),
        stored_run(
            &fixture.project_a,
            EngineKind::LibFuzzer,
            RunStatus::Done,
            ambiguous_a,
            300,
        ),
        stored_run(
            &fixture.project_a,
            EngineKind::LibFuzzer,
            RunStatus::Done,
            ambiguous_b,
            400,
        ),
    ]);

    let terminal = fixture.oxfuzz(&["runs", "stop", &done.to_string()]);
    assert!(!terminal.status.success());
    assert!(
        stderr(&terminal).contains("already finished"),
        "{}",
        stderr(&terminal)
    );

    let unknown = fixture.oxfuzz(&["runs", "stop", &Uuid::new_v4().to_string()]);
    assert!(!unknown.status.success());
    assert!(
        stderr(&unknown).contains("not found"),
        "{}",
        stderr(&unknown)
    );

    let ambiguous = fixture.oxfuzz(&["runs", "stop", "cccccccc"]);
    assert!(!ambiguous.status.success());
    assert!(
        stderr(&ambiguous).contains("ambiguous"),
        "{}",
        stderr(&ambiguous)
    );

    // A run owned by another process (a server, a TUI, another CLI) has no
    // cancellation token in this one: the command must say so, not pretend.
    let foreign = fixture.oxfuzz(&["runs", "stop", &running.to_string()]);
    assert!(!foreign.status.success());
    let message = stderr(&foreign);
    assert!(
        message.contains("running but owned by another process"),
        "{message}"
    );
    assert!(message.contains("POST /runs/"), "{message}");
}
