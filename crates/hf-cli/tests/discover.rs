//! Binary-level tests for `oxfuzz discover` harnessability reporting and the
//! `oxfuzz fuzz` auto-pick gate. No Docker, no providers: discovery is a pure
//! scan, and the fuzz pipeline fails at the discover stage before any sandbox
//! work.

use std::path::PathBuf;
use std::process::{Command, Output};

/// A throwaway oxfuzz environment: config, database, workspace, and a private
/// HOME so the child process's run journal and app data stay inside it.
struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary fixture root");
        std::fs::create_dir_all(directory.path().join("home")).unwrap();
        Self { directory }
    }

    fn oxfuzz(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxfuzz"));
        command
            .args(args)
            .env("HF_CONFIG_DIR", self.directory.path().join("config"))
            .env("HF_DB_PATH", self.directory.path().join("oxfuzz.db"))
            .env("HF_WORKSPACE_DIR", self.directory.path().join("workspace"))
            .env("HOME", self.directory.path().join("home"))
            .env("HF_USE_DOCKER", "0")
            .env_remove("HF_PROVIDER_API_KEY")
            .env_remove("HF_AUTO_APPROVE")
            .env_remove("HF_GUARDRAILS");
        command
    }

    /// A project with one exported, parameter-bearing Go function: a real
    /// discovery result with no harness path today.
    fn go_project(&self) -> PathBuf {
        let project = self.directory.path().join("goproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parser.go"),
            "package parser\n\nfunc ParsePacket(data []byte, offset int) bool {\n\treturn len(data) > offset\n}\n",
        )
        .unwrap();
        project
    }

    /// A project directory with one fuzzable C parser function.
    fn c_project(&self) -> PathBuf {
        let project = self.directory.path().join("cproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            "#include <stddef.h>\n#include <stdint.h>\n\
             int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
        )
        .unwrap();
        project
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn inventory(output: &Output) -> serde_json::Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|error| {
        panic!(
            "discover stdout must stay machine-readable: {error}; stderr={:?}",
            stderr(output)
        )
    })
}

#[test]
fn discover_go_scans_for_real_but_marks_every_candidate_not_harnessable() {
    let fixture = Fixture::new();
    let project = fixture.go_project();

    let run = fixture
        .oxfuzz(&["discover", &project.to_string_lossy(), "--lang", "go"])
        .output()
        .expect("spawn oxfuzz discover");

    assert!(
        run.status.success(),
        "explicit Go discovery still works: {}",
        stderr(&run)
    );
    let inventory = inventory(&run);
    let candidates = inventory["candidates"]
        .as_array()
        .expect("candidates array");
    assert_eq!(candidates.len(), 1, "the Go scan is real: {candidates:?}");
    assert_eq!(candidates[0]["symbol"], "ParsePacket");
    assert_eq!(
        candidates[0]["harnessable"],
        serde_json::Value::Bool(false),
        "the candidate is marked: {candidates:?}"
    );

    let err = stderr(&run);
    assert!(
        err.contains("harness generation is not yet available for go"),
        "the note names the language: {err}"
    );
    assert!(
        err.contains("c, cpp, rust"),
        "the note names what is supported: {err}"
    );
}

#[test]
fn discover_c_marks_candidates_harnessable_without_a_note() {
    let fixture = Fixture::new();
    let project = fixture.c_project();

    let run = fixture
        .oxfuzz(&["discover", &project.to_string_lossy(), "--lang", "c"])
        .output()
        .expect("spawn oxfuzz discover");

    assert!(run.status.success(), "{}", stderr(&run));
    let inventory = inventory(&run);
    let candidates = inventory["candidates"]
        .as_array()
        .expect("candidates array");
    assert!(!candidates.is_empty(), "the C scan finds the parser");
    assert_eq!(
        candidates[0]["harnessable"],
        serde_json::Value::Bool(true),
        "the candidate is marked: {candidates:?}"
    );
    assert!(
        !stderr(&run).contains("not yet available"),
        "a harnessable language gets no gating note: {}",
        stderr(&run)
    );
}

#[test]
fn fuzz_on_a_go_only_project_fails_at_discovery_naming_the_supported_set() {
    let fixture = Fixture::new();
    let project = fixture.go_project();

    let run = fixture
        .oxfuzz(&["fuzz", &project.to_string_lossy()])
        .output()
        .expect("spawn oxfuzz fuzz");

    assert!(!run.status.success(), "{}", stdout(&run));
    let err = stderr(&run);
    assert!(err.contains("discover"), "the stage is named: {err}");
    assert!(
        err.contains("not yet available"),
        "the capability gap is named: {err}"
    );
    assert!(
        err.contains("c, cpp, rust"),
        "the supported set is named: {err}"
    );
    assert!(
        !err.contains("[2/5] harness"),
        "the pipeline never reaches harness work: {err}"
    );
}
