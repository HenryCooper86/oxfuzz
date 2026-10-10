//! Binary-level tests for the `fuzz` onboarding command. Spawned with captured
//! output, the child's stdin is closed and its stderr is a pipe -- no terminal
//! -- so the approval gate falls back to the environment policy and never
//! prompts. No Docker, no live providers: the tests stop at stages that need
//! neither (empty discovery, and the compile authorization gate).

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
            // The assertions depend on the environment policy's starting
            // state, not the shell the test suite runs in.
            .env_remove("HF_AUTO_APPROVE")
            .env_remove("HF_GUARDRAILS");
        command
    }

    /// A project directory with one fuzzable C parser function.
    fn c_project(&self) -> PathBuf {
        let project = self.directory.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            "#include <stddef.h>\n#include <stdint.h>\n\
             int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
        )
        .unwrap();
        project
    }

    /// A project directory with no fuzzable source at all.
    fn empty_project(&self) -> PathBuf {
        let project = self.directory.path().join("empty");
        std::fs::create_dir_all(&project).unwrap();
        project
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn fuzz_on_an_empty_project_fails_at_discovery_with_a_remediation() {
    let fixture = Fixture::new();
    let project = fixture.empty_project();

    let run = fixture
        .oxfuzz(&["fuzz", &project.to_string_lossy()])
        .output()
        .expect("spawn oxfuzz fuzz");
    assert!(!run.status.success(), "{}", stdout(&run));
    let err = stderr(&run);
    assert!(err.contains("discover"), "the stage is named: {err}");
    assert!(err.contains("no fuzzable targets"), "the cause: {err}");
    assert!(err.contains("--lang"), "the remediation: {err}");
}

#[test]
fn fuzz_announces_each_stage_and_names_the_failing_one() {
    let fixture = Fixture::new();
    let project = fixture.c_project();

    // Without Docker the sandbox image cannot resolve, so the harness stage is
    // the first one that can fail; the point under test is that the failure is
    // attributed to its stage with a remediation, not the sandbox specifics.
    let run = fixture
        .oxfuzz(&["fuzz", &project.to_string_lossy()])
        .output()
        .expect("spawn oxfuzz fuzz");
    assert!(!run.status.success(), "{}", stdout(&run));
    let out = stdout(&run);
    assert!(
        out.contains("[1/5] discover"),
        "the pipeline announces discovery: {out}"
    );
    assert!(
        out.contains("[2/5] harness"),
        "the pipeline reaches the harness stage: {out}"
    );
    assert!(
        !out.contains("[3/5] smoke"),
        "a harness-stage failure never reaches smoke: {out}"
    );
    assert!(
        !out.contains("[5/5] campaign"),
        "a harness-stage failure never reaches the campaign: {out}"
    );

    let err = stderr(&run);
    assert!(
        err.contains("fuzz harness failed"),
        "the failing stage is named: {err}"
    );
    assert!(
        err.contains("remediation:"),
        "a remediation follows the failure: {err}"
    );
    assert!(
        !err.contains("[y]es/[n]o/[a]lways"),
        "a non-terminal context must never print the interactive prompt: {err}"
    );
}

#[test]
fn fuzz_json_keeps_stdout_machine_readable() {
    let fixture = Fixture::new();
    let project = fixture.empty_project();

    // Even on the failure path, stage headers must not pollute stdout.
    let run = fixture
        .oxfuzz(&["fuzz", &project.to_string_lossy(), "--json"])
        .output()
        .expect("spawn oxfuzz fuzz --json");
    assert!(!run.status.success());
    let out = stdout(&run);
    assert!(
        !out.contains("[1/5]"),
        "stage headers stay off stdout in --json mode: {out}"
    );
    let err = stderr(&run);
    assert!(
        err.contains("[1/5] discover"),
        "stage headers move to stderr in --json mode: {err}"
    );
}
