//! Binary-level tests for the CLI's interactive approval gate. Spawned with
//! captured output, the child's stdin is closed and its stderr is a pipe -- no
//! terminal -- so the gate must fall back to the environment policy: deny
//! unless `HF_AUTO_APPROVE` is set, and never print a prompt or block on
//! input. `oxfuzz defectdojo` reaches a High-risk authorization
//! (`publish_findings`) before any configuration or fixture state is needed,
//! which makes it the probe command.

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
        std::fs::create_dir_all(directory.path().join("project")).unwrap();
        Self { directory }
    }

    fn project(&self) -> PathBuf {
        self.directory.path().join("project")
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
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn high_risk_action_on_a_piped_terminal_denies_without_prompting() {
    let fixture = Fixture::new();

    let push = fixture
        .oxfuzz(&["defectdojo", &fixture.project().to_string_lossy()])
        .output()
        .expect("spawn oxfuzz defectdojo");
    assert!(
        !push.status.success(),
        "a denied push must fail: {}",
        stdout(&push)
    );
    let err = stderr(&push);
    assert!(
        err.contains("approval declined"),
        "the denial must come from the approval gate: {err}"
    );
    assert!(
        !err.contains("[y]es/[n]o/[a]lways"),
        "a non-terminal context must never print the interactive prompt: {err}"
    );

    // The denial flowed through the persisted audit trail.
    let decisions = fixture
        .oxfuzz(&["policy", "decisions"])
        .output()
        .expect("spawn oxfuzz policy decisions");
    assert!(decisions.status.success(), "{}", stderr(&decisions));
    let rows = stdout(&decisions);
    assert!(
        rows.contains("denied_by_operator") && rows.contains("publish_findings"),
        "the denial must be persisted in the decision trail: {rows}"
    );
}

#[test]
fn hf_guardrails_permissive_still_auto_approves_without_prompting() {
    let fixture = Fixture::new();

    let push = fixture
        .oxfuzz(&["defectdojo", &fixture.project().to_string_lossy()])
        .env("HF_GUARDRAILS", "permissive")
        .output()
        .expect("spawn oxfuzz defectdojo");
    let err = stderr(&push);
    assert!(
        !err.contains("approval declined"),
        "HF_GUARDRAILS=permissive must pass the gate: {err}"
    );
    assert!(
        !err.contains("[y]es/[n]o/[a]lways"),
        "HF_GUARDRAILS=permissive must not prompt: {err}"
    );
    // Past the gate, the push fails on its own merits: no triaged crashes.
    assert!(!push.status.success(), "{}", stdout(&push));
}

#[test]
fn hf_auto_approve_still_approves_a_piped_run_without_prompting() {
    let fixture = Fixture::new();

    let push = fixture
        .oxfuzz(&["defectdojo", &fixture.project().to_string_lossy()])
        .env("HF_AUTO_APPROVE", "1")
        .output()
        .expect("spawn oxfuzz defectdojo");
    let err = stderr(&push);
    assert!(
        !err.contains("approval declined"),
        "HF_AUTO_APPROVE=1 must pass the gate: {err}"
    );
    assert!(
        !err.contains("[y]es/[n]o/[a]lways"),
        "HF_AUTO_APPROVE=1 must not prompt: {err}"
    );
    // Past the gate, the push has nothing to send: the fixture has no triaged
    // crashes. The command fails later, on its own merits.
    assert!(!push.status.success(), "{}", stdout(&push));

    let decisions = fixture
        .oxfuzz(&["policy", "decisions"])
        .output()
        .expect("spawn oxfuzz policy decisions");
    assert!(decisions.status.success(), "{}", stderr(&decisions));
    let rows = stdout(&decisions);
    assert!(
        rows.contains("approved") && rows.contains("publish_findings"),
        "the approval must be persisted in the decision trail: {rows}"
    );
}
