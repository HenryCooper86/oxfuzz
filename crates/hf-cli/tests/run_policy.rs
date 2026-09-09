use std::path::Path;
use std::process::{Command, Output};

fn run(directory: &Path, duration: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxfuzz"));
    command
        .args(["run"])
        .arg(directory.join("project"))
        .args(["--target", "parse", "--engine", "libfuzzer"])
        .env("HF_CONFIG_DIR", directory)
        .env("HF_DB_PATH", directory.join("data.db"))
        .env("HF_WORKSPACE_DIR", directory.join("workspace"))
        .env("HF_USE_DOCKER", "0")
        .env_remove("HF_PROVIDER_API_KEY");
    if let Some(duration) = duration {
        command.args(["--duration", duration]);
    }
    command
        .output()
        .expect("run CLI with target execution disabled")
}

#[test]
fn rejected_run_policy_precedes_storage_and_seed_preparation() {
    for duration in [Some("0s"), Some("61s"), Some("invalid")] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("oxfuzz.toml"),
            "[fuzzing]\ndefault_duration_secs = 23\n[fuzzing.sandbox]\nmax_duration_secs = 60\n",
        )
        .unwrap();
        let output = run(directory.path(), duration);
        assert!(!output.status.success());
        assert!(
            !directory.path().join("data.db").exists(),
            "policy rejection created a database"
        );
        assert!(
            !directory.path().join("workspace").exists(),
            "policy rejection prepared a workspace"
        );
    }
}

#[test]
fn omitted_run_duration_uses_the_configured_default() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("project")).unwrap();
    std::fs::write(
        directory.path().join("oxfuzz.toml"),
        "[fuzzing]\ndefault_duration_secs = 23\n[fuzzing.sandbox]\nmax_duration_secs = 60\n",
    )
    .unwrap();
    let output = run(directory.path(), None);
    assert!(!output.status.success(), "fixture has no approved harness");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("for 23s"), "{stdout}");
}

#[test]
fn overflowing_duration_is_a_named_error_before_storage_or_seed_preparation() {
    for suffix in ['m', 'h'] {
        let directory = tempfile::tempdir().unwrap();
        let output = run(directory.path(), Some(&format!("{}{suffix}", u64::MAX)));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("duration exceeds"), "{stderr}");
        assert!(!directory.path().join("data.db").exists());
        assert!(!directory.path().join("workspace").exists());
    }
}
