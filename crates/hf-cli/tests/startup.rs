use std::process::{Command, Output};

fn assert_version(output: &Output) {
    assert!(
        output.status.success(),
        "CLI startup failed: {}; stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("oxfuzz {}", env!("CARGO_PKG_VERSION")),
    );
}

#[test]
fn version_starts_without_workspace_or_provider_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .arg("--version")
        .current_dir(directory.path())
        .env("HF_CONFIG_DIR", directory.path().join("absent-config"))
        .output()
        .unwrap();
    assert_version(&output);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[cfg(unix)]
fn limited_stack_command() -> Command {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "ulimit -s 1024 && exec \"$@\"",
        "oxfuzz-startup",
        env!("CARGO_BIN_EXE_oxfuzz"),
    ]);
    command
}

#[cfg(unix)]
#[test]
fn version_starts_with_a_one_mebibyte_process_stack() {
    let output = limited_stack_command().arg("--version").output().unwrap();
    assert_version(&output);
}

#[cfg(unix)]
#[test]
fn command_validation_runs_with_a_one_mebibyte_process_stack() {
    let directory = tempfile::tempdir().unwrap();
    for command in ["run", "campaign"] {
        let output = limited_stack_command()
            .args([
                command,
                ".",
                "--target",
                "parse",
                "--engine",
                "invalid-engine",
            ])
            .current_dir(directory.path())
            .env("HF_CONFIG_DIR", directory.path().join("absent-config"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("invalid-engine"), "{stderr}");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
