//! Binary-level tests for `oxfuzz doctor`: the Docker-down report and the
//! `--build-image` action's loud failure paths. No Docker daemon is required:
//! `HF_USE_DOCKER=0` pins the sandbox off, so nothing inside Docker is probed
//! and the build preflight fails before contacting a daemon. The image-missing
//! remedy text is covered by the `doctor_lines` and `system_status` unit tests.

use std::process::{Command, Output};

fn oxfuzz(args: &[&str]) -> Output {
    let directory = tempfile::tempdir().expect("temporary fixture root");
    Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .args(args)
        .env("HF_CONFIG_DIR", directory.path().join("config"))
        .env("HF_DB_PATH", directory.path().join("oxfuzz.db"))
        .env("HF_WORKSPACE_DIR", directory.path().join("workspace"))
        .env("HOME", directory.path().join("home"))
        .env("HF_USE_DOCKER", "0")
        .env_remove("HF_PROVIDER_API_KEY")
        .output()
        .expect("spawn oxfuzz")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn doctor_without_docker_reports_the_image_as_unknown_and_names_docker() {
    let output = oxfuzz(&["doctor"]);

    assert!(!output.status.success(), "not ready: {}", stdout(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("MISSING  Docker daemon"), "{stdout}");
    // Nothing inside Docker was probed, so the image is not reported missing
    // and no image build is suggested; the remedy is Docker itself.
    assert!(stdout.contains("UNKNOWN  sandbox image"), "{stdout}");
    assert!(!stdout.contains("--build-image"), "{stdout}");
    assert!(stdout.contains("start Docker"), "{stdout}");
}

#[test]
fn doctor_json_without_docker_omits_the_image_remedy() {
    let output = oxfuzz(&["doctor", "--json"]);

    assert!(!output.status.success());
    let report = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid JSON: {error}; {}", stderr(&output)));
    assert_eq!(report["docker"], false);
    assert_eq!(report["sandbox_image"], false);
    assert!(report["sandbox_image_remedy"].is_null(), "{report}");
    assert_eq!(report["defectdojo"], false);
}

#[test]
fn doctor_build_image_without_docker_fails_loud_without_building() {
    let output = oxfuzz(&["doctor", "--build-image"]);

    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("Docker is disabled") && stderr.contains("HF_USE_DOCKER"),
        "the exact blocker is named: {stderr}"
    );
}

#[test]
fn doctor_build_image_conflicts_with_engine_scope() {
    let output = oxfuzz(&["doctor", "--build-image", "--engine", "libfuzzer"]);

    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("cannot be used with"),
        "{}",
        stderr(&output)
    );
}
