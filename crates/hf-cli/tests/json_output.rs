use std::process::Command;

fn selected_doctor_with_invalid_provider(logging: &str) -> std::process::Output {
    let directory = tempfile::tempdir().expect("temporary configuration");
    std::fs::write(directory.path().join("providers.toml"), "invalid = [")
        .expect("write invalid provider fixture");
    let database = directory.path().join("data.db");
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .args([
            "doctor",
            "--engine",
            "libfuzzer",
            "--require-provider",
            "--json",
        ])
        .env("HF_CONFIG_DIR", directory.path())
        .env("HF_DB_PATH", &database)
        .env("HF_USE_DOCKER", "0")
        .env_remove("HF_PROVIDER_API_KEY")
        .env("RUST_LOG", logging)
        .output()
        .expect("run CLI preflight without target execution");
    assert!(!database.exists());
    output
}

#[test]
fn selected_doctor_keeps_diagnostics_out_of_json_stdout() {
    let output = selected_doctor_with_invalid_provider("info");
    assert!(!output.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout contains only the JSON report");
    assert_eq!(report["ready"], false);
    assert_eq!(report["provider_configured"], false);
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains("failed to parse"), "{diagnostics}");
}

#[test]
fn diagnostic_routing_preserves_the_requested_log_filter() {
    let output = selected_doctor_with_invalid_provider("off");
    assert!(!output.status.success());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(!diagnostics.contains("failed to parse"), "{diagnostics}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON remains available with logging off");
    assert_eq!(report["ready"], false);
}
