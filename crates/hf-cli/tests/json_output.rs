use std::process::{Command, Output};

fn json_report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI JSON failed: {error}; exit={}; stderr={:?}; stdout={:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        )
    })
}

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
    let report = json_report(&output);
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
    let report = json_report(&output);
    assert_eq!(report["ready"], false);
}

#[test]
fn configured_provider_requires_a_resolved_nonempty_key() {
    for key in [None, Some("")] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("providers.toml"),
            r#"[[providers]]
id = "fixture"
provider_type = "openai-compat"
model = "fixture"
api_key_env = "HF_TEST_PREFLIGHT_KEY"
"#,
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_oxfuzz"));
        command
            .args([
                "doctor",
                "--engine",
                "libfuzzer",
                "--require-provider",
                "--json",
            ])
            .env("HF_CONFIG_DIR", directory.path())
            .env("HF_USE_DOCKER", "0")
            .env_remove("HF_PROVIDER_API_KEY")
            .env_remove("HF_TEST_PREFLIGHT_KEY");
        if let Some(key) = key {
            command.env("HF_TEST_PREFLIGHT_KEY", key);
        }
        let output = command.output().unwrap();
        let report = json_report(&output);
        assert_eq!(report["provider_configured"], false, "{report}");
    }
}
