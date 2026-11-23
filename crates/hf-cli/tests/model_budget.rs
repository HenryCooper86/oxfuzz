#![cfg(feature = "model-budgets")]

use std::process::Command;

#[test]
fn model_budget_status_reads_selected_config_without_provider_access() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("oxfuzz.toml"),
        "[model_budget]\nscope_id='trial-a'\nmax_calls=2\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .arg("--config")
        .arg(directory.path())
        .arg("model-budget")
        .env("HF_DB_PATH", directory.path().join("trial.db"))
        .env_remove("HF_PROVIDER_API_KEY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::Value::Null
    );
    assert!(directory.path().join("trial.db").exists());
}

#[test]
fn model_budget_status_rejects_invalid_limits_before_opening_storage() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("oxfuzz.toml"),
        "[model_budget]\nscope_id='trial-a'\nmax_calls=0\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .arg("--config")
        .arg(directory.path())
        .arg("model-budget")
        .env("HF_DB_PATH", directory.path().join("trial.db"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("max_calls"));
    assert!(!directory.path().join("trial.db").exists());
}

#[test]
fn model_budget_status_says_when_no_workflow_is_configured() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("oxfuzz.toml"), "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .arg("--config")
        .arg(directory.path())
        .arg("model-budget")
        .env("HF_DB_PATH", directory.path().join("trial.db"))
        .env_remove("HF_PROVIDER_API_KEY")
        .output()
        .unwrap();
    assert!(output.status.success());
    // Standard output stays machine-readable; the explanation goes beside it.
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::Value::Null
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No [model_budget] workflow is configured"),
        "{stderr}"
    );
}

#[test]
fn model_budget_status_says_when_a_configured_workflow_has_no_spending() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("oxfuzz.toml"),
        "[model_budget]\nscope_id='trial-a'\nmax_calls=2\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxfuzz"))
        .arg("--config")
        .arg(directory.path())
        .arg("model-budget")
        .env("HF_DB_PATH", directory.path().join("trial.db"))
        .env_remove("HF_PROVIDER_API_KEY")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No spending is recorded yet for model budget workflow 'trial-a'"),
        "{stderr}"
    );
}
