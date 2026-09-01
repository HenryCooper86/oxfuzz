//! Dependency-boundary checks for thin presentation crates.

#[test]
fn presentations_depend_on_internal_logic_only_through_service() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for relative in [
        "hf-cli/Cargo.toml",
        "hf-web/Cargo.toml",
        "hf-gui/src-tauri/Cargo.toml",
    ] {
        let manifest = std::fs::read_to_string(crates_dir.join(relative)).unwrap();
        for line in manifest.lines().map(str::trim_start) {
            if line.starts_with("hf-")
                && !line.starts_with("hf-service =")
                && !(relative.starts_with("hf-cli") && line.starts_with("hf-web ="))
            {
                panic!("{relative} bypasses hf-service with dependency: {line}");
            }
        }
    }
}

#[test]
fn cli_ci_gate_delegates_without_process_global_guardrail_mutation() {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    // The CI command lives in a per-command module since the main.rs split,
    // so the assertions cover every hf-cli source file rather than main.rs.
    let mut sources = Vec::new();
    collect_rust_sources(&crates_dir.join("hf-cli/src"), &mut sources);
    assert!(
        !sources.is_empty(),
        "hf-cli sources must be discoverable for this boundary check"
    );
    let joined = sources.join("\n");

    assert!(
        joined.contains("run_ci_gate"),
        "CLI CI command must delegate orchestration to hf-service"
    );
    assert!(
        !joined.contains("set_var(\"HF_GUARDRAILS\""),
        "CLI must not mutate process-global guardrail configuration"
    );
}

fn collect_rust_sources(dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            if let Ok(source) = std::fs::read_to_string(&path) {
                out.push(source);
            }
        }
    }
}
