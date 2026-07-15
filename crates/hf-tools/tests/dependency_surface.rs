//! Architectural guard for retired, unreachable extension prototypes.

use std::path::Path;

#[test]
fn retired_extension_crates_are_not_workspace_dependencies() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .expect("hf-tools must remain under crates/");
    let workspace_manifest =
        std::fs::read_to_string(workspace_root.join("Cargo.toml")).expect("workspace Cargo.toml");
    let tools_manifest =
        std::fs::read_to_string(crate_dir.join("Cargo.toml")).expect("hf-tools Cargo.toml");

    for retired in ["hf-hooks", "hf-mcp"] {
        assert!(
            !workspace_manifest.contains(retired),
            "retired crate {retired} must not re-enter the workspace without a live integration"
        );
        assert!(
            !tools_manifest.contains(retired),
            "tool execution must not advertise the retired {retired} integration"
        );
    }
}
