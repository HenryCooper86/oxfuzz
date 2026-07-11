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
