//! Shared integration-test fixtures.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Install one unique, explicitly owned workspace root for this integration
/// test process.
///
/// Production deliberately refuses to adopt a non-empty `HF_WORKSPACE_DIR`
/// override without its ownership manifest. Tests that seed workspace files
/// directly therefore create the same versioned manifest before exposing the
/// root through the environment.
pub fn install_managed_workspace(prefix: &str) -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let parent = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let root = parent.join("workspace");
        std::fs::create_dir_all(&root).unwrap();
        let canonical = std::fs::canonicalize(&root).unwrap();
        let manifest = serde_json::json!({
            "application": "hobot_fuzz",
            "version": 1,
            "canonical_root": canonical,
        });
        std::fs::write(
            canonical.join(".hobot-fuzz-workspace.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        canonical
    });
    std::env::set_var("HF_WORKSPACE_DIR", root);
    root.clone()
}
