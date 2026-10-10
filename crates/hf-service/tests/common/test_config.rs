//! Selectively included fixture: pin a suite's fuzzing policy to a private
//! config directory. Included with `#[path]` by the test files that assert
//! exact compile flags, so suites that do not need it never compile it.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Pin the fuzzing policy to a private config directory with
/// function-coverage collection off.
///
/// Tests that assert exact compile flags cannot tolerate the ambient config:
/// the checked-in example enables collection (which injects profiling flags
/// into the build), and a developer's live checkout or per-user config varies
/// by machine.
pub fn install() {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "oxfuzz-test-config-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("oxfuzz.toml"),
            "[fuzzing]\ncollect_function_coverage = false\n",
        )
        .unwrap();
        dir
    });
    std::env::set_var("HF_CONFIG_DIR", dir);
}
