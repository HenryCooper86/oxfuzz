//! Public-API regressions for report-draft persistence atomicity.
//!
//! The test process owns an isolated `HF_REPORTS_DIR` (a unique directory
//! under the system temp dir, installed once before any test body runs), so
//! no real report data is ever touched. Each test scopes its assertions to
//! its own report id, so parallel tests in this process cannot observe each
//! other's drafts.

use std::path::PathBuf;
use std::sync::LazyLock;

use hf_core::error::ClassifiedError;
use hf_service::report_store::save_report_draft;
use uuid::Uuid;

struct FixtureEnv {
    reports_dir: PathBuf,
}

/// The isolated reports directory for this test process.
static ENV: LazyLock<FixtureEnv> = LazyLock::new(|| {
    let unique = format!(
        "oxfuzz_report_store_{}_{}",
        std::process::id(),
        Uuid::new_v4()
    );
    let reports_dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&reports_dir).expect("create isolated reports dir");
    // This test binary owns the variable for the whole process and sets it
    // exactly once (lazy initialization before any test body reads it), so
    // no concurrent mutation can race the override.
    std::env::set_var("HF_REPORTS_DIR", &reports_dir);
    FixtureEnv { reports_dir }
});

/// Every directory entry belonging to `id` (stored draft plus any staging
/// files), ignoring other tests' concurrently saved reports.
fn id_scoped_entries(id: &str) -> Vec<String> {
    std::fs::read_dir(&ENV.reports_dir)
        .expect("read isolated reports dir")
        .filter_map(|entry| {
            let name = entry
                .expect("read directory entry")
                .file_name()
                .into_string()
                .expect("utf-8 file name");
            (name.starts_with(&format!("{id}.")) || name.starts_with(&format!(".{id}.")))
                .then_some(name)
        })
        .collect()
}

/// A save whose publishing rename fails must leave no staging files behind:
/// leftover shared temporaries are exactly what let one overlapping save
/// publish another save's content or fail on a consumed temp file.
#[test]
fn failed_publication_cleans_up_temporary_staging_files() {
    // Force the process-isolated reports dir before any service operation,
    // so this test can never save into the real user report directory even
    // when it is the first test to run in this binary.
    let _env = &*ENV;
    let id = "failed_publish";
    // A directory at `{id}.json` makes the final rename fail deterministically
    // while staging itself succeeds.
    std::fs::create_dir_all(ENV.reports_dir.join(format!("{id}.json")))
        .expect("create rename blocker");

    let error = save_report_draft(
        Some(id.to_owned()),
        "Blocked",
        "/proj",
        None,
        "Draft",
        "body",
    )
    .expect_err("publishing onto a directory fails");
    assert!(
        matches!(error, ClassifiedError::Storage(_)),
        "expected a storage error, got: {error:?}"
    );

    assert_eq!(
        id_scoped_entries(id),
        vec![format!("{id}.json")],
        "a failed save must leave only the pre-existing blocker behind"
    );
}

/// A successful save publishes exactly one complete `{id}.json` and leaves no
/// staging residue of any spelling.
#[test]
fn successful_save_leaves_no_temporary_staging_files() {
    // Force the process-isolated reports dir before any service operation
    // (see the failure-cleanup test above), so this test can never save into
    // the real user report directory even when it runs first.
    let _env = &*ENV;
    let saved =
        save_report_draft(None, "Clean save", "/proj", None, "Draft", "body").expect("save draft");

    assert_eq!(
        id_scoped_entries(&saved.id),
        vec![format!("{}.json", saved.id)],
        "a successful save must leave only the stored draft"
    );
}
