//! Settings must show the configured database location rather than the checkout.
#[test]
fn settings_data_directory_follows_the_database_override() {
    let root = tempfile::tempdir().unwrap();
    let database = root.path().join("desktop-data/oxfuzz.db");
    std::env::set_var("HF_DB_PATH", &database);
    assert_eq!(
        hf_service::config::app_paths().data_dir,
        database.parent().unwrap().display().to_string()
    );
    std::env::set_var("HF_DB_PATH", "local.db");
    assert_eq!(hf_service::config::app_paths().data_dir, ".");
}
