//! Tests for workspace initialization.

#[tokio::test]
async fn init_scaffolds_missing_configs_and_db() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("providers.example.toml"), "x = 1\n").unwrap();
    std::fs::write(cfg.join("engines.example.toml"), "y = 2\n").unwrap();
    // A pre-existing target file must not be overwritten.
    std::fs::write(cfg.join("engines.toml"), "preexisting = true\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            cfg.join("engines.toml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let db = dir.path().join("data/test.db");

    let report = hf_service::init_at(&cfg, &db).await.unwrap();
    assert!(report
        .created_configs
        .contains(&"providers.toml".to_string()));
    assert!(!report.created_configs.contains(&"engines.toml".to_string()));
    assert!(cfg.join("providers.toml").exists());
    assert_eq!(
        std::fs::read_to_string(cfg.join("engines.toml")).unwrap(),
        "preexisting = true\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(cfg.join("engines.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(db.exists());

    // Idempotent: a second run materializes nothing new.
    let report2 = hf_service::init_at(&cfg, &db).await.unwrap();
    assert!(report2.created_configs.is_empty());
}
