use hf_core::grep_limits::GrepLimitsConfig;
use serde_json::json;

#[test]
fn grep_limits_validate_foreign_configuration_and_resolve_defaults() {
    let defaults = GrepLimitsConfig::default().resolve().unwrap();
    assert_eq!(defaults.output_bytes(), 10000);
    assert_eq!(defaults.heap_bytes(), 16 * 1024 * 1024);
    assert_eq!(defaults.timeout_secs(), 30);
    for (field, ceiling) in [
        ("output_bytes", 1024 * 1024),
        ("heap_bytes", 256 * 1024 * 1024),
        ("timeout_secs", 300),
    ] {
        for value in [0, ceiling + 1] {
            assert!(serde_json::from_value::<GrepLimitsConfig>(json!({(field):value})).is_err());
        }
        let exact: GrepLimitsConfig = serde_json::from_value(json!({(field):ceiling})).unwrap();
        assert!(exact.resolve().is_ok());
    }
    assert!(serde_json::from_value::<GrepLimitsConfig>(json!({"unknown":1})).is_err());
    assert!(GrepLimitsConfig {
        output_bytes: 0,
        ..GrepLimitsConfig::default()
    }
    .resolve()
    .is_err());
}
