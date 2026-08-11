#[test]
fn proofless_schedule_history_archive_entry_points_are_not_exposed() {
    let source = include_str!("../src/retired_engine.rs");

    for forbidden in [
        "pub async fn archive_schedule_history_for_retired_engine(",
        "async fn archive_schedule_history(&self",
    ] {
        assert!(
            !source.contains(forbidden),
            "proof-less retirement authority remains: {forbidden}"
        );
    }
    assert!(source.contains("pub async fn archive_schedule_history_for_retired_engine_operation("));
}
