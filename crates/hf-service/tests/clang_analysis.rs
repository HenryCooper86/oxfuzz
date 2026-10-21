#![cfg(feature = "clang-analysis")]
use hf_service::clang_analysis::{parse_clang_analysis_settings, StartClangAnalysisRequest};

#[test]
fn symbolic_settings_are_opt_in_and_reject_unused_or_out_of_range_limits() {
    let settings =
        parse_clang_analysis_settings("[clang_analysis.exploration]\nmax_nodes = 123").unwrap();
    let value = serde_json::to_value(settings).unwrap();
    assert_eq!(value["exploration"]["max_nodes"], 123);
    assert_eq!(value["exploration"]["max_records"], 256);
    for setting in [
        "max_nodes = 0",
        "max_records = 10001",
        "max_cfg_blocks = 0",
        "max_block_visits = 65",
        "max_inline_depth = 17",
        "unsupported = 1",
    ] {
        assert!(
            parse_clang_analysis_settings(&format!("[clang_analysis.exploration]\n{setting}"))
                .is_err()
        );
    }
    assert!(
        serde_json::to_value(parse_clang_analysis_settings("").unwrap()).unwrap()["exploration"]
            .is_null()
    );
}
use hf_service::{ServiceContainer, TargetLanguage};
use std::sync::Arc;

#[test]
fn analysis_settings_reject_zero_and_preserve_explicit_limits() {
    assert!(parse_clang_analysis_settings("[clang_analysis]\nmax_targets = 0").is_err());
    let settings = parse_clang_analysis_settings("[clang_analysis]\nmax_targets = 3").unwrap();
    assert_eq!(settings.resolve().unwrap().max_targets, 3);
    assert!(parse_clang_analysis_settings("[clang_analysis]\nunsupported = true").is_err());
}

#[tokio::test]
async fn explicit_analysis_requires_durable_storage_before_runtime() {
    let project = tempfile::tempdir().unwrap();
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let error = service
        .start_clang_analysis(StartClangAnalysisRequest {
            project: project.path().to_owned(),
            language: TargetLanguage::C,
            target_ids: vec![],
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("store"));
}

#[tokio::test]
async fn denied_analysis_cannot_reach_the_runtime_or_create_an_operation() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("denied.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(store.clone())
        .with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy {
                auto_allow_max: hf_guardrails::RiskTier::Low,
                deny_at: Some(hf_guardrails::RiskTier::Low),
            },
            Arc::new(hf_guardrails::EnvApprovalGate),
        ));
    let error = service
        .start_clang_analysis(StartClangAnalysisRequest {
            project: root.path().to_owned(),
            language: TargetLanguage::C,
            target_ids: vec![],
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("guardrail denied"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM clang_analysis_operations")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}
