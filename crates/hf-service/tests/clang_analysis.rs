#![cfg(feature = "clang-analysis")]
use hf_service::clang_analysis::{parse_clang_analysis_settings, StartClangAnalysisRequest};
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
