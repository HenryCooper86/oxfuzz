//! Configured storage failures must not masquerade as authoritative empty data.

use std::path::Path;
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_service::ServiceContainer;
use uuid::Uuid;

fn assert_storage_error(error: &ClassifiedError) {
    assert!(
        matches!(error, ClassifiedError::Storage(_)),
        "expected a classified storage error, got {error}"
    );
}

#[tokio::test]
async fn persisted_read_views_propagate_a_closed_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("closed.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));
    store.pool().close().await;

    assert_storage_error(&service.all_crashes().await.unwrap_err());
    assert_storage_error(&service.all_corpus_entries().await.unwrap_err());
    assert_storage_error(&service.run_history(None).await.unwrap_err());
    assert_storage_error(
        &service
            .run_coverage_series(&Uuid::nil().to_string())
            .await
            .unwrap_err(),
    );
    assert_storage_error(
        &service
            .run_harness_source(&Uuid::nil().to_string())
            .await
            .unwrap_err(),
    );
    assert_storage_error(&service.auto_revert_events(None, 20).await.unwrap_err());
    assert_storage_error(
        &service
            .project_auto_revert_override(Path::new("/project"))
            .await
            .unwrap_err(),
    );
    assert_storage_error(
        &service
            .effective_auto_revert_view(Path::new("/project"))
            .await
            .unwrap_err(),
    );
    assert_storage_error(&service.project_auto_revert_overrides().await.unwrap_err());
    assert_storage_error(&service.export_project_data(None).await.unwrap_err());
    assert_storage_error(
        &service
            .schedulable_targets(Path::new("/project"))
            .await
            .unwrap_err(),
    );
    assert_storage_error(
        &service
            .generate_report(Path::new("/project"), "target")
            .await
            .unwrap_err(),
    );
    assert_storage_error(
        &service
            .corpus_absorb_crashes(Path::new("/project"), "target")
            .await
            .unwrap_err(),
    );
    assert_storage_error(
        &service
            .workbench_dashboard(Some(Path::new("/project")), None)
            .await
            .unwrap_err(),
    );
    assert!(matches!(
        service.system_snapshot().await.unwrap_err(),
        hf_service::diagnostics::DiagnosticsError::ApplicationStore(_)
    ));
}

#[tokio::test]
async fn missing_optional_store_remains_distinct_from_a_broken_store() {
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    assert!(service.all_crashes().await.unwrap().is_empty());
    assert!(service.all_corpus_entries().await.unwrap().is_empty());
    assert!(service.run_history(None).await.unwrap().is_empty());
    assert!(service
        .run_coverage_series(&Uuid::nil().to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .run_harness_source(&Uuid::nil().to_string())
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .auto_revert_events(None, 20)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .project_auto_revert_overrides()
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .project_auto_revert_override(Path::new("/project"))
        .await
        .unwrap()
        .is_none());
}
