//! Runtime config saves replace admission policy without any external provider traffic.
#![cfg(feature = "model-budgets")]
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use hf_service::test_support::{ChatRequest, ProviderError, RouteRequest};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

async fn save(app: &Router, content: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config/write")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"name":"oxfuzz", "content":content}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn chat(container: &hf_service::ServiceContainer) -> Result<(), ProviderError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        container.provider_pool().unwrap().chat_completion(
            &ChatRequest::from_messages(vec![hf_service::Message::user("fixture")]),
            &RouteRequest::default(),
        ),
    )
    .await
    .unwrap()
    .map(|_| ())
}

#[tokio::test]
async fn settings_save_enforces_new_limits_and_preserves_spent_allowance_without_restart() {
    let root = tempfile::tempdir().unwrap();
    // This binary has one test; configuration and database are isolated to this process.
    std::env::set_var("HF_CONFIG_DIR", root.path());
    std::env::remove_var("HF_PROVIDER_API_KEY");
    std::env::set_var("HF_DB_PATH", root.path().join("budget.db"));
    std::fs::write(root.path().join("oxfuzz.toml"), "").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let fixture = Router::new().route("/v1/chat/completions", post(move || { let counter = counter.clone(); async move {
        counter.fetch_add(1, Ordering::SeqCst);
        Json(serde_json::json!({"id":"fixture", "object":"chat.completion", "created":0, "model":"fixture", "choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}))
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, fixture).await.unwrap();
    });
    let provider = format!("[[providers]]\nid='fixture'\nprovider_type='openai-compat'\nmodel='fixture'\napi_key='fixture'\nbase_url='{url}'\n");
    std::fs::write(root.path().join("providers.toml"), provider).unwrap();
    let container = hf_service::ServiceContainer::stubbed()
        .with_provider_pool(hf_service::provider_pool_from_config().unwrap());
    chat(&container).await.unwrap();
    chat(&container).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let security =
        hf_web::WebSecurityConfig::new(None, true, vec![], vec![root.path().into()]).unwrap();
    let app =
        hf_web::build_with_state_and_security(hf_web::AppState::new(container.clone()), security);
    let budget = "[model_budget]\nscope_id='saved-scope'\nmax_calls=1\n";
    assert_eq!(save(&app, budget).await, StatusCode::OK);
    chat(&container).await.unwrap();
    assert!(matches!(
        chat(&container).await,
        Err(ProviderError::ModelBudgetDenied { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(save(&app, budget).await, StatusCode::OK);
    assert!(matches!(
        chat(&container).await,
        Err(ProviderError::ModelBudgetDenied { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        save(&app, &budget.replace("saved-scope", "new-scope")).await,
        StatusCode::OK
    );
    chat(&container).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        save(&app, "[model_budget]\nmax_calls=0").await,
        StatusCode::BAD_REQUEST
    );
    assert!(matches!(
        chat(&container).await,
        Err(ProviderError::ModelBudgetDenied { .. })
    ));
    std::fs::remove_file(root.path().join("providers.toml")).unwrap();
    assert_eq!(save(&app, budget).await, StatusCode::BAD_REQUEST);
    assert!(
        container.provider_pool().is_none(),
        "activation failure must not keep an old unlimited or stale policy"
    );
    server.abort();
}
