//! Bounded experiment ingress through the actual router, including disabled builds.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    // Initial route-absence RED replies are empty instead of JSON.
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn ingress_is_bounded_before_json_and_all_operations_remain_registered() {
    let directory = tempfile::tempdir().unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, vec![], vec![directory.path().into()]).unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    for uri in [
        "/coverage/experiments",
        "/coverage/experiments/00000000-0000-4000-8000-000000000001/complete",
        "/coverage/experiments/00000000-0000-4000-8000-000000000001/cancel",
    ] {
        assert_eq!(
            request(&app, "POST", uri, vec![b'!'; 16_385]).await.0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            request(&app, "POST", uri, vec![b'!'; 16_384]).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    for uri in [
        "/coverage/experiments",
        "/coverage/experiments/00000000-0000-4000-8000-000000000001",
    ] {
        assert_eq!(
            request(&app, "GET", uri, vec![]).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let denied = tempfile::tempdir().unwrap();
    let make = |project: &std::path::Path| {
        serde_json::json!({"project":project,"target_id":"00000000-0000-4000-8000-000000000002","baseline_run_id":"00000000-0000-4000-8000-000000000003","kind":"grow_corpus","goal_function":"parse","hypothesis":"test hypothesis","duration_secs":60}).to_string().into_bytes()
    };
    assert_eq!(
        request(&app, "POST", "/coverage/experiments", make(denied.path()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let result = request(
        &app,
        "POST",
        "/coverage/experiments",
        make(directory.path()),
    )
    .await;
    #[cfg(feature = "coverage-experiments")]
    assert_eq!(
        result,
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"code":"storage_unavailable","error":"storage_unavailable"})
        )
    );
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(
        result,
        (
            StatusCode::NOT_IMPLEMENTED,
            serde_json::json!({"code":"feature_unavailable","error":"coverage experiments are not included in this application build"})
        )
    );
}

#[tokio::test]
async fn retained_owner_scope_and_result_roots_precede_lifecycle_or_feature_absence() {
    let (_directory, service, record, result_id) =
        hf_service::test_support::coverage_experiments::presentation_fixture().await;
    let denied = tempfile::tempdir().unwrap();
    let security = hf_web::WebSecurityConfig::new(
        None,
        true,
        vec![],
        vec![record.project_root.clone().into()],
    )
    .unwrap();
    let app =
        hf_web::build_with_state_and_security(hf_web::AppState::new(service.clone()), security);
    let scope = serde_json::json!({"project":record.project_root,"target_id":record.target_id});
    let query = format!(
        "project={}&target_id={}",
        record.project_root, record.target_id
    );
    let base = format!("/coverage/experiments/{}", record.id);
    let get = request(&app, "GET", &format!("{base}?{query}"), vec![]).await;
    #[cfg(feature = "coverage-experiments")]
    {
        assert_eq!(get.0, StatusCode::OK);
        assert_eq!(get.1["baseline"]["seed"], u64::MAX.to_string());
        assert_eq!(get.1["baseline"]["engine_env"][0][1], "[REDACTED]");
    }
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(
        get,
        (
            StatusCode::NOT_IMPLEMENTED,
            serde_json::json!({"code":"feature_unavailable","error":"coverage experiments are not included in this application build"})
        )
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!(
                "{base}?project={}&target_id={}",
                denied.path().display(),
                record.target_id
            ),
            vec![]
        )
        .await
        .1["code"],
        "different_project"
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!(
                "{base}?project={}&target_id={}",
                record.project_root,
                uuid::Uuid::new_v4()
            ),
            vec![]
        )
        .await
        .1["code"],
        "different_target"
    );
    let denied_app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(service.clone()),
        hf_web::WebSecurityConfig::new(None, true, vec![], vec![denied.path().into()]).unwrap(),
    );
    for (method, uri, body) in [
        ("GET", format!("{base}?{query}"), serde_json::Value::Null),
        (
            "POST",
            format!("{base}/complete"),
            serde_json::json!({"scope":scope,"result_run_id":result_id}),
        ),
        (
            "POST",
            format!("{base}/cancel"),
            serde_json::json!({"scope":scope,"reason":"stop"}),
        ),
    ] {
        assert_eq!(
            request(&denied_app, method, &uri, body.to_string().into_bytes())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let foreign = hf_service::test_support::coverage_experiments::retained_campaign(
        service.store().unwrap(),
        denied.path().canonicalize().unwrap().to_str().unwrap(),
        chrono::Utc::now() - chrono::Duration::minutes(2),
    )
    .await;
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{base}/complete"),
            serde_json::json!({"scope":scope,"result_run_id":foreign.id})
                .to_string()
                .into_bytes()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let missing = uuid::Uuid::new_v4();
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/coverage/experiments/{missing}?{query}"),
            vec![]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let list = request(
        &app,
        "GET",
        &format!("/coverage/experiments?{query}&limit=10"),
        vec![],
    )
    .await;
    #[cfg(feature = "coverage-experiments")]
    assert_eq!(list.1["items"][0]["id"], record.id.to_string());
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(list.0, StatusCode::NOT_IMPLEMENTED);
    let result = request(
        &app,
        "POST",
        &format!("{base}/complete"),
        serde_json::json!({"scope":scope,"result_run_id":result_id})
            .to_string()
            .into_bytes(),
    )
    .await;
    #[cfg(feature = "coverage-experiments")]
    {
        assert_eq!(result.0, StatusCode::OK, "{result:?}");
        assert_eq!(result.1["result"]["run"]["run_id"], result_id.to_string());
        assert_eq!(result.1["result"]["run"]["status"], "failed");
    }
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(result.0, StatusCode::NOT_IMPLEMENTED);
    let cancelled = request(
        &app,
        "POST",
        &format!("{base}/cancel"),
        serde_json::json!({"scope":scope,"reason":"abandoned"})
            .to_string()
            .into_bytes(),
    )
    .await;
    #[cfg(feature = "coverage-experiments")]
    assert_eq!(cancelled.0, StatusCode::CONFLICT);
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(cancelled.0, StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn exact_cap_valid_json_and_raw_query_limits_preserve_error_precedence() {
    let project = tempfile::tempdir().unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, vec![], vec![project.path().into()]).unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    let mut body=serde_json::json!({"project":project.path(),"target_id":"00000000-0000-4000-8000-000000000001","baseline_run_id":"00000000-0000-4000-8000-000000000002","kind":"grow_corpus","goal_function":"parse","hypothesis":"reviewed operator intent","duration_secs":60}).to_string().into_bytes();
    body.resize(16_384, b' ');
    let result = request(&app, "POST", "/coverage/experiments", body.clone()).await;
    #[cfg(feature = "coverage-experiments")]
    assert_eq!(result.1["code"], "storage_unavailable");
    #[cfg(not(feature = "coverage-experiments"))]
    assert_eq!(result.1["code"], "feature_unavailable");
    body.push(b' ');
    assert_eq!(
        request(&app, "POST", "/coverage/experiments", body).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for path in [
        "/coverage/experiments",
        "/coverage/experiments/00000000-0000-4000-8000-000000000001",
    ] {
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("{path}?{}", "!".repeat(16_385)),
                vec![]
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("{path}?{}", "!".repeat(16_384)),
                vec![]
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    for id in [
        "00000000-0000-4000-0000-000000000001",
        "00000000000040008000000000000001",
        "00000000-0000-4000-8000-00000000000A",
    ] {
        let uri=format!("/coverage/experiments?project={}&target_id=00000000-0000-4000-8000-000000000001&limit=10&before_created_at=2026-09-08T00:00:00.000000000Z&before_id={id}",project.path().display());
        assert_eq!(
            request(&app, "GET", &uri, vec![]).await.1["code"],
            "invalid_request"
        );
    }
}

#[cfg(feature = "coverage-experiments")]
#[tokio::test]
async fn actual_create_and_cancel_round_trip_preserves_intent() {
    let (_directory, service, record, _) =
        hf_service::test_support::coverage_experiments::presentation_fixture().await;
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(service),
        hf_web::WebSecurityConfig::new(
            None,
            true,
            vec![],
            vec![record.project_root.clone().into()],
        )
        .unwrap(),
    );
    let create = serde_json::json!({"project":record.project_root,"target_id":record.target_id,"baseline_run_id":record.baseline_run_id,"kind":"refine_harness","goal_function":"parse_value","hypothesis":"reviewed hypothesis","duration_secs":60});
    let response = request(
        &app,
        "POST",
        "/coverage/experiments",
        create.to_string().into_bytes(),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["hypothesis"], "reviewed hypothesis");
    assert_eq!(response.1["status"], "prepared");
    let id = response.1["id"].as_str().unwrap();
    let scope = serde_json::json!({"project":record.project_root,"target_id":record.target_id});
    let response = request(
        &app,
        "POST",
        &format!("/coverage/experiments/{id}/cancel"),
        serde_json::json!({"scope":scope,"reason":"abandoned deliberately"})
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["status"], "cancelled");
    assert_eq!(response.1["cancellation_reason"], "abandoned deliberately");
}
