#![cfg(feature = "automotive-scapy")]

//! Token-gated `/automotive/approval/mint` contract.
//!
//! This integration target owns `HF_CONFIG_DIR` and `HF_DB_PATH` for the whole
//! process: the mint reads the persisted operator policy and stores its
//! approval MAC key beside the database, so both point into fixtures here.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ImmutableImageReference, ResourceLimits, RuntimeAdapter};
use std::{path::Path, sync::Arc};
use tower::ServiceExt;

const TOKEN: &str = "correct-horse-battery-staple";

/// Runtime adapter modelling a pinned sidecar image without Docker: the mint
/// needs image presence (the default) and a content-addressed identity, but
/// never executes anything.
struct PinnedSidecarRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for PinnedSidecarRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        _cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Err(ClassifiedError::Sandbox("not implemented".to_owned()))
    }

    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        Ok(Some(
            ImmutableImageReference::from_sha256_id(format!("sha256:{}", "a".repeat(64))).unwrap(),
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Err(ClassifiedError::Sandbox("not implemented".to_owned()))
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Err(ClassifiedError::Sandbox("not implemented".to_owned()))
    }
}

/// Install an enabled physical-bench operator policy (UDS over `can0`).
fn install_physical_bench_policy(config_dir: &Path) {
    let mut settings = hf_service::config::AutomotiveSettings {
        ..hf_service::config::AutomotiveSettings::default()
    };
    settings.allowed_modes.push("physical_bench".to_owned());
    settings.limits.max_packets = 1_000;
    settings.physical_bench.enabled = true;
    settings.physical_bench.interfaces = vec!["can0".to_owned()];
    settings.physical_bench.arbitration_ids = vec![0x7e0];
    settings.physical_bench.uds_services = vec![0x22];
    hf_service::config::AutomotiveConfigStore::new(config_dir)
        .set(settings)
        .expect("install physical-bench automotive policy");
}

#[tokio::test]
async fn approval_mint_is_token_gated_and_returns_keyed_evidence() {
    let workspace = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", config_dir.path());
    std::env::set_var("HF_DB_PATH", state_dir.path().join("fixture.db"));
    install_physical_bench_policy(config_dir.path());

    let container = hf_service::ServiceContainer::new(Arc::new(PinnedSidecarRuntime), None);
    let security = hf_web::WebSecurityConfig::new(
        Some(TOKEN.to_owned()),
        false,
        Vec::new(),
        vec![workspace.path().to_path_buf()],
    )
    .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(container),
        security,
    );

    let body = serde_json::json!({
        "interface": "can0",
        "plan": {
            "protocol": "uds",
            "mode": "physical_bench",
            "deterministic_seed": 7,
            "steps": [{
                "sequence": 0,
                "delay_micros": 0,
                "action": "send",
                "message": {
                    "protocol": "uds",
                    "payload_hex": "221234",
                    "fields": {
                        "arbitration_id": "0x7e0",
                        "service": "0x22"
                    }
                }
            }]
        },
        "approved_by": "desktop-operator"
    });

    // The route is token-gated: no credential means 401.
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/automotive/approval/mint")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    // With the token, the mint returns keyed approval evidence.
    let minted = app
        .oneshot(
            Request::builder()
                .uri("/automotive/approval/mint")
                .method("POST")
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(minted.status(), StatusCode::OK);
    let bytes = to_bytes(minted.into_body(), 1024 * 1024).await.unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        !evidence["scope_hmac"]
            .as_str()
            .expect("evidence carries scope_hmac")
            .is_empty(),
        "minted evidence must carry a keyed scope HMAC"
    );
    assert!(!evidence["approval_id"].as_str().unwrap().is_empty());
    assert_eq!(evidence["approved_by"], "desktop-operator");
    assert!(!evidence["scope_sha256"].as_str().unwrap().is_empty());
}
