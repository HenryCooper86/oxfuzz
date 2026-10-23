use std::sync::atomic::Ordering;

use hf_core::provider::ToolCallingMode;
use hf_provider::{HttpProtocol, ProviderPoolConfig, ProviderPoolImpl};

mod common;

const INVALID_PROXY: &str = "http://review-user:review-secret@[";

fn config(url: &str, backend: &str) -> ProviderPoolConfig {
    serde_json::from_value(serde_json::json!({
        "providers": [{"id":"fixture", "provider_type":backend, "model":"fixture",
                       "api_key":"fixture", "base_url":url}],
        "proxy": {"global": {"url": INVALID_PROXY}}
    }))
    .unwrap()
}

#[tokio::test]
async fn invalid_proxy_cannot_connect_directly() {
    let fixture = common::server(200, vec![b"{}".to_vec()]).await;
    let result = hf_provider::http_headers::provider_http_client(
        HttpProtocol::Http1,
        Some(INVALID_PROXY.to_owned()),
    );
    match result {
        Ok(client) => {
            client.get(&fixture.url).send().await.unwrap();
            assert_eq!(
                fixture.calls.load(Ordering::SeqCst),
                0,
                "invalid proxy allowed a direct connection"
            );
            panic!("invalid proxy must fail construction");
        }
        Err(error) => {
            let detail = format!("{error} {error:?}");
            assert!(!detail.contains("review-user"));
            assert!(!detail.contains("review-secret"));
        }
    }
}

#[test]
fn pool_rejects_invalid_proxy_for_every_adapter() {
    for backend in ["openai", "anthropic", "azure", "gemini", "ollama"] {
        let config = config("http://127.0.0.1:1", backend);
        let error = ProviderPoolImpl::from_config(&config)
            .expect_err("invalid proxy must fail pool construction");
        let detail = format!("{error} {error:?}");
        assert!(!detail.contains("review-user"), "{backend}");
        assert!(!detail.contains("review-secret"), "{backend}");
        assert!(hf_provider::build_providers(&config).is_err(), "{backend}");
    }
}

#[test]
fn explicit_proxy_urls_require_a_supported_scheme_and_host() {
    for url in ["", "not a proxy", "http://", "ftp://127.0.0.1:8080"] {
        assert!(
            hf_provider::http_headers::provider_http_client(HttpProtocol::Http1, Some(url.into()))
                .is_err(),
            "{url}"
        );
    }
    for url in [
        "http://127.0.0.1:8080",
        "https://127.0.0.1:8443",
        "socks4://127.0.0.1:1080",
        "socks4a://127.0.0.1:1080",
        "socks5://127.0.0.1:1080",
        "socks5h://127.0.0.1:1080",
    ] {
        assert!(
            hf_provider::http_headers::provider_http_client(HttpProtocol::Http1, Some(url.into()))
                .is_ok(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn configured_proxy_receives_requests_and_disabled_entry_is_ignored() {
    let proxy = common::server(200, vec![b"proxied".to_vec()]).await;
    let origin = common::server(200, vec![b"direct".to_vec()]).await;
    let client = hf_provider::http_headers::provider_http_client(
        HttpProtocol::Http1,
        Some(proxy.url.clone()),
    )
    .unwrap();
    let body = client
        .get(&origin.url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "proxied");
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 1);
    assert_eq!(origin.calls.load(Ordering::SeqCst), 0);

    let mut config = config(&origin.url, "openai");
    config.proxy.global.as_mut().unwrap().enabled = false;
    assert!(config.validate().is_ok());
    assert!(ProviderPoolImpl::from_config(&config).is_ok());
}

#[test]
fn proxy_validation_checks_all_enabled_scopes() {
    for proxy in [
        serde_json::json!({"global":{"url":INVALID_PROXY}}),
        serde_json::json!({"tags":{"general":{"url":INVALID_PROXY}}}),
        serde_json::json!({"providers":{"fixture":{"url":INVALID_PROXY}}}),
    ] {
        let mut config = config("http://127.0.0.1:1", "openai");
        config.proxy = serde_json::from_value(proxy).unwrap();
        assert!(config.validate().is_err());
    }
}

#[tokio::test]
async fn direct_adapters_reject_invalid_proxy() {
    let fixture = common::server(400, vec![b"{}".to_vec()]).await;
    macro_rules! adapter {
        ($ty:ty) => {
            <$ty>::new(
                "fixture",
                "fixture",
                "fixture".into(),
                Some(fixture.url.clone()),
                Some(INVALID_PROXY.into()),
                vec!["general".into()],
                vec![],
                1,
                4096,
                ToolCallingMode::default(),
            )
            .expect_err("direct adapter must reject invalid proxy")
        };
    }
    let adapters = [
        adapter!(hf_provider::OpenAiProvider),
        adapter!(hf_provider::AnthropicProvider),
        adapter!(hf_provider::AzureOpenAiProvider),
        adapter!(hf_provider::GeminiProvider),
        adapter!(hf_provider::OllamaProvider),
    ];
    for error in adapters {
        let detail = format!("{error} {error:?}");
        assert!(!detail.contains("review-secret"));
        assert!(!detail.contains("review-user"));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}
