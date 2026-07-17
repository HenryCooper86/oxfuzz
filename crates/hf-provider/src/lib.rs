//! hf-provider: Provider pool — LLM communication, routing, freeze/thaw, metrics.
//!
//! Ported 1:1 from y-agent's `y-provider`. The agent/hook/embedding runners
//! (`agent_runner`, `hook_llm_runner`, `embedding`) are deferred until the
//! agent-loop infrastructure (`hf-core::{agent,hook}`) lands.
//!
//! - [`ProviderPoolImpl`] — implements `ProviderPool` with tag-based routing
//! - [`TagBasedRouter`] — multi-tag matching with preferred model support
//! - [`FreezeManager`] — exponential backoff freeze/thaw lifecycle
//! - [`HealthChecker`] — health probe for frozen provider recovery
//! - [`ProviderMetrics`] — lock-free per-provider request/token counters
//! - [`OpenAiProvider`] / [`AnthropicProvider`] / [`GeminiProvider`] /
//!   [`OllamaProvider`] / [`AzureOpenAiProvider`] — LLM backends

pub mod config;
pub mod error;
pub mod error_classifier;
pub mod freeze;
pub mod health;
pub mod http_headers;
mod inter_stream;
mod inter_stream_adapter;
pub mod metrics;
pub mod metrics_export;
pub mod pool;
pub mod providers;
pub mod router;
pub mod sse;
mod tool_call_accumulator;

// Re-export primary types.
pub use config::{
    drain_config_load_errors, HttpProtocol, ProviderConfig, ProviderPoolConfig, ProxySpec,
};
pub use error::ProviderPoolError;
pub use error_classifier::{classify, classify_provider_error, StandardError};
pub use freeze::FreezeManager;
pub use health::HealthChecker;
pub use metrics::{MetricsSnapshot, ProviderMetrics};
pub use metrics_export::render_prometheus;
pub use pool::{build_providers, ProviderPoolImpl};
pub use providers::anthropic::AnthropicProvider;
pub use providers::azure::AzureOpenAiProvider;
pub use providers::gemini::GeminiProvider;
pub use providers::ollama::OllamaProvider;
pub use providers::openai::OpenAiProvider;
pub use router::{SelectionStrategy, TagBasedRouter};
