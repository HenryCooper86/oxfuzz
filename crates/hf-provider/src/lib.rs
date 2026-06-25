//! hf-provider: LLM provider pool with tag routing and failover.
//!
//! Implements the `LlmProvider` and `ProviderPool` traits from `hf-core`.

pub mod error_classifier;
pub mod freeze;
pub mod http;
pub mod openai_compat;
pub mod pool;

pub use error_classifier::{classify, FailureClass};
pub use freeze::FreezeRegistry;
pub use http::HttpSender;
pub use openai_compat::{OpenAiCompatProvider, ProviderConfig};
pub use pool::DefaultProviderPool;
