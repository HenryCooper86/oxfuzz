//! hf-provider: LLM provider pool with tag routing and failover.
//!
//! Implements the `LlmProvider` and `ProviderPool` traits from `hf-core`.

pub mod pool;

pub use pool::DefaultProviderPool;
