//! Cost tracking per LLM provider.

use hf_core::types::TokenUsage;
use std::collections::HashMap;

/// Per-provider cost breakdown.
#[derive(Debug, Clone)]
pub struct ProviderCost {
    pub provider_id: String,
    pub total_tokens: u64,
    pub total_cost: f64,
}

/// Aggregated cost summary across all providers.
#[derive(Debug, Clone)]
pub struct CostSummary {
    pub total_tokens: u64,
    pub total_cost: f64,
    pub by_provider: Vec<ProviderCost>,
}

/// Accumulates token usage and dollar cost per provider.
pub struct CostTracker {
    by_provider: HashMap<String, (u64, f64)>,
}

impl CostTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_provider: HashMap::new(),
        }
    }

    /// Record a usage event.
    ///
    /// `cost_per_1k_input` and `cost_per_1k_output` are in dollars per 1000 tokens.
    pub fn record(
        &mut self,
        provider_id: &str,
        usage: &TokenUsage,
        cost_per_1k_input: f64,
        cost_per_1k_output: f64,
    ) {
        let cost = (usage.prompt_tokens as f64 / 1000.0 * cost_per_1k_input)
            + (usage.completion_tokens as f64 / 1000.0 * cost_per_1k_output);
        let entry = self
            .by_provider
            .entry(provider_id.to_owned())
            .or_insert((0, 0.0));
        entry.0 += usage.total_tokens;
        entry.1 += cost;
    }

    /// Produce a summary of all recorded costs.
    #[must_use]
    pub fn summary(&self) -> CostSummary {
        let mut by_provider: Vec<ProviderCost> = self
            .by_provider
            .iter()
            .map(|(id, (tokens, cost))| ProviderCost {
                provider_id: id.clone(),
                total_tokens: *tokens,
                total_cost: *cost,
            })
            .collect();
        by_provider.sort_by(|a, b| {
            b.total_cost
                .partial_cmp(&a.total_cost)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let total_tokens = by_provider.iter().map(|p| p.total_tokens).sum();
        let total_cost = by_provider.iter().map(|p| p.total_cost).sum();
        CostSummary {
            total_tokens,
            total_cost,
            by_provider,
        }
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self::new()
    }
}
