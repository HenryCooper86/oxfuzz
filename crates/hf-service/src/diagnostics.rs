//! LLM cost/trace recording, backed by `hf-diagnostics`.
//!
//! Every LLM call in the service (harness drafting, crash bug-report drafting,
//! chat) flows through [`LlmProviderBridge`](crate::container), the single
//! chokepoint that sees the model + token usage of each response. The bridge
//! reports each call here, where it is recorded as a diagnostics trace +
//! generation observation (with cost computed from the configured per-model
//! price). The GUI surfaces the aggregated session cost.
//!
//! The store is in-memory, so totals cover the current app session.

use std::collections::HashMap;
use std::sync::Arc;

use hf_core::types::TokenUsage;
use hf_diagnostics::types::{Observation, ObservationType, Trace};
use hf_diagnostics::{InMemoryTraceStore, TraceStore};
use serde::Serialize;
use uuid::Uuid;

/// A trace store the recorder writes to (in-memory or `SQLite`-backed).
pub type SharedTraceStore = Arc<dyn TraceStore>;

/// Per-model cost/usage rollup.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ModelCost {
    pub model: String,
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

/// Aggregated LLM cost/usage for the session.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CostSummary {
    pub calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub by_model: Vec<ModelCost>,
}

/// Records LLM generations as diagnostics traces and aggregates their cost.
pub struct DiagnosticsRecorder {
    store: SharedTraceStore,
    /// `model -> (cost_per_1k_input, cost_per_1k_output)` from provider config.
    costs: HashMap<String, (f64, f64)>,
    session_id: Uuid,
}

impl DiagnosticsRecorder {
    /// Build a recorder backed by an ephemeral in-memory store (resets per run).
    #[must_use]
    pub fn new(costs: HashMap<String, (f64, f64)>) -> Self {
        Self::with_store(costs, Arc::new(InMemoryTraceStore::new()))
    }

    /// Build a recorder backed by a specific (e.g. `SQLite`) trace store, so
    /// cost/usage persists across restarts. `summary` aggregates every trace in
    /// the store -- i.e. cumulative across sessions when persisted.
    #[must_use]
    pub fn with_store(costs: HashMap<String, (f64, f64)>, store: SharedTraceStore) -> Self {
        Self {
            store,
            costs,
            session_id: Uuid::new_v4(),
        }
    }

    /// Cost (USD) for a generation, from the configured per-1k-token price.
    fn cost_of(&self, model: &str, usage: &TokenUsage) -> f64 {
        let (per_in, per_out) = self.costs.get(model).copied().unwrap_or((0.0, 0.0));
        (f64::from(usage.input_tokens) / 1000.0)
            .mul_add(per_in, f64::from(usage.output_tokens) / 1000.0 * per_out)
    }

    /// Record one LLM generation. Best-effort: failures are logged, not returned.
    pub async fn record(&self, op: &str, model: &str, usage: &TokenUsage) {
        let cost = self.cost_of(model, usage);
        let mut trace = Trace::new(self.session_id, op);
        let trace_id = trace.id;
        trace.complete();
        if let Err(e) = self.store.insert_trace(trace).await {
            tracing::warn!("diagnostics insert_trace failed: {e}");
            return;
        }
        let mut obs = Observation::new(trace_id, ObservationType::Generation, op);
        obs.model = Some(model.to_owned());
        obs.input_tokens = u64::from(usage.input_tokens);
        obs.output_tokens = u64::from(usage.output_tokens);
        obs.cost_usd = cost;
        obs.complete();
        if let Err(e) = self.store.insert_observation(obs).await {
            tracing::warn!("diagnostics insert_observation failed: {e}");
        }
    }

    /// Aggregate cost/usage across every recorded generation this session.
    pub async fn summary(&self) -> CostSummary {
        let traces = self
            .store
            .list_traces(None, None, 100_000)
            .await
            .unwrap_or_default();
        let mut total = CostSummary::default();
        let mut by_model: HashMap<String, ModelCost> = HashMap::new();
        for trace in traces {
            let observations = self
                .store
                .get_observations(trace.id)
                .await
                .unwrap_or_default();
            for obs in observations
                .into_iter()
                .filter(|o| o.obs_type == ObservationType::Generation)
            {
                total.calls += 1;
                total.input_tokens += obs.input_tokens;
                total.output_tokens += obs.output_tokens;
                total.cost_usd += obs.cost_usd;
                let model = obs.model.clone().unwrap_or_else(|| "unknown".to_owned());
                let entry = by_model.entry(model.clone()).or_insert(ModelCost {
                    model,
                    ..ModelCost::default()
                });
                entry.calls += 1;
                entry.input_tokens += obs.input_tokens;
                entry.output_tokens += obs.output_tokens;
                entry.cost_usd += obs.cost_usd;
            }
        }
        total.by_model = by_model.into_values().collect();
        total.by_model.sort_by(|a, b| {
            b.cost_usd
                .total_cmp(&a.cost_usd)
                .then(b.calls.cmp(&a.calls))
        });
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(i: u32, o: u32) -> TokenUsage {
        TokenUsage {
            input_tokens: i,
            output_tokens: o,
            ..TokenUsage::default()
        }
    }

    #[tokio::test]
    async fn records_and_aggregates_cost() {
        let mut costs = HashMap::new();
        costs.insert("gpt".to_owned(), (1.0, 2.0)); // $1/1k in, $2/1k out
        let rec = DiagnosticsRecorder::new(costs);

        rec.record("harness_draft", "gpt", &usage(1000, 500)).await;
        rec.record("triage", "gpt", &usage(2000, 1000)).await;
        rec.record("chat", "free-model", &usage(500, 500)).await;

        let s = rec.summary().await;
        assert_eq!(s.calls, 3);
        assert_eq!(s.input_tokens, 3500);
        assert_eq!(s.output_tokens, 2000);
        // gpt call1 = 1.0 in + 1.0 out = 2.0; call2 = 2.0 + 2.0 = 4.0; total 6.0.
        // free-model has no price -> 0.
        assert!((s.cost_usd - 6.0).abs() < 1e-9, "cost was {}", s.cost_usd);
        assert_eq!(s.by_model.len(), 2);
        assert_eq!(s.by_model[0].model, "gpt"); // sorted by cost desc
    }

    #[tokio::test]
    async fn empty_summary_is_zero() {
        let rec = DiagnosticsRecorder::new(HashMap::new());
        let s = rec.summary().await;
        assert_eq!(s.calls, 0);
        assert!(s.by_model.is_empty());
    }
}
