//! Service-owned, durable workflow spending policy for individual provider attempts.

use serde::{Deserialize, Serialize};

pub(crate) mod presentation;
pub use presentation::{
    model_budget_view, ModelBudgetPolicyView, ModelBudgetUsageView, ModelBudgetView,
};

/// Operator policy for a campaign, trial, or multi-command workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelBudgetSettings {
    /// Stable workflow identity, retained across commands and restarts.
    pub scope_id: Option<String>,
    /// Maximum upstream attempts, including retries and health probes.
    pub max_calls: Option<u64>,
    /// Maximum input plus output tokens, including unresolved reservations.
    pub max_tokens: Option<u64>,
    /// Maximum cost in millionths of a US dollar.
    pub max_cost_microusd: Option<u64>,
    /// Explicit upper output allowance written into every admitted request.
    pub max_output_tokens: u32,
}

impl Default for ModelBudgetSettings {
    fn default() -> Self {
        Self {
            scope_id: None,
            max_calls: None,
            max_tokens: None,
            max_cost_microusd: None,
            max_output_tokens: 4096,
        }
    }
}

impl ModelBudgetSettings {
    /// Whether this policy enforces a spending limit.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.max_calls.is_some() || self.max_tokens.is_some() || self.max_cost_microusd.is_some()
    }

    /// Validate serialized operator input before assembling providers.
    pub fn validate(&self) -> Result<(), String> {
        if !cfg!(feature = "model-budgets") && self != &Self::default() {
            return Err("model_budget requires the model-budgets feature".into());
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > 1_000_000 {
            return Err("model_budget.max_output_tokens must be within 1..=1000000".into());
        }
        for (name, limit) in [
            ("max_calls", self.max_calls),
            ("max_tokens", self.max_tokens),
            ("max_cost_microusd", self.max_cost_microusd),
        ] {
            if limit.is_some_and(|value| value == 0 || value > i64::MAX as u64) {
                return Err(format!("model_budget.{name} must be within 1..=i64::MAX"));
            }
        }
        match &self.scope_id {
            Some(scope)
                if scope.is_empty()
                    || scope.len() > 128
                    || !scope
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)) =>
            {
                Err(
                    "model_budget.scope_id must contain 1..=128 ASCII letters, digits, or -_.:"
                        .into(),
                )
            }
            None if self.enabled() => {
                Err("model_budget.scope_id is required when a limit is configured".into())
            }
            Some(_) if !self.enabled() => {
                Err("model_budget.scope_id requires at least one spending limit".into())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "model-budgets")]
mod dispatch;
#[cfg(feature = "model-budgets")]
pub(crate) use dispatch::configured_budget_providers;
#[cfg(feature = "model-budgets")]
pub use dispatch::{budget_providers, model_budget_status};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_or_unscoped_limits_fail_config_loading() {
        for input in [
            "[model_budget]\nmax_calls=1",
            "[model_budget]\nscope_id='trial'\nmax_calls=0",
            "[model_budget]\nscope_id='trial'\nmax_tokens=-1",
            "[model_budget]\nscope_id='trial'\nmax_cost_microusd=0",
            "[model_budget]\nscope_id='trial'\nmax_calls=1\nmax_output_tokens=0",
            "[model_budget]\nscope_id='trial'\nmax_calls=1\nunknown=5",
        ] {
            assert!(
                crate::config::parse_model_budget_settings(input).is_err(),
                "{input}"
            );
        }
        assert_eq!(
            crate::config::parse_model_budget_settings("").unwrap(),
            ModelBudgetSettings::default()
        );
    }

    #[test]
    fn active_policy_requires_compiled_feature() {
        let parsed = crate::config::parse_model_budget_settings(
            "[model_budget]\nscope_id='trial'\nmax_calls=10",
        );
        assert_eq!(parsed.is_ok(), cfg!(feature = "model-budgets"));
    }
}

#[cfg(test)]
mod presentation_tests {
    #[test]
    fn budget_settings_json_preserves_large_integer_values() {
        let input =
            "[model_budget]\nscope_id='trial'\nmax_tokens=9007199254740993\nmax_output_tokens=4096";
        let value = crate::config::toml_to_json(input).unwrap();
        assert_eq!(value["model_budget"]["max_tokens"], "9007199254740993");
        assert_eq!(value["model_budget"]["max_output_tokens"], "4096");
        let restored = crate::config::json_to_toml(&value).unwrap();
        let parsed: toml::Value = toml::from_str(&restored).unwrap();
        assert_eq!(
            parsed["model_budget"]["max_tokens"].as_integer(),
            Some(9_007_199_254_740_993)
        );
    }

    #[test]
    fn budget_settings_json_rejects_invalid_decimal_limits() {
        for value in ["1.5", "-1", "0", "9223372036854775808", "1e6", ""] {
            let input = serde_json::json!({"model_budget":{"scope_id":"trial","max_calls":value}});
            assert!(crate::config::json_to_toml(&input).is_err(), "{value}");
        }
    }
}

#[cfg(all(test, feature = "model-budgets"))]
mod view_tests {
    use super::*;

    #[tokio::test]
    async fn presentation_reads_retained_scope_without_reserving_an_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let store = hf_storage::Store::connect(dir.path().join("budget.db"))
            .await
            .unwrap();
        let settings = ModelBudgetSettings {
            scope_id: Some("trial".into()),
            max_calls: Some(1),
            ..ModelBudgetSettings::default()
        };
        let policy = hf_storage::ModelBudgetPolicy {
            scope_id: "trial".into(),
            policy_json: "test".into(),
            max_calls: Some(1),
            max_tokens: None,
            max_cost_microusd: None,
        };
        let charge = hf_storage::ModelBudgetCharge {
            provider: "mock".into(),
            model: "mock".into(),
            input_tokens: 9_007_199_254_740_993,
            output_tokens: 0,
            cost_microusd: 7,
        };
        store.reserve_model_budget(&policy, &charge).await.unwrap();
        store.reserve_model_budget(&policy, &charge).await.unwrap();
        let view = presentation::read_view(&settings, &store).await.unwrap();
        let value = serde_json::to_value(view).unwrap();
        assert_eq!(value["settings"]["max_calls"], "1");
        assert_eq!(value["usage"]["scope_id"], "trial");
        assert_eq!(value["usage"]["tokens"], "9007199254740993");
        assert_eq!(value["usage"]["calls"], "1");
        assert_eq!(value["usage"]["terminal_reason"], "calls_exhausted");
    }
}
