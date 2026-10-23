//! Exact decimal presentation for operator settings and retained budget usage.
use serde::Serialize;
use serde_json::Value;

use super::ModelBudgetSettings;

const INTEGER_FIELDS: [&str; 4] = [
    "max_calls",
    "max_tokens",
    "max_cost_microusd",
    "max_output_tokens",
];

pub(crate) fn stringify_config(value: &mut Value) {
    let Some(budget) = value.get_mut("model_budget").and_then(Value::as_object_mut) else {
        return;
    };
    for key in INTEGER_FIELDS {
        if let Some(value) = budget.get_mut(key) {
            if let Some(number) = value.as_i64() {
                *value = Value::String(number.to_string());
            }
        }
    }
}

pub(crate) fn parse_config(value: &mut Value) -> Result<(), String> {
    let Some(budget) = value.get_mut("model_budget").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    for key in INTEGER_FIELDS {
        if let Some(value) = budget.get_mut(key) {
            if let Some(text) = value.as_str() {
                let parsed = text.parse::<i64>().map_err(|_| {
                    format!("model_budget.{key} must be a positive decimal integer")
                })?;
                if parsed <= 0 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(format!(
                        "model_budget.{key} must be a positive decimal integer"
                    ));
                }
                *value = Value::from(parsed);
            }
        }
    }
    Ok(())
}

/// Read-only policy and ledger view; integers are decimal strings for GUI precision.
#[derive(Debug, Serialize)]
pub struct ModelBudgetView {
    /// Whether this build supports budget enforcement.
    pub available: bool,
    /// Configured policy; provider instances require reload before adopting changes.
    pub settings: ModelBudgetPolicyView,
    /// Durable totals for the configured scope, including unresolved reservations.
    pub usage: Option<ModelBudgetUsageView>,
}

/// Durable scope totals without JavaScript number rounding.
#[derive(Debug, Serialize)]
pub struct ModelBudgetUsageView {
    /// Workflow identity.
    pub scope_id: String,
    /// Number of admitted upstream attempts.
    pub calls: String,
    /// Token charges and outstanding reservations.
    pub tokens: String,
    /// Cost charges and outstanding reservations in millionths of USD.
    pub cost_microusd: String,
    /// Latest recorded admission denial.
    pub terminal_reason: Option<String>,
    /// Whether accounting permanently blocked this scope.
    pub blocked: bool,
}

/// Configured spending limits represented without integer rounding.
#[derive(Debug, Serialize)]
pub struct ModelBudgetPolicyView {
    /// Workflow identity, absent when budgeting is disabled.
    pub scope_id: Option<String>,
    /// Upstream attempt limit.
    pub max_calls: Option<String>,
    /// Total token limit.
    pub max_tokens: Option<String>,
    /// Cost limit in millionths of USD.
    pub max_cost_microusd: Option<String>,
    /// Per-request output allowance.
    pub max_output_tokens: String,
}

fn empty_view(settings: &ModelBudgetSettings) -> ModelBudgetView {
    ModelBudgetView {
        available: cfg!(feature = "model-budgets"),
        settings: ModelBudgetPolicyView {
            scope_id: settings.scope_id.clone(),
            max_calls: settings.max_calls.map(|value| value.to_string()),
            max_tokens: settings.max_tokens.map(|value| value.to_string()),
            max_cost_microusd: settings.max_cost_microusd.map(|value| value.to_string()),
            max_output_tokens: settings.max_output_tokens.to_string(),
        },
        usage: None,
    }
}

#[cfg(feature = "model-budgets")]
pub(super) async fn read_view(
    settings: &ModelBudgetSettings,
    store: &hf_storage::Store,
) -> Result<ModelBudgetView, String> {
    let mut view = empty_view(settings);
    if let Some(scope) = &settings.scope_id {
        view.usage = store
            .model_budget_snapshot(scope)
            .await
            .map_err(|error| error.to_string())?
            .map(|usage| ModelBudgetUsageView {
                scope_id: usage.scope_id,
                calls: usage.calls.to_string(),
                tokens: usage.tokens.to_string(),
                cost_microusd: usage.cost_microusd.to_string(),
                terminal_reason: usage.terminal_reason,
                blocked: usage.blocked,
            });
    }
    Ok(view)
}

/// Read configured policy and its retained ledger without contacting a provider.
///
/// # Errors
/// Returns configuration and storage errors rather than hiding unavailable usage.
pub async fn model_budget_view() -> Result<ModelBudgetView, String> {
    let settings = crate::config::effective_model_budget_settings()?;
    #[cfg(feature = "model-budgets")]
    if settings.scope_id.is_some() {
        let store = hf_storage::Store::connect_from_env()
            .await
            .map_err(|error| error.to_string())?;
        return read_view(&settings, &store).await;
    }
    Ok(empty_view(&settings))
}
