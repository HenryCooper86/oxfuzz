use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, LlmProvider, ProviderError, ProviderMetadata,
    RequestMode,
};
use hf_core::types::{TokenUsage, TokenUsageSource};
use hf_storage::{
    ModelBudgetAdmission, ModelBudgetCharge, ModelBudgetPolicy, ModelBudgetSnapshot, Store,
};
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::ModelBudgetSettings;

struct BudgetController {
    settings: Result<ModelBudgetSettings, String>,
    store: OnceCell<Arc<Store>>,
}

impl BudgetController {
    fn denied(&self, reason: impl Into<String>) -> ProviderError {
        ProviderError::ModelBudgetDenied {
            scope_id: match &self.settings {
                Ok(settings) => settings
                    .scope_id
                    .clone()
                    .unwrap_or_else(|| "configuration".into()),
                Err(_) => "configuration".into(),
            },
            reason: reason.into(),
        }
    }

    async fn store(&self) -> Result<&Arc<Store>, ProviderError> {
        self.store
            .get_or_try_init(|| async { Store::connect_from_env().await.map(Arc::new) })
            .await
            .map_err(|error| self.denied(format!("accounting_unavailable: {error}")))
    }

    fn settings(&self) -> Result<&ModelBudgetSettings, ProviderError> {
        self.settings
            .as_ref()
            .map_err(|error| self.denied(format!("invalid_configuration: {error}")))
    }
}

/// Wrap providers before pool construction so retries and health probes are charged.
pub fn budget_providers(
    providers: Vec<Arc<dyn LlmProvider>>,
    settings: ModelBudgetSettings,
    store: Arc<Store>,
) -> Result<Vec<Arc<dyn LlmProvider>>, String> {
    settings.validate()?;
    if !settings.enabled() {
        return Ok(providers);
    }
    Ok(wrap(
        providers,
        BudgetController {
            settings: Ok(settings),
            store: OnceCell::new_with(Some(store)),
        },
    ))
}

pub(crate) fn configured_budget_providers(
    providers: Vec<Arc<dyn LlmProvider>>,
) -> Vec<Arc<dyn LlmProvider>> {
    let settings = crate::config::effective_model_budget_settings();
    if settings.as_ref().is_ok_and(|settings| !settings.enabled()) {
        return providers;
    }
    // A bad configuration installs a denying decorator. It must not cause the
    // pool factory's config-to-environment fallback to remove enforcement.
    wrap(
        providers,
        BudgetController {
            settings,
            store: OnceCell::new(),
        },
    )
}

fn wrap(
    providers: Vec<Arc<dyn LlmProvider>>,
    controller: BudgetController,
) -> Vec<Arc<dyn LlmProvider>> {
    let controller = Arc::new(controller);
    providers
        .into_iter()
        .map(|inner| {
            Arc::new(BudgetedProvider {
                inner,
                controller: controller.clone(),
            }) as Arc<dyn LlmProvider>
        })
        .collect()
}

/// Inspect the configured workflow without contacting a model.
pub async fn model_budget_status() -> Result<Option<ModelBudgetSnapshot>, String> {
    let settings = crate::config::effective_model_budget_settings()?;
    let Some(scope) = settings.scope_id else {
        return Ok(None);
    };
    let store = Store::connect_from_env()
        .await
        .map_err(|error| error.to_string())?;
    store
        .model_budget_snapshot(&scope)
        .await
        .map_err(|error| error.to_string())
}

struct BudgetedProvider {
    inner: Arc<dyn LlmProvider>,
    controller: Arc<BudgetController>,
}

struct Attempt {
    id: Uuid,
    controller: Arc<BudgetController>,
    input_price: f64,
    output_price: f64,
    priced: bool,
}

impl Attempt {
    async fn settle(&self, usage: &TokenUsage) -> Result<(), ProviderError> {
        if usage.source != TokenUsageSource::ProviderReported
            || usage.input_tokens == 0
            || usage.output_tokens == 0
        {
            return Ok(());
        }
        // Cache counters can be additional (Anthropic) or included (OpenAI).
        // Charging both is conservative until adapters expose disjoint counts.
        let input = i64::from(usage.input_tokens)
            + i64::from(usage.cache_read_tokens.unwrap_or(0))
            + i64::from(usage.cache_write_tokens.unwrap_or(0));
        let output = i64::from(usage.output_tokens);
        let cost = if self.priced {
            price(input, output, self.input_price, self.output_price)
                .map_err(|reason| self.controller.denied(reason))?
        } else {
            0
        };
        let within = self
            .controller
            .store()
            .await?
            .settle_model_budget(self.id, input, output, cost)
            .await
            .map_err(|error| {
                self.controller
                    .denied(format!("settlement_failed: {error}"))
            })?;
        if !within {
            return Err(self.controller.denied("usage_exceeded_reservation"));
        }
        Ok(())
    }
}

impl BudgetedProvider {
    async fn reserve(
        &self,
        request: &ChatRequest,
    ) -> Result<(ChatRequest, Attempt), ProviderError> {
        let controller = &self.controller;
        let settings = controller.settings()?;
        let meta = self.metadata();
        let metered = settings.max_tokens.is_some() || settings.max_cost_microusd.is_some();
        if metered
            && (request.request_mode != RequestMode::TextChat
                || request
                    .model
                    .as_ref()
                    .is_some_and(|model| model != &meta.model)
                || !(request.extra.is_null()
                    || request
                        .extra
                        .as_object()
                        .is_some_and(serde_json::Map::is_empty)))
        {
            return Err(controller.denied("unbounded_request_parameters"));
        }
        let priced = meta.cost_per_1k_input.is_finite()
            && meta.cost_per_1k_input > 0.0
            && meta.cost_per_1k_output.is_finite()
            && meta.cost_per_1k_output > 0.0;
        if settings.max_cost_microusd.is_some() && !priced {
            return Err(controller.denied("unknown_pricing"));
        }
        let mut effective = request.clone();
        let output = request
            .max_tokens
            .map_or(settings.max_output_tokens, |limit| {
                limit.min(settings.max_output_tokens)
            });
        if output == 0 || meta.context_window == 0 {
            return Err(controller.denied("unbounded_token_allowance"));
        }
        effective.max_tokens = Some(output);
        let input = i64::try_from(meta.context_window)
            .map_err(|_| controller.denied("token_allowance_overflow"))?;
        let cost = if priced {
            price(
                input,
                i64::from(output),
                meta.cost_per_1k_input,
                meta.cost_per_1k_output,
            )
            .map_err(|reason| controller.denied(reason))?
        } else {
            0
        };
        let policy = ModelBudgetPolicy {
            scope_id: settings
                .scope_id
                .clone()
                .ok_or_else(|| controller.denied("missing_scope"))?,
            policy_json: serde_json::to_string(settings)
                .map_err(|error| controller.denied(error.to_string()))?,
            max_calls: settings
                .max_calls
                .map(i64::try_from)
                .transpose()
                .map_err(|error| controller.denied(error.to_string()))?,
            max_tokens: settings
                .max_tokens
                .map(i64::try_from)
                .transpose()
                .map_err(|error| controller.denied(error.to_string()))?,
            max_cost_microusd: settings
                .max_cost_microusd
                .map(i64::try_from)
                .transpose()
                .map_err(|error| controller.denied(error.to_string()))?,
        };
        let charge = ModelBudgetCharge {
            provider: meta.id.to_string(),
            model: meta.model.clone(),
            input_tokens: input,
            output_tokens: i64::from(output),
            cost_microusd: cost,
        };
        let admission = controller
            .store()
            .await?
            .reserve_model_budget(&policy, &charge)
            .await
            .map_err(|error| controller.denied(format!("reservation_failed: {error}")))?;
        let id = match admission {
            ModelBudgetAdmission::Reserved(id) => id,
            ModelBudgetAdmission::Denied(reason) => return Err(controller.denied(reason)),
        };
        Ok((
            effective,
            Attempt {
                id,
                controller: controller.clone(),
                input_price: meta.cost_per_1k_input,
                output_price: meta.cost_per_1k_output,
                priced,
            },
        ))
    }
}

// Round each configured rate upward to integer microdollars per 1000 tokens,
// then perform multiplication and ceiling division with checked integers.
fn price(input: i64, output: i64, input_rate: f64, output_rate: f64) -> Result<i64, &'static str> {
    let charge = |tokens: i64, rate: f64| {
        let rate = (rate * 1_000_000.0).ceil();
        if !rate.is_finite() || rate < 0.0 || rate >= i64::MAX as f64 {
            return None;
        }
        let Ok(tokens) = u128::try_from(tokens) else {
            return None;
        };
        let value = tokens.checked_mul(rate as u128)?.div_ceil(1000);
        // A charge outside SQLite integer range is reported as cost_allowance_overflow.
        i64::try_from(value).ok()
    };
    charge(input, input_rate)
        .and_then(|input| charge(output, output_rate).and_then(|output| input.checked_add(output)))
        .ok_or("cost_allowance_overflow")
}

#[async_trait]
impl LlmProvider for BudgetedProvider {
    async fn chat_completion(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let (request, attempt) = self.reserve(request).await?;
        let response = self.inner.chat_completion(&request).await?;
        attempt.settle(&response.usage).await?;
        Ok(response)
    }

    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        let (request, attempt) = self.reserve(request).await?;
        let mut response = self.inner.chat_completion_stream(&request).await?;
        response.stream = Box::pin(futures::stream::unfold(
            (response.stream, Some(attempt), None, false),
            |(mut stream, mut attempt, mut usage, mut failed)| async move {
                if let Some(item) = stream.next().await {
                    match &item {
                        Ok(chunk) => {
                            if let Some(value) = &chunk.usage {
                                usage = Some(value.clone());
                            }
                        }
                        Err(_) => failed = true,
                    }
                    Some((item, (stream, attempt, usage, failed)))
                } else {
                    if !failed {
                        if let (Some(attempt), Some(usage)) = (attempt.take(), usage) {
                            if let Err(error) = attempt.settle(&usage).await {
                                return Some((Err(error), (stream, None, None, true)));
                            }
                        }
                    }
                    None
                }
            },
        ));
        Ok(response)
    }

    fn metadata(&self) -> &ProviderMetadata {
        self.inner.metadata()
    }
}
