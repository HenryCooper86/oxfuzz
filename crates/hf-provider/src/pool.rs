//! Provider pool implementation — the main `ProviderPool` trait impl.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::instrument;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, LlmProvider, ProviderError, ProviderMetadata,
    ProviderPool, ProviderStatus, RouteRequest,
};
use hf_core::types::ProviderId;

use crate::config::ProviderPoolConfig;
use crate::error::ProviderPoolError;
use crate::error_classifier;

use crate::freeze::FreezeManager;
use crate::health::HealthChecker;
use crate::metrics::{ProviderMetrics, SharedMetrics};
use crate::router::{RoutableProvider, TagBasedRouter};

/// Concrete implementation of the `ProviderPool` trait.
///
/// Manages a set of LLM providers with tag-based routing, freeze/thaw,
/// per-provider concurrency limits, global concurrency limit, and metrics tracking.
pub struct ProviderPoolImpl {
    providers: Vec<ProviderEntry>,
    router: TagBasedRouter,
    health_checker: HealthChecker,
    /// Cadence for the periodic health-check loop that recovers frozen
    /// providers, taken from `ProviderPoolConfig::health_check_interval_secs`
    /// (clamped to >= 1s so a zero config cannot spin the loop).
    health_check_interval: Duration,
    /// Global concurrency semaphore (across all providers).
    global_semaphore: Option<Arc<tokio::sync::Semaphore>>,
}

/// An entry in the pool combining provider, freeze state, semaphore, and metrics.
struct ProviderEntry {
    provider: Arc<dyn LlmProvider>,
    freeze_manager: Arc<FreezeManager>,
    semaphore: Arc<tokio::sync::Semaphore>,
    max_concurrency: usize,
    default_temperature: Option<f64>,
    default_top_p: Option<f64>,
    metrics: SharedMetrics,
    /// Explicit counter for active in-flight requests (including streaming),
    /// for observability. For streaming, both this counter and the concurrency
    /// permit are held (via the stream wrapper) until the stream is fully
    /// consumed or dropped, then released together.
    active_requests: Arc<AtomicUsize>,
}

/// Delegating provider whose metadata includes operator-configured pricing.
///
/// Backend constructors intentionally know nothing about deployment-specific
/// prices. Keeping the override at the pool boundary gives routing and metrics
/// the same effective metadata without duplicating cost arguments across every
/// provider implementation.
struct ConfiguredMetadataProvider {
    inner: Arc<dyn LlmProvider>,
    metadata: ProviderMetadata,
}

impl ConfiguredMetadataProvider {
    fn new(inner: Arc<dyn LlmProvider>, cost_in: f64, cost_out: f64) -> Self {
        let mut metadata = inner.metadata().clone();
        metadata.cost_per_1k_input = cost_in;
        metadata.cost_per_1k_output = cost_out;
        Self { inner, metadata }
    }
}

#[async_trait]
impl LlmProvider for ConfiguredMetadataProvider {
    async fn chat_completion(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        self.inner.chat_completion(request).await
    }

    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        self.inner.chat_completion_stream(request).await
    }

    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }
}

impl std::fmt::Debug for ProviderPoolImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderPoolImpl")
            .field("provider_count", &self.providers.len())
            .finish_non_exhaustive()
    }
}

/// RAII guard that decrements a provider's active-request counter on drop.
///
/// Used by both request paths so the counter is correct even under
/// cancellation: the non-streaming path holds it across the `await`, and the
/// streaming path moves it into the wrapped stream so it lives until the stream
/// is fully consumed or dropped.
struct ActiveRequestGuard(Arc<AtomicUsize>);

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// State threaded through the metrics-recording `unfold` that wraps a provider's
/// chunk stream, so a completed stream records its usage/cost exactly once (the
/// original stream reported nothing on success, leaving streamed spend invisible
/// while mid-stream errors were still counted -- skewing the error rate).
struct StreamMetricsState {
    stream: hf_core::provider::ChatStream,
    freeze_manager: Arc<FreezeManager>,
    metrics: crate::metrics::SharedMetrics,
    pid: ProviderId,
    cost_in: f64,
    cost_out: f64,
    /// Token counts from the most recent chunk that carried usage.
    usage: Option<(u32, u32)>,
    /// Set once the terminal outcome (success or error) has been recorded.
    recorded: bool,
}

impl ProviderPoolImpl {
    /// Create a new pool from a list of pre-constructed providers.
    ///
    /// Use this for testing or when providers are built externally.
    pub fn from_providers(
        providers: Vec<Arc<dyn LlmProvider>>,
        config: &ProviderPoolConfig,
    ) -> Self {
        let sampling_defaults = config
            .providers
            .iter()
            .map(|provider| (provider.id.as_str(), (provider.temperature, provider.top_p)))
            .collect::<std::collections::HashMap<_, _>>();

        let entries: Vec<ProviderEntry> = providers
            .into_iter()
            .map(|p| {
                let max_conc = p.metadata().max_concurrency;
                let (default_temperature, default_top_p) = sampling_defaults
                    .get(p.metadata().id.as_str())
                    .copied()
                    .unwrap_or((None, None));
                ProviderEntry {
                    provider: p,
                    freeze_manager: Arc::new(FreezeManager::new(
                        config.default_freeze_duration_secs,
                        config.max_freeze_duration_secs,
                    )),
                    semaphore: Arc::new(tokio::sync::Semaphore::new(max_conc)),
                    max_concurrency: max_conc,
                    default_temperature,
                    default_top_p,
                    metrics: Arc::new(ProviderMetrics::new()),
                    active_requests: Arc::new(AtomicUsize::new(0)),
                }
            })
            .collect();

        let global_semaphore = config
            .max_global_concurrency
            .map(|limit| Arc::new(tokio::sync::Semaphore::new(limit)));

        Self {
            providers: entries,
            router: TagBasedRouter::with_strategy(config.selection_strategy),
            // The `HealthChecker` duration is the per-request ping timeout,
            // NOT the check cadence; the cadence is `health_check_interval`
            // below, driven by the configured `health_check_interval_secs`.
            health_checker: HealthChecker::new(Duration::from_secs(10)),
            health_check_interval: Duration::from_secs(config.health_check_interval_secs.max(1)),
            global_semaphore,
        }
    }

    /// Create a new pool from a `ProviderPoolConfig`.
    ///
    /// Validates the config, resolves API keys and proxy URLs per provider,
    /// constructs the appropriate provider backend for each entry, and
    /// delegates to [`from_providers`](Self::from_providers).
    ///
    /// Providers with `enabled = false` are silently skipped.
    pub fn from_config(config: &ProviderPoolConfig) -> Result<Self, ProviderPoolError> {
        config.validate()?;
        let providers = build_providers(config);
        Ok(Self::from_providers(providers, config))
    }
}

/// Build provider instances from configuration.
///
/// Resolves API keys and proxy URLs per provider, constructs the appropriate
/// provider backend for each entry. Providers with `enabled = false` or
/// missing API keys are silently skipped (logged at info/warn level).
///
/// This is the **single source of truth** for provider construction.
/// Both `ProviderPoolImpl::from_config` and `ServiceContainer` must use
/// this function to avoid behavioral divergence.
pub fn build_providers(config: &ProviderPoolConfig) -> Vec<Arc<dyn LlmProvider>> {
    let mut providers: Vec<Arc<dyn LlmProvider>> = Vec::with_capacity(config.providers.len());

    for cfg in &config.providers {
        // Skip disabled providers.
        if !cfg.enabled {
            tracing::info!(
                provider_id = %cfg.id,
                "provider is disabled, skipping"
            );
            continue;
        }

        let Some(api_key) = cfg.resolve_api_key() else {
            let env_var = cfg.api_key_env.as_deref().unwrap_or("(not configured)");
            tracing::warn!(
                provider_id = %cfg.id,
                env_var = %env_var,
                "Skipping provider: API key not found in environment"
            );
            continue;
        };

        // Resolve the full proxy spec (URL + optional auth_env credentials) and
        // embed any credentials into the URL. reqwest applies embedded userinfo
        // as proxy basic auth, so credentials configured via `auth_env` are now
        // honored instead of silently dropped.
        let proxy_url = config
            .resolve_proxy_spec(&cfg.id, &cfg.tags)
            .map(|spec| spec.to_proxy_url());
        let tool_calling_mode = cfg.resolve_tool_calling_mode();
        let capabilities = cfg.resolve_capabilities();

        // DeepSeek uses an OpenAI-compatible REST API with a default base URL.
        let base_url_for_deepseek = || {
            cfg.base_url
                .clone()
                .or_else(|| Some("https://api.deepseek.com/v1".to_string()))
        };

        // Ollama Cloud is the hosted Ollama endpoint: the same native API as the
        // local server, but at ollama.com and authenticated with the API key.
        let base_url_for_ollama_cloud = || {
            cfg.base_url
                .clone()
                .or_else(|| Some("https://ollama.com".to_string()))
        };

        // Macro to reduce per-variant boilerplate.
        macro_rules! make_provider {
            ($ty:ty, $base:expr) => {
                Arc::new(<$ty>::with_headers(
                    &cfg.id,
                    &cfg.model,
                    api_key.clone(),
                    $base,
                    proxy_url.clone(),
                    cfg.tags.clone(),
                    capabilities.clone(),
                    cfg.max_concurrency,
                    cfg.context_window,
                    tool_calling_mode,
                    &cfg.headers,
                    cfg.http_protocol,
                )) as Arc<dyn LlmProvider>
            };
        }

        // OpenAI Response API and OpenAI-compat-shaped providers honor
        // `include_usage` from the provider config; default is `false`
        // because several upstream gateways (older vLLM, some Chinese
        // providers, stricter proxies) reject the `stream_options` field
        // with HTTP 400.
        let include_usage = cfg.include_usage.unwrap_or(false);
        // `use_max_completion_tokens` selects between the legacy `max_tokens`
        // wire field and the `max_completion_tokens` field required by newer
        // OpenAI reasoning models (o1, o3, gpt-5). Default `false` preserves
        // compatibility with the broader OpenAI-compatible ecosystem.
        let use_max_completion_tokens = cfg.use_max_completion_tokens.unwrap_or(false);
        // The reasoning wire shape follows the provider type: `openai`
        // (Response API) uses the nested `reasoning: { effort }` object, while
        // OpenAI-compatible Chat Completions backends use the top-level
        // `reasoning_effort` string.
        let use_reasoning_effort = crate::providers::openai::provider_type_uses_reasoning_effort(
            cfg.provider_type.as_str(),
        );
        let make_openai = |base: Option<String>| -> Arc<dyn LlmProvider> {
            Arc::new(
                crate::providers::openai::OpenAiProvider::with_headers(
                    &cfg.id,
                    &cfg.model,
                    api_key.clone(),
                    base,
                    proxy_url.clone(),
                    cfg.tags.clone(),
                    capabilities.clone(),
                    cfg.max_concurrency,
                    cfg.context_window,
                    tool_calling_mode,
                    &cfg.headers,
                    cfg.http_protocol,
                )
                .with_include_usage(include_usage)
                .with_use_max_completion_tokens(use_max_completion_tokens)
                .with_use_reasoning_effort(use_reasoning_effort),
            ) as Arc<dyn LlmProvider>
        };
        let make_azure = || -> Arc<dyn LlmProvider> {
            Arc::new(
                crate::providers::azure::AzureOpenAiProvider::with_headers(
                    &cfg.id,
                    &cfg.model,
                    api_key.clone(),
                    cfg.base_url.clone(),
                    proxy_url.clone(),
                    cfg.tags.clone(),
                    capabilities.clone(),
                    cfg.max_concurrency,
                    cfg.context_window,
                    tool_calling_mode,
                    &cfg.headers,
                    cfg.http_protocol,
                )
                .with_include_usage(include_usage)
                .with_use_max_completion_tokens(use_max_completion_tokens)
                .with_azure_config(
                    cfg.azure_resource_name.as_deref(),
                    cfg.azure_use_deployment_urls.unwrap_or(false),
                    cfg.azure_api_version.as_deref(),
                    cfg.azure_auth_mode
                        .unwrap_or(crate::config::AzureAuthMode::ApiKey),
                ),
            ) as Arc<dyn LlmProvider>
        };

        let provider: Option<Arc<dyn LlmProvider>> = match cfg.provider_type.as_str() {
            // OpenAI Response API and compatible aliases share this transport.
            "openai" | "openai-compat" | "openai_compatible" | "custom" => {
                Some(make_openai(cfg.base_url.clone()))
            }
            "anthropic" => Some(make_provider!(
                crate::providers::anthropic::AnthropicProvider,
                cfg.base_url.clone()
            )),
            "gemini" => Some(make_provider!(
                crate::providers::gemini::GeminiProvider,
                cfg.base_url.clone()
            )),
            "ollama" => Some(make_provider!(
                crate::providers::ollama::OllamaProvider,
                cfg.base_url.clone()
            )),
            "ollama-cloud" => Some(make_provider!(
                crate::providers::ollama::OllamaProvider,
                base_url_for_ollama_cloud()
            )),
            "azure" => Some(make_azure()),
            "deepseek" => Some(make_openai(base_url_for_deepseek())),
            other => {
                tracing::warn!(
                    provider_id = %cfg.id,
                    provider_type = %other,
                    "Skipping provider: unsupported type \
                    (supported: openai, openai-compat, anthropic, gemini, ollama, ollama-cloud, azure, deepseek)"
                );
                None
            }
        };

        if let Some(provider) = provider {
            providers.push(Arc::new(ConfiguredMetadataProvider::new(
                provider,
                cfg.cost_per_1k_input,
                cfg.cost_per_1k_output,
            )));
        }
    }

    providers
}

impl ProviderPoolImpl {
    /// Build the routable providers list for the router.
    fn routable_providers(&self) -> Vec<RoutableProvider> {
        self.providers
            .iter()
            .map(|e| RoutableProvider {
                provider: Arc::clone(&e.provider),
                freeze_manager: Arc::clone(&e.freeze_manager),
                concurrency_semaphore: Arc::clone(&e.semaphore),
                max_concurrency: e.max_concurrency,
            })
            .collect()
    }

    /// Find an entry by provider ID.
    fn find_entry(&self, provider_id: &ProviderId) -> Option<&ProviderEntry> {
        self.providers
            .iter()
            .find(|e| e.provider.metadata().id == *provider_id)
    }

    /// Classify a provider error and freeze the provider accordingly.
    ///
    /// Takes the provider's `FreezeManager` directly (rather than looking it up
    /// via `&self`) so it can be called from a detached streaming task that
    /// outlives the pool borrow (see the mid-stream error path in
    /// `chat_completion_stream`).
    fn classify_and_freeze(
        freeze_manager: &FreezeManager,
        provider_id: &ProviderId,
        error: &ProviderError,
    ) {
        // Use the error classifier (P1-5) for freeze decisions.
        let std_error = error_classifier::classify_provider_error(error);

        if !std_error.should_freeze() {
            tracing::debug!(
                provider_id = %provider_id,
                error = %error,
                classification = ?std_error,
                "error does not warrant provider freeze"
            );
            return;
        }

        if std_error.is_permanent() {
            freeze_manager.freeze_permanent(format!("{error}"));
            tracing::warn!(
                provider_id = %provider_id,
                error = %error,
                classification = ?std_error,
                "provider permanently frozen"
            );
        } else {
            // Every transient, freezable error carries a concrete freeze
            // duration (see `StandardError::freeze_duration`, which is `Some`
            // for all non-permanent freezable variants). Passing the `Option`
            // straight to `freeze` keeps behavior identical while removing the
            // previously-unreachable adaptive fallback branch: a hypothetical
            // future `None` still degrades safely to adaptive backoff.
            let duration = std_error.freeze_duration();
            freeze_manager.freeze(format!("{error}"), duration);
            tracing::info!(
                provider_id = %provider_id,
                error = %error,
                classification = ?std_error,
                freeze_secs = duration.map(|d| d.as_secs()),
                "provider frozen with error-type-specific duration"
            );
        }
    }

    /// Apply provider-level sampling defaults without overriding explicit request values.
    fn apply_request_defaults(request: &ChatRequest, entry: &ProviderEntry) -> ChatRequest {
        let mut effective_request = request.clone();
        effective_request.temperature = effective_request.temperature.or(entry.default_temperature);
        effective_request.top_p = effective_request.top_p.or(entry.default_top_p);
        effective_request
    }
}

/// Total attempts (initial call + retries) a single pool call makes against its
/// selected provider on transient errors before giving up (L7).
const MAX_IN_CALL_ATTEMPTS: usize = 3;
/// Upper bound on any single in-call retry backoff.
const MAX_IN_CALL_BACKOFF: Duration = Duration::from_secs(2);

/// Backoff before the `attempt`-th in-call retry: a provider-supplied
/// `Retry-After` (rate limit) wins, otherwise exponential from a modest base,
/// both capped at [`MAX_IN_CALL_BACKOFF`].
fn in_call_backoff(attempt: usize, class: &error_classifier::StandardError) -> Duration {
    if let error_classifier::StandardError::RateLimited {
        retry_after: Some(delay),
    } = class
    {
        return (*delay).min(MAX_IN_CALL_BACKOFF);
    }
    let shift = u32::try_from(attempt.saturating_sub(1)).unwrap_or(0).min(4);
    Duration::from_millis(250)
        .saturating_mul(1u32 << shift)
        .min(MAX_IN_CALL_BACKOFF)
}

#[async_trait]
impl ProviderPool for ProviderPoolImpl {
    #[instrument(skip(self, request), fields(tags = ?route.required_tags))]
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        let routable = self.routable_providers();
        let idx = self.router.select(&routable, route)?;
        let entry = &self.providers[idx];

        // Acquire global semaphore permit if configured.
        let _global_permit = if let Some(ref sem) = self.global_semaphore {
            Some(sem.acquire().await.map_err(|_| ProviderError::Other {
                message: "global semaphore closed".into(),
            })?)
        } else {
            None
        };

        // Acquire per-provider semaphore permit for concurrency control.
        let _permit = entry
            .semaphore
            .acquire()
            .await
            .map_err(|_| ProviderError::Other {
                message: "semaphore closed".into(),
            })?;

        // Track active request for observability. Use the RAII guard (not a
        // manual fetch_sub) so the counter is decremented even if this future is
        // cancelled/dropped mid-await (e.g. wrapped in a timeout) -- a manual
        // decrement after the await would be skipped on cancellation, leaking
        // the count upward forever.
        entry.active_requests.fetch_add(1, Ordering::Relaxed);
        let _active = ActiveRequestGuard(Arc::clone(&entry.active_requests));
        let effective_request = Self::apply_request_defaults(request, entry);

        // In-call retry (L7): a transient failure (5xx / network / rate-limit /
        // unknown) is retried on the selected provider with backoff before the
        // call gives up, so a single blip does not fail the whole turn. The
        // provider is frozen (for next-call failover) only once the in-call
        // retries are spent, or immediately for a non-transient error. Permits and
        // the active-request guard are held across the retries -- this is one
        // logical in-flight call.
        let mut attempt = 0usize;
        let error = loop {
            match entry.provider.chat_completion(&effective_request).await {
                Ok(mut response) => {
                    let meta = entry.provider.metadata();
                    entry.metrics.record_success_with_cost(
                        response.usage.input_tokens,
                        response.usage.output_tokens,
                        meta.cost_per_1k_input,
                        meta.cost_per_1k_output,
                    );
                    response.provider_id = Some(meta.id.clone());
                    return Ok(response);
                }
                Err(e) => {
                    attempt += 1;
                    let class = error_classifier::classify_provider_error(&e);
                    if class.is_transient() && attempt < MAX_IN_CALL_ATTEMPTS {
                        tokio::time::sleep(in_call_backoff(attempt, &class)).await;
                        continue;
                    }
                    break e;
                }
            }
        };
        entry.metrics.record_error();
        self.report_error(&entry.provider.metadata().id, &error);
        Err(error)
    }

    #[instrument(skip(self, request), fields(tags = ?route.required_tags))]
    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        let routable = self.routable_providers();
        let idx = self.router.select(&routable, route)?;
        let entry = &self.providers[idx];

        // Acquire OWNED permits: a streaming response outlives this function, so
        // a borrowed permit would drop here (before the stream is consumed) and
        // stop enforcing the concurrency limit. Owned permits are moved into the
        // stream wrapper below and released only when the stream ends or drops.
        let global_permit = if let Some(ref sem) = self.global_semaphore {
            Some(
                Arc::clone(sem)
                    .acquire_owned()
                    .await
                    .map_err(|_| ProviderError::Other {
                        message: "global semaphore closed".into(),
                    })?,
            )
        } else {
            None
        };

        let permit = Arc::clone(&entry.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| ProviderError::Other {
                message: "semaphore closed".into(),
            })?;

        // Track active request for observability (decremented when stream is
        // fully consumed or dropped, via ActiveRequestGuard).
        entry.active_requests.fetch_add(1, Ordering::Relaxed);
        let guard = ActiveRequestGuard(Arc::clone(&entry.active_requests));
        let effective_request = Self::apply_request_defaults(request, entry);

        // Streaming metrics are tracked at the caller level when the stream
        // completes or errors. We do NOT record a premature success here
        // because the stream has not started consuming yet.

        let meta = entry.provider.metadata();
        let stream_result = entry
            .provider
            .chat_completion_stream(&effective_request)
            .await;

        match stream_result {
            Ok(mut stream_response) => {
                stream_response.provider_id = Some(meta.id.clone());
                stream_response.model.clone_from(&meta.model);
                stream_response.context_window = meta.context_window;

                // Wrap the inner stream so the active-request guard AND the
                // concurrency permits are all held until the stream is fully
                // consumed or dropped (enforcing max_concurrency for streams).
                //
                // A stream that establishes successfully but then yields an
                // error mid-flight (e.g. a connection reset after the first
                // byte) must still count against the provider and trigger a
                // freeze; otherwise a provider that always fails after the
                // handshake is never frozen and failover never engages. We
                // report the first such error once, then keep forwarding items.
                let keepalive = (guard, permit, global_permit);
                stream_response.stream = Box::pin(futures::stream::unfold(
                    StreamMetricsState {
                        stream: stream_response.stream,
                        freeze_manager: Arc::clone(&entry.freeze_manager),
                        metrics: Arc::clone(&entry.metrics),
                        pid: meta.id.clone(),
                        cost_in: meta.cost_per_1k_input,
                        cost_out: meta.cost_per_1k_output,
                        // Last usage seen (the final chunk carries it); recorded
                        // on clean completion.
                        usage: None,
                        // Whether the request's terminal outcome (success or
                        // error) has been recorded, so it counts exactly once.
                        recorded: false,
                    },
                    move |mut st: StreamMetricsState| {
                        // Hold the concurrency permits + active-request guard for
                        // the whole stream: captured by this `move` closure, they
                        // drop (releasing the slot) when the stream ends or is
                        // dropped.
                        let _keepalive = &keepalive;
                        async move {
                            use futures::StreamExt;
                            match st.stream.next().await {
                                // Clean end of stream: record the completed request
                                // once (tokens + cost), unless an error already
                                // terminated it. A stream dropped before this point
                                // is left uncounted (in-flight, not done).
                                None => {
                                    if !st.recorded {
                                        st.recorded = true;
                                        let (input, output) = st.usage.unwrap_or((0, 0));
                                        st.metrics.record_success_with_cost(
                                            input,
                                            output,
                                            st.cost_in,
                                            st.cost_out,
                                        );
                                    }
                                    None
                                }
                                Some(item) => {
                                    match &item {
                                        Ok(chunk) => {
                                            if let Some(u) = &chunk.usage {
                                                st.usage = Some((u.input_tokens, u.output_tokens));
                                            }
                                        }
                                        // A mid-stream error counts against the
                                        // provider and triggers a freeze, once.
                                        Err(err) => {
                                            if !st.recorded {
                                                st.recorded = true;
                                                st.metrics.record_error();
                                                Self::classify_and_freeze(
                                                    &st.freeze_manager,
                                                    &st.pid,
                                                    err,
                                                );
                                            }
                                        }
                                    }
                                    Some((item, st))
                                }
                            }
                        }
                    },
                ));

                Ok(stream_response)
            }
            Err(e) => {
                entry.metrics.record_error();
                self.report_error(&meta.id, &e);
                // guard + permits drop here, releasing the slot
                Err(e)
            }
        }
    }

    fn report_error(&self, provider_id: &ProviderId, error: &ProviderError) {
        if let Some(entry) = self.find_entry(provider_id) {
            Self::classify_and_freeze(&entry.freeze_manager, provider_id, error);
        }
    }

    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        self.providers
            .iter()
            .map(|entry| {
                let meta = entry.provider.metadata();
                let freeze_status = entry.freeze_manager.status();
                let metrics = entry.metrics.snapshot();

                ProviderStatus {
                    id: meta.id.clone(),
                    is_frozen: freeze_status.is_frozen,
                    frozen_since: freeze_status.frozen_since.map(|inst| {
                        chrono::Utc::now()
                            - chrono::Duration::from_std(inst.elapsed()).unwrap_or_default()
                    }),
                    thaw_at: freeze_status.thaw_at.map(|inst| {
                        let now = std::time::Instant::now();
                        if inst > now {
                            chrono::Utc::now()
                                + chrono::Duration::from_std(inst - now).unwrap_or_default()
                        } else {
                            chrono::Utc::now()
                        }
                    }),
                    freeze_reason: freeze_status.reason,
                    active_requests: entry.active_requests.load(Ordering::Relaxed),
                    total_requests: metrics.total_requests,
                    total_errors: metrics.total_errors,
                }
            })
            .collect()
    }

    async fn freeze(&self, provider_id: &ProviderId, reason: String) {
        if let Some(entry) = self.find_entry(provider_id) {
            entry.freeze_manager.freeze(reason, None);
        }
    }

    async fn thaw(&self, provider_id: &ProviderId) -> Result<(), ProviderError> {
        let entry = self
            .find_entry(provider_id)
            .ok_or_else(|| ProviderError::Other {
                message: format!("provider not found: {provider_id}"),
            })?;

        self.health_checker
            .check_and_thaw(&entry.provider, &entry.freeze_manager)
            .await
    }

    fn health_check_interval(&self) -> Duration {
        self.health_check_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hf_core::provider::*;
    use hf_core::types::TokenUsage;

    struct MockProvider {
        meta: ProviderMetadata,
        should_fail: bool,
        /// Number of leading calls that fail with a transient error before the
        /// provider starts succeeding (for in-call retry tests).
        fail_first: Arc<AtomicUsize>,
        /// Total calls received, so a test can assert the retry count.
        call_count: Arc<AtomicUsize>,
        recorded_request: Arc<std::sync::Mutex<Option<ChatRequest>>>,
    }

    impl MockProvider {
        fn new_provider(
            id: &str,
            tags: Vec<&str>,
            should_fail: bool,
        ) -> (
            Arc<dyn LlmProvider>,
            Arc<std::sync::Mutex<Option<ChatRequest>>>,
        ) {
            let recorded_request = Arc::new(std::sync::Mutex::new(None));
            (
                Arc::new(Self {
                    meta: ProviderMetadata {
                        id: ProviderId::from_string(id),
                        provider_type: ProviderType::OpenAi,
                        model: "test-model".into(),
                        tags: tags.into_iter().map(String::from).collect(),
                        capabilities: vec![],
                        max_concurrency: 5,
                        context_window: 128_000,
                        cost_per_1k_input: 0.01,
                        cost_per_1k_output: 0.03,
                        tool_calling_mode: ToolCallingMode::default(),
                    },
                    should_fail,
                    fail_first: Arc::new(AtomicUsize::new(0)),
                    call_count: Arc::new(AtomicUsize::new(0)),
                    recorded_request: Arc::clone(&recorded_request),
                }),
                recorded_request,
            )
        }

        /// A provider that fails transiently `fail_first` times, then succeeds.
        /// Returns the shared call counter so a test can assert retry behavior.
        fn flaky(
            id: &str,
            tags: Vec<&str>,
            fail_first: usize,
        ) -> (Arc<dyn LlmProvider>, Arc<AtomicUsize>) {
            let call_count = Arc::new(AtomicUsize::new(0));
            let provider: Arc<dyn LlmProvider> = Arc::new(Self {
                meta: ProviderMetadata {
                    id: ProviderId::from_string(id),
                    provider_type: ProviderType::OpenAi,
                    model: "test-model".into(),
                    tags: tags.into_iter().map(String::from).collect(),
                    capabilities: vec![],
                    max_concurrency: 5,
                    context_window: 128_000,
                    cost_per_1k_input: 0.01,
                    cost_per_1k_output: 0.03,
                    tool_calling_mode: ToolCallingMode::default(),
                },
                should_fail: false,
                fail_first: Arc::new(AtomicUsize::new(fail_first)),
                call_count: Arc::clone(&call_count),
                recorded_request: Arc::new(std::sync::Mutex::new(None)),
            });
            (provider, call_count)
        }

        fn ok(id: &str, tags: Vec<&str>) -> Arc<dyn LlmProvider> {
            Self::new_provider(id, tags, false).0
        }

        fn failing(id: &str, tags: Vec<&str>) -> Arc<dyn LlmProvider> {
            Self::new_provider(id, tags, true).0
        }

        fn ok_with_recorder(
            id: &str,
            tags: Vec<&str>,
        ) -> (
            Arc<dyn LlmProvider>,
            Arc<std::sync::Mutex<Option<ChatRequest>>>,
        ) {
            Self::new_provider(id, tags, false)
        }
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        async fn chat_completion(
            &self,
            request: &ChatRequest,
        ) -> Result<ChatResponse, ProviderError> {
            *self.recorded_request.lock().expect("mock mutex poisoned") = Some(request.clone());
            self.call_count.fetch_add(1, Ordering::Relaxed);
            if self.should_fail {
                return Err(ProviderError::ServerError {
                    provider: self.meta.id.to_string(),
                    message: "mock failure".into(),
                });
            }
            // Consume one transient failure per call until the budget is spent.
            if self
                .fail_first
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(ProviderError::ServerError {
                    provider: self.meta.id.to_string(),
                    message: "transient mock failure".into(),
                });
            }
            Ok(ChatResponse {
                id: "resp-1".into(),
                model: self.meta.model.clone(),
                content: Some("test response".into()),
                reasoning_content: None,
                tool_calls: vec![],
                usage: TokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_read_tokens: None,
                    cache_write_tokens: None,
                    ..Default::default()
                },
                finish_reason: FinishReason::Stop,
                raw_request: None,
                raw_response: None,
                provider_id: None,
                generated_images: vec![],
            })
        }

        async fn chat_completion_stream(
            &self,
            _request: &ChatRequest,
        ) -> Result<ChatStreamResponse, ProviderError> {
            if self.should_fail {
                return Err(ProviderError::ServerError {
                    provider: self.meta.id.to_string(),
                    message: "mock failure".into(),
                });
            }
            // Emit one final chunk carrying usage, so consuming the stream to its
            // end exercises the pool's completion metrics; permit-lifetime tests
            // that never consume it are unaffected.
            let chunk = ChatStreamChunk {
                delta_content: Some("hi".into()),
                delta_reasoning_content: None,
                delta_tool_calls: vec![],
                usage: Some(TokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_read_tokens: None,
                    cache_write_tokens: None,
                    ..Default::default()
                }),
                finish_reason: Some(FinishReason::Stop),
                delta_images: vec![],
            };
            Ok(ChatStreamResponse {
                stream: Box::pin(futures::stream::iter(vec![Ok(chunk)])),
                raw_request: None,
                provider_id: None,
                model: self.meta.model.clone(),
                context_window: self.meta.context_window,
            })
        }

        fn metadata(&self) -> &ProviderMetadata {
            &self.meta
        }
    }

    fn test_config() -> ProviderPoolConfig {
        ProviderPoolConfig {
            providers: vec![],
            proxy: crate::config::ProxyConfig::default(),
            default_freeze_duration_secs: 30,
            max_freeze_duration_secs: 3600,
            health_check_interval_secs: 60,
            selection_strategy: crate::router::SelectionStrategy::default(),
            max_global_concurrency: None,
        }
    }

    fn provider_config_with_temperature(id: &str, temperature: Option<f64>) -> ProviderPoolConfig {
        ProviderPoolConfig {
            providers: vec![crate::config::ProviderConfig {
                id: id.to_string(),
                provider_type: "openai".into(),
                model: "test-model".into(),
                enabled: true,
                tags: vec!["gen".into()],
                capabilities: vec![],
                max_concurrency: 5,
                context_window: 128_000,
                cost_per_1k_input: 0.0,
                cost_per_1k_output: 0.0,
                api_key: None,
                api_key_env: None,
                base_url: None,
                headers: std::collections::HashMap::new(),
                temperature,
                top_p: None,
                tool_calling_mode: None,
                icon: None,
                azure_resource_name: None,
                azure_api_version: None,
                azure_use_deployment_urls: None,
                azure_auth_mode: None,
                http_protocol: crate::config::HttpProtocol::Http1,
                include_usage: None,
                use_max_completion_tokens: None,
            }],
            ..test_config()
        }
    }

    fn test_request() -> ChatRequest {
        ChatRequest {
            messages: vec![hf_core::types::Message {
                message_id: String::new(),
                role: hf_core::types::Role::User,
                content: "test".into(),
                tool_call_id: None,
                tool_calls: vec![],
                timestamp: chrono::Utc::now(),
                metadata: serde_json::Value::Null,
            }],
            model: None,
            request_mode: RequestMode::TextChat,
            max_tokens: Some(100),
            temperature: None,
            top_p: None,
            tools: vec![],
            tool_calling_mode: ToolCallingMode::default(),
            stop: vec![],
            extra: serde_json::Value::Null,
            thinking: None,
            response_format: None,
            image_generation_options: None,
        }
    }

    #[test]
    fn in_call_backoff_prefers_retry_after_and_caps_growth() {
        use crate::error_classifier::StandardError;
        // A provider-supplied Retry-After wins outright.
        assert_eq!(
            in_call_backoff(
                1,
                &StandardError::RateLimited {
                    retry_after: Some(Duration::from_millis(400))
                }
            ),
            Duration::from_millis(400)
        );
        // Otherwise exponential from the base...
        assert_eq!(
            in_call_backoff(1, &StandardError::ServerError),
            Duration::from_millis(250)
        );
        assert_eq!(
            in_call_backoff(2, &StandardError::ServerError),
            Duration::from_millis(500)
        );
        // ...capped, including an over-long Retry-After.
        assert!(in_call_backoff(20, &StandardError::ServerError) <= MAX_IN_CALL_BACKOFF);
        assert_eq!(
            in_call_backoff(
                1,
                &StandardError::RateLimited {
                    retry_after: Some(Duration::from_secs(60))
                }
            ),
            MAX_IN_CALL_BACKOFF
        );
    }

    #[tokio::test(start_paused = true)]
    async fn transient_errors_are_retried_in_call_until_success() {
        let (provider, calls) = MockProvider::flaky("p1", vec!["gen"], 2);
        let pool = ProviderPoolImpl::from_providers(vec![provider], &test_config());
        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };
        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(
            result.is_ok(),
            "in-call retry should recover from transient blips: {result:?}"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "one initial call plus two retries"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn transient_errors_stop_at_the_attempt_budget() {
        let (provider, calls) = MockProvider::flaky("p1", vec!["gen"], 99);
        let pool = ProviderPoolImpl::from_providers(vec![provider], &test_config());
        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };
        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(result.is_err(), "exhausted retries surface the error");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            MAX_IN_CALL_ATTEMPTS,
            "attempts are bounded"
        );
    }

    #[tokio::test]
    async fn test_concurrency_semaphore_release_on_completion() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let before = pool.providers[0].semaphore.available_permits();
        let _ = pool.chat_completion(&test_request(), &route).await;
        let after = pool.providers[0].semaphore.available_permits();

        assert_eq!(
            before, after,
            "semaphore permits should be released after completion"
        );
    }

    #[tokio::test]
    async fn streaming_holds_concurrency_permit_until_stream_dropped() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );
        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let before = pool.providers[0].semaphore.available_permits();
        let stream = pool
            .chat_completion_stream(&test_request(), &route)
            .await
            .expect("stream should start");

        // While the (unconsumed) stream is alive, the permit must still be held.
        assert_eq!(
            pool.providers[0].semaphore.available_permits(),
            before - 1,
            "streaming must hold the concurrency permit for the stream's lifetime"
        );

        drop(stream);
        // Dropping the stream releases the permit.
        assert_eq!(
            pool.providers[0].semaphore.available_permits(),
            before,
            "dropping the stream must release the permit"
        );
    }

    #[tokio::test]
    async fn completed_stream_records_usage_and_cost() {
        use futures::StreamExt;
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );
        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        // Nothing recorded until the stream is actually consumed to completion.
        assert_eq!(pool.providers[0].metrics.snapshot().total_requests, 0);

        let mut resp = pool
            .chat_completion_stream(&test_request(), &route)
            .await
            .expect("stream should start");
        while resp.stream.next().await.is_some() {}

        let snap = pool.providers[0].metrics.snapshot();
        assert_eq!(snap.total_requests, 1, "a completed stream counts once");
        assert_eq!(snap.total_errors, 0);
        assert_eq!(snap.total_input_tokens, 10);
        assert_eq!(snap.total_output_tokens, 5);
        // 10/1000*0.01 + 5/1000*0.03 = 0.00025 USD = 250 micro-dollars.
        assert_eq!(snap.estimated_cost_micros, 250);
    }

    #[tokio::test]
    async fn test_concurrency_semaphore_release_on_error() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::failing("p1", vec!["gen"])],
            &test_config(),
        );

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let before = pool.providers[0].semaphore.available_permits();
        let _ = pool.chat_completion(&test_request(), &route).await;
        let after = pool.providers[0].semaphore.available_permits();

        assert_eq!(
            before, after,
            "semaphore permits should be released even on error"
        );
    }

    #[tokio::test]
    async fn test_pool_routes_to_best_provider() {
        let pool = ProviderPoolImpl::from_providers(
            vec![
                MockProvider::ok("p1", vec!["reasoning"]),
                MockProvider::ok("p2", vec!["fast"]),
                MockProvider::ok("p3", vec!["reasoning", "code"]),
            ],
            &test_config(),
        );

        let route = RouteRequest {
            required_tags: vec!["reasoning".into()],
            ..Default::default()
        };

        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pool_all_providers_frozen() {
        let pool = ProviderPoolImpl::from_providers(
            vec![
                MockProvider::ok("p1", vec!["gen"]),
                MockProvider::ok("p2", vec!["gen"]),
            ],
            &test_config(),
        );

        // Freeze all providers.
        for entry in &pool.providers {
            entry.freeze_manager.freeze("test".into(), None);
        }

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(matches!(
            result,
            Err(ProviderError::NoProviderAvailable { .. })
        ));
    }

    #[tokio::test]
    async fn test_pool_failover_on_error() {
        let pool = ProviderPoolImpl::from_providers(
            vec![
                MockProvider::failing("p1", vec!["gen"]),
                MockProvider::ok("p2", vec!["gen"]),
            ],
            &test_config(),
        );

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        // First call may hit p1 (fails) or p2 (succeeds) — depends on round-robin.
        // After p1 fails and gets frozen, subsequent calls should use p2.
        let _ = pool.chat_completion(&test_request(), &route).await;
        // Now p1 should be frozen from the error report.
        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(result.is_ok(), "should route to p2 after p1 is frozen");
    }

    #[tokio::test]
    async fn test_provider_temperature_default_applies_when_request_omits_temperature() {
        let (provider, recorded_request) = MockProvider::ok_with_recorder("p1", vec!["gen"]);
        let config = provider_config_with_temperature("p1", Some(1.0));
        let pool = ProviderPoolImpl::from_providers(vec![provider], &config);

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let result = pool.chat_completion(&test_request(), &route).await;
        assert!(result.is_ok());

        let recorded_temperature = recorded_request
            .lock()
            .expect("mock mutex poisoned")
            .as_ref()
            .and_then(|request| request.temperature);
        assert_eq!(recorded_temperature, Some(1.0));
    }

    #[tokio::test]
    async fn test_explicit_request_temperature_overrides_provider_default() {
        let (provider, recorded_request) = MockProvider::ok_with_recorder("p1", vec!["gen"]);
        let config = provider_config_with_temperature("p1", Some(1.0));
        let pool = ProviderPoolImpl::from_providers(vec![provider], &config);

        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        let mut request = test_request();
        request.temperature = Some(0.2);

        let result = pool.chat_completion(&request, &route).await;
        assert!(result.is_ok());

        let recorded_temperature = recorded_request
            .lock()
            .expect("mock mutex poisoned")
            .as_ref()
            .and_then(|captured| captured.temperature);
        assert_eq!(recorded_temperature, Some(0.2));
    }

    #[tokio::test]
    async fn test_pool_provider_statuses() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );

        let statuses = pool.provider_statuses().await;
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].is_frozen);
        assert_eq!(statuses[0].total_requests, 0);
    }

    #[test]
    fn pool_reports_the_configured_health_check_interval() {
        let config = ProviderPoolConfig {
            health_check_interval_secs: 5,
            ..test_config()
        };
        let pool =
            ProviderPoolImpl::from_providers(vec![MockProvider::ok("p1", vec!["gen"])], &config);

        assert_eq!(pool.health_check_interval(), Duration::from_secs(5));
    }

    #[test]
    fn health_check_interval_is_clamped_to_at_least_one_second() {
        // A zero interval would spin the periodic health-check loop; clamp it.
        let config = ProviderPoolConfig {
            health_check_interval_secs: 0,
            ..test_config()
        };
        let pool =
            ProviderPoolImpl::from_providers(vec![MockProvider::ok("p1", vec!["gen"])], &config);

        assert_eq!(pool.health_check_interval(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn thaw_frozen_providers_recovers_a_healthy_frozen_provider() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );
        let pid = ProviderId::from_string("p1");
        pool.freeze(&pid, "test freeze".into()).await;
        assert!(pool.provider_statuses().await[0].is_frozen);

        let thawed = pool.thaw_frozen_providers().await;

        assert_eq!(thawed, 1);
        assert!(!pool.provider_statuses().await[0].is_frozen);
    }

    #[tokio::test]
    async fn thaw_frozen_providers_recovers_a_permanently_frozen_provider() {
        // The invalid-key/quota scenario: a permanent freeze has no auto-thaw,
        // but a successful health check must still recover it.
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::ok("p1", vec!["gen"])],
            &test_config(),
        );
        pool.providers[0]
            .freeze_manager
            .freeze_permanent("invalid api key".into());
        assert!(pool.provider_statuses().await[0].is_frozen);

        let thawed = pool.thaw_frozen_providers().await;

        assert_eq!(thawed, 1);
        assert!(!pool.provider_statuses().await[0].is_frozen);
    }

    #[tokio::test]
    async fn thaw_frozen_providers_keeps_a_failing_provider_frozen() {
        let pool = ProviderPoolImpl::from_providers(
            vec![MockProvider::failing("p1", vec!["gen"])],
            &test_config(),
        );
        let pid = ProviderId::from_string("p1");
        pool.freeze(&pid, "test freeze".into()).await;

        let thawed = pool.thaw_frozen_providers().await;

        assert_eq!(thawed, 0);
        assert!(pool.provider_statuses().await[0].is_frozen);
    }

    #[tokio::test]
    async fn thaw_frozen_providers_never_pings_a_provider_that_is_not_frozen() {
        let (provider, recorded_request) = MockProvider::ok_with_recorder("p1", vec!["gen"]);
        let pool = ProviderPoolImpl::from_providers(vec![provider], &test_config());

        let thawed = pool.thaw_frozen_providers().await;

        assert_eq!(thawed, 0);
        assert!(
            recorded_request
                .lock()
                .expect("mock mutex poisoned")
                .is_none(),
            "a healthy provider must not pay for a health-check ping"
        );
    }

    /// A provider whose `chat_completion` never returns, to exercise the
    /// cancellation path.
    struct SlowProvider {
        meta: ProviderMetadata,
    }

    #[async_trait]
    impl LlmProvider for SlowProvider {
        async fn chat_completion(
            &self,
            _request: &ChatRequest,
        ) -> Result<ChatResponse, ProviderError> {
            // Far longer than any test timeout; the future is dropped instead.
            tokio::time::sleep(std::time::Duration::from_hours(1)).await;
            unreachable!("cancelled before completing")
        }
        async fn chat_completion_stream(
            &self,
            _request: &ChatRequest,
        ) -> Result<ChatStreamResponse, ProviderError> {
            Err(ProviderError::Other {
                message: "no stream".into(),
            })
        }
        fn metadata(&self) -> &ProviderMetadata {
            &self.meta
        }
    }

    #[tokio::test]
    async fn active_requests_counter_released_on_cancellation() {
        let (ok, _) = MockProvider::new_provider("template", vec!["gen"], false);
        let meta = ok.metadata().clone();
        let provider: Arc<dyn LlmProvider> = Arc::new(SlowProvider { meta });
        let pool = ProviderPoolImpl::from_providers(vec![provider], &test_config());
        let route = RouteRequest {
            required_tags: vec!["gen".into()],
            ..Default::default()
        };

        // Cancel the in-flight request by letting a short timeout fire; the
        // inner future is dropped, which must run the guard's Drop and release
        // the active-request counter.
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            pool.chat_completion(&test_request(), &route),
        )
        .await;
        assert!(result.is_err(), "request should have timed out");

        let statuses = pool.provider_statuses().await;
        assert_eq!(
            statuses[0].active_requests, 0,
            "active-request counter leaked after cancellation"
        );
    }

    // -----------------------------------------------------------------------
    // from_config() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_from_config_creates_providers() {
        use crate::config::{ProviderConfig, ProxyEntry};

        let config = ProviderPoolConfig {
            providers: vec![
                ProviderConfig {
                    id: "openai-1".into(),
                    provider_type: "openai".into(),
                    model: "gpt-4o".into(),
                    enabled: true,
                    tags: vec!["general".into()],
                    capabilities: vec![],
                    max_concurrency: 3,
                    context_window: 128_000,
                    cost_per_1k_input: 0.005,
                    cost_per_1k_output: 0.015,
                    api_key: Some("sk-test".into()),
                    api_key_env: None,
                    base_url: None,
                    headers: std::collections::HashMap::new(),
                    http_protocol: crate::config::HttpProtocol::Http1,
                    include_usage: None,
                    use_max_completion_tokens: None,
                    temperature: None,
                    top_p: None,
                    tool_calling_mode: None,
                    icon: None,
                    azure_resource_name: None,
                    azure_api_version: None,
                    azure_use_deployment_urls: None,
                    azure_auth_mode: None,
                },
                ProviderConfig {
                    id: "anthropic-1".into(),
                    provider_type: "anthropic".into(),
                    model: "claude-3-opus".into(),
                    enabled: true,
                    tags: vec!["reasoning".into()],
                    capabilities: vec![],
                    max_concurrency: 3,
                    context_window: 200_000,
                    cost_per_1k_input: 0.015,
                    cost_per_1k_output: 0.075,
                    api_key: Some("sk-ant-test".into()),
                    api_key_env: None,
                    base_url: None,
                    headers: std::collections::HashMap::new(),
                    http_protocol: crate::config::HttpProtocol::Http1,
                    include_usage: None,
                    use_max_completion_tokens: None,
                    temperature: None,
                    top_p: None,
                    tool_calling_mode: None,
                    icon: None,
                    azure_resource_name: None,
                    azure_api_version: None,
                    azure_use_deployment_urls: None,
                    azure_auth_mode: None,
                },
                ProviderConfig {
                    id: "gemini-1".into(),
                    provider_type: "gemini".into(),
                    model: "gemini-2.0-flash".into(),
                    enabled: true,
                    tags: vec!["fast".into()],
                    capabilities: vec![],
                    max_concurrency: 5,
                    context_window: 1_000_000,
                    cost_per_1k_input: 0.0,
                    cost_per_1k_output: 0.0,
                    api_key: Some("AIza-test".into()),
                    api_key_env: None,
                    base_url: None,
                    headers: std::collections::HashMap::new(),
                    http_protocol: crate::config::HttpProtocol::Http1,
                    include_usage: None,
                    use_max_completion_tokens: None,
                    temperature: None,
                    top_p: None,
                    tool_calling_mode: None,
                    icon: None,
                    azure_resource_name: None,
                    azure_api_version: None,
                    azure_use_deployment_urls: None,
                    azure_auth_mode: None,
                },
                ProviderConfig {
                    id: "ollama-local".into(),
                    provider_type: "ollama".into(),
                    model: "llama3.1:8b".into(),
                    enabled: true,
                    tags: vec!["local".into()],
                    capabilities: vec![],
                    max_concurrency: 3,
                    context_window: 32_768,
                    cost_per_1k_input: 0.0,
                    cost_per_1k_output: 0.0,
                    api_key: Some("ollama-key".into()),
                    api_key_env: None,
                    base_url: None,
                    headers: std::collections::HashMap::new(),
                    http_protocol: crate::config::HttpProtocol::Http1,
                    include_usage: None,
                    use_max_completion_tokens: None,
                    temperature: None,
                    top_p: None,
                    tool_calling_mode: None,
                    icon: None,
                    azure_resource_name: None,
                    azure_api_version: None,
                    azure_use_deployment_urls: None,
                    azure_auth_mode: None,
                },
                ProviderConfig {
                    id: "azure-1".into(),
                    provider_type: "azure".into(),
                    model: "gpt-4o".into(),
                    enabled: true,
                    tags: vec!["cloud".into()],
                    capabilities: vec![],
                    max_concurrency: 5,
                    context_window: 128_000,
                    cost_per_1k_input: 0.005,
                    cost_per_1k_output: 0.015,
                    api_key: Some("azure-key".into()),
                    api_key_env: None,
                    base_url: Some("https://res.openai.azure.com/openai/deployments/gpt-4o".into()),
                    headers: std::collections::HashMap::new(),
                    http_protocol: crate::config::HttpProtocol::Http1,
                    include_usage: None,
                    use_max_completion_tokens: None,
                    temperature: None,
                    top_p: None,
                    tool_calling_mode: None,
                    icon: None,
                    azure_resource_name: None,
                    azure_api_version: None,
                    azure_use_deployment_urls: None,
                    azure_auth_mode: None,
                },
            ],
            proxy: crate::config::ProxyConfig {
                providers: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(
                        "ollama-local".into(),
                        ProxyEntry {
                            url: None,
                            enabled: false,
                            auth_env: None,
                        },
                    );
                    m
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let pool = ProviderPoolImpl::from_config(&config).expect("should create pool");
        assert_eq!(pool.providers.len(), 5);

        // Verify provider types via metadata.
        let ids: Vec<String> = pool
            .providers
            .iter()
            .map(|e| e.provider.metadata().id.to_string())
            .collect();
        assert_eq!(
            ids,
            vec![
                "openai-1",
                "anthropic-1",
                "gemini-1",
                "ollama-local",
                "azure-1"
            ]
        );
    }

    #[test]
    fn test_from_config_empty_fails() {
        let config = ProviderPoolConfig::default();
        let result = ProviderPoolImpl::from_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_config_unknown_type_fails() {
        use crate::config::ProviderConfig;
        let config = ProviderPoolConfig {
            providers: vec![ProviderConfig {
                id: "unknown-1".into(),
                provider_type: "supermodel".into(),
                model: "best".into(),
                enabled: true,
                tags: vec![],
                capabilities: vec![],
                max_concurrency: 5,
                context_window: 128_000,
                cost_per_1k_input: 0.0,
                cost_per_1k_output: 0.0,
                api_key: None,
                api_key_env: None,
                base_url: None,
                headers: std::collections::HashMap::new(),
                http_protocol: crate::config::HttpProtocol::Http1,
                include_usage: None,
                use_max_completion_tokens: None,
                temperature: None,
                top_p: None,
                tool_calling_mode: None,
                icon: None,
                azure_resource_name: None,
                azure_api_version: None,
                azure_use_deployment_urls: None,
                azure_auth_mode: None,
            }],
            ..Default::default()
        };

        let pool = ProviderPoolImpl::from_config(&config).expect("should create pool");
        // Unknown provider type is gracefully skipped, resulting in 0 providers.
        assert_eq!(pool.providers.len(), 0);
    }
}
