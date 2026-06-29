// Provider pool form types + normalization (1:1 with hf_provider::ProviderConfig).
// Kept out of ProvidersTab.tsx so the component file only exports components
// (satisfies react-refresh/only-export-components).

export interface Provider {
  id: string;
  provider_type: string;
  model: string;
  enabled: boolean;
  tags: string[];
  capabilities: string[];
  max_concurrency: number;
  context_window: number;
  cost_per_1k_input: number;
  cost_per_1k_output: number;
  api_key: string | null;
  api_key_env: string | null;
  base_url: string | null;
  headers: Record<string, string>;
  http_protocol: "http1" | "http2";
  include_usage: boolean | null;
  use_max_completion_tokens: boolean | null;
  temperature: number | null;
  top_p: number | null;
  tool_calling_mode: string | null;
  icon: string | null;
  azure_resource_name: string | null;
  azure_api_version: string | null;
  azure_use_deployment_urls: boolean | null;
  azure_auth_mode: string | null;
}

// Fill defaults for any field the backend omitted (None -> null/empty), so the
// controlled form never binds to `undefined`.
export function normalizeProvider(p: Partial<Provider>): Provider {
  return {
    id: p.id ?? "new-provider",
    provider_type: p.provider_type ?? "openai-compat",
    model: p.model ?? "",
    enabled: p.enabled ?? true,
    tags: p.tags ?? [],
    capabilities: p.capabilities ?? [],
    max_concurrency: p.max_concurrency ?? 3,
    context_window: p.context_window ?? 128000,
    cost_per_1k_input: p.cost_per_1k_input ?? 0,
    cost_per_1k_output: p.cost_per_1k_output ?? 0,
    api_key: p.api_key ?? null,
    api_key_env: p.api_key_env ?? null,
    base_url: p.base_url ?? null,
    headers: p.headers ?? {},
    http_protocol: p.http_protocol ?? "http1",
    include_usage: p.include_usage ?? null,
    use_max_completion_tokens: p.use_max_completion_tokens ?? null,
    temperature: p.temperature ?? null,
    top_p: p.top_p ?? null,
    tool_calling_mode: p.tool_calling_mode ?? null,
    icon: p.icon ?? null,
    azure_resource_name: p.azure_resource_name ?? null,
    azure_api_version: p.azure_api_version ?? null,
    azure_use_deployment_urls: p.azure_use_deployment_urls ?? null,
    azure_auth_mode: p.azure_auth_mode ?? null,
  };
}
