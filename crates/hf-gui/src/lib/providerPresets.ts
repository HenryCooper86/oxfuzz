import type { Provider } from "../components/settings/providerTypes";

interface ProviderPreset {
  label: string;
  providerType: string;
  baseUrl: string;
  model: string;
  keyOptional: boolean;
  nativeToolCalling?: boolean;
  codingPlan?: boolean;
  helpKey?: string;
  alternateBaseUrls?: string[];
}

// Selection IDs identify services/plans; providerType identifies the backend adapter.
// Ollama uses its native host root; compatible APIs include their versioned path.
export const PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  openai: { label: "OpenAI", baseUrl: "https://api.openai.com/v1", model: "gpt-4o", keyOptional: false, providerType: "openai" },
  "openai-compat": { label: "OpenAI-compatible", baseUrl: "", model: "", keyOptional: false, providerType: "openai-compat" },
  ollama: { label: "Ollama (local)", baseUrl: "http://localhost:11434", model: "llama3.1:8b", keyOptional: true, providerType: "ollama" },
  "ollama-cloud": { label: "Ollama Cloud", baseUrl: "https://ollama.com", model: "gpt-oss:120b", keyOptional: false, providerType: "ollama-cloud" },
  anthropic: { label: "Anthropic", baseUrl: "https://api.anthropic.com/v1", model: "", keyOptional: false, providerType: "anthropic" },
  gemini: { label: "Gemini", baseUrl: "https://generativelanguage.googleapis.com/v1beta", model: "", keyOptional: false, providerType: "gemini" },
  deepseek: { label: "DeepSeek", baseUrl: "https://api.deepseek.com", model: "deepseek-flash", keyOptional: false, providerType: "deepseek", helpKey: "setup.providerHelp.deepseek" },
  "kimi-api": { label: "Kimi API (Moonshot)", baseUrl: "https://api.moonshot.ai/v1", alternateBaseUrls: ["https://api.moonshot.cn/v1"], model: "kimi-k3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.kimiApi" },
  "kimi-coding": { label: "Kimi Coding (subscription)", baseUrl: "https://api.kimi.ai/coding/v1", alternateBaseUrls: ["https://api.kimi.com/coding/v1"], model: "kimi-for-coding", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.kimiCoding" },
  "glm-bigmodel": { label: "GLM API (BigModel.cn)", baseUrl: "https://open.bigmodel.cn/api/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.glmBigmodel" },
  "glm-coding": { label: "GLM Coding Plan (BigModel.cn)", baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.glmCoding" },
  "zai-glm": { label: "GLM API (Z.AI)", baseUrl: "https://api.z.ai/api/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.zaiGlm" },
  "zai-coding": { label: "GLM Coding Plan (Z.AI)", baseUrl: "https://api.z.ai/api/coding/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.zaiCoding" },
  azure: { label: "Azure OpenAI", baseUrl: "", model: "", keyOptional: false, providerType: "azure" },
};

export const PROVIDER_OPTIONS = Object.entries(PROVIDER_PRESETS).map(([value, preset]) => ({ value, label: preset.label }));

export function providerPreset(selection: string): ProviderPreset {
  return PROVIDER_PRESETS[selection] ?? PROVIDER_PRESETS["openai-compat"];
}

// Recover branded selections from persisted adapter + endpoint, without rewriting
// custom models, URLs, credentials or older configurations on load.
export function providerPresetId(provider: Provider): string {
  if (provider.provider_type !== "openai-compat") return provider.provider_type;
  const url = (provider.base_url ?? "").replace(/\/+$/, "");
  return Object.entries(PROVIDER_PRESETS).find(([id, preset]) =>
    id !== "openai-compat" && preset.providerType === provider.provider_type
    && (preset.baseUrl === url || preset.alternateBaseUrls?.includes(url)),
  )?.[0] ?? "openai-compat";
}

export function applyProviderPreset(provider: Provider, selection: string): Provider {
  const preset = providerPreset(selection);
  return {
    ...provider,
    provider_type: preset.providerType,
    base_url: preset.baseUrl || null,
    model: preset.model,
    tool_calling_mode: preset.nativeToolCalling ? "native" : null,
    api_key: null,
    api_key_env: null,
    api_key_configured: false,
    api_key_env_configured: false,
    headers: {},
    headers_configured: false,
  };
}
