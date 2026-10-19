// Pure provider-resolution logic for the setup wizard's Providers step.
// Kept out of SetupWizard.tsx so the component file only exports components
// (satisfies react-refresh/only-export-components) and so this is unit-testable.

import { normalizeProvider, type Provider } from "../settings/providerTypes";

export interface WizardProviderInput {
  providerType: string;
  apiKey: string;
  model: string;
  baseUrl: string;
}

interface ProviderPreset {
  // Base URL prefilled when the user has not typed one. For Ollama this is the
  // native host root (NO `/v1`): the native provider appends `/api/chat`, so a
  // `/v1` suffix would produce the invalid `.../v1/api/chat`. For Anthropic
  // protocol selections it must already carry the `/v1`-style path because the
  // anthropic adapter appends only `/messages`.
  baseUrl: string;
  // Default model, used only when confidently known from the provider's
  // current docs; blank means "let the user type it" (the input hint guides
  // them).
  model: string;
  // Local providers (Ollama) need no API key.
  keyOptional: boolean;
  // Backend `provider_type` persisted for this selection. Branded quick-start
  // entries deliberately reuse an existing adapter (openai-compat, deepseek)
  // instead of inventing provider_type strings the pool would skip.
  providerType: string;
  // These APIs officially document native tool calling, but the openai-compat
  // adapter defaults to prompt-based tools; persist an explicit override so
  // structured tool calls reach APIs that support them.
  nativeToolCalling?: boolean;
  // Subscription/coding-plan selections: the key is issued for a dedicated
  // coding endpoint and must never be sent to the provider's public API URL.
  codingPlan?: boolean;
  // Localized explanation (key/endpoint sourcing and plan caveats) rendered
  // under the provider selector; undefined hides the paragraph.
  helpKey?: string;
}

// The quick-start selections offered in the wizard's provider step. Values are
// wizard selection ids, not necessarily backend provider types: branded
// entries (Kimi, GLM, ...) map to an existing adapter via their preset's
// `providerType`, which keeps the selection identity stable in the UI while
// the persisted provider still routes to a supported backend. The full set
// (Azure, ...) lives in Settings > Providers.
export const WIZARD_PROVIDER_TYPES: { value: string; label: string }[] = [
  { value: "openai", label: "OpenAI" },
  { value: "openai-compat", label: "OpenAI-compatible" },
  { value: "ollama", label: "Ollama (local)" },
  { value: "ollama-cloud", label: "Ollama Cloud" },
  { value: "anthropic", label: "Anthropic" },
  { value: "gemini", label: "Gemini" },
  { value: "deepseek", label: "DeepSeek" },
  { value: "kimi-api", label: "Kimi API (Moonshot)" },
  { value: "kimi-coding", label: "Kimi Coding (subscription)" },
  { value: "glm-bigmodel", label: "GLM API (BigModel.cn)" },
  { value: "glm-coding", label: "GLM Coding Plan (BigModel.cn)" },
  { value: "zai-glm", label: "GLM API (Z.AI)" },
  { value: "zai-coding", label: "GLM Coding Plan (Z.AI)" },
];

export const WIZARD_PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4o", keyOptional: false, providerType: "openai" },
  "openai-compat": { baseUrl: "", model: "", keyOptional: false, providerType: "openai-compat" },
  ollama: { baseUrl: "http://localhost:11434", model: "llama3.1:8b", keyOptional: true, providerType: "ollama" },
  // Ollama Cloud: hosted at ollama.com, needs an API key (unlike local).
  "ollama-cloud": { baseUrl: "https://ollama.com", model: "gpt-oss:120b", keyOptional: false, providerType: "ollama-cloud" },
  anthropic: { baseUrl: "https://api.anthropic.com/v1", model: "", keyOptional: false, providerType: "anthropic" },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com/v1beta", model: "", keyOptional: false, providerType: "gemini" },
  // DeepSeek native: the backend routes provider_type "deepseek" through the
  // OpenAI adapter and already resolves native tool calling for it.
  deepseek: { baseUrl: "https://api.deepseek.com", model: "deepseek-flash", keyOptional: false, providerType: "deepseek", helpKey: "setup.providerHelp.deepseek" },
  // Kimi public API (platform.kimi.ai): OpenAI-compatible chat completions.
  // Mainland China accounts use https://api.moonshot.cn/v1 instead (editable
  // under Advanced).
  "kimi-api": { baseUrl: "https://api.moonshot.ai/v1", model: "kimi-k3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.kimiApi" },
  // Kimi Coding subscription: the membership key only works on the dedicated
  // coding endpoint, which also serves OpenAI-compatible chat completions.
  "kimi-coding": { baseUrl: "https://api.kimi.ai/coding/v1", model: "kimi-for-coding", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.kimiCoding" },
  // GLM standard API on BigModel.cn (pay-as-you-go platform key).
  "glm-bigmodel": { baseUrl: "https://open.bigmodel.cn/api/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.glmBigmodel" },
  // GLM Coding Plan on BigModel.cn: coding-plan keys are separate from
  // platform keys and only draw plan quota on this dedicated endpoint.
  "glm-coding": { baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.glmCoding" },
  // Z.AI (international) GLM standard API.
  "zai-glm": { baseUrl: "https://api.z.ai/api/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, helpKey: "setup.providerHelp.zaiGlm" },
  // Z.AI GLM Coding Plan: OpenAI-compatible coding endpoint documented for
  // third-party OpenAI-compatible clients.
  "zai-coding": { baseUrl: "https://api.z.ai/api/coding/paas/v4", model: "glm-5.3", keyOptional: false, providerType: "openai-compat", nativeToolCalling: true, codingPlan: true, helpKey: "setup.providerHelp.zaiCoding" },
};

export function wizardProviderPreset(providerType: string): ProviderPreset {
  return WIZARD_PROVIDER_PRESETS[providerType] ?? WIZARD_PROVIDER_PRESETS["openai-compat"];
}

// Build the provider to persist from the wizard's Providers step, or null when
// there is nothing to save (no API key and no base URL). Persists the preset's
// backend `providerType` -- branded selections must reach a supported adapter,
// and guessing OpenAI-compat from the URL would misroute native providers --
// while honoring any endpoint/model the user edited.
export function resolveWizardProvider(input: WizardProviderInput): Provider | null {
  const preset = wizardProviderPreset(input.providerType || "openai");
  const key = input.apiKey.trim();
  const url = input.baseUrl.trim() || preset.baseUrl;
  const model = input.model.trim() || preset.model;

  // Persist only when we have a credential or an endpoint to reach. Local
  // providers supply a preset base URL, so Ollama always has something to save.
  if (!key && !url) return null;

  return normalizeProvider({
    id: "default",
    provider_type: preset.providerType,
    model,
    base_url: url || null,
    api_key: key || null,
    tool_calling_mode: preset.nativeToolCalling ? "native" : null,
    tags: ["general", "reasoning", "code"],
  });
}
