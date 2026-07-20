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
  // `/v1` suffix would produce the invalid `.../v1/api/chat`.
  baseUrl: string;
  // Default model, used only when confidently known; blank means "let the user
  // type it" (the input placeholder guides them).
  model: string;
  // Local providers (Ollama) need no API key.
  keyOptional: boolean;
}

// The provider types offered in the wizard's quick-start selector. The full set
// (Azure, DeepSeek, ...) lives in Settings > Providers.
export const WIZARD_PROVIDER_TYPES: { value: string; label: string }[] = [
  { value: "openai", label: "OpenAI" },
  { value: "openai-compat", label: "OpenAI-compatible" },
  { value: "ollama", label: "Ollama (local)" },
  { value: "ollama-cloud", label: "Ollama Cloud" },
  { value: "anthropic", label: "Anthropic" },
  { value: "gemini", label: "Gemini" },
];

export const WIZARD_PROVIDER_PRESETS: Record<string, ProviderPreset> = {
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4o", keyOptional: false },
  "openai-compat": { baseUrl: "", model: "", keyOptional: false },
  ollama: { baseUrl: "http://localhost:11434", model: "llama3.1:8b", keyOptional: true },
  // Ollama Cloud: hosted at ollama.com, needs an API key (unlike local).
  "ollama-cloud": { baseUrl: "https://ollama.com", model: "gpt-oss:120b", keyOptional: false },
  anthropic: { baseUrl: "https://api.anthropic.com/v1", model: "", keyOptional: false },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com/v1beta", model: "", keyOptional: false },
};

export function wizardProviderPreset(providerType: string): ProviderPreset {
  return WIZARD_PROVIDER_PRESETS[providerType] ?? WIZARD_PROVIDER_PRESETS["openai-compat"];
}

// Build the provider to persist from the wizard's Providers step, or null when
// there is nothing to save (no API key and no base URL). Uses the explicitly
// selected provider type -- it no longer guesses OpenAI-compat from the URL, so
// local providers like Ollama reach their native backend.
export function resolveWizardProvider(input: WizardProviderInput): Provider | null {
  const providerType = input.providerType || "openai";
  const preset = wizardProviderPreset(providerType);
  const key = input.apiKey.trim();
  const url = input.baseUrl.trim() || preset.baseUrl;
  const model = input.model.trim() || preset.model;

  // Persist only when we have a credential or an endpoint to reach. Local
  // providers supply a preset base URL, so Ollama always has something to save.
  if (!key && !url) return null;

  return normalizeProvider({
    id: "default",
    provider_type: providerType,
    model,
    base_url: url || null,
    api_key: key || null,
    tags: ["general", "reasoning", "code"],
  });
}
