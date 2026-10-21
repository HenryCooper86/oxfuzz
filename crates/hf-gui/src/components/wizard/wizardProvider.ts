// Pure provider-resolution logic for the setup wizard's Providers step.
// Kept out of SetupWizard.tsx so the component file only exports components
// (satisfies react-refresh/only-export-components) and so this is unit-testable.

import { normalizeProvider, type Provider } from "../settings/providerTypes";
import { providerPreset } from "../../lib/providerPresets";

export interface WizardProviderInput {
  providerType: string;
  apiKey: string;
  model: string;
  baseUrl: string;
}


// Build the provider to persist from the wizard's Providers step, or null when
// there is nothing to save (no API key and no base URL). Persists the preset's
// backend `providerType` -- branded selections must reach a supported adapter,
// and guessing OpenAI-compat from the URL would misroute native providers --
// while honoring any endpoint/model the user edited.
export function resolveWizardProvider(input: WizardProviderInput): Provider | null {
  const preset = providerPreset(input.providerType || "openai");
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
