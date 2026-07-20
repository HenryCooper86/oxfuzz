import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

describe("setup wizard: Ollama provider support", () => {
  const wizard = source("../components/wizard/SetupWizard.tsx");

  it("offers a provider-type selector wired to the shared preset list", () => {
    expect(wizard).toContain("WIZARD_PROVIDER_TYPES");
    expect(wizard).toContain('t("wizard.providerType")');
  });

  it("persists the selected provider type via resolveWizardProvider (no URL guessing)", () => {
    expect(wizard).toContain("resolveWizardProvider(");
    // The old heuristic that forced the type from the URL is gone.
    expect(wizard).not.toContain('? "openai" : "openai-compat"');
  });

  it("advertises the correct native Ollama base URL in Settings (no /v1)", () => {
    const providers = source("../components/settings/ProvidersTab.tsx");
    expect(providers).toContain('ollama: "http://localhost:11434"');
    expect(providers).not.toContain("http://localhost:11434/v1");
  });
});

describe("setup wizard: DefectDojo step", () => {
  it("registers a defectdojo step and renders the live step component", () => {
    const wizard = source("../components/wizard/SetupWizard.tsx");
    expect(wizard).toContain('"defectdojo"');
    expect(wizard).toContain("DefectDojoWizardStep");
  });

  it("drives the DefectDojo lifecycle + config commands", () => {
    const step = source("../components/wizard/DefectDojoWizardStep.tsx");
    expect(step).toContain('"defectdojo_status"');
    expect(step).toContain('"defectdojo_start"');
    expect(step).toContain('"get_defectdojo_config"');
    expect(step).toContain('"patch_defectdojo_config"');
  });
});
