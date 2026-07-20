import { describe, expect, it } from "vitest";
import { resolveWizardProvider, WIZARD_PROVIDER_PRESETS } from "./wizardProvider";

describe("resolveWizardProvider", () => {
  it("persists a native Ollama provider from defaults with no API key", () => {
    const p = resolveWizardProvider({ providerType: "ollama", apiKey: "", model: "", baseUrl: "" });
    expect(p).not.toBeNull();
    expect(p?.provider_type).toBe("ollama");
    // The native provider appends /api/chat, so the base URL must NOT carry /v1.
    expect(p?.base_url).toBe("http://localhost:11434");
    expect(p?.base_url).not.toContain("/v1");
    expect(p?.api_key).toBeNull();
    expect(p?.model).toBe(WIZARD_PROVIDER_PRESETS.ollama.model);
  });

  it("honors an explicit Ollama base URL the user typed", () => {
    const p = resolveWizardProvider({
      providerType: "ollama",
      apiKey: "",
      model: "qwen2.5:7b",
      baseUrl: "http://192.168.1.5:11434",
    });
    expect(p?.base_url).toBe("http://192.168.1.5:11434");
    expect(p?.model).toBe("qwen2.5:7b");
  });

  it("keeps the selected provider type instead of guessing from the URL", () => {
    const p = resolveWizardProvider({
      providerType: "openai-compat",
      apiKey: "sk-x",
      model: "llama-3.1-70b",
      baseUrl: "https://api.together.xyz/v1",
    });
    expect(p?.provider_type).toBe("openai-compat");
  });

  it("persists a standard OpenAI provider", () => {
    const p = resolveWizardProvider({
      providerType: "openai",
      apiKey: "sk-abc",
      model: "",
      baseUrl: "https://api.openai.com/v1",
    });
    expect(p?.provider_type).toBe("openai");
    expect(p?.api_key).toBe("sk-abc");
    expect(p?.model).toBe("gpt-4o");
  });

  it("returns null when there is nothing to persist (no key, no URL)", () => {
    const p = resolveWizardProvider({ providerType: "openai-compat", apiKey: "", model: "", baseUrl: "" });
    expect(p).toBeNull();
  });
});
